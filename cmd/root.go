// Package cmd implements all CLI commands for the f2b tool, providing secure
// Fail2Ban management operations including jail monitoring, IP banning/unbanning,
// log analysis, and service management with comprehensive input validation.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ivuorinen/f2b/constants"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// interruptCode holds 128+n when signal n interrupted the current Execute
// run, 0 otherwise. Read via SignalExitCode after Execute returns.
var interruptCode atomic.Int32

// SignalExitCode returns the conventional exit code for a signal-interrupted
// run (130 for SIGINT, 143 for SIGTERM), or 0 when no signal was received.
func SignalExitCode() int {
	return int(interruptCode.Load())
}

// EnvConfig returns the package-level config built from the environment at
// init time — the same instance the CLI flags are bound to. main uses it so
// the environment is read (and warned about) once per process.
func EnvConfig() Config {
	return cfg
}

// Config holds global configuration for the CLI, including log and filter directories and output format.
type Config struct {
	LogDir          string        // Path to Fail2Ban log directory
	FilterDir       string        // Path to Fail2Ban filter directory
	Format          string        // Output format: PlainFormat or JSONFormat
	CommandTimeout  time.Duration // Timeout for individual fail2ban commands
	FileTimeout     time.Duration // Timeout for file operations
	ParallelTimeout time.Duration // Timeout for parallel operations

	// configErr holds a fatal configuration error (e.g. an explicitly-set but
	// invalid F2B_LOG_DIR/F2B_FILTER_DIR) discovered while building the config.
	// Execute returns it instead of running against silently-substituted defaults.
	configErr error
}

var (
	rootCmd = &cobra.Command{
		Use:   "f2b",
		Short: "Fail2Ban CLI helper",
		Long:  "Fail2Ban CLI tool implemented in Go using Cobra.",
		// Report runtime errors once via our own handler instead of letting
		// cobra reprint them and dump usage as if they were syntax errors.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cfg Config

	// Resource cleanup tracking
	logFile      *os.File
	logFileMutex sync.Mutex
)

// Execute runs the CLI application with the given client and configuration.
func Execute(client fail2ban.Client, config Config) error {
	cfg = config
	// Fail fast on a fatal config error (e.g. an explicitly-set but invalid
	// F2B_LOG_DIR/F2B_FILTER_DIR) rather than operating on a silently
	// substituted default directory.
	if cfg.configErr != nil {
		return cfg.configErr
	}
	// Ensure cleanup happens even if the program exits unexpectedly
	defer cleanupResources()

	// Derive a context that is canceled on SIGINT/SIGTERM so long-running
	// commands (e.g. logs-watch) can shut down gracefully via cmd.Context().
	// The signal is recorded before cancellation so main can exit 128+n
	// (130/143) after the graceful teardown, and handling reverts to the
	// default after the first signal so a second Ctrl-C force-kills a command
	// stuck in non-context-aware work.
	interruptCode.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	stopWatching := watchSignals(sigCh, cancel)
	defer func() {
		signal.Stop(sigCh)
		stopWatching()
	}()
	// Re-register from scratch: cobra does not dedupe AddCommand, so a second
	// Execute in the same process (tests, embedding) would otherwise dispatch
	// to the closures bound to the FIRST call's client and signal context.
	rootCmd.ResetCommands()
	rootCmd.AddCommand(ListJailsCmd(client, &cfg))
	rootCmd.AddCommand(StatusCmd(client, &cfg))
	rootCmd.AddCommand(BannedCmd(client, &cfg))
	rootCmd.AddCommand(BanCmd(client, &cfg))
	rootCmd.AddCommand(UnbanCmd(client, &cfg))
	rootCmd.AddCommand(TestIPCmd(client, &cfg))
	rootCmd.AddCommand(LogsCmd(client, &cfg))
	rootCmd.AddCommand(LogsWatchCmd(client, &cfg))
	rootCmd.AddCommand(ServiceCmd(&cfg))
	rootCmd.AddCommand(VersionCmd(&cfg))
	rootCmd.AddCommand(TestFilterCmd(client, &cfg))
	rootCmd.AddCommand(completionCmd())
	return rootCmd.ExecuteContext(ctx)
}

// watchSignals records the first signal from sigCh as the exit code, restores
// default handling so a second Ctrl-C force-kills, and cancels the command.
//
// The returned stop joins the goroutine and then drains a signal still
// buffered, so a signal that arrived as the command completed is recorded
// before Execute returns and main reads SignalExitCode. sigCh is never closed:
// os/signal may still send on it.
func watchSignals(sigCh chan os.Signal, cancel context.CancelFunc) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case sig := <-sigCh:
			recordSignal(sig)
			signal.Stop(sigCh)
			cancel()
		case <-quit:
		}
	}()
	return func() {
		close(quit)
		<-done
		select {
		case sig := <-sigCh:
			recordSignal(sig)
		default:
		}
	}
}

// recordSignal stores the conventional 128+n exit code for sig.
func recordSignal(sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		interruptCode.Store(int32(128 + int(s))) // #nosec G115 -- signal numbers are tiny
	}
}

func init() {
	// Set defaults from env
	cfg = NewConfigFromEnv()

	rootCmd.PersistentFlags().StringVar(&cfg.LogDir, "log-dir", cfg.LogDir, "Fail2Ban log directory")
	rootCmd.PersistentFlags().StringVar(&cfg.FilterDir, "filter-dir", cfg.FilterDir, "Fail2Ban filter directory")
	rootCmd.PersistentFlags().StringVar(&cfg.Format, constants.FlagFormat, cfg.Format, constants.FlagDescFormat)
	rootCmd.PersistentFlags().
		DurationVar(&cfg.CommandTimeout, "command-timeout", cfg.CommandTimeout, "Timeout for individual fail2ban commands")
	rootCmd.PersistentFlags().
		DurationVar(&cfg.FileTimeout, "file-timeout", cfg.FileTimeout, "Timeout for file operations")
	rootCmd.PersistentFlags().
		DurationVar(&cfg.ParallelTimeout, "parallel-timeout", cfg.ParallelTimeout, "Timeout for parallel operations")

	// Log level configuration
	logLevel := os.Getenv(constants.EnvLogLevel)
	if logLevel == "" {
		logLevel = constants.DefaultLogLevel
	}

	// Log file support
	logFile := os.Getenv("F2B_LOG_FILE")
	rootCmd.PersistentFlags().String(constants.FlagLogFile, logFile, "Path to log file for f2b logs (optional)")
	rootCmd.PersistentFlags().String(
		constants.FlagLogLevel, logLevel, "Log level (debug, info, warn|warning, error, fatal, panic)",
	)

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		// Validate AFTER flag parsing so flag-provided values are covered too
		// (validating before ExecuteContext left --format/--command-timeout/
		// --log-dir entirely unvalidated). Invalid values are a hard error.
		if err := cfg.ValidateConfig(); err != nil {
			return err
		}

		// Apply --log-level first so it takes effect even if --log-file setup
		// later fails; previously an invalid log-file path returned early and
		// silently skipped the level change.
		level, _ := cmd.Flags().GetString(constants.FlagLogLevel)
		Logger.SetLevel(parseLogLevel(level))

		// The one place the log format is chosen: JSON for a --log-file, text
		// for the terminal. Logger and the contextual logger share this
		// handler, so a sink never mixes formats, and every line carries the
		// command path so a "Command failed" record says which one failed.
		format := fail2ban.SlogText
		logFileFlag, _ := cmd.Flags().GetString(constants.FlagLogFile)
		if logFileFlag != "" {
			cleanPath, err := resolveLogFilePath(logFileFlag)
			if err != nil {
				return err
			}

			// #nosec G304 - resolveLogFilePath confines the file to the log allowlist.
			f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, constants.DefaultFilePermissions)
			if err != nil {
				return fmt.Errorf("failed to open log file %s: %w", cleanPath, err)
			}
			Logger.SetOutput(f)
			// Register cleanup for graceful shutdown
			registerLogFileCleanup(f)
			format = fail2ban.SlogJSON
		}
		Logger.Reconfigure(format, logFieldCommandPath, cmd.CommandPath())
		return nil
	}
}

// logFieldCommandPath is the log field naming the running command, e.g.
// "f2b ban". It is not "command": the IP commands already log that key with
// the bare command name.
const logFieldCommandPath = "command_path"

// resolveLogFilePath returns the absolute --log-file path after confining its
// directory to the log allowlist. The file is created or appended for every
// subcommand, so under `sudo f2b` an unchecked path let the caller create a
// root-owned file anywhere (e.g. /etc/cron.d/x) or append log lines to one
// (e.g. /root/.bashrc).
func resolveLogFilePath(logFile string) (string, error) {
	cleanPath, err := filepath.Abs(filepath.Clean(logFile))
	if err != nil {
		return "", fmt.Errorf("invalid log file path %s: %w", logFile, err)
	}
	dir, err := fail2ban.ValidatePathWithSecurity(filepath.Dir(cleanPath), fail2ban.CreateLogPathConfig())
	if err != nil {
		return "", fmt.Errorf("log file %s is outside the allowed log directories: %w", cleanPath, err)
	}
	return filepath.Join(dir, filepath.Base(cleanPath)), nil
}

// registerLogFileCleanup registers a log file so cleanupResources closes it
// when Execute returns. Signal handling lives in Execute's watchSignals: a
// signal cancels the command context, the command returns, and the deferred
// cleanup runs — no competing handler that os.Exits mid-command and skips the
// log-file defer.
func registerLogFileCleanup(f *os.File) {
	logFileMutex.Lock()
	logFile = f
	logFileMutex.Unlock()
}

// cleanupResources performs cleanup of allocated resources
func cleanupResources() {
	logFileMutex.Lock()
	defer logFileMutex.Unlock()

	if logFile != nil {
		if err := logFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to close log file: %v\n", err)
		}
		logFile = nil
	}
}

// slog has no Fatal/Panic levels; map them above Error so selecting them still
// silences everything below, preserving logrus's original level ordering.
const (
	levelFatal = slog.LevelError + 4
	levelPanic = slog.LevelError + 8
)

// parseLogLevel converts a string log level to its slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case constants.DefaultLogLevel:
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "fatal":
		return levelFatal
	case "panic":
		return levelPanic
	default:
		// Log warning about invalid log level before falling back to default
		Logger.WithField("invalid_level", level).Warn("Invalid log level specified, falling back to 'info'")
		return slog.LevelInfo
	}
}

// completionCmd provides shell completion scripts for bash, zsh, fish, and powershell.
func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `To load completions:

Bash:

	$ source <(f2b completion bash)

	# To load completions for each session, execute once:
	# Linux:
	$ f2b completion bash > /etc/bash_completion.d/f2b
	# macOS:
	$ f2b completion bash > /usr/local/etc/bash_completion.d/f2b

Zsh:

	$ echo "autoload -U compinit; compinit" >> ~/.zshrc
	$ f2b completion zsh > "${fpath[1]}/_f2b"

Fish:

	$ f2b completion fish | source
	$ f2b completion fish > ~/.config/fish/completions/f2b.fish

PowerShell:

	PS> f2b completion powershell | Out-String | Invoke-Expression
	PS> f2b completion powershell > f2b.ps1
`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		// RunE so a failed write (e.g. redirecting into a full filesystem)
		// fails the command instead of exiting 0 with a truncated script.
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get the root command from the current command's parent hierarchy
			root := cmd.Root()
			// Note: Cobra's Args validation ensures we have exactly 1 valid argument
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default: // "powershell"
				return root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			}
		},
	}
}
