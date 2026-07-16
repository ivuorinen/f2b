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
	defer func() {
		signal.Stop(sigCh)
		// A signal delivered as the command completed may still sit in the
		// buffer with its goroutine not yet scheduled — record it so main
		// doesn't exit 0 on an interrupted run.
		select {
		case sig := <-sigCh:
			if s, ok := sig.(syscall.Signal); ok {
				interruptCode.Store(int32(128 + int(s))) // #nosec G115 -- signal numbers are tiny
			}
		default:
		}
		close(sigCh)
	}()
	go func() {
		sig, ok := <-sigCh
		if !ok {
			return
		}
		if s, ok := sig.(syscall.Signal); ok {
			interruptCode.Store(int32(128 + int(s))) // #nosec G115 -- signal numbers are tiny
		}
		signal.Stop(sigCh)
		cancel()
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
	rootCmd.AddCommand(LogsWatchCmd(ctx, client, &cfg))
	rootCmd.AddCommand(ServiceCmd(&cfg))
	rootCmd.AddCommand(VersionCmd(&cfg))
	rootCmd.AddCommand(TestFilterCmd(client, &cfg))
	rootCmd.AddCommand(completionCmd())
	return rootCmd.ExecuteContext(ctx)
}

func init() {
	// Initialize logging configuration
	initLogging()

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
	rootCmd.PersistentFlags().String(constants.FlagLogLevel, logLevel, "Log level (debug, info, warn, error)")

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

		logFileFlag, _ := cmd.Flags().GetString(constants.FlagLogFile)
		if logFileFlag == "" {
			syncContextualLogger()
			return nil
		}

		// Validate log file path for security
		cleanPath, err := filepath.Abs(filepath.Clean(logFileFlag))
		if err != nil {
			return fmt.Errorf("invalid log file path %s: %w", logFileFlag, err)
		}

		// #nosec G304 - Path is cleaned and made absolute above; filepath.Clean
		// already normalizes any traversal sequences.
		f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, constants.DefaultFilePermissions)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %w", cleanPath, err)
		}
		Logger.SetOutput(f)
		// Register cleanup for graceful shutdown
		registerLogFileCleanup(f, cleanPath)
		syncContextualLogger()
		return nil
	}
}

// syncContextualLogger propagates the configured level and output of the main
// Logger to the structured operation logger, which was otherwise frozen at its
// package-init values and ignored --log-level/--log-file.
func syncContextualLogger() {
	if cl := GetContextualLogger(); cl != nil {
		cl.SetLevel(Logger.GetLevel())
		cl.SetOutput(Logger.Output())
	}
}

// registerLogFileCleanup registers a log file so cleanupResources closes it
// when Execute returns. Signal handling lives in Execute's NotifyContext: a
// signal cancels the command context, the command returns, and the deferred
// cleanup runs — no competing handler that os.Exits mid-command and skips the
// metrics/log-file defers.
func registerLogFileCleanup(f *os.File, _ string) {
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
		Run: func(cmd *cobra.Command, args []string) {
			// Get the root command from the current command's parent hierarchy
			root := cmd.Root()
			// Note: Cobra's Args validation ensures we have exactly 1 valid argument
			switch args[0] {
			case "bash":
				_ = root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				_ = root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				_ = root.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				_ = root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			}
		},
	}
}
