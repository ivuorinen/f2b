package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// Config holds global configuration for the CLI, including log and filter directories and output format.
type Config struct {
	LogDir          string        // Path to Fail2Ban log directory
	FilterDir       string        // Path to Fail2Ban filter directory
	Format          string        // Output format: "plain" or "json"
	CommandTimeout  time.Duration // Timeout for individual fail2ban commands
	FileTimeout     time.Duration // Timeout for file operations
	ParallelTimeout time.Duration // Timeout for parallel operations
}

var (
	rootCmd = &cobra.Command{
		Use:   "f2b",
		Short: "Fail2Ban CLI helper",
		Long:  "Fail2Ban CLI tool implemented in Go using Cobra.",
	}
	cfg Config

	// Resource cleanup tracking
	logFile      *os.File
	logFileMutex sync.Mutex
	cleanupOnce  sync.Once
)

// Execute runs the CLI application with the given client and configuration.
func Execute(client fail2ban.Client, config Config) error {
	cfg = config
	// Ensure cleanup happens even if the program exits unexpectedly
	defer cleanupResources()
	ctx := context.Background()
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
	return rootCmd.Execute()
}

func init() {
	// Set defaults from env
	cfg = NewConfigFromEnv()

	rootCmd.PersistentFlags().StringVar(&cfg.LogDir, "log-dir", cfg.LogDir, "Fail2Ban log directory")
	rootCmd.PersistentFlags().StringVar(&cfg.FilterDir, "filter-dir", cfg.FilterDir, "Fail2Ban filter directory")
	rootCmd.PersistentFlags().StringVar(&cfg.Format, "format", cfg.Format, "Output format: plain or json")
	rootCmd.PersistentFlags().
		DurationVar(&cfg.CommandTimeout, "command-timeout", cfg.CommandTimeout, "Timeout for individual fail2ban commands")
	rootCmd.PersistentFlags().
		DurationVar(&cfg.FileTimeout, "file-timeout", cfg.FileTimeout, "Timeout for file operations")
	rootCmd.PersistentFlags().
		DurationVar(&cfg.ParallelTimeout, "parallel-timeout", cfg.ParallelTimeout, "Timeout for parallel operations")

	// Log level configuration
	logLevel := os.Getenv("F2B_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	// Log file support
	logFile := os.Getenv("F2B_LOG_FILE")
	rootCmd.PersistentFlags().String("log-file", logFile, "Path to log file for f2b logs (optional)")
	rootCmd.PersistentFlags().String("log-level", logLevel, "Log level (debug, info, warn, error)")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		logFileFlag, _ := cmd.Flags().GetString("log-file")
		if logFileFlag != "" {
			// Validate log file path for security
			cleanPath, err := filepath.Abs(filepath.Clean(logFileFlag))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid log file path %s: %v\n", logFileFlag, err)
				return
			}

			// Additional security check: ensure path doesn't contain dangerous patterns
			if strings.Contains(cleanPath, "..") || strings.Contains(cleanPath, "//") {
				fmt.Fprintf(os.Stderr, "Invalid log file path %s: contains dangerous patterns\n", logFileFlag)
				return
			}

			// #nosec G304 - Path is validated and sanitized above
			f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err == nil {
				Logger.SetOutput(f)
				// Register cleanup for graceful shutdown
				registerLogFileCleanup(f, cleanPath)
			} else {
				fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", cleanPath, err)
			}
		}
		level, _ := cmd.Flags().GetString("log-level")
		Logger.SetLevel(parseLogLevel(level))
	}
}

// registerLogFileCleanup registers a log file for cleanup and sets up signal handling
func registerLogFileCleanup(f *os.File, _ string) {
	logFileMutex.Lock()
	logFile = f
	logFileMutex.Unlock()

	// Setup signal handler for graceful cleanup (only once)
	cleanupOnce.Do(func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			cleanupResources()
			os.Exit(0)
		}()
	})
}

// cleanupResources performs cleanup of allocated resources
func cleanupResources() {
	logFileMutex.Lock()
	defer logFileMutex.Unlock()

	if logFile != nil {
		if err := logFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to close log file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Log file closed successfully\n")
		}
		logFile = nil
	}
}

// parseLogLevel parses a string log level for logrus.
func parseLogLevel(level string) logrus.Level {
	switch level {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn", "warning":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	case "panic":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
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
			default:
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Unsupported shell type: %s\n", args[0]); err != nil {
					Logger.WithError(err).Error("failed to write unsupported shell type")
				}
			}
		},
	}
}
