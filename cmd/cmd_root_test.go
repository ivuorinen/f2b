package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected slog.Level
	}{
		{
			name:     "debug level",
			level:    "debug",
			expected: slog.LevelDebug,
		},
		{
			name:     "info level",
			level:    "info",
			expected: slog.LevelInfo,
		},
		{
			name:     "warn level",
			level:    "warn",
			expected: slog.LevelWarn,
		},
		{
			name:     "warning level",
			level:    "warning",
			expected: slog.LevelWarn,
		},
		{
			name:     "error level",
			level:    "error",
			expected: slog.LevelError,
		},
		{
			name:     "fatal level",
			level:    "fatal",
			expected: levelFatal,
		},
		{
			name:     "panic level",
			level:    "panic",
			expected: levelPanic,
		},
		{
			name:     "unknown level defaults to info",
			level:    "unknown",
			expected: slog.LevelInfo,
		},
		{
			name:     "empty level defaults to info",
			level:    "",
			expected: slog.LevelInfo,
		},
		{
			name:     "uppercase level",
			level:    "DEBUG",
			expected: slog.LevelInfo, // case sensitive, so falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.level)
			if result != tt.expected {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test that Config struct has reasonable defaults
	config := Config{}

	// Initially empty
	if config.LogDir != "" {
		t.Errorf("expected empty LogDir, got %q", config.LogDir)
	}
	if config.FilterDir != "" {
		t.Errorf("expected empty FilterDir, got %q", config.FilterDir)
	}
	if config.Format != "" {
		t.Errorf("expected empty Format, got %q", config.Format)
	}
}

func TestEnvironmentVariableSetup(t *testing.T) {
	// Save original environment
	// Set up environment variables using t.Setenv for automatic cleanup
	t.Setenv("F2B_LOG_DIR", os.Getenv("F2B_LOG_DIR"))
	t.Setenv("F2B_FILTER_DIR", os.Getenv("F2B_FILTER_DIR"))
	t.Setenv("F2B_LOG_LEVEL", os.Getenv("F2B_LOG_LEVEL"))
	t.Setenv("F2B_LOG_FILE", os.Getenv("F2B_LOG_FILE"))

	tests := []struct {
		name     string
		envVar   string
		envValue string
		expected string
	}{
		{
			name:     "F2B_LOG_DIR environment variable",
			envVar:   "F2B_LOG_DIR",
			envValue: "/custom/log/dir",
			expected: "/custom/log/dir",
		},
		{
			name:     "F2B_FILTER_DIR environment variable",
			envVar:   "F2B_FILTER_DIR",
			envValue: "/custom/filter/dir",
			expected: "/custom/filter/dir",
		},
		{
			name:     "F2B_LOG_LEVEL environment variable",
			envVar:   "F2B_LOG_LEVEL",
			envValue: "debug",
			expected: "debug",
		},
		{
			name:     "F2B_LOG_FILE environment variable",
			envVar:   "F2B_LOG_FILE",
			envValue: "/tmp/f2b.log",
			expected: "/tmp/f2b.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable using t.Setenv for automatic cleanup
			t.Setenv(tt.envVar, tt.envValue)

			// Get the value
			result := os.Getenv(tt.envVar)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestConfigStructure(t *testing.T) {
	config := Config{
		LogDir:    "/test/log",
		FilterDir: "/test/filter",
		Format:    "json",
	}

	if config.LogDir != "/test/log" {
		t.Errorf("expected LogDir '/test/log', got %q", config.LogDir)
	}
	if config.FilterDir != "/test/filter" {
		t.Errorf("expected FilterDir '/test/filter', got %q", config.FilterDir)
	}
	if config.Format != "json" {
		t.Errorf("expected Format 'json', got %q", config.Format)
	}
}

func TestCompletionCmdStructure(t *testing.T) {
	cmd := completionCmd()

	if cmd.Use != "completion [bash|zsh|fish|powershell]" {
		t.Errorf("unexpected completion command Use: %q", cmd.Use)
	}

	if cmd.Short != "Generate shell completion scripts" {
		t.Errorf("unexpected completion command Short: %q", cmd.Short)
	}

	expectedValidArgs := []string{"bash", "zsh", "fish", "powershell"}
	if len(cmd.ValidArgs) != len(expectedValidArgs) {
		t.Errorf("expected %d ValidArgs, got %d", len(expectedValidArgs), len(cmd.ValidArgs))
	}

	for i, expected := range expectedValidArgs {
		if i >= len(cmd.ValidArgs) || cmd.ValidArgs[i] != expected {
			t.Errorf("expected ValidArgs[%d] = %q, got %q", i, expected, cmd.ValidArgs[i])
		}
	}

	if !cmd.DisableFlagsInUseLine {
		t.Errorf("expected DisableFlagsInUseLine to be true")
	}
}

func TestGlobalVariables(t *testing.T) {
	// Test that global variables are properly initialized
	if rootCmd == nil {
		t.Fatal("rootCmd should be initialized")
	}

	if rootCmd.Use != "f2b" {
		t.Errorf("expected rootCmd.Use to be 'f2b', got %q", rootCmd.Use)
	}

	if rootCmd.Short != "Fail2Ban CLI helper" {
		t.Errorf("expected rootCmd.Short to be 'Fail2Ban CLI helper', got %q", rootCmd.Short)
	}

	expectedLong := "Fail2Ban CLI tool implemented in Go using Cobra."
	if rootCmd.Long != expectedLong {
		t.Errorf("expected rootCmd.Long to be %q, got %q", expectedLong, rootCmd.Long)
	}
}

// BenchmarkParseLogLevel benchmarks the log level parsing function
func BenchmarkParseLogLevel(b *testing.B) {
	levels := []string{"debug", "info", "warn", "error", "unknown"}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		level := levels[i%len(levels)]
		parseLogLevel(level)
	}
}

// TestDefaultValues tests the default values used in the configuration
func TestDefaultValues(t *testing.T) {
	// Clear environment variables for this test using t.Setenv
	t.Setenv("F2B_LOG_DIR", "")
	t.Setenv("F2B_FILTER_DIR", "")

	// Test default values when environment variables are not set
	logDir := os.Getenv("F2B_LOG_DIR")
	if logDir != "" {
		t.Errorf("expected empty F2B_LOG_DIR, got %q", logDir)
	}

	filterDir := os.Getenv("F2B_FILTER_DIR")
	if filterDir != "" {
		t.Errorf("expected empty F2B_FILTER_DIR, got %q", filterDir)
	}
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() fail2ban.Client
		config      Config
		wantError   bool
	}{
		{
			name: "successful execution with mock client",
			setupClient: func() fail2ban.Client {
				return fail2ban.NewMockClient()
			},
			config:    validTestConfig("plain"),
			wantError: false,
		},
		{
			name: "execution with json format",
			setupClient: func() fail2ban.Client {
				return fail2ban.NewMockClient()
			},
			config:    validTestConfig("json"),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			// Capture stdout to prevent output during tests
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w

			// Set up a simple test command that will exit quickly
			originalArgs := os.Args
			os.Args = []string{"f2b", "version"}

			err = Execute(client, tt.config)

			// Restore stdout
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close writer: %v", err)
			}
			os.Stdout = oldStdout
			os.Args = originalArgs

			// Read and discard output
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}

			AssertError(t, err, tt.wantError, tt.name)
		})
	}
}

func TestExecuteWithRealCommands(t *testing.T) {
	// Test that Execute properly adds all commands
	client := fail2ban.NewMockClient()
	config := Config{
		LogDir:    "/tmp",
		FilterDir: "/tmp",
		Format:    "plain",
	}

	// Create a new root command to test command registration
	originalRootCmd := rootCmd
	rootCmd = &cobra.Command{
		Use:   "f2b",
		Short: "Fail2Ban CLI helper",
		Long:  "Fail2Ban CLI tool implemented in Go using Cobra.",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	originalArgs := os.Args
	os.Args = []string{"f2b", "help"}

	err = Execute(client, config)

	// Restore
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	os.Stdout = oldStdout
	os.Args = originalArgs
	rootCmd = originalRootCmd

	// Read output
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	output := buf.String()

	AssertError(t, err, false, "root help command")

	// Check that help output contains expected commands
	expectedCommands := []string{
		"list-jails",
		"status",
		"banned",
		"ban",
		"unban",
		"test",
		"logs",
		"logs-watch",
		"service",
		"version",
		"test-filter",
		"completion",
	}
	for _, cmd := range expectedCommands {
		if !strings.Contains(output, cmd) {
			t.Errorf("expected help output to contain command %q", cmd)
		}
	}
}

func TestCompletionCmdExecution(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "bash completion",
			args:       []string{"bash"},
			wantOutput: "__start_f2b",
			wantError:  false,
		},
		{
			name:       "zsh completion",
			args:       []string{"zsh"},
			wantOutput: "#compdef f2b",
			wantError:  false,
		},
		{
			name:       "fish completion",
			args:       []string{"fish"},
			wantOutput: "complete -c f2b",
			wantError:  false,
		},
		{
			name:       "powershell completion",
			args:       []string{"powershell"},
			wantOutput: "Register-ArgumentCompleter",
			wantError:  false,
		},
		{
			name:      "unsupported shell",
			args:      []string{"unsupported"},
			wantError: true, // Cobra returns an error for invalid args due to OnlyValidArgs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Framework doesn't support completion cmd yet, so keeping manual approach:
			// Create a proper root command structure for the test
			testRoot := &cobra.Command{
				Use:   "f2b",
				Short: "Test root command",
			}

			// Add mock client for commands that need it
			mockClient := NewMockClient()
			testConfig := Config{Format: "plain"}

			// Add all the f2b subcommands to create a realistic structure
			testRoot.AddCommand(ListJailsCmd(mockClient, &testConfig))
			testRoot.AddCommand(StatusCmd(mockClient, &testConfig))
			testRoot.AddCommand(BannedCmd(mockClient, &testConfig))
			testRoot.AddCommand(BanCmd(mockClient, &testConfig))
			testRoot.AddCommand(UnbanCmd(mockClient, &testConfig))
			testRoot.AddCommand(TestIPCmd(mockClient, &testConfig))
			testRoot.AddCommand(LogsCmd(mockClient, &testConfig))
			testRoot.AddCommand(LogsWatchCmd(mockClient, &testConfig))
			testRoot.AddCommand(ServiceCmd(&testConfig))
			testRoot.AddCommand(VersionCmd(&testConfig))
			testRoot.AddCommand(TestFilterCmd(mockClient, &testConfig))
			testRoot.AddCommand(completionCmd())

			// Execute the completion command via the root
			// Capture stdout
			var outBuf bytes.Buffer
			testRoot.SetOut(&outBuf)

			// Capture stderr
			var errBuf bytes.Buffer
			testRoot.SetErr(&errBuf)

			args := append([]string{"completion"}, tt.args...)
			testRoot.SetArgs(args)
			err := testRoot.Execute()

			AssertError(t, err, tt.wantError, tt.name)

			output := outBuf.String() + errBuf.String()
			if tt.wantOutput != "" && !tt.wantError {
				// Check for substring anywhere in the output, ignoring leading/trailing whitespace
				if !strings.Contains(output, tt.wantOutput) {
					t.Errorf("expected output to contain %q, got %q", tt.wantOutput, strings.TrimSpace(output))
				}
			}
		})
	}
}

func TestInitFunctionCoverage(t *testing.T) {
	// Test that init function sets up flags correctly
	// We can't directly test init() but we can test its effects

	// Test that persistent flags are set
	if rootCmd.PersistentFlags().Lookup("log-dir") == nil {
		t.Errorf("expected log-dir persistent flag to be set")
	}

	if rootCmd.PersistentFlags().Lookup("filter-dir") == nil {
		t.Errorf("expected filter-dir persistent flag to be set")
	}

	if rootCmd.PersistentFlags().Lookup("format") == nil {
		t.Errorf("expected format persistent flag to be set")
	}

	if rootCmd.PersistentFlags().Lookup("log-file") == nil {
		t.Errorf("expected log-file persistent flag to be set")
	}

	if rootCmd.PersistentFlags().Lookup("log-level") == nil {
		t.Errorf("expected log-level persistent flag to be set")
	}
}

func TestPersistentPreRun(t *testing.T) {
	// Test the PersistentPreRunE function
	if rootCmd.PersistentPreRunE == nil {
		t.Errorf("expected PersistentPreRunE to be set")
		return
	}

	// Create a temporary log file
	tmpFile, err := os.CreateTemp(t.TempDir(), "f2b-test-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil { // #nosec G703 -- test file, path from CreateTemp
			t.Fatalf("failed to remove temp file: %v", err)
		}
	}()
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Fatalf("failed to close temp file: %v", err)
		}
	}()

	// The temp file lives under the dev-path allowlist (/tmp, /var/folders);
	// --log-file is confined to the log allowlist.
	t.Setenv("ALLOW_DEV_PATHS", "1")

	// Test with log file flag
	cmd := &cobra.Command{}
	cmd.Flags().String("log-file", tmpFile.Name(), "test log file")
	cmd.Flags().String("log-level", "debug", "test log level")

	// PersistentPreRunE validates the global cfg first; give it a valid one and
	// restore all mutated global state afterward.
	originalCfg := cfg
	cfg = validTestConfig("plain")
	originalOutput := Logger.Output()
	originalLevel := Logger.GetLevel()
	defer func() {
		cfg = originalCfg
		Logger.SetOutput(originalOutput)
		Logger.SetLevel(originalLevel)
	}()

	// A valid log-file and cfg must succeed and apply the requested level.
	if err := rootCmd.PersistentPreRunE(cmd, []string{}); err != nil {
		t.Fatalf("PersistentPreRunE with a valid log file returned error: %v", err)
	}
	if got := Logger.GetLevel(); got != slog.LevelDebug {
		t.Errorf("log level after PersistentPreRunE = %v, want debug", got)
	}

	// Each --log-level maps to the expected slog level through PersistentPreRunE
	// (empty log-file so no file is opened; "invalid" falls back to info).
	tests := []struct {
		name     string
		logLevel string
		want     slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"invalid", "invalid", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run("log_level_"+tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("log-file", "", "")
			cmd.Flags().String("log-level", tt.logLevel, "")

			if err := rootCmd.PersistentPreRunE(cmd, []string{}); err != nil {
				t.Fatalf("PersistentPreRunE returned error: %v", err)
			}
			if got := Logger.GetLevel(); got != tt.want {
				t.Errorf("log level for %q = %v, want %v", tt.logLevel, got, tt.want)
			}
		})
	}
}

func TestPersistentPreRunWithInvalidLogFile(t *testing.T) {
	// An unopenable path inside the allowlist must return an error (aborting
	// the command) rather than printing to stderr and continuing.
	// PersistentPreRunE validates the global cfg first, so give it a valid one
	// for the duration of the test.
	originalCfg := cfg
	cfg = validTestConfig("plain")
	defer func() { cfg = originalCfg }()
	cmd := &cobra.Command{}
	cmd.Flags().String("log-file", "/var/log/f2b-missing-dir/sub/logfile.log", "invalid log file")
	cmd.Flags().String("log-level", "info", "test log level")

	err := rootCmd.PersistentPreRunE(cmd, []string{})
	if err == nil {
		t.Fatal("expected an error for an unopenable log file path")
	}
	if !strings.Contains(err.Error(), "failed to open log file") {
		t.Errorf("expected error about failing to open log file, got: %v", err)
	}
}

// TestPersistentPreRunRejectsLogFileOutsideAllowlist pins the --log-file
// confinement: under `sudo f2b` an unchecked path let the caller create or
// append root-owned files anywhere (e.g. /etc/cron.d/x, /root/.bashrc).
func TestPersistentPreRunRejectsLogFileOutsideAllowlist(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "")
	originalCfg := cfg
	cfg = validTestConfig("plain")
	defer func() { cfg = originalCfg }()

	for _, path := range []string{"/etc/cron.d/f2b-test-x", "/root/.bashrc", "/var/logx/f2b.log", "/var/log/../etc/x"} {
		t.Run(path, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("log-file", path, "")
			cmd.Flags().String("log-level", "info", "")
			err := rootCmd.PersistentPreRunE(cmd, []string{})
			if err == nil {
				t.Fatalf("--log-file=%s was accepted", path)
			}
			if !strings.Contains(err.Error(), "outside the allowed log directories") {
				t.Errorf("error = %v, want an allowlist rejection", err)
			}
		})
	}
}

// TestWatchSignalsRecordsSignalBeforeStopReturns pins the join: a signal that
// arrives as the command completes is recorded before stop returns. The
// unjoined goroutine could store the exit code after main had read it.
func TestWatchSignalsRecordsSignalBeforeStopReturns(t *testing.T) {
	for i := range 1000 {
		interruptCode.Store(0)
		sigCh := make(chan os.Signal, 1)
		canceled := make(chan struct{})
		stop := watchSignals(sigCh, func() { close(canceled) })
		// Let the watcher park in its receive, so the signal is handed to it
		// directly (the case the join exists for) rather than buffered.
		time.Sleep(100 * time.Microsecond)
		sigCh <- syscall.SIGTERM
		stop()
		if got := SignalExitCode(); got != 143 {
			t.Fatalf("iteration %d: SignalExitCode() = %d after stop, want 143", i, got)
		}
	}
	interruptCode.Store(0)
}

// TestWatchSignalsCancelsOnSignal checks the live path: a signal cancels the
// command and is recorded, and stop with no signal records nothing.
func TestWatchSignalsCancelsOnSignal(t *testing.T) {
	interruptCode.Store(0)
	t.Cleanup(func() { interruptCode.Store(0) })

	sigCh := make(chan os.Signal, 1)
	canceled := make(chan struct{})
	stop := watchSignals(sigCh, func() { close(canceled) })
	sigCh <- os.Interrupt
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("signal did not cancel the command")
	}
	stop()
	if got := SignalExitCode(); got != 130 {
		t.Errorf("SignalExitCode() = %d, want 130", got)
	}

	interruptCode.Store(0)
	stop = watchSignals(make(chan os.Signal, 1), func() {})
	stop()
	if got := SignalExitCode(); got != 0 {
		t.Errorf("SignalExitCode() = %d without a signal, want 0", got)
	}
}

// TestLogLevelHelpListsAcceptedLevels pins the flag contract to the parser:
// every level the help names parses, and the help names every accepted one.
func TestLogLevelHelpListsAcceptedLevels(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("log-level")
	if flag == nil {
		t.Fatal("log-level flag missing")
	}
	for _, level := range []string{"debug", "info", "warn", "warning", "error", "fatal", "panic"} {
		if !strings.Contains(flag.Usage, level) {
			t.Errorf("log-level help %q does not list accepted level %q", flag.Usage, level)
		}
	}
}

// failWriter fails every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// TestCompletionReportsWriteErrors pins that a failed completion write fails
// the command instead of exiting 0 with a truncated script.
func TestCompletionReportsWriteErrors(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		root := &cobra.Command{Use: "f2b"}
		root.AddCommand(completionCmd())
		root.SetOut(failWriter{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"completion", shell})
		if err := root.Execute(); err == nil {
			t.Errorf("completion %s succeeded although its output write failed", shell)
		}
	}
}

// TestLogFormatChosenOnce pins the single log format: text on the terminal,
// JSON for a --log-file, with the contextual logger writing through the same
// handler so one sink never mixes formats.
func TestLogFormatChosenOnce(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "1")
	originalCfg := cfg
	cfg = validTestConfig(PlainFormat)
	oldOutput, oldLevel := Logger.Output(), Logger.GetLevel()
	t.Cleanup(func() {
		cleanupResources()
		cfg = originalCfg
		Logger.SetOutput(oldOutput)
		Logger.SetLevel(oldLevel)
		Logger.Reconfigure(fail2ban.SlogText)
	})

	if GetContextualLogger().SlogLogger != Logger {
		t.Fatal("contextual logger does not share the main Logger")
	}

	run := func(logFile string) {
		t.Helper()
		cmd := &cobra.Command{Use: "status"}
		cmd.Flags().String("log-file", logFile, "")
		cmd.Flags().String("log-level", "info", "")
		if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
			t.Fatalf("PersistentPreRunE: %v", err)
		}
	}

	var terminal bytes.Buffer
	run("")
	Logger.SetOutput(&terminal)
	Logger.Info("text line")
	GetContextualLogger().WithContext(context.Background()).Info("contextual text line")
	for line := range strings.SplitSeq(strings.TrimSpace(terminal.String()), "\n") {
		if strings.HasPrefix(line, "{") {
			t.Errorf("terminal log line is JSON: %s", line)
		}
	}

	logFile := filepath.Join(t.TempDir(), "f2b.log")
	run(logFile)
	Logger.Info("json line")
	GetContextualLogger().WithContext(context.Background()).Info("contextual json line")
	cleanupResources()
	data, err := os.ReadFile(logFile) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("log file has %d lines, want 2: %q", len(lines), data)
	}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Errorf("log file line is not JSON: %s", line)
			continue
		}
		if record["command_path"] != "status" {
			t.Errorf("log file line lacks command_path=status: %s", line)
		}
	}
}

func TestCompletionCmdLongDescription(t *testing.T) {
	cmd := completionCmd()

	// Test that the long description contains instructions for all shells
	expectedShells := []string{"Bash:", "Zsh:", "Fish:", "PowerShell:"}
	for _, shell := range expectedShells {
		if !strings.Contains(cmd.Long, shell) {
			t.Errorf("expected completion long description to contain %q", shell)
		}
	}

	// Test that it contains example commands
	expectedExamples := []string{
		"f2b completion bash",
		"f2b completion zsh",
		"f2b completion fish",
		"f2b completion powershell",
	}
	for _, example := range expectedExamples {
		if !strings.Contains(cmd.Long, example) {
			t.Errorf("expected completion long description to contain example %q", example)
		}
	}
}

func TestGlobalConfigVariable(t *testing.T) {
	// Test that global cfg variable can be accessed and modified
	originalCfg := cfg
	defer func() { cfg = originalCfg }()

	cfg = Config{
		LogDir:    "/test/log",
		FilterDir: "/test/filter",
		Format:    "json",
	}

	if cfg.LogDir != "/test/log" {
		t.Errorf("expected LogDir to be '/test/log', got %q", cfg.LogDir)
	}
	if cfg.FilterDir != "/test/filter" {
		t.Errorf("expected FilterDir to be '/test/filter', got %q", cfg.FilterDir)
	}
	if cfg.Format != "json" {
		t.Errorf("expected Format to be 'json', got %q", cfg.Format)
	}
}

// TestExecuteIntegration tests the Execute function with different command combinations
func TestExecuteIntegration(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		config   Config
		setupEnv func()
		cleanup  func()
	}{
		{
			name:   "execute with environment variables",
			args:   []string{"f2b", "version"},
			config: validTestConfig("plain"),
			setupEnv: func() {
				// Environment variables will be set using t.Setenv in test loop
			},
			cleanup: func() {
				// Cleanup handled automatically by t.Setenv
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertExecuteIntegrationCase(t, tt.name, tt.args, tt.config)
		})
	}
}

// assertExecuteIntegrationCase runs a single TestExecuteIntegration table case.
func assertExecuteIntegrationCase(t *testing.T, name string, args []string, config Config) {
	t.Helper()
	// Integration test requires manual approach:
	// Set up environment variables using t.Setenv for automatic cleanup
	if config.LogDir != "" {
		t.Setenv("F2B_LOG_DIR", config.LogDir)
	}
	if config.FilterDir != "" {
		t.Setenv("F2B_FILTER_DIR", config.FilterDir)
	}

	client := fail2ban.NewMockClient()

	// Capture output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	originalArgs := os.Args
	os.Args = args

	err = Execute(client, config)

	// Restore
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("failed to close writer: %v", closeErr)
	}
	os.Stdout = oldStdout
	os.Args = originalArgs

	// Read output
	var buf bytes.Buffer
	if _, readErr := buf.ReadFrom(r); readErr != nil {
		t.Fatalf("failed to read output: %v", readErr)
	}

	AssertError(t, err, false, name)
}

func TestCompletionCmdWithUnsupportedShell(t *testing.T) {
	cmd := completionCmd()

	// Capture stderr to check for error message
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)

	cmd.SetArgs([]string{"invalid-shell"})
	err := cmd.Execute()

	// Should return error due to Cobra's OnlyValidArgs validation
	if err == nil {
		t.Errorf("expected error for invalid shell type")
	}

	// Error should mention invalid argument
	if !strings.Contains(err.Error(), "invalid argument") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected error message about invalid argument, got: %v", err)
	}
}

// Benchmark tests
func BenchmarkParseLogLevelExtended(b *testing.B) {
	levels := []string{"debug", "info", "warn", "warning", "error", "fatal", "panic", "invalid", ""}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		level := levels[i%len(levels)]
		parseLogLevel(level)
	}
}

func BenchmarkExecute(b *testing.B) {
	client := fail2ban.NewMockClient()
	config := Config{
		LogDir:    "/tmp",
		FilterDir: "/tmp",
		Format:    "plain",
	}

	// Suppress output
	oldStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		b.Fatalf("failed to open dev null: %v", err)
	}
	defer func() {
		if cerr := devNull.Close(); cerr != nil {
			b.Fatalf("failed to close dev null: %v", cerr)
		}
	}()
	os.Stdout = devNull

	defer func() {
		os.Stdout = oldStdout
	}()

	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()

	b.ResetTimer()
	for b.Loop() {
		os.Args = []string{"f2b", "version"}
		if err := Execute(client, config); err != nil {
			b.Fatalf("execute failed: %v", err)
		}
	}
}
