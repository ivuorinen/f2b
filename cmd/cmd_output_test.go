package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestPrintOutput(t *testing.T) {
	tests := []struct {
		name     string
		data     any
		format   string
		expected string
	}{
		{
			name:     "plain string output",
			data:     "hello world",
			format:   "plain",
			expected: "hello world\n",
		},
		{
			name:     "json string output",
			data:     "hello world",
			format:   JSONFormat,
			expected: "\"hello world\"\n",
		},
		{
			name:     "json object output",
			data:     map[string]string{"key": "value"},
			format:   JSONFormat,
			expected: "{\n  \"key\": \"value\"\n}\n",
		},
		{
			name:     "json array output",
			data:     []string{"item1", "item2"},
			format:   JSONFormat,
			expected: "[\n  \"item1\",\n  \"item2\"\n]\n",
		},
		{
			name:     "plain struct output",
			data:     struct{ Name string }{"test"},
			format:   "plain",
			expected: "{test}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w

			printErr := PrintOutput(tt.data, tt.format)

			if err := w.Close(); err != nil {
				t.Fatalf("unexpected close error: %v", err)
			}
			os.Stdout = oldStdout

			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			output := buf.String()

			if printErr != nil {
				t.Errorf("PrintOutput returned error: %v", printErr)
			}
			if output != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestPrintOutputTo(t *testing.T) {
	tests := []struct {
		name     string
		data     any
		format   string
		expected string
	}{
		{
			name:     "plain output to buffer",
			data:     "test message",
			format:   "plain",
			expected: "test message\n",
		},
		{
			name:     "json output to buffer",
			data:     map[string]int{"count": 42},
			format:   JSONFormat,
			expected: "{\n  \"count\": 42\n}\n",
		},
		{
			name:     "unknown format defaults to plain",
			data:     "test",
			format:   "unknown",
			expected: "test\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := PrintOutputTo(&buf, tt.data, tt.format); err != nil {
				t.Fatalf("PrintOutputTo returned error: %v", err)
			}

			output := buf.String()
			if output != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}

// TestPrintOutputTo_JSONError pins that an encode failure is returned (so the
// command exits non-zero) and that nothing reaches the output stream.
func TestPrintOutputTo_JSONError(t *testing.T) {
	var buf bytes.Buffer

	// Function type cannot be marshaled to JSON
	err := PrintOutputTo(&buf, func() {}, JSONFormat)
	if err == nil || !strings.Contains(err.Error(), "failed to encode JSON output") {
		t.Fatalf("error = %v, want a JSON encoding error", err)
	}
	if buf.Len() != 0 {
		t.Errorf("encode failure wrote %q to the output", buf.String())
	}
}

// failingWriter fails every write, like a full disk or a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// TestOutputWriteErrorFailsCommand pins that a failed stdout write is returned
// as the command's error and so changes the exit status.
func TestOutputWriteErrorFailsCommand(t *testing.T) {
	for _, format := range []string{PlainFormat, JSONFormat} {
		if err := PrintOutputTo(failingWriter{}, []string{"x"}, format); err == nil {
			t.Errorf("PrintOutputTo(%s) to a failing writer returned nil", format)
		}
	}

	mock := NewMockClient()
	mock.LogLines = []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"}
	commands := map[string]*cobra.Command{
		"version": VersionCmd(&Config{Format: PlainFormat}),
		"logs":    LogsCmd(mock, &Config{Format: PlainFormat, FileTimeout: time.Second}),
		"banned": BannedCmd(mock, &Config{
			Format: JSONFormat, CommandTimeout: time.Second, ParallelTimeout: time.Second,
		}),
	}
	for name, cmd := range commands {
		cmd.SetOut(failingWriter{})
		cmd.SetArgs(nil)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s exited successfully although its output write failed", name)
		}
	}
}

// TestCommandFailedLogCarriesCommandPath pins that the "Command failed" record
// names the failing command: PersistentPreRunE stamps the command path on
// every line of the shared logger.
func TestCommandFailedLogCarriesCommandPath(t *testing.T) {
	originalCfg := cfg
	cfg = validTestConfig(PlainFormat)
	oldOutput, oldLevel := Logger.Output(), Logger.GetLevel()
	var logBuf bytes.Buffer
	Logger.SetOutput(&logBuf)
	t.Cleanup(func() {
		cfg = originalCfg
		Logger.SetOutput(oldOutput)
		Logger.SetLevel(oldLevel)
		Logger.Reconfigure(fail2ban.SlogText)
	})

	cmd := &cobra.Command{Use: "banned"}
	cmd.Flags().String("log-file", "", "")
	cmd.Flags().String("log-level", "error", "")
	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("PersistentPreRunE: %v", err)
	}
	_, _ = captureStdoutStderr(func() error {
		PrintError(errors.New("boom"))
		return nil
	})

	if !strings.Contains(logBuf.String(), "Command failed") ||
		!strings.Contains(logBuf.String(), "command_path=banned") {
		t.Errorf("Command failed record lacks the command path: %q", logBuf.String())
	}
}

func TestPrintError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		expectLog bool
	}{
		{
			name:      "nil error",
			err:       nil,
			expectLog: false,
		},
		{
			name:      "actual error",
			err:       &testError{"test error message"},
			expectLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPrintErrorCase(t, tt.err, tt.expectLog)
		})
	}
}

// assertPrintErrorCase runs PrintError for a single case and verifies the
// captured stderr and log output against the expectLog expectation.
func assertPrintErrorCase(t *testing.T, err error, expectLog bool) {
	t.Helper()

	// Capture stderr
	oldStderr := os.Stderr
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("failed to create pipe: %v", perr)
	}
	os.Stderr = w

	// Capture log output
	oldOutput := Logger.Output()
	var logBuf bytes.Buffer
	Logger.SetOutput(&logBuf)

	PrintError(err)

	if cerr := w.Close(); cerr != nil {
		t.Fatalf("failed to close pipe writer: %v", cerr)
	}
	os.Stderr = oldStderr
	Logger.SetOutput(oldOutput)

	var stderrBuf bytes.Buffer
	if _, rerr := stderrBuf.ReadFrom(r); rerr != nil {
		t.Fatalf("failed to read stderr: %v", rerr)
	}
	stderrOutput := stderrBuf.String()
	logOutput := logBuf.String()

	if expectLog {
		if !strings.Contains(logOutput, "Command failed") {
			t.Errorf("expected error to be logged, got: %s", logOutput)
		}
		if !strings.Contains(stderrOutput, "Error: test error message") {
			t.Errorf("expected error in stderr, got: %s", stderrOutput)
		}
	} else {
		if stderrOutput != "" {
			t.Errorf("expected no stderr output for nil error, got: %s", stderrOutput)
		}
	}
}

func TestGetCmdOutput(t *testing.T) {
	assertCmdWriter(t, GetCmdOutput, (*cobra.Command).SetOut, os.Stdout, "os.Stdout")
}

// assertCmdWriter verifies that a cmd-writer getter returns the process default
// (dflt) when no writer is set or the command is nil, and a custom writer
// otherwise. Currently only GetCmdOutput uses it.
func assertCmdWriter(
	t *testing.T,
	get func(*cobra.Command) io.Writer,
	set func(*cobra.Command, io.Writer),
	dflt io.Writer,
	dfltName string,
) {
	t.Helper()
	tests := []struct {
		name       string
		setupCmd   func() *cobra.Command
		expectDflt bool
	}{
		{"command with writer set", func() *cobra.Command {
			cmd := &cobra.Command{}
			set(cmd, &bytes.Buffer{})
			return cmd
		}, false},
		{"nil command", func() *cobra.Command { return nil }, true},
		{"command without writer set", func() *cobra.Command { return &cobra.Command{} }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := get(tt.setupCmd())
			if tt.expectDflt && got != dflt {
				t.Errorf("expected %s, got a different writer", dfltName)
			}
			if !tt.expectDflt && got == dflt {
				t.Errorf("expected a custom writer, got %s", dfltName)
			}
		})
	}
}

func TestLoggerInitialization(t *testing.T) {
	// Save and restore logger output
	oldOut := Logger.Output()
	defer Logger.SetOutput(oldOut)
	Logger.SetOutput(os.Stderr)

	if Logger == nil {
		t.Fatal("Logger should be initialized")
	}

	// Test default output
	if Logger.Output() != os.Stderr {
		t.Errorf("expected Logger output to be os.Stderr")
	}
}

func TestJSONFormatConstant(t *testing.T) {
	if JSONFormat != "json" {
		t.Errorf("expected JSONFormat to be 'json', got %q", JSONFormat)
	}
}

// testError is a simple error implementation for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

// Benchmark tests for performance
func BenchmarkPrintOutputPlain(b *testing.B) {
	var buf bytes.Buffer
	data := "test message"

	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		_ = PrintOutputTo(&buf, data, "plain")
	}
}

func BenchmarkPrintOutputJSON(b *testing.B) {
	var buf bytes.Buffer
	data := map[string]string{"key": "value"}

	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		_ = PrintOutputTo(&buf, data, JSONFormat)
	}
}

func BenchmarkPrintError(b *testing.B) {
	err := &testError{"benchmark error"}

	// Suppress output for benchmarking
	oldStderr := os.Stderr
	oldOutput := Logger.Output()

	devNull, derr := os.Open(os.DevNull)
	if derr != nil {
		b.Fatalf("failed to open dev null: %v", derr)
	}
	defer func() {
		if cerr := devNull.Close(); cerr != nil {
			b.Fatalf("failed to close dev null: %v", cerr)
		}
	}()

	os.Stderr = devNull
	Logger.SetOutput(devNull)

	defer func() {
		os.Stderr = oldStderr
		Logger.SetOutput(oldOutput)
	}()

	b.ResetTimer()
	for b.Loop() {
		PrintError(err)
	}
}
