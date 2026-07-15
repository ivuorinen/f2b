package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

			PrintOutput(tt.data, tt.format)

			if err := w.Close(); err != nil {
				t.Fatalf("unexpected close error: %v", err)
			}
			os.Stdout = oldStdout

			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			output := buf.String()

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
			PrintOutputTo(&buf, tt.data, tt.format)

			output := buf.String()
			if output != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestPrintOutputTo_JSONError(t *testing.T) {
	// Test with data that cannot be marshaled to JSON
	var buf bytes.Buffer

	// Capture log output
	oldOutput := Logger.Output()
	var logBuf bytes.Buffer
	Logger.SetOutput(&logBuf)
	defer Logger.SetOutput(oldOutput)

	// Function type cannot be marshaled to JSON
	PrintOutputTo(&buf, func() {}, JSONFormat)

	// Should have logged an error
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Failed to encode JSON output") {
		t.Errorf("expected JSON encoding error to be logged, got: %s", logOutput)
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
			// Capture stderr
			oldStderr := os.Stderr
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stderr = w

			// Capture log output
			oldOutput := Logger.Output()
			var logBuf bytes.Buffer
			Logger.SetOutput(&logBuf)

			PrintError(tt.err)

			if err := w.Close(); err != nil {
				t.Fatalf("failed to close pipe writer: %v", err)
			}
			os.Stderr = oldStderr
			Logger.SetOutput(oldOutput)

			var stderrBuf bytes.Buffer
			if _, err := stderrBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read stderr: %v", err)
			}
			stderrOutput := stderrBuf.String()
			logOutput := logBuf.String()

			if tt.expectLog {
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
		})
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
		PrintOutputTo(&buf, data, "plain")
	}
}

func BenchmarkPrintOutputJSON(b *testing.B) {
	var buf bytes.Buffer
	data := map[string]string{"key": "value"}

	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		PrintOutputTo(&buf, data, JSONFormat)
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
