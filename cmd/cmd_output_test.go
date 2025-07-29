package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func TestPrintOutput(t *testing.T) {
	tests := []struct {
		name     string
		data     interface{}
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
		data     interface{}
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
	oldOutput := Logger.Out
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
			oldOutput := Logger.Out
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

func TestPrintErrorf(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Capture log output
	oldOutput := Logger.Out
	var logBuf bytes.Buffer
	Logger.SetOutput(&logBuf)

	PrintErrorf("formatted error: %s %d", "test", 42)

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

	expectedStderr := "Error: formatted error: test 42\n"
	if stderrOutput != expectedStderr {
		t.Errorf("expected stderr %q, got %q", expectedStderr, stderrOutput)
	}

	if !strings.Contains(logOutput, "formatted error: test 42") {
		t.Errorf("expected error to be logged, got: %s", logOutput)
	}
}

func TestGetCmdOutput(t *testing.T) {
	tests := []struct {
		name         string
		setupCmd     func() *cobra.Command
		expectStdout bool
	}{
		{
			name: "command with output set",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				var buf bytes.Buffer
				cmd.SetOut(&buf)
				return cmd
			},
			expectStdout: false,
		},
		{
			name: "nil command",
			setupCmd: func() *cobra.Command {
				return nil
			},
			expectStdout: true,
		},
		{
			name: "command without output set",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{}
			},
			expectStdout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.setupCmd()
			output := GetCmdOutput(cmd)

			if tt.expectStdout {
				if output != os.Stdout {
					t.Errorf("expected os.Stdout, got different writer")
				}
			} else {
				if output == os.Stdout {
					t.Errorf("expected custom writer, got os.Stdout")
				}
			}
		})
	}
}

func TestGetCmdError(t *testing.T) {
	tests := []struct {
		name         string
		setupCmd     func() *cobra.Command
		expectStderr bool
	}{
		{
			name: "command with error output set",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				var buf bytes.Buffer
				cmd.SetErr(&buf)
				return cmd
			},
			expectStderr: false,
		},
		{
			name: "nil command",
			setupCmd: func() *cobra.Command {
				return nil
			},
			expectStderr: true,
		},
		{
			name: "command without error output set",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{}
			},
			expectStderr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.setupCmd()
			output := GetCmdError(cmd)

			if tt.expectStderr {
				if output != os.Stderr {
					t.Errorf("expected os.Stderr, got different writer")
				}
			} else {
				if output == os.Stderr {
					t.Errorf("expected custom writer, got os.Stderr")
				}
			}
		})
	}
}

func TestLoggerInitialization(t *testing.T) {
	// Save and restore logger output
	oldOut := Logger.Out
	defer Logger.SetOutput(oldOut)
	Logger.SetOutput(os.Stderr)

	if Logger == nil {
		t.Fatal("Logger should be initialized")
	}

	// Test default formatter
	if _, ok := Logger.Formatter.(*logrus.TextFormatter); !ok {
		t.Errorf("expected TextFormatter, got %T", Logger.Formatter)
	}

	// Test default output
	if Logger.Out != os.Stderr {
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
	for i := 0; i < b.N; i++ {
		buf.Reset()
		PrintOutputTo(&buf, data, "plain")
	}
}

func BenchmarkPrintOutputJSON(b *testing.B) {
	var buf bytes.Buffer
	data := map[string]string{"key": "value"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		PrintOutputTo(&buf, data, JSONFormat)
	}
}

func BenchmarkPrintError(b *testing.B) {
	err := &testError{"benchmark error"}

	// Suppress output for benchmarking
	oldStderr := os.Stderr
	oldOutput := Logger.Out

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
	for i := 0; i < b.N; i++ {
		PrintError(err)
	}
}
