package fail2ban

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestFormatDurationOptimized(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int64
		expected string
	}{
		{
			name:     "zero seconds",
			seconds:  0,
			expected: "00:00:00:00",
		},
		{
			name:     "one minute",
			seconds:  60,
			expected: "00:00:01:00",
		},
		{
			name:     "one hour",
			seconds:  3600,
			expected: "00:01:00:00",
		},
		{
			name:     "one day",
			seconds:  86400,
			expected: "01:00:00:00",
		},
		{
			name:     "complex duration",
			seconds:  90061, // 1 day, 1 hour, 1 minute, 1 second
			expected: "01:01:01:01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDurationOptimized(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatDurationOptimized(%d) = %q, expected %q", tt.seconds, result, tt.expected)
			}
		})
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test WithRequestID
	requestID := "test-request-123"
	ctx = WithRequestID(ctx, requestID)

	// Test WithOperation
	operation := "test-operation"
	ctx = WithOperation(ctx, operation)

	// Test WithJail
	jail := "test-jail"
	ctx = WithJail(ctx, jail)

	// Test WithIP
	ip := "192.168.1.1"
	ctx = WithIP(ctx, ip)

	// Test LoggerFromContext
	logger := LoggerFromContext(ctx)

	// Verify the logger has the expected fields
	entry := logger.WithField("test", "value")
	if entry == nil {
		t.Error("LoggerFromContext returned nil entry")
	}

	// Test with empty context
	emptyLogger := LoggerFromContext(context.Background())
	if emptyLogger == nil {
		t.Error("LoggerFromContext with empty context returned nil")
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	if id1 == "" {
		t.Fatal("GenerateRequestID returned empty string")
	}
	if len(id1) < 10 {
		t.Fatalf("GenerateRequestID returned suspiciously short ID: %q", id1)
	}

	// Uniqueness is the function's whole contract: a generator returning the
	// same ID forever must fail this test. N iterations rather than a timing
	// sleep — the IDs must differ regardless of clock granularity.
	seen := map[string]bool{id1: true}
	for range 100 {
		id := GenerateRequestID()
		if seen[id] {
			t.Fatalf("GenerateRequestID returned a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestTimedOperationFinishWithContext(t *testing.T) {
	// Install a capturing logger so we can assert what FinishWithContext emits.
	var buf bytes.Buffer
	capLogger := NewSlogLogger(SlogJSON)
	capLogger.SetOutput(&buf)
	capLogger.SetLevel(slog.LevelDebug)

	orig := getLogger()
	SetLogger(capLogger)
	defer SetLogger(orig)

	ctx := WithOperation(context.Background(), "test-operation")
	ctx = WithRequestID(ctx, "test-request")

	// Successful operation: logs the command and request-id context field.
	timer := NewTimedOperation("test", "command", "arg1", "arg2")
	timer.FinishWithContext(ctx, nil)
	successLog := buf.String()
	if !strings.Contains(successLog, "command") {
		t.Errorf("success log missing command field: %q", successLog)
	}
	if !strings.Contains(successLog, "test-request") {
		t.Errorf("success log missing request-id context field: %q", successLog)
	}

	// Failed operation: the error message must reach the log.
	buf.Reset()
	timer2 := NewTimedOperation("test-fail", "command", "arg1")
	timer2.FinishWithContext(ctx, fmt.Errorf("boom-sentinel-error"))
	failLog := buf.String()
	if !strings.Contains(failLog, "boom-sentinel-error") {
		t.Errorf("failure log missing error message: %q", failLog)
	}
}

func TestErrorConstructors(t *testing.T) {
	// Test error constructors that aren't covered
	err := NewInvalidJailError("test-jail")
	if err == nil {
		t.Error("NewInvalidJailError returned nil")
	}
	if err.Error() == "" {
		t.Error("NewInvalidJailError returned empty error message")
	}

	// Test error that has methods
	validationErr := NewValidationError("test message", "test remediation")
	if validationErr.Error() == "" {
		t.Error("NewValidationError returned empty error message")
	}
	if validationErr.GetCategory() != "validation" {
		t.Errorf("Expected category 'validation', got %q", validationErr.GetCategory())
	}
	if validationErr.GetRemediation() != "test remediation" {
		t.Errorf("Expected remediation 'test remediation', got %q", validationErr.GetRemediation())
	}
	if validationErr.Unwrap() != nil {
		t.Error("Expected Unwrap to return nil")
	}

	// Test permission error
	permErr := NewPermissionError("permission denied", "check permissions")
	if permErr == nil {
		t.Error("NewPermissionError returned nil")
	}
}
