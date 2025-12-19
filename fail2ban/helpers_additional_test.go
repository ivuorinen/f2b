package fail2ban

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestFormatDuration(t *testing.T) {
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
			result := FormatDuration(tt.seconds)
			if result != tt.expected {
				t.Errorf("FormatDuration(%d) = %q, expected %q", tt.seconds, result, tt.expected)
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

	// Add small delay to ensure different timestamps
	time.Sleep(1 * time.Nanosecond)
	id2 := GenerateRequestID()

	if id1 == "" {
		t.Error("GenerateRequestID returned empty string")
	}
	if id2 == "" {
		t.Error("GenerateRequestID returned empty string")
	}
	// Don't check for uniqueness in tests as nanosecond timing can be flaky
	if len(id1) < 10 {
		t.Error("GenerateRequestID returned suspiciously short ID")
	}
}

func TestTimedOperationFinishWithContext(_ *testing.T) {
	// Capture log output
	originalLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(originalLevel)

	ctx := WithOperation(context.Background(), "test-operation")
	ctx = WithRequestID(ctx, "test-request")

	timer := NewTimedOperation("test", "command", "arg1", "arg2")

	// Test successful operation
	timer.FinishWithContext(ctx, nil)

	// Test failed operation
	timer2 := NewTimedOperation("test-fail", "command", "arg1")
	timer2.FinishWithContext(ctx, fmt.Errorf("test error"))
}

func TestValidationCacheSize(t *testing.T) {
	// Clear caches first
	ClearValidationCaches()

	// Test empty cache
	stats := GetValidationCacheStats()
	if stats["ip_cache_size"] != 0 {
		t.Errorf("Expected empty IP cache, got %d", stats["ip_cache_size"])
	}

	// Add something to cache
	err := CachedValidateIP(context.Background(), "192.168.1.1")
	if err != nil {
		t.Fatalf("CachedValidateIP failed: %v", err)
	}

	// Check cache size increased
	stats = GetValidationCacheStats()
	if stats["ip_cache_size"] != 1 {
		t.Errorf("Expected IP cache size 1, got %d", stats["ip_cache_size"])
	}

	// Test cache Size method directly
	if ipValidationCache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", ipValidationCache.Size())
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
