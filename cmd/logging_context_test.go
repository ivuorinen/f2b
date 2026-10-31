package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// setupTestLogger creates a ContextualLogger with a buffer for testing
func setupTestLogger(t *testing.T) (*ContextualLogger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := fail2ban.NewSlogLogger(fail2ban.SlogJSON)
	logger.SetOutput(&buf)
	return &ContextualLogger{SlogLogger: logger}, &buf
}

// SetContextualLogger replaces the global contextual logger. It is a test
// seam only, so it lives in a test file instead of the cmd API.
//
// Not synchronized: call only before concurrent readers exist.
func SetContextualLogger(logger *ContextualLogger) {
	contextualLoggerOnce.Do(func() {
		// Consume the once so the lazy initializer in GetContextualLogger
		// never overwrites this explicitly-set logger.
	})
	contextualLogger = logger
}

// TestSetContextualLogger tests the SetContextualLogger function
func TestSetContextualLogger(t *testing.T) {
	// Save original logger
	originalLogger := GetContextualLogger()
	defer SetContextualLogger(originalLogger)

	// Create new logger
	logger := fail2ban.NewSlogLogger(fail2ban.SlogText)
	newLogger := &ContextualLogger{SlogLogger: logger}

	// Set new logger
	SetContextualLogger(newLogger)

	// Verify new logger is set
	currentLogger := GetContextualLogger()
	assert.Equal(t, newLogger, currentLogger)
}

// TestLogOperation tests the LogOperation method
func TestLogOperation(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		fn        func(context.Context) error
		expectErr bool
		contains  string
	}{
		{
			name:      "successful operation",
			operation: "test-operation",
			fn: func(context.Context) error {
				return nil
			},
			expectErr: false,
			contains:  "Operation completed",
		},
		{
			name:      "failed operation",
			operation: "failing-operation",
			fn: func(context.Context) error {
				return errors.New("operation failed")
			},
			expectErr: true,
			contains:  "Operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, buf := setupTestLogger(t)
			ctx := context.Background()

			// Execute operation
			err := cl.LogOperation(ctx, tt.operation, tt.fn)

			// Verify error
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify logging output
			output := buf.String()
			assert.Contains(t, output, tt.contains)
			assert.Contains(t, output, tt.operation)
			assert.Contains(t, output, "Operation started")
		})
	}
}

// TestLogOperationPassesEnrichedContext pins that the operation body receives
// the context carrying request_id and operation, so nested log lines share
// the start/finish lines' request_id.
func TestLogOperationPassesEnrichedContext(t *testing.T) {
	cl, buf := setupTestLogger(t)

	var nestedID any
	err := cl.LogOperation(context.Background(), "nested-op", func(ctx context.Context) error {
		nestedID = ctx.Value(constants.ContextKeyRequestID)
		cl.WithContext(ctx).Info("nested line")
		return nil
	})
	require.NoError(t, err)
	requestID, ok := nestedID.(string)
	require.True(t, ok, "operation body context has no request_id")

	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		assert.Contains(t, line, requestID, "log line without the operation's request_id: %s", line)
		assert.Contains(t, line, `"operation":"nested-op"`)
	}
}

// TestLogBanOperation tests the LogBanOperation method
func TestLogBanOperation(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		ip        string
		jail      string
		success   bool
		duration  time.Duration
		contains  string
	}{
		{
			name:      "successful ban",
			operation: "ban",
			ip:        "192.168.1.1",
			jail:      "sshd",
			success:   true,
			duration:  50 * time.Millisecond,
			contains:  "Ban operation completed",
		},
		{
			name:      "failed ban",
			operation: "ban",
			ip:        "192.168.1.2",
			jail:      "apache",
			success:   false,
			duration:  30 * time.Millisecond,
			contains:  "Ban operation failed",
		},
		{
			name:      "successful unban",
			operation: "unban",
			ip:        "192.168.1.3",
			jail:      "sshd",
			success:   true,
			duration:  40 * time.Millisecond,
			contains:  "Ban operation completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, buf := setupTestLogger(t)
			ctx := context.Background()

			// Log ban operation
			cl.LogBanOperation(ctx, tt.operation, tt.ip, tt.jail, tt.success, tt.duration)

			// Verify output
			output := buf.String()
			assert.Contains(t, output, tt.contains)
			assert.Contains(t, output, tt.ip)
			assert.Contains(t, output, tt.jail)
			assert.Contains(t, output, "duration_ms")
		})
	}
}
