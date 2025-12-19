package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/shared"
)

// setupTestLogger creates a ContextualLogger with a buffer for testing
func setupTestLogger(t *testing.T) (*ContextualLogger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
	})
	return &ContextualLogger{Logger: logger}, &buf
}

// TestWithRequestID tests the WithRequestID function
func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-123"

	// Add request ID to context
	ctxWithID := WithRequestID(ctx, requestID)

	// Verify request ID is in context
	value := ctxWithID.Value(shared.ContextKeyRequestID)
	require.NotNil(t, value)
	assert.Equal(t, requestID, value)
}

// TestLogCommandExecution tests the LogCommandExecution method
func TestLogCommandExecution(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		duration time.Duration
		err      error
		contains string
	}{
		{
			name:     "successful command execution",
			command:  "fail2ban-client",
			args:     []string{"status", "sshd"},
			duration: 100 * time.Millisecond,
			err:      nil,
			contains: "Command executed successfully",
		},
		{
			name:     "failed command execution",
			command:  "fail2ban-client",
			args:     []string{"invalid"},
			duration: 50 * time.Millisecond,
			err:      errors.New("command not found"),
			contains: "Command execution failed",
		},
		{
			name:     "command with no args",
			command:  "fail2ban-client",
			args:     []string{},
			duration: 10 * time.Millisecond,
			err:      nil,
			contains: "Command executed successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, buf := setupTestLogger(t)
			ctx := context.Background()

			// Log command execution
			cl.LogCommandExecution(ctx, tt.command, tt.args, tt.duration, tt.err)

			// Verify output
			output := buf.String()
			assert.Contains(t, output, tt.contains)
			assert.Contains(t, output, tt.command)
			assert.Contains(t, output, "duration_ms")
		})
	}
}

// TestSetContextualLogger tests the SetContextualLogger function
func TestSetContextualLogger(t *testing.T) {
	// Save original logger
	originalLogger := GetContextualLogger()
	defer SetContextualLogger(originalLogger)

	// Create new logger
	logger := logrus.New()
	newLogger := &ContextualLogger{Logger: logger}

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
		fn        func() error
		expectErr bool
		contains  string
	}{
		{
			name:      "successful operation",
			operation: "test-operation",
			fn: func() error {
				return nil
			},
			expectErr: false,
			contains:  "Operation completed",
		},
		{
			name:      "failed operation",
			operation: "failing-operation",
			fn: func() error {
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
