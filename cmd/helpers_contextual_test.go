package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewContextualCommand_ExecutionWithContext tests command execution with context
func TestNewContextualCommand_ExecutionWithContext(t *testing.T) {
	handlerCalled := false
	var receivedCtx context.Context

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		handlerCalled = true
		receivedCtx = ctx
		return nil
	}

	cmd := NewContextualCommand("test", "Test command", nil, config, handler)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.True(t, handlerCalled, "Handler should be called")
	assert.NotNil(t, receivedCtx, "Handler should receive context")

	// Verify context has timeout
	_, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline, "Context should have deadline")
}

// TestNewContextualCommand_NilCobraContext tests fallback to Background context
func TestNewContextualCommand_NilCobraContext(t *testing.T) {
	var receivedCtx context.Context

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		receivedCtx = ctx
		return nil
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	// Don't set a context on the command - should use Background

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx, "Should receive a context")

	// Should still have timeout even with Background base
	_, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline, "Background context should still get timeout wrapper")
}

// TestNewContextualCommand_WithCobraContext tests using Cobra's context
func TestNewContextualCommand_WithCobraContext(t *testing.T) {
	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	var receivedCtx context.Context

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		receivedCtx = ctx
		return nil
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	// Set Cobra context
	cmd.SetContext(parentCtx)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)

	// Context should have timeout
	_, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline)
}

// TestNewContextualCommand_HandlerError tests error propagation
func TestNewContextualCommand_HandlerError(t *testing.T) {
	expectedErr := errors.New("handler error")

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(_ context.Context, _ *cobra.Command, _ []string) error {
		return expectedErr
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	err := cmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err, "Should propagate handler error")
}

// TestNewContextualCommand_WithArgs tests passing arguments
func TestNewContextualCommand_WithArgs(t *testing.T) {
	var receivedArgs []string

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(_ context.Context, _ *cobra.Command, args []string) error {
		receivedArgs = args
		return nil
	}

	cmd := NewContextualCommand("test <arg>", "Test", nil, config, handler)
	cmd.SetArgs([]string{"value1", "value2"})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Equal(t, []string{"value1", "value2"}, receivedArgs, "Should receive args")
}

// TestNewContextualCommand_NilConfig tests default timeout with nil config
func TestNewContextualCommand_NilConfig(t *testing.T) {
	var receivedCtx context.Context

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		receivedCtx = ctx
		return nil
	}

	cmd := NewContextualCommand("test", "Test", nil, nil, handler)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)

	// Should still have timeout (default timeout)
	_, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline, "Should use default timeout when config is nil")
}

// TestNewContextualCommand_ZeroTimeout tests config with zero timeout
func TestNewContextualCommand_ZeroTimeout(t *testing.T) {
	var receivedCtx context.Context

	config := &Config{CommandTimeout: 0} // Zero timeout

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		receivedCtx = ctx
		return nil
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)

	// Should still have timeout (falls back to default)
	_, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline, "Should use default timeout when config timeout is 0")
}

// TestNewContextualCommand_CustomTimeout tests custom timeout value
func TestNewContextualCommand_CustomTimeout(t *testing.T) {
	customTimeout := 10 * time.Second
	var receivedCtx context.Context
	var receivedDeadline time.Time

	config := &Config{CommandTimeout: customTimeout}

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		receivedCtx = ctx
		deadline, _ := ctx.Deadline()
		receivedDeadline = deadline
		return nil
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	startTime := time.Now()
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)

	// Verify timeout duration is approximately correct
	expectedDeadline := startTime.Add(customTimeout)
	// Allow 1 second tolerance for test execution time
	assert.WithinDuration(t, expectedDeadline, receivedDeadline, 1*time.Second,
		"Deadline should be approximately %s from start", customTimeout)
}

// TestNewContextualCommand_WithAliases tests command with aliases
func TestNewContextualCommand_WithAliases(t *testing.T) {
	handlerCalled := false

	config := &Config{CommandTimeout: 5 * time.Second}

	handler := func(_ context.Context, _ *cobra.Command, _ []string) error {
		handlerCalled = true
		return nil
	}

	aliases := []string{"t", "tst"}
	cmd := NewContextualCommand("test", "Test command", aliases, config, handler)

	assert.Equal(t, aliases, cmd.Aliases, "Should set aliases")
	assert.Equal(t, "test", cmd.Use)
	assert.Equal(t, "Test command", cmd.Short)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

// TestNewContextualCommand_ContextCancellation tests context cancellation
func TestNewContextualCommand_ContextCancellation(t *testing.T) {
	parentCtx, parentCancel := context.WithCancel(context.Background())

	var receivedErr error

	config := &Config{CommandTimeout: 10 * time.Second}

	handler := func(ctx context.Context, _ *cobra.Command, _ []string) error {
		// Cancel parent context during handler execution
		parentCancel()

		// Wait a bit to see if context cancellation propagates
		select {
		case <-ctx.Done():
			receivedErr = ctx.Err()
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	}

	cmd := NewContextualCommand("test", "Test", nil, config, handler)
	cmd.SetContext(parentCtx)

	err := cmd.Execute()

	// Should get cancellation error
	require.Error(t, err)
	assert.Equal(t, context.Canceled, receivedErr, "Should receive cancellation error")
}

// TestNewContextualCommand_CommandNameExtraction tests command name handling
func TestNewContextualCommand_CommandNameExtraction(t *testing.T) {
	tests := []struct {
		name        string
		use         string
		expectedUse string
	}{
		{
			name:        "simple command name",
			use:         "test",
			expectedUse: "test",
		},
		{
			name:        "command with args",
			use:         "test <arg>",
			expectedUse: "test <arg>",
		},
		{
			name:        "command with optional args",
			use:         "test [options]",
			expectedUse: "test [options]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{CommandTimeout: 5 * time.Second}
			handler := func(_ context.Context, _ *cobra.Command, _ []string) error {
				return nil
			}

			cmd := NewContextualCommand(tt.use, "Test", nil, config, handler)
			assert.Equal(t, tt.expectedUse, cmd.Use)
		})
	}
}
