package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ivuorinen/f2b/shared"
)

// TestRecordValidationFailure tests the RecordValidationFailure method
func TestRecordValidationFailure(t *testing.T) {
	m := NewMetrics()

	// Initial failures should be 0
	assert.Equal(t, int64(0), m.ValidationFailures)

	// Record failures
	m.RecordValidationFailure()
	assert.Equal(t, int64(1), m.ValidationFailures)

	m.RecordValidationFailure()
	assert.Equal(t, int64(2), m.ValidationFailures)

	// Test concurrent recording
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			m.RecordValidationFailure()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, int64(12), m.ValidationFailures)
}

// TestNewTimedOperation tests the NewTimedOperation function
func TestNewTimedOperation(t *testing.T) {
	m := NewMetrics()
	ctx := context.Background()

	tests := []struct {
		name      string
		category  string
		operation string
	}{
		{
			name:      "command operation",
			category:  "command",
			operation: "ban",
		},
		{
			name:      "client operation",
			category:  "client",
			operation: "status",
		},
		{
			name:      "ban operation",
			category:  shared.MetricsBan,
			operation: "banip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := NewTimedOperation(ctx, m, tt.category, tt.operation)

			assert.NotNil(t, op)
			assert.Equal(t, m, op.metrics)
			assert.Equal(t, tt.operation, op.operation)
			assert.Equal(t, tt.category, op.category)
			assert.False(t, op.startTime.IsZero())
		})
	}
}

// TestTimedOperationFinish tests the Finish method
func TestTimedOperationFinish(t *testing.T) {
	tests := []struct {
		name      string
		category  string
		operation string
		success   bool
		sleep     time.Duration
	}{
		{
			name:      "successful command operation",
			category:  "command",
			operation: "ban",
			success:   true,
			sleep:     10 * time.Millisecond,
		},
		{
			name:      "failed command operation",
			category:  "command",
			operation: "unban",
			success:   false,
			sleep:     5 * time.Millisecond,
		},
		{
			name:      "successful client operation",
			category:  "client",
			operation: "status",
			success:   true,
			sleep:     8 * time.Millisecond,
		},
		{
			name:      "failed client operation",
			category:  "client",
			operation: "ping",
			success:   false,
			sleep:     3 * time.Millisecond,
		},
		{
			name:      "successful ban operation",
			category:  shared.MetricsBan,
			operation: shared.MetricsBan, // Must be "ban" to match in RecordBanOperation
			success:   true,
			sleep:     12 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMetrics()
			ctx := context.Background()

			// Start operation
			op := NewTimedOperation(ctx, m, tt.category, tt.operation)

			// Simulate work
			time.Sleep(tt.sleep)

			// Finish operation
			op.Finish(tt.success)

			// Verify metrics were recorded based on category
			switch tt.category {
			case "command":
				// Command metrics should have been recorded
				assert.Greater(t, m.CommandExecutions, int64(0))
			case "client":
				// Client metrics should have been recorded
				assert.Greater(t, m.ClientOperations, int64(0))
			case shared.MetricsBan:
				// Ban metrics should have been recorded
				assert.Greater(t, m.BanOperations, int64(0))
			}
		})
	}
}

// TestTimedOperationConcurrentFinish tests concurrent Finish calls
func TestTimedOperationConcurrentFinish(t *testing.T) {
	m := NewMetrics()
	ctx := context.Background()

	// Start multiple operations concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			op := NewTimedOperation(ctx, m, "command", "test")
			time.Sleep(5 * time.Millisecond)
			op.Finish(true)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all operations were recorded
	assert.Equal(t, int64(10), m.CommandExecutions)
}

// TestRecordValidationFailureConcurrent tests concurrent validation failure recording
func TestRecordValidationFailureConcurrent(t *testing.T) {
	m := NewMetrics()

	// Record 100 failures concurrently
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			m.RecordValidationFailure()
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	assert.Equal(t, int64(100), m.ValidationFailures)
}
