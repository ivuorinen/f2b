package cmd

import (
	"errors"
	"testing"
)

func TestParallelOperationProcessor_IndexValidation(t *testing.T) {
	// Test to ensure negative indices don't cause panics
	processor := NewParallelOperationProcessor(2)

	// Mock client for testing
	mockClient := NewMockClient()

	jails := []string{"sshd", "apache"} // Use default jails from mock

	// This should not panic even if there were negative indices
	results, err := processor.ProcessBanOperationParallel(mockClient, "192.168.1.100", jails)

	if err != nil {
		t.Fatalf("ProcessBanOperationParallel failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// Verify all results are valid
	for i, result := range results {
		if result.Jail == "" {
			t.Errorf("Result %d has empty jail", i)
		}
		if result.Status == "" {
			t.Errorf("Result %d has empty status", i)
		}
	}
}

func TestParallelOperationProcessor_UnbanIndexValidation(t *testing.T) {
	// Test unban operations for index validation
	processor := NewParallelOperationProcessor(2)

	// Mock client for testing - need to ban first
	mockClient := NewMockClient()

	// Ban the IP first so we can unban it
	_, _ = mockClient.BanIP("192.168.1.100", "sshd")
	_, _ = mockClient.BanIP("192.168.1.100", "apache")

	jails := []string{"sshd", "apache"}

	// This should not panic even if there were negative indices
	results, err := processor.ProcessUnbanOperationParallel(mockClient, "192.168.1.100", jails)

	if err != nil {
		t.Fatalf("ProcessUnbanOperationParallel failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// Verify all results are valid
	for i, result := range results {
		if result.Jail == "" {
			t.Errorf("Result %d has empty jail", i)
		}
		if result.Status == "" {
			t.Errorf("Result %d has empty status", i)
		}
	}
}

func TestParallelOperationProcessor_EmptyJailsList(t *testing.T) {
	// Test edge case with empty jails list
	processor := NewParallelOperationProcessor(2)
	mockClient := NewMockClient()

	results, err := processor.ProcessBanOperationParallel(mockClient, "192.168.1.100", []string{})

	if err != nil {
		t.Fatalf("ProcessBanOperationParallel with empty jails failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty jails, got %d", len(results))
	}
}

func TestParallelOperationProcessor_ErrorHandling(t *testing.T) {
	// Test error handling doesn't cause index issues
	processor := NewParallelOperationProcessor(2)

	// Mock client for testing
	mockClient := NewMockClient()

	// Use non-existent jail to trigger error
	jails := []string{"nonexistent1", "nonexistent2"}

	results, err := processor.ProcessBanOperationParallel(mockClient, "192.168.1.100", jails)

	if err != nil {
		t.Fatalf("ProcessBanOperationParallel failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// All results should have errors for non-existent jails
	for i, result := range results {
		if result.Jail == "" {
			t.Errorf("Result %d has empty jail", i)
		}
		// Status should indicate the error (e.g., "jail 'nonexistent1' not found")
		if result.Status == "" {
			t.Errorf("Result %d has empty status", i)
		}
	}
}

func TestParallelOperationProcessor_ConcurrentSafety(t *testing.T) {
	// Test concurrent access doesn't cause race conditions or index issues
	processor := NewParallelOperationProcessor(4)
	mockClient := NewMockClient()

	// Set up for multiple IPs and jails
	ips := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	jails := []string{"sshd", "apache"} // Use existing jails in mock

	// Run multiple operations concurrently
	errChan := make(chan error, len(ips))

	for _, ip := range ips {
		go func(testIP string) {
			results, err := processor.ProcessBanOperationParallel(mockClient, testIP, jails)
			if err != nil {
				errChan <- err
				return
			}
			if len(results) != len(jails) {
				errChan <- errors.New("incorrect number of results")
				return
			}
			errChan <- nil
		}(ip)
	}

	// Check all operations completed successfully
	for i := 0; i < len(ips); i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent operation %d failed: %v", i, err)
		}
	}
}

func TestNewParallelOperationProcessor(t *testing.T) {
	// Test processor creation with various worker counts
	tests := []struct {
		name        string
		workerCount int
		expectCPU   bool
	}{
		{"positive worker count", 4, false},
		{"zero worker count uses CPU count", 0, true},
		{"negative worker count uses CPU count", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewParallelOperationProcessor(tt.workerCount)

			if processor == nil {
				t.Fatal("NewParallelOperationProcessor returned nil")
			}

			if tt.expectCPU {
				// Should use CPU count when invalid worker count provided
				if processor.workerCount <= 0 {
					t.Error("Worker count should be positive when using CPU count")
				}
			} else {
				if processor.workerCount != tt.workerCount {
					t.Errorf("Expected worker count %d, got %d", tt.workerCount, processor.workerCount)
				}
			}
		})
	}
}
