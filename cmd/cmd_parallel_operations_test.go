package cmd

import (
	"errors"
	"testing"
)

func TestParallelOperations_IndexValidation(t *testing.T) {
	// Test to ensure negative indices don't cause panics
	mockClient := NewMockClient()

	jails := []string{"sshd", "apache"} // Use default jails from mock

	// This should not panic even if there were negative indices
	results, err := ProcessBanOperationParallel(mockClient, "192.168.1.100", jails)

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

func TestParallelOperations_UnbanIndexValidation(t *testing.T) {
	// Test unban operations for index validation
	mockClient := NewMockClient()

	// Ban the IP first so we can unban it using framework for consistency
	NewCommandTest(t, "ban").WithArgs("192.168.1.100", "sshd").WithMockClient(mockClient).ExpectSuccess().Run()
	NewCommandTest(t, "ban").WithArgs("192.168.1.100", "apache").WithMockClient(mockClient).ExpectSuccess().Run()

	jails := []string{"sshd", "apache"}

	// This should not panic even if there were negative indices
	results, err := ProcessUnbanOperationParallel(mockClient, "192.168.1.100", jails)

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

func TestParallelOperations_EmptyJailsList(t *testing.T) {
	// Test edge case with empty jails list
	mockClient := NewMockClient()

	results, err := ProcessBanOperationParallel(mockClient, "192.168.1.100", []string{})

	if err != nil {
		t.Fatalf("ProcessBanOperationParallel with empty jails failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty jails, got %d", len(results))
	}
}

func TestParallelOperations_ErrorHandling(t *testing.T) {
	// Test error handling returns aggregated errors while still populating results
	mockClient := NewMockClient()

	// Use non-existent jail to trigger error
	jails := []string{"nonexistent1", "nonexistent2"}

	results, err := ProcessBanOperationParallel(mockClient, "192.168.1.100", jails)

	// Errors should now be returned (aggregated)
	if err == nil {
		t.Error("Expected error for non-existent jails, got nil")
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// All results should still be populated with error status
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

func TestParallelOperations_ConcurrentSafety(t *testing.T) {
	// Test concurrent access doesn't cause race conditions or index issues
	mockClient := NewMockClient()

	// Set up for multiple IPs and jails
	ips := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	jails := []string{"sshd", "apache"} // Use existing jails in mock

	// Run multiple operations concurrently
	errChan := make(chan error, len(ips))

	for _, ip := range ips {
		go func(testIP string) {
			results, err := ProcessBanOperationParallel(mockClient, testIP, jails)
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
	for i := range ips {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent operation %d failed: %v", i, err)
		}
	}
}
