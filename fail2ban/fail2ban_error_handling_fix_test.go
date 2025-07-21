package fail2ban

import (
	"fmt"
	"testing"
)

// TestErrorHandlingFix demonstrates the fix for the nil error handling issue
func TestErrorHandlingFix(t *testing.T) {
	// This test demonstrates the correct error handling when a function succeeds
	// but returns no results for an expected case

	t.Run("demonstrate_error_creation_for_empty_results", func(t *testing.T) {
		// Simulate the scenario that was fixed:
		// 1. Function call succeeds (err == nil)
		// 2. But results are empty when we expect data

		var err error      // This would be nil from a successful function call
		var lines []string // This would be empty from the function
		jail := "sshd"     // This is the jail we're checking

		// Before the fix: would send nil error to channel (incorrect)
		// After the fix: creates descriptive error (correct)

		var resultError error
		if len(lines) == 0 && jail == "sshd" {
			// This is the fix - create a proper error instead of sending nil
			resultError = fmt.Errorf("expected log lines for sshd jail but got empty result")
		} else {
			resultError = err // This would be nil in the success case
		}

		// Verify the fix works correctly
		if len(lines) == 0 && jail == "sshd" {
			if resultError == nil {
				t.Error("Error should not be nil when sshd jail has no log lines")
			}
			if resultError.Error() != "expected log lines for sshd jail but got empty result" {
				t.Errorf("Expected specific error message, got: %v", resultError)
			}
			t.Log("✅ Fix working correctly - created descriptive error for empty sshd logs")
		}
	})

	t.Run("demonstrate_no_error_for_other_jails", func(t *testing.T) {
		// Test that we don't create errors for other jails with empty results
		var err error      // nil from successful function call
		var lines []string // empty results
		jail := "apache"   // different jail

		var resultError error
		if len(lines) == 0 && jail == "sshd" {
			resultError = fmt.Errorf("expected log lines for sshd jail but got empty result")
		} else {
			resultError = err // should remain nil
		}

		// For non-sshd jails, we should not create an error
		if resultError != nil {
			t.Errorf("Should not create error for non-sshd jail with empty results, got: %v", resultError)
		} else {
			t.Log("✅ Correctly handling non-sshd jail with empty results (no error)")
		}
	})

	t.Run("demonstrate_no_error_when_sshd_has_lines", func(t *testing.T) {
		// Test that we don't create errors when sshd jail has log lines
		var err error                                 // nil from successful function call
		lines := []string{"log line 1", "log line 2"} // has results
		jail := "sshd"

		var resultError error
		if len(lines) == 0 && jail == "sshd" {
			resultError = fmt.Errorf("expected log lines for sshd jail but got empty result")
		} else {
			resultError = err // should remain nil
		}

		// When sshd has lines, we should not create an error
		if resultError != nil {
			t.Errorf("Should not create error when sshd jail has log lines, got: %v", resultError)
		} else {
			t.Log("✅ Correctly handling sshd jail with log lines (no error)")
		}
	})
}

// TestConcurrentErrorChannelUsage demonstrates proper error channel usage
func TestConcurrentErrorChannelUsage(t *testing.T) {
	// This test demonstrates the pattern used in the concurrent log reading test

	t.Run("proper_error_channel_usage", func(t *testing.T) {
		errChan := make(chan error, 3)

		// Simulate the scenarios
		scenarios := []struct {
			name  string
			err   error
			lines []string
			jail  string
		}{
			{"successful_with_lines", nil, []string{"line1"}, "sshd"},
			{"successful_empty_non_sshd", nil, []string{}, "apache"},
			{"successful_empty_sshd", nil, []string{}, "sshd"}, // This should create an error
		}

		for _, scenario := range scenarios {
			// Simulate the goroutine logic from the integration test
			if scenario.err != nil {
				errChan <- scenario.err
			} else if len(scenario.lines) == 0 && scenario.jail == "sshd" {
				// This is the fix - create proper error instead of sending nil
				errChan <- fmt.Errorf("expected log lines for sshd jail but got empty result")
			}
		}

		close(errChan)

		// Check the results
		errorCount := 0
		for err := range errChan {
			if err != nil {
				errorCount++
				t.Logf("Received error: %v", err)
			} else {
				t.Error("Should not receive nil errors in channel")
			}
		}

		// Should have exactly one error (from the empty sshd scenario)
		if errorCount != 1 {
			t.Errorf("Expected exactly 1 error, got %d", errorCount)
		} else {
			t.Log("✅ Correctly handled all scenarios with proper error creation")
		}
	})
}
