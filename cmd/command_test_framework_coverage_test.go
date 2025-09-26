package cmd

import (
	"testing"
)

// TestCommandTestFrameworkCoverage tests the uncovered functions in the test framework
func TestCommandTestFrameworkCoverage(t *testing.T) {
	t.Run("WithName", func(t *testing.T) {
		// Test the WithName method that has 0% coverage
		builder := NewCommandTest(t, "status")
		result := builder.WithName("test-status-command")

		if result.name != "test-status-command" {
			t.Errorf("Expected name to be set to 'test-status-command', got %s", result.name)
		}

		// Verify it returns the builder for method chaining
		if result != builder {
			t.Error("WithName should return the same builder instance for chaining")
		}
	})

	t.Run("AssertEmpty", func(t *testing.T) {
		// Test AssertEmpty with empty output
		result := &CommandTestResult{
			Output: "",
			Error:  nil,
			t:      t,
			name:   "test",
		}

		// This should not panic since output is empty
		result.AssertEmpty()
	})

	t.Run("TestEnvironmentReadStdout", func(t *testing.T) {
		// Test ReadStdout method that has 0% coverage
		env := NewTestEnvironment()
		defer env.Cleanup()

		// Test reading stdout when no pipes are set up
		output := env.ReadStdout()
		if output != "" {
			t.Errorf("Expected empty output when no pipes set up, got %s", output)
		}
	})

	t.Run("AssertEmpty_with_whitespace", func(t *testing.T) {
		// Test AssertEmpty with whitespace-only output
		result := &CommandTestResult{
			Output: "   \n  \t  ",
			Error:  nil,
			t:      t,
			name:   "whitespace-test",
		}

		// AssertEmpty should handle whitespace-only output as empty
		result.AssertEmpty()
	})

	t.Run("AssertNotEmpty", func(t *testing.T) {
		// Test AssertNotEmpty with non-empty output
		result := &CommandTestResult{
			Output: "some content",
			Error:  nil,
			t:      t,
			name:   "content-test",
		}

		// This should not panic since output has content
		result.AssertNotEmpty()
	})
}

// TestStringHelpers tests the new string helper functions for code deduplication
func TestStringHelpers(t *testing.T) {
	t.Run("TrimmedString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"  hello  ", "hello"},
			{"\n\tworld\t\n", "world"},
			{"", ""},
			{"   ", ""},
		}

		for _, tt := range tests {
			result := TrimmedString(tt.input)
			if result != tt.expected {
				t.Errorf("TrimmedString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("IsEmptyString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected bool
		}{
			{"", true},
			{"   ", true},
			{"\n\t  \n", true},
			{"hello", false},
			{"  hello  ", false},
		}

		for _, tt := range tests {
			result := IsEmptyString(tt.input)
			if result != tt.expected {
				t.Errorf("IsEmptyString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("NonEmptyString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected bool
		}{
			{"", false},
			{"   ", false},
			{"\n\t  \n", false},
			{"hello", true},
			{"  hello  ", true},
		}

		for _, tt := range tests {
			result := NonEmptyString(tt.input)
			if result != tt.expected {
				t.Errorf("NonEmptyString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})
}
