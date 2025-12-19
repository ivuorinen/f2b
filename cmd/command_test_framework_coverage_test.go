package cmd

import (
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
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

// TestCommandTestBuilder_WithArgs tests the WithArgs method
func TestCommandTestBuilder_WithArgs(t *testing.T) {
	builder := NewCommandTest(t, "status")
	result := builder.WithArgs("arg1", "arg2", "arg3")

	if len(result.args) != 3 {
		t.Errorf("Expected 3 args, got %d", len(result.args))
	}

	if result.args[0] != "arg1" || result.args[1] != "arg2" || result.args[2] != "arg3" {
		t.Errorf("Args not set correctly: %v", result.args)
	}

	// Verify method chaining
	if result != builder {
		t.Error("WithArgs should return the same builder instance for chaining")
	}
}

// TestCommandTestBuilder_WithJSONFormat tests the WithJSONFormat method
func TestCommandTestBuilder_WithJSONFormat(t *testing.T) {
	builder := NewCommandTest(t, "status")
	result := builder.WithJSONFormat()

	// Verify JSON format was set
	if result.config.Format != JSONFormat {
		t.Errorf("Expected JSONFormat, got %s", result.config.Format)
	}

	// Verify method chaining
	if result != builder {
		t.Error("WithJSONFormat should return the same builder instance for chaining")
	}
}

// TestCommandTestBuilder_WithSetup tests the WithSetup callback execution
func TestCommandTestBuilder_WithSetup(t *testing.T) {
	setupCalled := false
	builder := NewCommandTest(t, "version")

	builder.WithSetup(func(mockClient *fail2ban.MockClient) {
		setupCalled = true
		// Verify we received a mock client
		if mockClient == nil {
			t.Error("Setup should receive a non-nil mock client")
		}
	})

	// Setup should be stored but not called yet
	if setupCalled {
		t.Error("Setup should not be called during WithSetup")
	}

	// Run the command to trigger setup
	builder.Run()

	// Now setup should have been called
	if !setupCalled {
		t.Error("Setup callback should be executed during Run")
	}
}

// TestCommandTestBuilder_Run tests the Run method
func TestCommandTestBuilder_Run(t *testing.T) {
	builder := NewCommandTest(t, "version")

	// Should not panic and should return a result
	result := builder.Run()

	if result == nil {
		t.Fatal("Run should return a non-nil result")
		return
	}

	if result.name != "version" {
		t.Errorf("Expected command name 'version', got %s", result.name)
	}
}

// TestCommandTestBuilder_AssertContains tests the AssertContains method
func TestCommandTestBuilder_AssertContains(t *testing.T) {
	builder := NewCommandTest(t, "version")

	// Run command and assert output contains "f2b"
	result := builder.Run()
	result.AssertContains("f2b")
}

// TestCommandTestBuilder_MethodChaining tests chaining multiple configurations
func TestCommandTestBuilder_MethodChaining(t *testing.T) {
	builder := NewCommandTest(t, "status")

	// Chain multiple configurations
	result := builder.
		WithName("test-status").
		WithArgs("--format", "json").
		WithJSONFormat()

	// Verify all configurations were applied
	if result.name != "test-status" {
		t.Errorf("Expected name 'test-status', got %s", result.name)
	}

	if len(result.args) != 2 || result.args[0] != "--format" || result.args[1] != "json" {
		t.Errorf("Expected args [--format json], got %v", result.args)
	}

	if result.config.Format != JSONFormat {
		t.Errorf("Expected JSONFormat, got %s", result.config.Format)
	}

	// Verify chaining works (should be same instance)
	if result != builder {
		t.Error("Method chaining should return the same builder instance")
	}
}

// TestCommandTestResult_AssertExactOutput tests exact output matching
func TestCommandTestResult_AssertExactOutput(t *testing.T) {
	result := &CommandTestResult{
		Output: "exact output",
		Error:  nil,
		t:      t,
		name:   "exact-test",
	}

	// This should not panic since output matches exactly
	result.AssertExactOutput("exact output")
}

// TestCommandTestResult_AssertContains tests substring matching
func TestCommandTestResult_AssertContains(t *testing.T) {
	result := &CommandTestResult{
		Output: "this is test output",
		Error:  nil,
		t:      t,
		name:   "contains-test",
	}

	// This should not panic since output contains the substring
	result.AssertContains("test")
}

// TestCommandTestResult_AssertNotContains tests negative substring matching
func TestCommandTestResult_AssertNotContains(t *testing.T) {
	result := &CommandTestResult{
		Output: "this is test output",
		Error:  nil,
		t:      t,
		name:   "not-contains-test",
	}

	// This should not panic since output doesn't contain "error"
	result.AssertNotContains("error")
}

// TestEnvironmentCleanup tests the environment cleanup functionality
func TestEnvironmentCleanup(t *testing.T) {
	cleanupCalled := false

	env := NewTestEnvironment()
	// Add a custom cleanup function to track if cleanup is called
	env.cleanup = append(env.cleanup, func() {
		cleanupCalled = true
	})

	// Trigger cleanup
	env.Cleanup()

	if !cleanupCalled {
		t.Error("Cleanup should be called")
	}
}

// TestCommandTestBuilder_MultipleArgsVariations tests different argument patterns
func TestCommandTestBuilder_MultipleArgsVariations(t *testing.T) {
	t.Run("empty_args", func(t *testing.T) {
		builder := NewCommandTest(t, "status")
		result := builder.WithArgs()

		if len(result.args) != 0 {
			t.Errorf("Expected 0 args, got %d", len(result.args))
		}
	})

	t.Run("single_arg", func(t *testing.T) {
		builder := NewCommandTest(t, "status")
		result := builder.WithArgs("--help")

		if len(result.args) != 1 || result.args[0] != "--help" {
			t.Errorf("Expected args [--help], got %v", result.args)
		}
	})

	t.Run("multiple_args", func(t *testing.T) {
		builder := NewCommandTest(t, "status")
		result := builder.WithArgs("--format", "json", "--verbose")

		if len(result.args) != 3 {
			t.Errorf("Expected 3 args, got %d", len(result.args))
		}

		expected := []string{"--format", "json", "--verbose"}
		for i, arg := range result.args {
			if arg != expected[i] {
				t.Errorf("Arg %d: expected %s, got %s", i, expected[i], arg)
			}
		}
	})
}

// TestMockClientBuilder_WithJails tests jail configuration
func TestMockClientBuilder_WithJails(t *testing.T) {
	builder := NewMockClientBuilder()
	builder.WithJails("sshd", "apache")

	client := builder.Build()

	if len(client.Jails) != 2 {
		t.Errorf("Expected 2 jails, got %d", len(client.Jails))
	}
}

// TestMockClientBuilder_WithBannedIP tests banned IP configuration
func TestMockClientBuilder_WithBannedIP(t *testing.T) {
	builder := NewMockClientBuilder()
	builder.WithBannedIP("192.168.1.100", "sshd")

	client := builder.Build()

	if client.BanResults == nil {
		t.Error("BanResults should be initialized")
	}

	if status, ok := client.BanResults["192.168.1.100"]["sshd"]; !ok || status != 1 {
		t.Error("IP should be marked as banned in jail")
	}
}

// TestCommandTestBuilder_WithMockBuilder tests MockClientBuilder integration
func TestCommandTestBuilder_WithMockBuilder(t *testing.T) {
	mockBuilder := NewMockClientBuilder().
		WithJails("sshd").
		WithBannedIP("192.168.1.100", "sshd")

	builder := NewCommandTest(t, "status").
		WithMockBuilder(mockBuilder)

	// Verify mock client was set
	if builder.mockClient == nil {
		t.Error("Mock client should be set")
	}

	if len(builder.mockClient.Jails) != 1 {
		t.Errorf("Expected 1 jail, got %d", len(builder.mockClient.Jails))
	}
}
