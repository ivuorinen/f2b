package cmd

import (
	"errors"
	"testing"
)

// TestMockClientBuilder demonstrates the new fluent mock builder pattern
func TestMockClientBuilder(t *testing.T) {
	t.Run("basic_builder_usage", func(t *testing.T) {
		// Using the new MockClientBuilder for complex mock setup
		mockBuilder := NewMockClientBuilder().
			WithJails("sshd", "apache").
			WithBannedIP("192.168.1.100", "sshd").
			WithBanRecord("sshd", "192.168.1.100", "01:30:00").
			WithLogLine("2024-01-01 12:00:00 [sshd] Ban 192.168.1.100").
			WithStatusResponse("sshd", "Mock status for jail sshd")

		NewCommandTest(t, "banned").
			WithArgs("sshd").
			WithMockBuilder(mockBuilder).
			ExpectSuccess().
			ExpectOutput("sshd | 192.168.1.100").
			Run()
	})

	t.Run("builder_with_errors", func(t *testing.T) {
		// Complex error scenario setup
		mockBuilder := NewMockClientBuilder().
			WithJails("sshd").
			WithBanError("sshd", "192.168.1.100", errors.New("ban operation failed"))

		NewCommandTest(t, "ban").
			WithArgs("192.168.1.100", "sshd").
			WithMockBuilder(mockBuilder).
			ExpectError().
			Run().
			AssertContains("ban operation failed")
	})

	t.Run("builder_with_multiple_ban_records", func(t *testing.T) {
		// Complex scenario with multiple ban records
		mockBuilder := NewMockClientBuilder().
			WithJails("sshd", "apache").
			WithBanRecord("sshd", "192.168.1.100", "01:30:00").
			WithBanRecord("apache", "192.168.1.101", "02:15:30").
			WithBanRecord("sshd", "192.168.1.102", "00:45:00")

		NewCommandTest(t, "banned").
			ExpectSuccess().
			WithMockBuilder(mockBuilder).
			Run().
			AssertContains("192.168.1.100").
			AssertContains("192.168.1.101").
			AssertContains("192.168.1.102")
	})

	t.Run("complex_multi_command_scenario", func(t *testing.T) {
		// Demonstrate comprehensive mock setup for multiple commands
		mockBuilder := NewMockClientBuilder().
			WithJails("sshd", "apache").
			WithBanRecord("sshd", "192.168.1.100", "01:30:00").
			WithBanRecord("apache", "192.168.1.101", "02:15:30").
			WithLogLine("2024-01-01 12:00:00 [sshd] Ban 192.168.1.100").
			WithLogLine("2024-01-01 12:01:00 [apache] Ban 192.168.1.101").
			WithStatusResponse("sshd", "Mock status for jail sshd")

		// Test status command
		NewCommandTest(t, "status").
			WithArgs("sshd").
			WithMockBuilder(mockBuilder).
			ExpectSuccess().
			ExpectOutput("Mock status for jail sshd").
			Run()

		// Test banned command
		NewCommandTest(t, "banned").
			WithMockBuilder(mockBuilder).
			ExpectSuccess().
			Run().
			AssertContains("192.168.1.100").
			AssertContains("192.168.1.101")

		// Test logs command
		NewCommandTest(t, "logs").
			WithMockBuilder(mockBuilder).
			ExpectSuccess().
			Run().
			AssertContains("Ban 192.168.1.100").
			AssertContains("Ban 192.168.1.101")
	})
}

// TestMockBuilderAdvancedFeatures tests advanced builder capabilities
func TestMockBuilderAdvancedFeatures(t *testing.T) {
	t.Run("chained_operations", func(t *testing.T) {
		// Demonstrate that builder can be reused and modified
		baseBuilder := NewMockClientBuilder().
			WithJails("sshd", "apache")

		// Create specialized builders from base
		sshBannedBuilder := baseBuilder.
			WithBannedIP("192.168.1.100", "sshd").
			WithBanRecord("sshd", "192.168.1.100", "01:30:00")

		apacheBannedBuilder := baseBuilder.
			WithBannedIP("192.168.1.101", "apache").
			WithBanRecord("apache", "192.168.1.101", "02:15:30")

		// Test SSH banned IP
		NewCommandTest(t, "banned").
			WithArgs("sshd").
			WithMockBuilder(sshBannedBuilder).
			ExpectSuccess().
			ExpectOutput("sshd | 192.168.1.100").
			Run()

		// Test Apache banned IP
		NewCommandTest(t, "banned").
			WithArgs("apache").
			WithMockBuilder(apacheBannedBuilder).
			ExpectSuccess().
			ExpectOutput("apache | 192.168.1.101").
			Run()
	})

	t.Run("error_scenarios", func(t *testing.T) {
		// Test various error scenarios with builder
		errorBuilder := NewMockClientBuilder().
			WithJails("sshd").
			WithBanError("sshd", "192.168.1.100", errors.New("IP already banned")).
			WithUnbanError("sshd", "192.168.1.101", errors.New("IP not found"))

		// Test ban error
		NewCommandTest(t, "ban").
			WithArgs("192.168.1.100", "sshd").
			WithMockBuilder(errorBuilder).
			ExpectError().
			Run().
			AssertContains("IP already banned")

		// Test unban error
		NewCommandTest(t, "unban").
			WithArgs("192.168.1.101", "sshd").
			WithMockBuilder(errorBuilder).
			ExpectError().
			Run().
			AssertContains("IP not found")
	})
}
