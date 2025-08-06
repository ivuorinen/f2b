package cmd

import (
	"testing"
)

func TestIntegration_BanUnbanFlow(t *testing.T) {
	mock := NewMockClient()

	// Ban an IP in sshd
	NewCommandTest(t, "ban").
		WithArgs("1.2.3.4", "sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Banned 1.2.3.4 in sshd").
		Run()

	// Ban again (should be already banned)
	NewCommandTest(t, "ban").
		WithArgs("1.2.3.4", "sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Already banned 1.2.3.4 in sshd").
		Run()

	// Unban the IP
	NewCommandTest(t, "unban").
		WithArgs("1.2.3.4", "sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Unbanned 1.2.3.4 in sshd").
		Run()

	// Unban again (should be already unbanned)
	NewCommandTest(t, "unban").
		WithArgs("1.2.3.4", "sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Already unbanned 1.2.3.4 in sshd").
		Run()
}

func TestIntegration_BannedCommandAndTestIP(t *testing.T) {
	mock := NewMockClient()

	// Ban two IPs in different jails
	NewCommandTest(t, "ban").WithArgs("1.2.3.4", "sshd").WithMockClient(mock).ExpectSuccess().Run()
	NewCommandTest(t, "ban").WithArgs("5.6.7.8", "apache").WithMockClient(mock).ExpectSuccess().Run()

	// List banned IPs
	NewCommandTest(t, "banned").
		WithArgs("sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("sshd | 1.2.3.4").
		Run()

	// Test IP command - banned IP
	NewCommandTest(t, "test").
		WithArgs("1.2.3.4").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("is banned in").
		Run()

	// Test IP command - not banned IP
	NewCommandTest(t, "test").
		WithArgs("9.9.9.9").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("is not banned").
		Run()
}

func TestIntegration_LogsFilteringAndFormat(t *testing.T) {
	mock := NewMockClient()

	// Ban IPs to generate logs
	NewCommandTest(t, "ban").WithArgs("1.2.3.4", "sshd").WithMockClient(mock).ExpectSuccess().Run()
	NewCommandTest(t, "ban").WithArgs("5.6.7.8", "apache").WithMockClient(mock).ExpectSuccess().Run()

	// Get logs for sshd
	NewCommandTest(t, "logs").
		WithArgs("sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("sshd").
		Run()

	// Get logs for specific IP
	NewCommandTest(t, "logs").
		WithArgs("apache", "5.6.7.8").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("5.6.7.8").
		Run()

	// Test JSON output
	NewCommandTest(t, "logs").
		WithArgs("sshd").
		WithMockClient(mock).
		WithJSONFormat().
		ExpectSuccess().
		ExpectOutput("[").
		Run()
}

func TestIntegration_InvalidInputAndErrors(t *testing.T) {
	mock := NewMockClient()

	// Ban with invalid jail
	NewCommandTest(t, "ban").
		WithArgs("1.2.3.4", "notajail").
		WithMockClient(mock).
		ExpectError().
		ExpectOutput("not found").
		Run()

	// Ban with invalid IP
	NewCommandTest(t, "ban").
		WithArgs("notanip", "sshd").
		WithMockClient(mock).
		ExpectError().
		ExpectOutput("invalid IP address").
		Run()

	// Unban with invalid jail
	NewCommandTest(t, "unban").
		WithArgs("1.2.3.4", "notajail").
		WithMockClient(mock).
		ExpectError().
		ExpectOutput("not found").
		Run()
}

func TestIntegration_ListJailsAndStatus(t *testing.T) {
	mock := NewMockClient()

	// List jails
	result := NewCommandTest(t, "list-jails").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("sshd").
		Run()

	// Also check for apache jail
	result.AssertContains("apache")

	// Status all
	NewCommandTest(t, "status").
		WithArgs("all").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Mock status for all jails").
		Run()

	// Status specific jail
	NewCommandTest(t, "status").
		WithArgs("sshd").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Mock status for jail sshd").
		Run()
}

func TestIntegration_BannedCommand_JSON(t *testing.T) {
	mock := NewMockClient()

	// Ban an IP
	NewCommandTest(t, "ban").WithArgs("1.2.3.4", "sshd").WithMockClient(mock).ExpectSuccess().Run()

	// List banned IPs in JSON
	NewCommandTest(t, "banned").
		WithArgs("sshd").
		WithMockClient(mock).
		WithJSONFormat().
		ExpectSuccess().
		ExpectOutput("\"Jail\"").
		Run()
}

// Optionally, add more tests for edge cases, concurrency, and error propagation.
