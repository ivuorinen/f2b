package cmd

import (
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestDemoCommandTestFramework shows how to use the new framework vs old patterns
func TestDemoCommandTestFramework(t *testing.T) {
	// OLD WAY (verbose, lots of setup code):
	t.Run("old_way_example", func(t *testing.T) {
		// Setup mock client (8 lines of repetitive code)
		mock := NewMockClient()
		setMockJails(mock, []string{"sshd", "apache"})
		mock.StatusAllData = "Status for all jails"
		mock.StatusJailData = map[string]string{
			"sshd":   "Status for sshd jail",
			"apache": "Status for apache jail",
		}

		// Execute command (3 lines)
		output, err := executeCommand(mock, "status", "all")

		// Validate results (4-5 lines)
		AssertError(t, err, false, "status all command")
		if output != "Status for all jails\n" {
			t.Errorf("expected 'Status for all jails\\n', got %q", output)
		}
	})

	// NEW WAY (concise, fluent interface):
	t.Run("new_way_example", func(t *testing.T) {
		NewCommandTest(t, "status").
			WithArgs("all").
			WithSetup(func(mock *fail2ban.MockClient) {
				mock.StatusAllData = "Status for all jails"
				setMockJails(mock, []string{"sshd", "apache"})
			}).
			ExpectSuccess().
			ExpectOutput("Status for all jails").
			Run()
	})

	// Advanced example with environment setup
	t.Run("advanced_environment_example", func(t *testing.T) {
		env := NewTestEnvironment().
			WithPrivileges(true).
			WithMockRunner()
		defer env.Cleanup()

		NewCommandTest(t, "ban").
			WithArgs("192.168.1.100", "sshd").
			WithEnvironment(env).
			WithSetup(func(mock *fail2ban.MockClient) {
				setMockJails(mock, []string{"sshd"})
			}).
			ExpectSuccess().
			ExpectOutput("Banned 192.168.1.100 in sshd").
			Run()
	})

	// JSON output testing example
	t.Run("json_output_example", func(t *testing.T) {
		NewCommandTest(t, "banned").
			WithArgs("sshd").
			WithJSONFormat().
			WithSetup(func(mock *fail2ban.MockClient) {
				setMockJails(mock, []string{"sshd"})
				// Pre-ban an IP for testing
				_, _ = mock.BanIP("192.168.1.100", "sshd")
			}).
			ExpectSuccess().
			Run().
			AssertJSONField("Jail", "sshd")
	})

	// Error testing example
	t.Run("error_handling_example", func(t *testing.T) {
		NewCommandTest(t, "ban").
			WithArgs("192.168.1.100", "nonexistent").
			ExpectError().
			Run().
			AssertContains("not found")
	})
}

// TestDemoTableDrivenWithFramework shows how to use the framework with table-driven tests
func TestDemoTableDrivenWithFramework(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		args        []string
		setup       func(*fail2ban.MockClient)
		expectError bool
		expectedOut string
	}{
		{
			name:    "list jails success",
			command: "list-jails",
			setup: func(mock *fail2ban.MockClient) {
				setMockJails(mock, []string{"sshd", "apache"})
			},
			expectError: false,
			expectedOut: "apache",
		},
		{
			name:    "status specific jail",
			command: "status",
			args:    []string{"sshd"},
			setup: func(mock *fail2ban.MockClient) {
				setMockJails(mock, []string{"sshd"})
				mock.StatusJailData = map[string]string{"sshd": "Status for sshd"}
			},
			expectError: false,
			expectedOut: "Status for sshd",
		},
		{
			name:        "ban invalid jail",
			command:     "ban",
			args:        []string{"192.168.1.100", "nonexistent"},
			expectError: true,
			expectedOut: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Single line test execution with framework
			builder := NewCommandTest(t, tt.command).
				WithArgs(tt.args...)

			if tt.setup != nil {
				builder = builder.WithSetup(tt.setup)
			}

			if tt.expectError {
				builder = builder.ExpectError()
			} else {
				builder = builder.ExpectSuccess()
			}

			if tt.expectedOut != "" {
				builder = builder.ExpectOutput(tt.expectedOut)
			}

			builder.Run()
		})
	}
}
