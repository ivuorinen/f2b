package cmd

import (
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestStatusCommandRefactored demonstrates the new framework vs the old approach
func TestStatusCommandRefactored(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		jails      []string
		statusAll  string
		statusJail map[string]string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "status all",
			args:       []string{"all"},
			jails:      []string{"sshd"},
			statusAll:  "Status for all jails\n",
			wantOutput: "Status for all jails\n",
			wantError:  false,
		},
		{
			name:       "status specific jail",
			args:       []string{"sshd"},
			jails:      []string{"sshd"},
			statusJail: map[string]string{"sshd": "Status for sshd jail\n"},
			wantOutput: "Status for sshd jail\n",
			wantError:  false,
		},
		{
			name:       "status nonexistent jail",
			args:       []string{"nonexistent"},
			jails:      []string{"sshd"},
			wantOutput: "Error: jail 'nonexistent' not found",
			wantError:  true,
		},
		{
			name:       "status no args shows usage",
			args:       []string{},
			jails:      []string{"sshd"},
			wantOutput: "Available jails: sshd",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		// OLD WAY (current approach - 10 lines of setup and validation per test)
		t.Run("old_"+tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, tt.jails)
			mock.StatusAllData = tt.statusAll
			mock.StatusJailData = tt.statusJail

			output, err := executeCommand(mock, append([]string{"status"}, tt.args...)...)

			AssertError(t, err, tt.wantError, tt.name)

			if tt.wantOutput != "" && !strings.Contains(output, tt.wantOutput) {
				t.Errorf("expected output to contain %q, got %q", tt.wantOutput, output)
			}
		})

		// NEW WAY (framework approach - 1 concise fluent call)
		t.Run("new_"+tt.name, func(t *testing.T) {
			builder := NewCommandTest(t, "status").
				WithArgs(tt.args...).
				WithSetup(func(mock *fail2ban.MockClient) {
					setMockJails(mock, tt.jails)
					if tt.statusAll != "" {
						mock.StatusAllData = tt.statusAll
					}
					if tt.statusJail != nil {
						mock.StatusJailData = tt.statusJail
					}
				})

			if tt.wantError {
				builder = builder.ExpectError()
			} else {
				builder = builder.ExpectSuccess()
			}

			if tt.wantOutput != "" {
				builder = builder.ExpectOutput(tt.wantOutput)
			}

			builder.Run()
		})
	}
}

// TestStatusCommandFrameworkAdvanced shows advanced features of the framework
func TestStatusCommandFrameworkAdvanced(t *testing.T) {
	// Environment setup with privileges
	env := NewTestEnvironment().
		WithPrivileges(true).
		WithMockRunner()
	defer env.Cleanup()

	// Complex test scenario with JSON output
	NewCommandTest(t, "status").
		WithArgs("sshd").
		WithJSONFormat().
		WithEnvironment(env).
		WithSetup(func(mock *fail2ban.MockClient) {
			setMockJails(mock, []string{"sshd", "apache"})
			mock.StatusJailData = map[string]string{
				"sshd": "Status for sshd jail",
			}
		}).
		ExpectSuccess().
		Run().
		AssertContains("Status for sshd jail").
		AssertNotContains("apache") // Should not contain other jail info

	// Chained assertions example
	result := NewCommandTest(t, "status").
		WithArgs("all").
		WithSetup(func(mock *fail2ban.MockClient) {
			setMockJails(mock, []string{"sshd", "apache", "nginx"})
			mock.StatusAllData = "All jails status summary"
		}).
		ExpectSuccess().
		Run()

	// Multiple assertions on same result
	result.AssertContains("All jails").
		AssertContains("status").
		AssertNotEmpty().
		AssertNotContains("error")
}
