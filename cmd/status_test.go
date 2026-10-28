package cmd

import (
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestStatusCommandRefactored demonstrates comprehensive status command testing with the modern framework
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
		// Framework approach with fluent interface
		t.Run(tt.name, func(t *testing.T) {
			assertStatusRefactoredCase(t, tt.args, tt.jails, tt.statusAll,
				tt.statusJail, tt.wantOutput, tt.wantError)
		})
	}
}

// assertStatusRefactoredCase runs a single TestStatusCommandRefactored table case.
func assertStatusRefactoredCase(t *testing.T, args, jails []string, statusAll string,
	statusJail map[string]string, wantOutput string, wantError bool) {
	t.Helper()
	builder := NewCommandTest(t, "status").
		WithArgs(args...).
		WithSetup(func(mock *fail2ban.MockClient) {
			setMockJails(mock, jails)
			if statusAll != "" {
				mock.StatusAllData = statusAll
			}
			if statusJail != nil {
				mock.StatusJailData = statusJail
			}
		})

	if wantError {
		builder = builder.ExpectError()
	} else {
		builder = builder.ExpectSuccess()
	}

	if wantOutput != "" {
		builder = builder.ExpectOutput(wantOutput)
	}

	builder.Run()
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
