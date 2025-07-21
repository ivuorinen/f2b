package main

import (
	"os"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMain(m *testing.M) {
	// Set up mock sudo checker with privileges for all tests
	originalChecker := fail2ban.GetSudoChecker()
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Run tests
	code := m.Run()

	// Restore original checker
	fail2ban.SetSudoChecker(originalChecker)

	os.Exit(code)
}

// shouldSkipClientInit determines if client initialization should be skipped
// based on the command arguments. Returns true for commands that don't require
// fail2ban client initialization.
func shouldSkipClientInit(args []string) bool {
	if len(args) <= 1 {
		return false
	}
	switch args[1] {
	case "service", "version", "test-filter", "completion", "help":
		return true
	}
	return false
}

func TestClientInitializationLogic(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldSkip  bool
		description string
	}{
		{
			name:        "version command should skip",
			args:        []string{"f2b", "version"},
			shouldSkip:  true,
			description: "version command doesn't need fail2ban client",
		},
		{
			name:        "service command should skip",
			args:        []string{"f2b", "service", "status"},
			shouldSkip:  true,
			description: "service command doesn't need fail2ban client",
		},
		{
			name:        "test-filter command should skip",
			args:        []string{"f2b", "test-filter", "sshd"},
			shouldSkip:  true,
			description: "test-filter command doesn't need fail2ban client",
		},
		{
			name:        "completion command should skip",
			args:        []string{"f2b", "completion", "bash"},
			shouldSkip:  true,
			description: "completion command doesn't need fail2ban client",
		},
		{
			name:        "help command should skip",
			args:        []string{"f2b", "help"},
			shouldSkip:  true,
			description: "help command doesn't need fail2ban client",
		},
		{
			name:        "status command should not skip",
			args:        []string{"f2b", "status"},
			shouldSkip:  false,
			description: "status command needs fail2ban client",
		},
		{
			name:        "banned command should not skip",
			args:        []string{"f2b", "banned"},
			shouldSkip:  false,
			description: "banned command needs fail2ban client",
		},
		{
			name:        "empty args should not skip",
			args:        []string{},
			shouldSkip:  false,
			description: "empty args should not skip client init",
		},
		{
			name:        "single arg should not skip",
			args:        []string{"f2b"},
			shouldSkip:  false,
			description: "single arg should not skip client init",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipClientInit(tt.args)
			if result != tt.shouldSkip {
				t.Errorf("shouldSkipClientInit(%v) = %v, want %v. %s",
					tt.args, result, tt.shouldSkip, tt.description)
			}
		})
	}
}
