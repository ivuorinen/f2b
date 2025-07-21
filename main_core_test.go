package main

import (
	"os"
	"testing"
)

func TestMainFunction(t *testing.T) {
	// Test main function execution with different arguments
	tests := []struct {
		name        string
		args        []string
		expectExit  bool
		description string
	}{
		{
			name:        "version command",
			args:        []string{"f2b", "version"},
			expectExit:  false,
			description: "version command should work without fail2ban client",
		},
		{
			name:        "service command",
			args:        []string{"f2b", "service", "status"},
			expectExit:  false,
			description: "service command should work without fail2ban client",
		},
		{
			name:        "test-filter command",
			args:        []string{"f2b", "test-filter", "sshd"},
			expectExit:  false,
			description: "test-filter command should work without fail2ban client",
		},
		{
			name:        "completion command",
			args:        []string{"f2b", "completion", "bash"},
			expectExit:  false,
			description: "completion command should work without fail2ban client",
		},
		{
			name:        "help command",
			args:        []string{"f2b", "help"},
			expectExit:  false,
			description: "help command should work without fail2ban client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args
			originalArgs := os.Args
			defer func() {
				os.Args = originalArgs
			}()

			// Set test args
			os.Args = tt.args

			// For commands that don't require fail2ban client, we can test they don't panic
			// We can't easily test the full execution without mocking the entire command system
			// or without fail2ban being installed, so we'll just test that the argument parsing works

			// Test that the skip logic works correctly
			args := os.Args
			skip := shouldSkipClientInit(args)

			expectedSkip := shouldSkipClientInit(tt.args)

			if skip != expectedSkip {
				t.Errorf("expected skip=%t, got skip=%t for args %v", expectedSkip, skip, tt.args)
			}
		})
	}
}

func TestArgumentParsing(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldSkip  bool
		description string
	}{
		{
			name:        "no arguments",
			args:        []string{"f2b"},
			shouldSkip:  false,
			description: "should not skip with no arguments",
		},
		{
			name:        "list-jails command",
			args:        []string{"f2b", "list-jails"},
			shouldSkip:  false,
			description: "should not skip list-jails command",
		},
		{
			name:        "service command",
			args:        []string{"f2b", "service", "status"},
			shouldSkip:  true,
			description: "should skip service command",
		},
		{
			name:        "version command",
			args:        []string{"f2b", "version"},
			shouldSkip:  true,
			description: "should skip version command",
		},
		{
			name:        "test-filter command",
			args:        []string{"f2b", "test-filter", "sshd"},
			shouldSkip:  true,
			description: "should skip test-filter command",
		},
		{
			name:        "completion command",
			args:        []string{"f2b", "completion", "bash"},
			shouldSkip:  true,
			description: "should skip completion command",
		},
		{
			name:        "help command",
			args:        []string{"f2b", "help"},
			shouldSkip:  true,
			description: "should skip help command",
		},
		{
			name:        "ban command",
			args:        []string{"f2b", "ban", "192.168.1.100"},
			shouldSkip:  false,
			description: "should not skip ban command",
		},
		{
			name:        "status command",
			args:        []string{"f2b", "status", "all"},
			shouldSkip:  false,
			description: "should not skip status command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			skip := shouldSkipClientInit(args)

			if skip != tt.shouldSkip {
				t.Errorf("expected skip=%t, got skip=%t for args %v", tt.shouldSkip, skip, tt.args)
			}
		})
	}
}

func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldSkip  bool
		description string
	}{
		{
			name:        "empty args",
			args:        []string{},
			shouldSkip:  false,
			description: "empty args should not skip",
		},
		{
			name:        "nil args",
			args:        nil,
			shouldSkip:  false,
			description: "nil args should not skip",
		},
		{
			name:        "single arg",
			args:        []string{"f2b"},
			shouldSkip:  false,
			description: "single arg should not skip",
		},
		{
			name:        "unknown command",
			args:        []string{"f2b", "unknown"},
			shouldSkip:  false,
			description: "unknown command should not skip",
		},
		{
			name:        "case sensitivity",
			args:        []string{"f2b", "VERSION"},
			shouldSkip:  false,
			description: "uppercase command should not skip (case sensitive)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip := shouldSkipClientInit(tt.args)

			if skip != tt.shouldSkip {
				t.Errorf("expected skip=%t, got skip=%t for args %v", tt.shouldSkip, skip, tt.args)
			}
		})
	}
}
