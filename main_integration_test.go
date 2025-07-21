package main

import (
	"os"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestMainIntegration tests the main function logic without actual execution
func TestMainIntegration(t *testing.T) {
	// Set up mock sudo checker for integration tests
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// This test verifies the main function's logic structure
	// without actually calling main() to avoid exit() calls

	testCases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "service command skips client init",
			args:     []string{"f2b", "service"},
			expected: "should skip client initialization",
		},
		{
			name:     "version command skips client init",
			args:     []string{"f2b", "version"},
			expected: "should skip client initialization",
		},
		{
			name:     "test-filter command skips client init",
			args:     []string{"f2b", "test-filter"},
			expected: "should skip client initialization",
		},
		{
			name:     "completion command skips client init",
			args:     []string{"f2b", "completion"},
			expected: "should skip client initialization",
		},
		{
			name:     "help command skips client init",
			args:     []string{"f2b", "help"},
			expected: "should skip client initialization",
		},
		{
			name:     "other commands need client init",
			args:     []string{"f2b", "list-jails"},
			expected: "should require client initialization",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the main function's argument parsing logic
			args := tc.args
			skip := shouldSkipClientInit(args)

			if strings.Contains(tc.expected, "skip") && !skip {
				t.Errorf("expected to skip client initialization for %v", tc.args)
			}
			if strings.Contains(tc.expected, "require") && skip {
				t.Errorf("expected to require client initialization for %v", tc.args)
			}
		})
	}
}

// TestMainFunctionLogic tests the main function logic without calling main() directly
func TestMainFunctionLogic(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		envVars        map[string]string
		expectSkip     bool
		expectedLogDir string
		expectedFormat string
	}{
		{
			name:           "service command skips client init",
			args:           []string{"f2b", "service", "status"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "version command skips client init",
			args:           []string{"f2b", "version"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "test-filter command skips client init",
			args:           []string{"f2b", "test-filter", "sshd"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "completion command skips client init",
			args:           []string{"f2b", "completion", "bash"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "help command skips client init",
			args:           []string{"f2b", "help"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "ban command needs client init",
			args:           []string{"f2b", "ban", "192.168.1.100"},
			expectSkip:     false,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
		{
			name:           "custom log dir from env",
			args:           []string{"f2b", "version"},
			envVars:        map[string]string{"F2B_LOG_DIR": "/custom/log"},
			expectSkip:     true,
			expectedLogDir: "/custom/log",
			expectedFormat: "plain",
		},
		{
			name:           "custom filter dir from env",
			args:           []string{"f2b", "version"},
			envVars:        map[string]string{"F2B_FILTER_DIR": "/custom/filter"},
			expectSkip:     true,
			expectedLogDir: "/var/log",
			expectedFormat: "plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment using t.Setenv for automatic cleanup
			t.Setenv("F2B_LOG_DIR", os.Getenv("F2B_LOG_DIR"))
			t.Setenv("F2B_FILTER_DIR", os.Getenv("F2B_FILTER_DIR"))

			// Set test env vars
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			// Test the main function's logic
			args := tt.args

			// Build config from env/flags (mimic main function)
			config := struct {
				LogDir    string
				FilterDir string
				Format    string
			}{}

			config.LogDir = os.Getenv("F2B_LOG_DIR")
			if config.LogDir == "" {
				config.LogDir = "/var/log"
			}
			config.FilterDir = os.Getenv("F2B_FILTER_DIR")
			if config.FilterDir == "" {
				config.FilterDir = "/etc/fail2ban/filter.d"
			}
			config.Format = "plain"

			// Test skip logic
			skip := shouldSkipClientInit(args)

			if skip != tt.expectSkip {
				t.Errorf("expected skip=%t, got skip=%t", tt.expectSkip, skip)
			}

			if config.LogDir != tt.expectedLogDir {
				t.Errorf("expected LogDir=%q, got %q", tt.expectedLogDir, config.LogDir)
			}

			if config.Format != tt.expectedFormat {
				t.Errorf("expected Format=%q, got %q", tt.expectedFormat, config.Format)
			}
		})
	}
}
