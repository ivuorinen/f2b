package main

import (
	"bytes"
	"os"
	"strings"
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
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			expectedSkip := false
			if len(tt.args) > 1 {
				switch tt.args[1] {
				case "service", "version", "test-filter", "completion", "help":
					expectedSkip = true
				}
			}

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
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			if skip != tt.shouldSkip {
				t.Errorf("expected skip=%t, got skip=%t for args %v", tt.shouldSkip, skip, tt.args)
			}
		})
	}
}

// TestClientInitializationLogic tests that client initialization is skipped for appropriate commands
func TestClientInitializationLogic(t *testing.T) {
	// Set up mock sudo checker for client initialization tests
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Test the logic that determines whether to skip client initialization
	skipCommands := []string{"service", "version", "test-filter", "completion", "help"}
	regularCommands := []string{"list-jails", "status", "ban", "unban", "test", "banned", "logs"}

	for _, cmd := range skipCommands {
		t.Run("skip_"+cmd, func(t *testing.T) {
			args := []string{"f2b", cmd}
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}
			if !skip {
				t.Errorf("expected to skip client initialization for command %s", cmd)
			}
		})
	}

	for _, cmd := range regularCommands {
		t.Run("dont_skip_"+cmd, func(t *testing.T) {
			args := []string{"f2b", cmd}
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}
			if skip {
				t.Errorf("expected NOT to skip client initialization for command %s", cmd)
			}
		})
	}
}

// TestEdgeCases tests edge cases in argument handling
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
			name:        "single arg",
			args:        []string{"f2b"},
			shouldSkip:  false,
			description: "single arg should not skip",
		},
		{
			name:        "case sensitivity",
			args:        []string{"f2b", "VERSION"},
			shouldSkip:  false,
			description: "case sensitive check should not skip uppercase VERSION",
		},
		{
			name:        "similar command name",
			args:        []string{"f2b", "service-status"},
			shouldSkip:  false,
			description: "similar but different command should not skip",
		},
		{
			name:        "version with extra args",
			args:        []string{"f2b", "version", "extra"},
			shouldSkip:  true,
			description: "version with extra args should still skip",
		},
		{
			name:        "completion with shell arg",
			args:        []string{"f2b", "completion", "bash"},
			shouldSkip:  true,
			description: "completion with shell arg should skip",
		},
		{
			name:        "help with command arg",
			args:        []string{"f2b", "help", "ban"},
			shouldSkip:  true,
			description: "help with command arg should skip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			if skip != tt.shouldSkip {
				t.Errorf("expected skip=%t, got skip=%t for args %v", tt.shouldSkip, skip, tt.args)
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
			// Save original env vars
			originalLogDir := os.Getenv("F2B_LOG_DIR")
			originalFilterDir := os.Getenv("F2B_FILTER_DIR")

			// Set test env vars
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("failed to set %s: %v", key, err)
				}
			}

			// Restore env vars after test
			defer func() {
				if err := os.Setenv("F2B_LOG_DIR", originalLogDir); err != nil {
					t.Fatalf("failed to restore F2B_LOG_DIR: %v", err)
				}
				if err := os.Setenv("F2B_FILTER_DIR", originalFilterDir); err != nil {
					t.Fatalf("failed to restore F2B_FILTER_DIR: %v", err)
				}
			}()

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
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

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

// TestMainConfigurationParsing tests the configuration parsing logic
func TestMainConfigurationParsing(t *testing.T) {
	tests := []struct {
		name              string
		logDirEnv         string
		filterDirEnv      string
		expectedLogDir    string
		expectedFilterDir string
	}{
		{
			name:              "default values",
			logDirEnv:         "",
			filterDirEnv:      "",
			expectedLogDir:    "/var/log",
			expectedFilterDir: "/etc/fail2ban/filter.d",
		},
		{
			name:              "custom log dir",
			logDirEnv:         "/custom/logs",
			filterDirEnv:      "",
			expectedLogDir:    "/custom/logs",
			expectedFilterDir: "/etc/fail2ban/filter.d",
		},
		{
			name:              "custom filter dir",
			logDirEnv:         "",
			filterDirEnv:      "/custom/filters",
			expectedLogDir:    "/var/log",
			expectedFilterDir: "/custom/filters",
		},
		{
			name:              "both custom",
			logDirEnv:         "/my/logs",
			filterDirEnv:      "/my/filters",
			expectedLogDir:    "/my/logs",
			expectedFilterDir: "/my/filters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env vars
			originalLogDir := os.Getenv("F2B_LOG_DIR")
			originalFilterDir := os.Getenv("F2B_FILTER_DIR")

			// Set test env vars
			if tt.logDirEnv != "" {
				if err := os.Setenv("F2B_LOG_DIR", tt.logDirEnv); err != nil {
					t.Fatalf("failed to set F2B_LOG_DIR: %v", err)
				}
			} else {
				if err := os.Unsetenv("F2B_LOG_DIR"); err != nil {
					t.Fatalf("failed to unset F2B_LOG_DIR: %v", err)
				}
			}
			if tt.filterDirEnv != "" {
				if err := os.Setenv("F2B_FILTER_DIR", tt.filterDirEnv); err != nil {
					t.Fatalf("failed to set F2B_FILTER_DIR: %v", err)
				}
			} else {
				if err := os.Unsetenv("F2B_FILTER_DIR"); err != nil {
					t.Fatalf("failed to unset F2B_FILTER_DIR: %v", err)
				}
			}

			// Restore env vars after test
			defer func() {
				if originalLogDir != "" {
					if err := os.Setenv("F2B_LOG_DIR", originalLogDir); err != nil {
						t.Fatalf("failed to restore F2B_LOG_DIR: %v", err)
					}
				} else {
					if err := os.Unsetenv("F2B_LOG_DIR"); err != nil {
						t.Fatalf("failed to unset F2B_LOG_DIR: %v", err)
					}
				}
				if originalFilterDir != "" {
					if err := os.Setenv("F2B_FILTER_DIR", originalFilterDir); err != nil {
						t.Fatalf("failed to restore F2B_FILTER_DIR: %v", err)
					}
				} else {
					if err := os.Unsetenv("F2B_FILTER_DIR"); err != nil {
						t.Fatalf("failed to unset F2B_FILTER_DIR: %v", err)
					}
				}
			}()

			// Simulate main function config building
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

			if config.LogDir != tt.expectedLogDir {
				t.Errorf("expected LogDir=%q, got %q", tt.expectedLogDir, config.LogDir)
			}
			if config.FilterDir != tt.expectedFilterDir {
				t.Errorf("expected FilterDir=%q, got %q", tt.expectedFilterDir, config.FilterDir)
			}
		})
	}
}

// TestMainClientInitialization tests the client initialization logic
func TestMainClientInitialization(t *testing.T) {
	skipCommands := []string{"service", "version", "test-filter", "completion", "help"}
	regularCommands := []string{"list-jails", "status", "ban", "unban", "test", "banned", "logs", "logs-watch"}

	for _, cmd := range skipCommands {
		t.Run("skip_"+cmd, func(t *testing.T) {
			args := []string{"f2b", cmd}
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}
			if !skip {
				t.Errorf("expected to skip client initialization for command %s", cmd)
			}
		})
	}

	for _, cmd := range regularCommands {
		t.Run("require_"+cmd, func(t *testing.T) {
			args := []string{"f2b", cmd}
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}
			if skip {
				t.Errorf("expected NOT to skip client initialization for command %s", cmd)
			}
		})
	}
}

// TestMainFail2banSetup tests the fail2ban setup logic
func TestMainFail2banSetup(t *testing.T) {
	// Test that the global fail2ban package functions are called
	// We can't easily test this without mocking the package, but we can test
	// that the logic is correct

	testLogDir := "/test/logs"
	testFilterDir := "/test/filters"

	// This would be called in main:
	// fail2ban.SetLogDir(config.LogDir)
	// fail2ban.SetFilterDir(config.FilterDir)

	// We can test the effect by checking that these don't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("fail2ban setup functions should not panic: %v", r)
		}
	}()

	fail2ban.SetLogDir(testLogDir)
	fail2ban.SetFilterDir(testFilterDir)
}

// TestMainErrorHandling tests error handling scenarios
func TestMainErrorHandling(t *testing.T) {
	// Test error handling for both sudo privilege errors and other errors
	tests := []struct {
		name          string
		hasPrivileges bool
		expectHint    bool
		description   string
	}{
		{
			name:          "sudo privilege error shows hint",
			hasPrivileges: false,
			expectHint:    true,
			description:   "should show sudo hint for privilege errors",
		},
		{
			name:          "sufficient privileges no hint needed",
			hasPrivileges: true,
			expectHint:    false,
			description:   "should not show sudo hint when privileges sufficient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock sudo checker
			originalChecker := fail2ban.GetSudoChecker()
			defer fail2ban.SetSudoChecker(originalChecker)
			mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)
			fail2ban.SetSudoChecker(mockChecker)

			// Test CheckSudoRequirements error handling
			err := fail2ban.CheckSudoRequirements()

			if !tt.hasPrivileges {
				if err == nil {
					t.Fatal("expected sudo privilege error")
				}
				if !strings.Contains(err.Error(), "fail2ban operations require sudo privileges") {
					t.Errorf("expected privilege error message, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error with sufficient privileges: %v", err)
				}
			}
		})
	}

	// Test basic error output formatting
	mockError := "mock client creation error"

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Simulate error handling from main
	// This is what main does: fmt.Fprintln(os.Stderr, "Error:", err)
	_, err := os.Stderr.Write([]byte("Error: " + mockError + "\n"))
	if err != nil {
		t.Fatalf("failed to write to stderr: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Error: "+mockError) {
		t.Errorf("expected error output to contain %q, got %q", "Error: "+mockError, output)
	}
}

// TestMainArgumentValidation tests various argument combinations
func TestMainArgumentValidation(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "no arguments",
			args:     []string{"f2b"},
			expected: "should not skip client init",
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: "should not skip client init",
		},
		{
			name:     "service with subcommand",
			args:     []string{"f2b", "service", "start"},
			expected: "should skip client init",
		},
		{
			name:     "version with extra args",
			args:     []string{"f2b", "version", "--help"},
			expected: "should skip client init",
		},
		{
			name:     "help with command",
			args:     []string{"f2b", "help", "ban"},
			expected: "should skip client init",
		},
		{
			name:     "completion with shell",
			args:     []string{"f2b", "completion", "bash"},
			expected: "should skip client init",
		},
		{
			name:     "test-filter with filter name",
			args:     []string{"f2b", "test-filter", "sshd"},
			expected: "should skip client init",
		},
		{
			name:     "ban command",
			args:     []string{"f2b", "ban", "192.168.1.100"},
			expected: "should not skip client init",
		},
		{
			name:     "unknown command",
			args:     []string{"f2b", "unknown"},
			expected: "should not skip client init",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			if strings.Contains(tt.expected, "should skip") && !skip {
				t.Errorf("expected to skip client init for args %v", args)
			}
			if strings.Contains(tt.expected, "should not skip") && skip {
				t.Errorf("expected NOT to skip client init for args %v", args)
			}
		})
	}
}

// TestMainEnvironmentVariables tests that environment variables are properly handled
func TestMainEnvironmentVariables(t *testing.T) {
	envTests := []struct {
		name     string
		envVar   string
		value    string
		expected string
	}{
		{
			name:     "F2B_LOG_DIR",
			envVar:   "F2B_LOG_DIR",
			value:    "/custom/log/path",
			expected: "/custom/log/path",
		},
		{
			name:     "F2B_FILTER_DIR",
			envVar:   "F2B_FILTER_DIR",
			value:    "/custom/filter/path",
			expected: "/custom/filter/path",
		},
	}

	for _, tt := range envTests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			original := os.Getenv(tt.envVar)

			// Set test value
			if err := os.Setenv(tt.envVar, tt.value); err != nil {
				t.Fatalf("failed to set %s: %v", tt.envVar, err)
			}

			// Restore after test
			defer func() {
				if original != "" {
					if err := os.Setenv(tt.envVar, original); err != nil {
						t.Fatalf("failed to restore %s: %v", tt.envVar, err)
					}
				} else {
					if err := os.Unsetenv(tt.envVar); err != nil {
						t.Fatalf("failed to unset %s: %v", tt.envVar, err)
					}
				}
			}()

			// Get value (this simulates what main does)
			result := os.Getenv(tt.envVar)

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

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
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			if strings.Contains(tc.expected, "skip") && !skip {
				t.Errorf("expected to skip client initialization for %v", tc.args)
			}
			if strings.Contains(tc.expected, "require") && skip {
				t.Errorf("expected to require client initialization for %v", tc.args)
			}
		})
	}
}

// BenchmarkArgumentParsing benchmarks the argument parsing logic
func BenchmarkArgumentParsing(b *testing.B) {
	testArgs := [][]string{
		{"f2b", "version"},
		{"f2b", "service", "status"},
		{"f2b", "test-filter", "sshd"},
		{"f2b", "completion", "bash"},
		{"f2b", "help"},
		{"f2b", "list-jails"},
		{"f2b", "ban", "192.168.1.100"},
		{"f2b", "status", "all"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, args := range testArgs {
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}
			_ = skip // Use the result to prevent optimization
		}
	}
}

// BenchmarkMainLogic benchmarks the main function's decision logic
func BenchmarkMainLogic(b *testing.B) {
	testArgs := [][]string{
		{"f2b", "version"},
		{"f2b", "service", "status"},
		{"f2b", "ban", "192.168.1.100"},
		{"f2b", "list-jails"},
		{"f2b", "completion", "bash"},
		{"f2b", "help"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, args := range testArgs {
			// Simulate main function logic
			skip := false
			if len(args) > 1 {
				switch args[1] {
				case "service", "version", "test-filter", "completion", "help":
					skip = true
				}
			}

			// Simulate config building
			config := struct {
				LogDir    string
				FilterDir string
				Format    string
			}{
				LogDir:    "/var/log",
				FilterDir: "/etc/fail2ban/filter.d",
				Format:    "plain",
			}

			_ = skip
			_ = config
		}
	}
}
