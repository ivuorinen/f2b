package cmd

import (
	"bytes"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// MockClient is a type alias for the enhanced MockClient from fail2ban package
type MockClient = fail2ban.MockClient

// NewMockClient creates a new MockClient for testing
func NewMockClient() *MockClient {
	return fail2ban.NewMockClient()
}

// setMockJails sets jails for the enhanced MockClient
func setMockJails(mock *MockClient, jails []string) {
	mock.Jails = make(map[string]struct{})
	for _, jail := range jails {
		mock.Jails[jail] = struct{}{}
	}
}

// setupMockEnvironment sets up mock sudo checker for testing
func setupMockEnvironment() func() {
	// Set up mock sudo checker
	originalChecker := fail2ban.GetSudoChecker()
	mockChecker := &fail2ban.MockSudoChecker{
		MockHasPrivileges:     true,
		ExplicitPrivilegesSet: true,
	}
	fail2ban.SetSudoChecker(mockChecker)

	// Return cleanup function
	return func() {
		fail2ban.SetSudoChecker(originalChecker)
	}
}

// executeCommand executes a command with proper mock setup and output capture
func executeCommand(client fail2ban.Client, args ...string) (string, error) {
	// Suppress logrus output during tests
	oldLoggerOut := Logger.Out
	Logger.SetOutput(io.Discard)
	defer Logger.SetOutput(oldLoggerOut)

	// Ensure mock sudo checker is set for commands that need it
	cleanup := setupMockEnvironment()
	defer cleanup()

	rootCmd := &cobra.Command{Use: "f2b"}
	config := Config{Format: "plain"}

	// Set up persistent flags like in the real root command
	rootCmd.PersistentFlags().StringVar(&config.Format, "format", config.Format, "Output format: plain or json")

	rootCmd.AddCommand(ListJailsCmd(client, &config))
	rootCmd.AddCommand(StatusCmd(client, &config))
	rootCmd.AddCommand(BanCmd(client, &config))
	rootCmd.AddCommand(UnbanCmd(client, &config))
	rootCmd.AddCommand(TestIPCmd(client, &config))
	rootCmd.AddCommand(LogsCmd(client, &config))
	rootCmd.AddCommand(BannedCmd(client, &config))
	rootCmd.AddCommand(VersionCmd(&config))
	rootCmd.AddCommand(TestFilterCmd(client, &config))
	rootCmd.AddCommand(MetricsCmd(client, &config))

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()

	// Filter out logrus lines (starting with "time="), but keep "Error:" lines for error output tests
	lines := strings.Split(buf.String(), "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "time=") {
			filtered = append(filtered, line)
		}
	}
	// Remove trailing empty lines
	for len(filtered) > 0 && filtered[len(filtered)-1] == "" {
		filtered = filtered[:len(filtered)-1]
	}
	return strings.Join(filtered, "\n") + "\n", err
}

// AssertError provides standardized error checking for command tests
func AssertError(t interface {
	Helper()
	Fatalf(string, ...interface{})
}, err error, expectError bool, testName string) {
	t.Helper()
	if expectError && err == nil {
		t.Fatalf("%s: expected error but got none", testName)
	}
	if !expectError && err != nil {
		t.Fatalf("%s: unexpected error: %v", testName, err)
	}
}

// AssertOutputContains checks that output contains expected substring
func AssertOutputContains(t interface {
	Helper()
	Fatalf(string, ...interface{})
}, output, expectedSubstring, testName string) {
	t.Helper()
	if !strings.Contains(output, expectedSubstring) {
		t.Fatalf("%s: expected output containing %q but got %q", testName, expectedSubstring, output)
	}
}
