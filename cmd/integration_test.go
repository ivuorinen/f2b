package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Helper to execute a Cobra command and capture stdout/stderr
func executeCobraCommand(root *cobra.Command, args ...string) (string, error) {
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.Execute()
	output := outBuf.String() + errBuf.String()
	return output, err
}

func setupRootWithMock(mock *MockClient, config Config) *cobra.Command {
	root := &cobra.Command{Use: "f2b"}
	root.AddCommand(ListJailsCmd(mock))
	root.AddCommand(StatusCmd(mock, &config))
	root.AddCommand(BanCmd(mock, &config))
	root.AddCommand(UnbanCmd(mock, &config))
	root.AddCommand(TestIPCmd(mock, config.Format))
	root.AddCommand(LogsCmd(mock, &config))
	root.AddCommand(BannedCmd(mock, config.Format))
	return root
}

func TestIntegration_BanUnbanFlow(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: "plain"}
	root := setupRootWithMock(mock, config)

	// Ban an IP in sshd
	out, err := executeCobraCommand(root, "ban", "1.2.3.4", "sshd")
	if err != nil || !strings.Contains(out, "Banned 1.2.3.4 in sshd") {
		t.Fatalf("ban failed: %v, output: %s", err, out)
	}

	// Ban again (should be already banned)
	out, err = executeCobraCommand(root, "ban", "1.2.3.4", "sshd")
	if err != nil || !strings.Contains(out, "Already banned 1.2.3.4 in sshd") {
		t.Fatalf("ban (already banned) failed: %v, output: %s", err, out)
	}

	// Unban the IP
	out, err = executeCobraCommand(root, "unban", "1.2.3.4", "sshd")
	if err != nil || !strings.Contains(out, "Unbanned 1.2.3.4 in sshd") {
		t.Fatalf("unban failed: %v, output: %s", err, out)
	}

	// Unban again (should be already unbanned)
	out, err = executeCobraCommand(root, "unban", "1.2.3.4", "sshd")
	if err != nil || !strings.Contains(out, "Already unbanned 1.2.3.4 in sshd") {
		t.Fatalf("unban (already unbanned) failed: %v, output: %s", err, out)
	}
}

func TestIntegration_BannedCommandAndTestIP(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: "plain"}
	root := setupRootWithMock(mock, config)

	// Ban two IPs in different jails
	_, _ = executeCobraCommand(root, "ban", "1.2.3.4", "sshd")
	_, _ = executeCobraCommand(root, "ban", "5.6.7.8", "apache")

	// List banned IPs
	out, err := executeCobraCommand(root, "banned", "sshd")
	if err != nil || !strings.Contains(out, "sshd | 1.2.3.4") {
		t.Errorf("expected banned IP in sshd, got: %s", out)
	}

	// Test IP command
	out, err = executeCobraCommand(root, "test", "1.2.3.4")
	if err != nil || !strings.Contains(out, "is banned in") {
		t.Errorf("expected test to show banned, got: %s", out)
	}
	out, err = executeCobraCommand(root, "test", "9.9.9.9")
	if err != nil || !strings.Contains(out, "is not banned") {
		t.Errorf("expected test to show not banned, got: %s", out)
	}
}

func TestIntegration_LogsFilteringAndFormat(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: "plain"}
	root := setupRootWithMock(mock, config)

	// Ban IPs to generate logs
	_, _ = executeCobraCommand(root, "ban", "1.2.3.4", "sshd")
	_, _ = executeCobraCommand(root, "ban", "5.6.7.8", "apache")

	// Get logs for sshd
	out, err := executeCobraCommand(root, "logs", "sshd")
	if err != nil || !strings.Contains(out, "sshd") {
		t.Errorf("expected logs for sshd, got: %s", out)
	}

	// Get logs for specific IP
	out, err = executeCobraCommand(root, "logs", "apache", "5.6.7.8")
	if err != nil || !strings.Contains(out, "5.6.7.8") {
		t.Errorf("expected logs for 5.6.7.8, got: %s", out)
	}

	// Test JSON output
	config.Format = JSONFormat
	root = setupRootWithMock(mock, config)
	out, err = executeCobraCommand(root, "logs", "sshd")
	if err != nil || !strings.Contains(out, "[") {
		t.Errorf("expected JSON output for logs, got: %s", out)
	}
}

func TestIntegration_InvalidInputAndErrors(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: "plain"}
	root := setupRootWithMock(mock, config)

	// Ban with invalid jail
	out, err := executeCobraCommand(root, "ban", "1.2.3.4", "notajail")
	if err == nil || !strings.Contains(out, "not found") {
		t.Errorf("expected error for invalid jail, got: %s", out)
	}

	// Ban with invalid IP
	out, err = executeCobraCommand(root, "ban", "notanip", "sshd")
	if err == nil || !strings.Contains(out, "invalid IP address") {
		t.Errorf("expected error for invalid IP, got: %s", out)
	}

	// Unban with invalid jail
	out, err = executeCobraCommand(root, "unban", "1.2.3.4", "notajail")
	if err == nil || !strings.Contains(out, "not found") {
		t.Errorf("expected error for invalid jail on unban, got: %s", out)
	}
}

func TestIntegration_ListJailsAndStatus(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: "plain"}
	root := setupRootWithMock(mock, config)

	// List jails
	out, err := executeCobraCommand(root, "list-jails")
	if err != nil || !(strings.Contains(out, "sshd") && strings.Contains(out, "apache")) {
		t.Errorf("expected jails in output, got: %s", out)
	}

	// Status all
	out, err = executeCobraCommand(root, "status", "all")
	if err != nil || !strings.Contains(out, "Mock status for all jails") {
		t.Errorf("expected status all, got: %s", out)
	}

	// Status specific jail
	out, err = executeCobraCommand(root, "status", "sshd")
	if err != nil || !strings.Contains(out, "Mock status for jail sshd") {
		t.Errorf("expected status for sshd, got: %s", out)
	}
}

func TestIntegration_BannedCommand_JSON(t *testing.T) {
	mock := NewMockClient()
	config := Config{Format: JSONFormat}
	root := setupRootWithMock(mock, config)

	// Ban an IP
	_, _ = executeCobraCommand(root, "ban", "1.2.3.4", "sshd")

	// List banned IPs in JSON
	out, err := executeCobraCommand(root, "banned", "sshd")
	if err != nil || !strings.Contains(out, "\"Jail\"") {
		t.Errorf("expected JSON output for banned, got: %s", out)
	}
}

// Optionally, add more tests for edge cases, concurrency, and error propagation.
