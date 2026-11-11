// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestSetRunner tests the runner setting functionality
func TestSetRunner(t *testing.T) {
	// Create a test runner
	testRunner := &fail2bantest.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	// Set the test runner (and restore the original afterwards so later
	// tests don't inherit this mock)
	orig := fail2ban.GetRunner()
	t.Cleanup(func() { fail2ban.SetRunner(orig) })
	fail2ban.SetRunner(testRunner)

	// Test that the runner is used
	testRunner.SetResponse("fail2ban-client status sshd", []byte("test-output"))

	output, err := fail2ban.GetRunner().CombinedOutputWithSudoContext(
		context.Background(),
		"fail2ban-client",
		"status",
		"sshd",
	)
	fail2bantest.AssertError(t, err, false, "RunnerCombinedOutputWithSudoContext")

	if string(output) != "test-output" {
		t.Errorf("expected output %q, got %q", "test-output", string(output))
	}
}

// TestOSRunnerWithoutSudo tests that the OS runner enforces the command
// allowlist: a command outside it must be rejected before any exec.
func TestOSRunnerWithoutSudo(t *testing.T) {
	runner := &fail2ban.OSRunner{}

	if _, err := runner.CombinedOutputWithSudoContext(context.Background(), "echo", "hello"); err == nil {
		t.Fatal("expected non-allowlisted command to be rejected")
	}
}

// TestOSRunnerWithSudo tests the OS runner with sudo
func TestOSRunnerWithSudo(t *testing.T) {
	// Do not parallelize: this test mutates global runner
	orig := fail2ban.GetRunner()
	t.Cleanup(func() { fail2ban.SetRunner(orig) })
	mock := &fail2bantest.MockRunner{
		Responses: map[string][]byte{"sudo fail2ban-client status": []byte("ok\n")},
		Errors:    map[string]error{},
	}
	fail2ban.SetRunner(mock)
	out, err := fail2ban.GetRunner().
		CombinedOutputWithSudoContext(context.Background(), "sudo", "fail2ban-client", "status")
	fail2bantest.AssertError(t, err, false, "CombinedOutputWithSudoContext with sudo (mocked)")
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("expected %q, got %q", "ok", strings.TrimSpace(string(out)))
	}
}
