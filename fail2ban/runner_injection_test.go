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

// TestOSRunnerRefusesCallerSuppliedSudo pins the boundary MockRunner mirrors:
// the runner adds sudo itself, so a caller naming sudo as the command is
// refused before anything runs. The context is already canceled, so even if
// validation regressed, exec would refuse to start real sudo.
func TestOSRunnerRefusesCallerSuppliedSudo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (&fail2ban.OSRunner{}).CombinedOutputWithSudoContext(ctx, "sudo", "fail2ban-client", "status")

	if err == nil || !strings.Contains(err.Error(), "command validation failed") {
		t.Fatalf("expected sudo as a command to be refused by validation, got %v", err)
	}
}
