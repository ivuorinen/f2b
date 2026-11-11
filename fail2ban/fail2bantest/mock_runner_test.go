package fail2bantest

import (
	"context"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMockRunnerMethods(t *testing.T) {
	mockRunner := NewMockRunner()

	mockRunner.SetResponse("fail2ban-client status", []byte("response1"))
	mockRunner.SetError("fail2ban-client reload", fail2ban.NewInvalidIPError("test error"))

	out, err := mockRunner.CombinedOutput("fail2ban-client", "status")
	if err != nil || string(out) != "response1" {
		t.Fatalf("configured response did not round-trip: out=%q err=%v", out, err)
	}
	if _, err := mockRunner.CombinedOutput("fail2ban-client", "reload"); err == nil {
		t.Fatal("configured error was not returned")
	}

	ctx := context.Background()
	if _, err := mockRunner.CombinedOutputWithSudoContext(ctx, "fail2ban-client", "status"); err != nil {
		t.Fatalf("sudo context variant failed: %v", err)
	}

	calls := mockRunner.GetCalls()
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 recorded calls, got %d: %v", len(calls), calls)
	}
	if calls[0] != "fail2ban-client status" {
		t.Fatalf("first recorded call = %q, want %q", calls[0], "fail2ban-client status")
	}

	// A non-allowlisted command must be rejected by the mock's validation.
	if _, err := mockRunner.CombinedOutput("cmd1"); err == nil {
		t.Fatal("expected non-allowlisted command to be rejected")
	}
}
