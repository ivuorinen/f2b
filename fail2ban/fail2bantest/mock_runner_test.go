package fail2bantest

import (
	"context"
	"slices"
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

	// A mock checker for a non-root user with sudo, so the sudo branch runs
	// on every host instead of depending on the real UID and groups.
	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(&MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true})
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })
	mockRunner.SetResponse("sudo fail2ban-client status", []byte("sudo response"))

	out, err = mockRunner.CombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "status")
	if err != nil || string(out) != "sudo response" {
		t.Fatalf("sudo context variant did not return the sudo response: out=%q err=%v", out, err)
	}

	calls := mockRunner.GetCalls()
	want := []string{"fail2ban-client status", "fail2ban-client reload", "sudo fail2ban-client status"}
	if !slices.Equal(calls, want) {
		t.Fatalf("recorded calls = %v, want %v", calls, want)
	}

	// A non-allowlisted command must be rejected by the mock's validation.
	if _, err := mockRunner.CombinedOutput("cmd1"); err == nil {
		t.Fatal("expected non-allowlisted command to be rejected")
	}
}
