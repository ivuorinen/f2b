package fail2ban_test

import (
	"context"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestGlobalStateAccessors covers the runner setter and getter.
func TestGlobalStateAccessors(t *testing.T) {
	mockRunner := fail2bantest.NewMockRunner()
	t.Cleanup(fail2bantest.WithTestRunner(t, mockRunner))
	if fail2ban.GetRunner() != mockRunner {
		t.Error("SetRunner/GetRunner not working properly")
	}
}

// TestRunnerCombinedOutputWithSudoContext checks that the global-runner entry
// point delegates to the current runner and returns its output.
func TestRunnerCombinedOutputWithSudoContext(t *testing.T) {
	mockRunner := fail2bantest.NewMockRunner()
	mockRunner.SetResponse("fail2ban-client status", []byte("test output"))
	t.Cleanup(fail2bantest.WithTestRunner(t, mockRunner))

	output, err := fail2ban.GetRunner().CombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "status")
	if err != nil {
		t.Fatalf("RunnerCombinedOutputWithSudoContext failed: %v", err)
	}
	if string(output) != "test output" {
		t.Errorf("Expected 'test output', got %q", string(output))
	}
}

func TestRealClientHelperMethods(t *testing.T) {
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, false)
	defer cleanup()
	fail2bantest.StandardMockSetup(fail2bantest.MustMockRunner(t)) // NewClient's version check needs a response

	// NewClient against valid temp directories must succeed in the test
	// environment; skipping here would hide a real NewClient regression
	// behind a green skip.
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	tmpDir := t.TempDir()
	client, err := fail2ban.NewClient(tmpDir, tmpDir)
	if err != nil {
		t.Fatalf("NewClient with valid temp dirs failed: %v", err)
	}

	// A directory holding no fail2ban log is an error, not an empty result.
	ctx := context.Background()
	if lines, err := client.GetLogLinesWithContext(ctx, "sshd", "192.168.1.1"); err == nil {
		t.Fatalf("GetLogLinesWithContext on empty dir returned no error, lines=%v", lines)
	}
	if lines, err := client.GetLogLinesWithLimitContext(ctx, "sshd", "192.168.1.1", 10); err == nil {
		t.Fatalf("GetLogLinesWithLimitContext on empty dir returned no error, lines=%v", lines)
	}
}
