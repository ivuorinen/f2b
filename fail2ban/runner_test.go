package fail2ban

import (
	"context"
	"fmt"
	"testing"
)

// TestGlobalStateAccessors covers the log-dir and runner setters/getters.
func TestGlobalStateAccessors(t *testing.T) {
	logDir := GetLogDir()
	if logDir == "" {
		t.Error("GetLogDir returned empty string")
	}

	originalLogDir := GetLogDir()
	t.Cleanup(func() { SetLogDir(originalLogDir) })
	SetLogDir("/tmp/test")
	if GetLogDir() != "/tmp/test" {
		t.Error("SetLogDir/GetLogDir not working properly")
	}

	mockRunner := NewMockRunner()
	t.Cleanup(WithTestRunner(t, mockRunner))
	if GetRunner() != mockRunner {
		t.Error("SetRunner/GetRunner not working properly")
	}
}

// TestRunnerCombinedOutputWithSudoContext checks that the global-runner entry
// point delegates to the current runner and returns its output.
func TestRunnerCombinedOutputWithSudoContext(t *testing.T) {
	mockRunner := NewMockRunner()
	mockRunner.SetResponse("fail2ban-client status", []byte("test output"))
	t.Cleanup(WithTestRunner(t, mockRunner))

	output, err := RunnerCombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "status")
	if err != nil {
		t.Fatalf("RunnerCombinedOutputWithSudoContext failed: %v", err)
	}
	if string(output) != "test output" {
		t.Errorf("Expected 'test output', got %q", string(output))
	}
}

func TestMockRunnerMethods(t *testing.T) {
	mockRunner := NewMockRunner()

	mockRunner.SetResponse("fail2ban-client status", []byte("response1"))
	mockRunner.SetError("fail2ban-client reload", NewInvalidIPError("test error"))

	out, err := mockRunner.CombinedOutput("fail2ban-client", "status")
	if err != nil || string(out) != "response1" {
		t.Fatalf("configured response did not round-trip: out=%q err=%v", out, err)
	}
	if _, err := mockRunner.CombinedOutput("fail2ban-client", "reload"); err == nil {
		t.Fatal("configured error was not returned")
	}

	ctx := context.Background()
	out, err = mockRunner.CombinedOutputWithContext(ctx, "fail2ban-client", "status")
	if err != nil || string(out) != "response1" {
		t.Fatalf("context variant did not round-trip: out=%q err=%v", out, err)
	}
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

// recordingT captures Fatalf calls so assert-helper failure paths are
// testable without failing the real test.
type recordingT struct {
	*testing.T
	fatal string
}

func (r *recordingT) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}

func TestTestHelperFunctions(t *testing.T) {
	// Test SetupBasicMockClient
	client := SetupBasicMockClient()
	if client == nil {
		t.Error("SetupBasicMockClient returned nil")
	}

	// Green paths run against the real t: a helper falsely failing here
	// fails the test. (No recover() wrappers: t.Fatalf exits via
	// runtime.Goexit, which recover cannot intercept anyway.)
	err := NewInvalidIPError("test")
	AssertError(t, err, true, "test error expected")
	AssertErrorContains(t, err, "test", "error should contain test")
	AssertCommandSuccess(t, nil, "output", "output", "test command success")
	AssertCommandError(t, NewInvalidIPError("test error"), "test error", "test error", "test command error")

	// Failure paths run against a recording shim: a helper falsely PASSING
	// (the dangerous regression) is caught here.
	rt := &recordingT{T: t}
	AssertError(rt, nil, true, "should record missing error")
	if rt.fatal == "" {
		t.Fatal("AssertError(nil, expectError=true) did not fail")
	}
	rt = &recordingT{T: t}
	AssertErrorContains(rt, NewInvalidIPError("test"), "absent-substring", "should record mismatch")
	if rt.fatal == "" {
		t.Fatal("AssertErrorContains with absent substring did not fail")
	}
	rt = &recordingT{T: t}
	AssertCommandSuccess(rt, NewInvalidIPError("boom"), "output", "output", "should record command error")
	if rt.fatal == "" {
		t.Fatal("AssertCommandSuccess with an error did not fail")
	}
	rt = &recordingT{T: t}
	AssertCommandError(rt, nil, "out", "expected", "should record missing error")
	if rt.fatal == "" {
		t.Fatal("AssertCommandError with nil error did not fail")
	}
}

func TestRealClientHelperMethods(t *testing.T) {
	_, cleanup := SetupMockEnvironmentWithSudo(t, false)
	defer cleanup()
	StandardMockSetup(MustMockRunner(t)) // NewClient's version check needs a response

	// NewClient against valid temp directories must succeed in the test
	// environment; skipping here would hide a real NewClient regression
	// behind a green skip.
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	tmpDir := t.TempDir()
	client, err := NewClient(tmpDir, tmpDir)
	if err != nil {
		t.Fatalf("NewClient with valid temp dirs failed: %v", err)
	}

	// An empty log directory yields empty results without error.
	ctx := context.Background()
	lines, err := client.GetLogLinesWithContext(ctx, "sshd", "192.168.1.1")
	if err != nil || len(lines) != 0 {
		t.Fatalf("GetLogLinesWithContext on empty dir: lines=%v err=%v", lines, err)
	}
	lines, err = client.GetLogLinesWithLimitContext(ctx, "sshd", "192.168.1.1", 10)
	if err != nil || len(lines) != 0 {
		t.Fatalf("GetLogLinesWithLimitContext on empty dir: lines=%v err=%v", lines, err)
	}
}
