package fail2bantest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

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
	err := fail2ban.NewInvalidIPError("test")
	AssertError(t, err, true, "test error expected")
	AssertErrorContains(t, err, "test", "error should contain test")
	AssertCommandSuccess(t, nil, "output", "output", "test command success")
	AssertCommandError(t, fail2ban.NewInvalidIPError("test error"), "test error", "test error", "test command error")

	// Failure paths run against a recording shim: a helper falsely PASSING
	// (the dangerous regression) is caught here.
	rt := &recordingT{T: t}
	AssertError(rt, nil, true, "should record missing error")
	if rt.fatal == "" {
		t.Fatal("AssertError(nil, expectError=true) did not fail")
	}
	rt = &recordingT{T: t}
	AssertErrorContains(rt, fail2ban.NewInvalidIPError("test"), "absent-substring", "should record mismatch")
	if rt.fatal == "" {
		t.Fatal("AssertErrorContains with absent substring did not fail")
	}
	rt = &recordingT{T: t}
	AssertCommandSuccess(rt, fail2ban.NewInvalidIPError("boom"), "output", "output", "should record command error")
	if rt.fatal == "" {
		t.Fatal("AssertCommandSuccess with an error did not fail")
	}
	rt = &recordingT{T: t}
	AssertCommandError(rt, nil, "out", "expected", "should record missing error")
	if rt.fatal == "" {
		t.Fatal("AssertCommandError with nil error did not fail")
	}
}

// SetupBasicMockClient creates a mock client with standard responses configured
func SetupBasicMockClient() *MockClient {
	client := NewMockClient()
	// Set up common test data
	client.StatusAllData = "Status: [sshd, apache] Jail list: sshd, apache"
	client.StatusJailData["sshd"] = "Status for jail: sshd"
	client.StatusJailData["apache"] = "Status for jail: apache"
	return client
}

// AssertErrorContains checks that error contains expected substring
func AssertErrorContains(tb testing.TB, err error, expectedSubstring string, testName string) {
	tb.Helper()
	if err == nil {
		tb.Fatalf("%s: expected error containing %q but got none", testName, expectedSubstring)
	}
	if !strings.Contains(err.Error(), expectedSubstring) {
		tb.Fatalf("%s: expected error containing %q but got %q", testName, expectedSubstring, err.Error())
	}
}

// AssertCommandSuccess checks that command succeeded and output contains expected text
func AssertCommandSuccess(tb testing.TB, err error, output, expectedOutput, testName string) {
	tb.Helper()
	if err != nil {
		tb.Fatalf(constants.ErrTestUnexpectedWithOutput, testName, err, output)
	}
	if expectedOutput != "" && !strings.Contains(output, expectedOutput) {
		tb.Fatalf(constants.ErrTestExpectedOutput, testName, expectedOutput, output)
	}
}

// AssertCommandError checks that command failed and output contains expected error text
func AssertCommandError(tb testing.TB, err error, output, expectedError, testName string) {
	tb.Helper()
	if err == nil {
		tb.Fatalf("%s: expected error but got none, output: %s", testName, output)
	}
	if expectedError != "" && !strings.Contains(output, expectedError) {
		tb.Fatalf("%s: expected error output to contain %q, got: %s", testName, expectedError, output)
	}
}
