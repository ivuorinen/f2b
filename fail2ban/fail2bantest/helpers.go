package fail2bantest

// Environment helpers that install the doubles as fail2ban's global runner and
// sudo checker, plus the assertion helper the test packages share.

import (
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// SetupMockEnvironment sets up complete mock environment with client, runner, and sudo checker
func SetupMockEnvironment(tb testing.TB) (client *MockClient, cleanup func()) {
	tb.Helper()

	// Store original components
	originalChecker := fail2ban.GetSudoChecker()
	originalRunner := fail2ban.GetRunner()

	// Set up mocks
	mockClient := NewMockClient()
	mockChecker := &MockSudoChecker{
		MockHasPrivileges:     true,
		ExplicitPrivilegesSet: true,
	}
	mockRunner := NewMockRunner()

	fail2ban.SetSudoChecker(mockChecker)
	fail2ban.SetRunner(mockRunner)

	// Configure comprehensive mock responses
	mockRunner.SetResponse(constants.MockCommandVersion, []byte(constants.VersionOutput))
	mockRunner.SetResponse(constants.MockCommandStatus, []byte(constants.StatusOutput))
	mockRunner.SetResponse(constants.MockCommandPing, []byte(constants.PingOutput))

	// Standard jail responses
	mockRunner.SetResponse(constants.MockCommandStatusSSHD, []byte("Status for the jail: sshd"))
	mockRunner.SetResponse(constants.MockCommandStatusApache, []byte("Status for the jail: apache"))

	// Standard ban responses
	mockRunner.SetResponse(constants.MockCommandBanIP, []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse(constants.MockCommandUnbanIP, []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse(constants.MockCommandBanned, []byte(constants.MockBannedOutput))

	cleanup = func() {
		fail2ban.SetSudoChecker(originalChecker)
		fail2ban.SetRunner(originalRunner)
	}

	return mockClient, cleanup
}

// SetupMockEnvironmentWithSudo sets up mock environment with specific sudo privileges
func SetupMockEnvironmentWithSudo(tb testing.TB, hasSudo bool) (client *MockClient, cleanup func()) {
	tb.Helper()

	// Store original components
	originalChecker := fail2ban.GetSudoChecker()
	originalRunner := fail2ban.GetRunner()

	// Set up mocks
	mockClient := NewMockClient()
	mockChecker := &MockSudoChecker{
		MockHasPrivileges:     hasSudo,
		ExplicitPrivilegesSet: true,
	}
	mockRunner := NewMockRunner()

	fail2ban.SetSudoChecker(mockChecker)
	fail2ban.SetRunner(mockRunner)

	// Configure mock responses based on sudo availability
	if hasSudo {
		mockRunner.SetResponse(constants.MockCommandVersion, []byte(constants.VersionOutput))
		mockRunner.SetResponse(constants.MockCommandPing, []byte(constants.PingOutput))
		mockRunner.SetResponse(constants.MockCommandStatus, []byte(constants.StatusOutput))
	}

	cleanup = func() {
		fail2ban.SetSudoChecker(originalChecker)
		fail2ban.SetRunner(originalRunner)
	}

	return mockClient, cleanup
}

// AssertError provides standardized error checking for tests
func AssertError(tb testing.TB, err error, expectError bool, testName string) {
	tb.Helper()
	if expectError && err == nil {
		tb.Fatalf(constants.ErrTestExpectedError, testName)
	}
	if !expectError && err != nil {
		tb.Fatalf(constants.ErrTestUnexpected, testName, err)
	}
}

// WithTestRunner sets a test runner and returns a cleanup function.
// Usage: defer fail2bantest.WithTestRunner(t, mockRunner)()
func WithTestRunner(tb testing.TB, runner fail2ban.Runner) func() {
	tb.Helper()
	original := fail2ban.GetRunner()
	fail2ban.SetRunner(runner)
	return func() { fail2ban.SetRunner(original) }
}

// MustMockRunner returns the current global runner as a *MockRunner, failing
// the test when the global runner is anything else (e.g. a prior test leaked
// a different runner).
func MustMockRunner(tb testing.TB) *MockRunner {
	tb.Helper()
	mock, ok := fail2ban.GetRunner().(*MockRunner)
	if !ok {
		tb.Fatalf("global runner is %T, want *MockRunner", fail2ban.GetRunner())
	}
	return mock
}

// MustMockSudoChecker returns the current sudo checker as a *MockSudoChecker,
// failing the test when it is anything else.
func MustMockSudoChecker(tb testing.TB) *MockSudoChecker {
	tb.Helper()
	mock, ok := fail2ban.GetSudoChecker().(*MockSudoChecker)
	if !ok {
		tb.Fatalf("sudo checker is %T, want *MockSudoChecker", fail2ban.GetSudoChecker())
	}
	return mock
}

// StandardMockSetup configures comprehensive standard responses for MockRunner
// This eliminates the need for repetitive SetResponse calls in individual tests
func StandardMockSetup(mockRunner *MockRunner) {
	// Version responses
	mockRunner.SetResponse("fail2ban-client -V", []byte(constants.MockVersion))
	mockRunner.SetResponse("sudo fail2ban-client -V", []byte(constants.MockVersion))

	// Ping responses
	mockRunner.SetResponse("fail2ban-client ping", []byte(constants.PingOutput))
	mockRunner.SetResponse("sudo fail2ban-client ping", []byte(constants.PingOutput))

	// Status responses
	statusResponse := "Status\n|- Number of jail:      2\n`- Jail list:   sshd, apache"
	mockRunner.SetResponse("fail2ban-client status", []byte(statusResponse))
	mockRunner.SetResponse("sudo fail2ban-client status", []byte(statusResponse))

	// Individual jail status responses
	sshdStatus := "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  " +
		"|- Total failed:\t5\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   " +
		"|- Currently banned:\t1\n   |- Total banned:\t2\n   `- Banned IP list:\t192.168.1.100"

	mockRunner.SetResponse(constants.MockCommandStatusSSHD, []byte(sshdStatus))
	mockRunner.SetResponse("sudo "+constants.MockCommandStatusSSHD, []byte(sshdStatus))

	apacheStatus := "Status for the jail: apache\n|- Filter\n|  |- Currently failed:\t0\n|  " +
		"|- Total failed:\t3\n|  `- File list:\t/var/log/apache2/error.log\n`- Actions\n   " +
		"|- Currently banned:\t0\n   |- Total banned:\t1\n   `- Banned IP list:\t"

	mockRunner.SetResponse(constants.MockCommandStatusApache, []byte(apacheStatus))
	mockRunner.SetResponse("sudo "+constants.MockCommandStatusApache, []byte(apacheStatus))

	// Ban/unban responses
	mockRunner.SetResponse(constants.MockCommandBanIP, []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse("sudo "+constants.MockCommandBanIP, []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse(constants.MockCommandUnbanIP, []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse("sudo "+constants.MockCommandUnbanIP, []byte(constants.Fail2BanStatusSuccess))

	mockRunner.SetResponse("fail2ban-client set apache banip 192.168.1.101", []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse(
		"sudo fail2ban-client set apache banip 192.168.1.101",
		[]byte(constants.Fail2BanStatusSuccess),
	)
	mockRunner.SetResponse("fail2ban-client set apache unbanip 192.168.1.101", []byte(constants.Fail2BanStatusSuccess))
	mockRunner.SetResponse(
		"sudo fail2ban-client set apache unbanip 192.168.1.101",
		[]byte(constants.Fail2BanStatusSuccess),
	)

	// Banned IP responses
	mockRunner.SetResponse("fail2ban-client banned 192.168.1.100", []byte(constants.MockBannedOutput))
	mockRunner.SetResponse("sudo fail2ban-client banned 192.168.1.100", []byte(constants.MockBannedOutput))
	mockRunner.SetResponse("fail2ban-client banned 192.168.1.101", []byte("[]"))
	mockRunner.SetResponse("sudo fail2ban-client banned 192.168.1.101", []byte("[]"))
}

// SetupMockEnvironmentWithStandardResponses combines mock environment setup with standard responses
// This is a convenience function for tests that need comprehensive mock responses
func SetupMockEnvironmentWithStandardResponses(tb testing.TB) (client *MockClient, cleanup func()) {
	tb.Helper()

	client, cleanup = SetupMockEnvironment(tb)

	// Safe type assertion with error handling
	mockRunner, ok := fail2ban.GetRunner().(*MockRunner)
	if !ok {
		tb.Fatalf("Expected GetRunner() to return *MockRunner, got %T", fail2ban.GetRunner())
	}

	StandardMockSetup(mockRunner)

	return client, cleanup
}
