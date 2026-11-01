package fail2ban

// Test support shared with the cmd and main test packages. It has to live in
// a non-test file because Go test files are invisible to other packages, and
// it cannot move to a separate fail2bantest package because fail2ban's own
// internal tests use it too (that package would import fail2ban, a cycle).
// It must not import "testing": that would link the testing package into the
// release binary. TestingInterface stands in for testing.TB, and helpers used
// only by fail2ban's own tests live in _test.go files.

import (
	"github.com/ivuorinen/f2b/constants"
)

// TestingInterface is the subset of testing.TB these helpers need.
type TestingInterface interface {
	Helper()
	Fatalf(format string, args ...any)
}

// SetupMockEnvironment sets up complete mock environment with client, runner, and sudo checker
func SetupMockEnvironment(t TestingInterface) (client *MockClient, cleanup func()) {
	t.Helper()

	// Store original components
	originalChecker := GetSudoChecker()
	originalRunner := GetRunner()

	// Set up mocks
	mockClient := NewMockClient()
	mockChecker := &MockSudoChecker{
		MockHasPrivileges:     true,
		ExplicitPrivilegesSet: true,
	}
	mockRunner := NewMockRunner()

	SetSudoChecker(mockChecker)
	SetRunner(mockRunner)

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
		SetSudoChecker(originalChecker)
		SetRunner(originalRunner)
	}

	return mockClient, cleanup
}

// SetupMockEnvironmentWithSudo sets up mock environment with specific sudo privileges
func SetupMockEnvironmentWithSudo(t TestingInterface, hasSudo bool) (client *MockClient, cleanup func()) {
	t.Helper()

	// Store original components
	originalChecker := GetSudoChecker()
	originalRunner := GetRunner()

	// Set up mocks
	mockClient := NewMockClient()
	mockChecker := &MockSudoChecker{
		MockHasPrivileges:     hasSudo,
		ExplicitPrivilegesSet: true,
	}
	mockRunner := NewMockRunner()

	SetSudoChecker(mockChecker)
	SetRunner(mockRunner)

	// Configure mock responses based on sudo availability
	if hasSudo {
		mockRunner.SetResponse(constants.MockCommandVersion, []byte(constants.VersionOutput))
		mockRunner.SetResponse(constants.MockCommandPing, []byte(constants.PingOutput))
		mockRunner.SetResponse(constants.MockCommandStatus, []byte(constants.StatusOutput))
	}

	cleanup = func() {
		SetSudoChecker(originalChecker)
		SetRunner(originalRunner)
	}

	return mockClient, cleanup
}

// AssertError provides standardized error checking for tests
func AssertError(t TestingInterface, err error, expectError bool, testName string) {
	t.Helper()
	if expectError && err == nil {
		t.Fatalf(constants.ErrTestExpectedError, testName)
	}
	if !expectError && err != nil {
		t.Fatalf(constants.ErrTestUnexpected, testName, err)
	}
}

// WithTestRunner sets a test runner and returns a cleanup function.
// Usage: defer fail2ban.WithTestRunner(t, mockRunner)()
func WithTestRunner(t TestingInterface, runner Runner) func() {
	t.Helper()
	original := GetRunner()
	SetRunner(runner)
	return func() { SetRunner(original) }
}

// MustMockRunner returns the current global runner as a *MockRunner, failing
// the test when the global runner is anything else (e.g. a prior test leaked
// a different runner).
func MustMockRunner(t TestingInterface) *MockRunner {
	t.Helper()
	mock, ok := GetRunner().(*MockRunner)
	if !ok {
		t.Fatalf("global runner is %T, want *MockRunner", GetRunner())
	}
	return mock
}

// MustMockSudoChecker returns the current sudo checker as a *MockSudoChecker,
// failing the test when it is anything else.
func MustMockSudoChecker(t TestingInterface) *MockSudoChecker {
	t.Helper()
	mock, ok := GetSudoChecker().(*MockSudoChecker)
	if !ok {
		t.Fatalf("sudo checker is %T, want *MockSudoChecker", GetSudoChecker())
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
func SetupMockEnvironmentWithStandardResponses(t TestingInterface) (client *MockClient, cleanup func()) {
	t.Helper()

	client, cleanup = SetupMockEnvironment(t)

	// Safe type assertion with error handling
	mockRunner, ok := GetRunner().(*MockRunner)
	if !ok {
		t.Fatalf("Expected GetRunner() to return *MockRunner, got %T", GetRunner())
	}

	StandardMockSetup(mockRunner)

	return client, cleanup
}
