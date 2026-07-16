package fail2ban

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// TestingInterface represents the common interface between testing.T and testing.B
type TestingInterface interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
	TempDir() string
}

// setupTestLogEnvironment creates a temp directory, copies test data, and sets up log directory
// Returns a cleanup function that should be deferred
func setupTestLogEnvironment(t *testing.T, testDataFile string) (cleanup func()) {
	t.Helper()
	// Validate test data file exists and is safe to read
	absTestLogFile, err := filepath.Abs(testDataFile)
	if err != nil {
		t.Fatalf(constants.ErrFailedToGetAbsPath, err)
	}
	if _, err := os.Stat(absTestLogFile); os.IsNotExist(err) {
		t.Skipf(constants.ErrTestDataNotFound, absTestLogFile)
	}

	// Ensure the file is within testdata directory for security
	if !strings.Contains(absTestLogFile, constants.TestDataDir) {
		t.Fatalf("Test file must be in testdata directory: %s", absTestLogFile)
	}

	// Create temp directory and copy test file
	tempDir := t.TempDir()
	mainLog := filepath.Join(tempDir, "fail2ban.log")

	// #nosec G304 - This is test code reading controlled test data files
	data, err := os.ReadFile(absTestLogFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	// #nosec G703 -- path is constructed from t.TempDir() and a literal string, not user input
	if err := os.WriteFile(mainLog, data, constants.DefaultFilePermissions); err != nil {
		t.Fatalf("Failed to create test log: %v", err)
	}

	// Set up test environment
	origLogDir := GetLogDir()
	SetLogDir(tempDir)

	return func() {
		SetLogDir(origLogDir)
	}
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

// SetupBasicMockClient creates a mock client with standard responses configured
func SetupBasicMockClient() *MockClient {
	client := NewMockClient()
	// Set up common test data
	client.StatusAllData = "Status: [sshd, apache] Jail list: sshd, apache"
	client.StatusJailData["sshd"] = "Status for jail: sshd"
	client.StatusJailData["apache"] = "Status for jail: apache"
	return client
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

// AssertErrorContains checks that error contains expected substring
func AssertErrorContains(t TestingInterface, err error, expectedSubstring string, testName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error containing %q but got none", testName, expectedSubstring)
	}
	if !strings.Contains(err.Error(), expectedSubstring) {
		t.Fatalf("%s: expected error containing %q but got %q", testName, expectedSubstring, err.Error())
	}
}

// AssertCommandSuccess checks that command succeeded and output contains expected text
func AssertCommandSuccess(t TestingInterface, err error, output, expectedOutput, testName string) {
	t.Helper()
	if err != nil {
		t.Fatalf(constants.ErrTestUnexpectedWithOutput, testName, err, output)
	}
	if expectedOutput != "" && !strings.Contains(output, expectedOutput) {
		t.Fatalf(constants.ErrTestExpectedOutput, testName, expectedOutput, output)
	}
}

// AssertCommandError checks that command failed and output contains expected error text
func AssertCommandError(t TestingInterface, err error, output, expectedError, testName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error but got none, output: %s", testName, output)
	}
	if expectedError != "" && !strings.Contains(output, expectedError) {
		t.Fatalf("%s: expected error output to contain %q, got: %s", testName, expectedError, output)
	}
}

// createTestGzipFile creates a gzip file with given content for testing
func createTestGzipFile(t TestingInterface, path string, content []byte) {
	// Validate path is safe for test file creation
	if !strings.Contains(path, os.TempDir()) && !strings.Contains(path, constants.TestDataDir) {
		t.Fatalf("Test file path must be in temp directory or testdata: %s", path)
	}

	// #nosec G304 - This is test code creating files in controlled test locations
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("Failed to close file: %v", err)
		}
	}()

	gz := gzip.NewWriter(f)

	_, err = gz.Write(content)
	if err != nil {
		t.Fatalf("Failed to write gzip content: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("Failed to close gzip writer: %v", err)
	}
}

// setupTempDirWithFiles creates a temp directory with multiple test files
func setupTempDirWithFiles(t TestingInterface, files map[string][]byte) string {
	tempDir := t.TempDir()

	for filename, content := range files {
		path := filepath.Join(tempDir, filename)
		if err := os.WriteFile(path, content, constants.DefaultFilePermissions); err != nil {
			t.Fatalf("Failed to create file %s: %v", filename, err)
		}
	}

	return tempDir
}

// validateTestDataFile checks if a test data file exists and returns its absolute path
func validateTestDataFile(t *testing.T, testDataFile string) string {
	t.Helper()
	absTestLogFile, err := filepath.Abs(testDataFile)
	if err != nil {
		t.Fatalf(constants.ErrFailedToGetAbsPath, err)
	}
	if _, err := os.Stat(absTestLogFile); os.IsNotExist(err) {
		t.Skipf(constants.ErrTestDataNotFound, absTestLogFile)
	}
	return absTestLogFile
}

// assertMinimumLines checks that result has at least the expected number of lines
func assertMinimumLines(t *testing.T, lines []string, minimum int, description string) {
	t.Helper()
	if len(lines) < minimum {
		t.Errorf("Expected at least %d %s, got %d", minimum, description, len(lines))
	}
}

// assertContainsText checks that at least one line contains the expected text
func assertContainsText(t *testing.T, lines []string, text string) {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(line, text) {
			return
		}
	}
	t.Errorf("Expected to find '%s' in results", text)
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
func MustMockRunner(tb testing.TB) *MockRunner {
	tb.Helper()
	mock, ok := GetRunner().(*MockRunner)
	if !ok {
		tb.Fatalf("global runner is %T, want *MockRunner", GetRunner())
	}
	return mock
}

// MustMockSudoChecker returns the current sudo checker as a *MockSudoChecker,
// failing the test when it is anything else.
func MustMockSudoChecker(tb testing.TB) *MockSudoChecker {
	tb.Helper()
	mock, ok := GetSudoChecker().(*MockSudoChecker)
	if !ok {
		tb.Fatalf("sudo checker is %T, want *MockSudoChecker", GetSudoChecker())
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
