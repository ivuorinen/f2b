package fail2ban

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestingInterface represents the common interface between testing.T and testing.B
type TestingInterface interface {
	Helper()
	Fatalf(format string, args ...interface{})
	Skipf(format string, args ...interface{})
	TempDir() string
}

// setupTestLogEnvironment creates a temp directory, copies test data, and sets up log directory
// Returns a cleanup function that should be deferred
func setupTestLogEnvironment(t *testing.T, testDataFile string) (cleanup func()) {
	t.Helper()
	// Validate test data file exists and is safe to read
	absTestLogFile, err := filepath.Abs(testDataFile)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absTestLogFile); os.IsNotExist(err) {
		t.Skipf("Test data file not found: %s", absTestLogFile)
	}

	// Ensure the file is within testdata directory for security
	if !strings.Contains(absTestLogFile, "testdata") {
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
	if err := os.WriteFile(mainLog, data, 0600); err != nil {
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
	mockRunner.SetResponse("fail2ban-client -V", []byte("fail2ban-client v0.11.2"))
	mockRunner.SetResponse(
		"fail2ban-client status",
		[]byte("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, apache"),
	)
	mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))

	// Standard jail responses
	mockRunner.SetResponse("fail2ban-client status sshd", []byte("Status for the jail: sshd"))
	mockRunner.SetResponse("fail2ban-client status apache", []byte("Status for the jail: apache"))

	// Standard ban responses
	mockRunner.SetResponse("fail2ban-client set sshd banip 192.168.1.100", []byte("0"))
	mockRunner.SetResponse("fail2ban-client set sshd unbanip 192.168.1.100", []byte("0"))
	mockRunner.SetResponse("fail2ban-client banned 192.168.1.100", []byte("[]"))

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
		mockRunner.SetResponse("fail2ban-client -V", []byte("fail2ban-client v0.11.2"))
		mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
		mockRunner.SetResponse(
			"fail2ban-client status",
			[]byte("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, apache"),
		)
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
		t.Fatalf("%s: expected error but got none", testName)
	}
	if !expectError && err != nil {
		t.Fatalf("%s: unexpected error: %v", testName, err)
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
		t.Fatalf("%s: unexpected error: %v, output: %s", testName, err, output)
	}
	if expectedOutput != "" && !strings.Contains(output, expectedOutput) {
		t.Fatalf("%s: expected output to contain %q, got: %s", testName, expectedOutput, output)
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
	if !strings.Contains(path, os.TempDir()) && !strings.Contains(path, "testdata") {
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
		if err := os.WriteFile(path, content, 0600); err != nil {
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
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absTestLogFile); os.IsNotExist(err) {
		t.Skipf("Test data file not found: %s", absTestLogFile)
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
