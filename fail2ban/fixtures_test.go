package fail2ban

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// Test fixtures used only by this package's tests. They live in a _test.go
// file so neither they nor the "testing" import reach the release binary.

const (
	// testDataDir is the directory holding checked-in test data files.
	testDataDir = "testdata"
	// errTestDataNotFound reports a missing checked-in fixture.
	errTestDataNotFound = "Test data file not found: %s"
	// errFailedToGetAbsPath reports a failed filepath.Abs.
	errFailedToGetAbsPath = "Failed to get absolute path: %v"
)

// dangerousCommandSentinels are placeholder command names used by the
// injection tests. They are test fixtures, not attack signatures, so they are
// kept out of the production GetDangerousCommandPatterns list.
var dangerousCommandSentinels = []string{
	"DANGEROUS_RM_COMMAND",
	"DANGEROUS_SYSTEM_CALL",
	"DANGEROUS_COMMAND",
	"DANGEROUS_PWD_COMMAND",
	"DANGEROUS_LIST_COMMAND",
	"DANGEROUS_READ_COMMAND",
	"DANGEROUS_OUTPUT_FILE",
	"DANGEROUS_INPUT_FILE",
	"DANGEROUS_EXEC_COMMAND",
	"DANGEROUS_WGET_COMMAND",
	"DANGEROUS_CURL_COMMAND",
	"DANGEROUS_EXEC_FUNCTION",
	"DANGEROUS_SYSTEM_FUNCTION",
	"DANGEROUS_EVAL_FUNCTION",
}

// readLogs reads through RealClient, the single production log-read entry
// point, from the global log directory setupTestLogEnvironment points at.
func readLogs(ctx context.Context, jail, ip string) ([]string, error) {
	return (&RealClient{LogDir: GetLogDir()}).GetLogLinesWithContext(ctx, jail, ip)
}

// readLogsWithLimit is readLogs with an explicit line limit.
func readLogsWithLimit(ctx context.Context, jail, ip string, maxLines int) ([]string, error) {
	return (&RealClient{LogDir: GetLogDir()}).GetLogLinesWithLimitContext(ctx, jail, ip, maxLines)
}

// validateTestDataFile returns the absolute path of a checked-in fixture. A
// missing fixture fails the test: skipping silently disabled every log test
// that depends on it.
func validateTestDataFile(t *testing.T, testDataFile string) string {
	t.Helper()
	absTestLogFile, err := filepath.Abs(testDataFile)
	if err != nil {
		t.Fatalf(errFailedToGetAbsPath, err)
	}
	if _, err := os.Stat(absTestLogFile); err != nil {
		t.Fatalf(errTestDataNotFound+" (%v)", absTestLogFile, err)
	}
	return absTestLogFile
}

// setupTestLogEnvironment copies a checked-in fixture into a temp directory as
// fail2ban.log and points the global log directory at it. The returned
// cleanup restores the previous log directory.
func setupTestLogEnvironment(t *testing.T, testDataFile string) (cleanup func()) {
	t.Helper()
	absTestLogFile := validateTestDataFile(t, testDataFile)

	// Ensure the file is within testdata directory for security
	if !strings.Contains(absTestLogFile, testDataDir) {
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

	origLogDir := GetLogDir()
	SetLogDir(tempDir)

	return func() {
		SetLogDir(origLogDir)
	}
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

// createTestGzipFile creates a gzip file with given content for testing
func createTestGzipFile(tb testing.TB, path string, content []byte) {
	tb.Helper()
	// Validate path is safe for test file creation
	if !strings.Contains(path, os.TempDir()) && !strings.Contains(path, testDataDir) {
		tb.Fatalf("Test file path must be in temp directory or testdata: %s", path)
	}

	// #nosec G304 - This is test code creating files in controlled test locations
	f, err := os.Create(path)
	if err != nil {
		tb.Fatalf("Failed to create gzip file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			tb.Fatalf("Failed to close file: %v", err)
		}
	}()

	gz := gzip.NewWriter(f)

	_, err = gz.Write(content)
	if err != nil {
		tb.Fatalf("Failed to write gzip content: %v", err)
	}
	if err := gz.Close(); err != nil {
		tb.Fatalf("Failed to close gzip writer: %v", err)
	}
}

// setupTempDirWithFiles creates a temp directory with multiple test files
func setupTempDirWithFiles(tb testing.TB, files map[string][]byte) string {
	tb.Helper()
	tempDir := tb.TempDir()

	for filename, content := range files {
		path := filepath.Join(tempDir, filename)
		if err := os.WriteFile(path, content, constants.DefaultFilePermissions); err != nil {
			tb.Fatalf("Failed to create file %s: %v", filename, err)
		}
	}

	return tempDir
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
