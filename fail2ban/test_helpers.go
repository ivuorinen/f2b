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
	defer f.Close()

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
