package fail2ban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLogFileSecurityValidation(t *testing.T) {
	// Test that readLogFile now uses comprehensive security validation
	maliciousPaths := []string{
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"logs\\..\\..\\windows\\system32",
		"..%00/etc/shadow",
		"%252e%252e%252f",
		"\\u002e\\u002e/etc/passwd",
	}

	for _, path := range maliciousPaths {
		t.Run("malicious_log_path_"+path, func(t *testing.T) {
			_, err := readLogFile(path)
			if err == nil {
				t.Errorf("readLogFile should have rejected malicious path: %s", path)
			}
			// Should contain security-related error message
			errorMsg := err.Error()
			if !containsAnyString(
				errorMsg,
				[]string{
					"path traversal",
					"invalid path",
					"not in expected system location",
					"outside allowed directories",
					"null byte",
				},
			) {
				t.Errorf("Error should be security-related, got: %s", errorMsg)
			}
		})
	}
}

func TestReadLogFileValidation_ComprehensiveCheck(t *testing.T) {
	// Save original log directory
	originalLogDir := GetLogDir()

	// Create a temporary test directory
	tempDir := t.TempDir()
	SetLogDir(tempDir)
	defer SetLogDir(originalLogDir)

	// Create a test log file
	testLogFile := filepath.Join(tempDir, "test.log")
	err := os.WriteFile(testLogFile, []byte("test log content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	// Test that legitimate files work
	content, err := readLogFile(testLogFile)
	if err != nil {
		t.Errorf("readLogFile should accept legitimate file: %v", err)
	}
	if string(content) != "test log content" {
		t.Errorf("Expected 'test log content', got %s", string(content))
	}

	// Test that the function properly validates paths
	// This should fail because it's outside the allowed log directory
	_, err = readLogFile("/etc/passwd")
	if err == nil {
		t.Errorf("readLogFile should reject paths outside log directory")
	}
}

func TestLogValidationConsistency(t *testing.T) {
	// Test that both validateLogPath and readLogFile reject the same malicious paths
	testPaths := []string{
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%00/etc/shadow",
	}

	for _, path := range testPaths {
		t.Run("consistency_check_"+path, func(t *testing.T) {
			// Both should reject the path
			_, validateErr := validateLogPath(path)
			_, readErr := readLogFile(path)

			if validateErr == nil {
				t.Errorf("validateLogPath should reject malicious path: %s", path)
			}
			if readErr == nil {
				t.Errorf("readLogFile should reject malicious path: %s", path)
			}
		})
	}
}

// Helper function to check if error message contains any of the expected strings
func containsAnyString(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func BenchmarkReadLogFileSecurity(b *testing.B) {
	// Benchmark the security validation in readLogFile
	testPaths := []string{
		"/var/log/fail2ban.log",
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range testPaths {
			// This will fail validation, but we're measuring the security check performance
			_, _ = readLogFile(path)
		}
	}
}
