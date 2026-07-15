package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLogPathSecurityValidation verifies ValidateLogPath — the gate every log
// read routes through — rejects path-traversal and encoding attacks.
func TestLogPathSecurityValidation(t *testing.T) {
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
			_, err := ValidateLogPath(context.Background(), path, GetLogDir())
			if err == nil {
				t.Errorf("ValidateLogPath should have rejected malicious path: %s", path)
				return
			}
			if !containsAnyString(err.Error(), []string{
				"path traversal",
				"invalid path",
				"not in expected system location",
				"outside allowed directories",
				"null byte",
			}) {
				t.Errorf("Error should be security-related, got: %s", err.Error())
			}
		})
	}
}

// TestLogPathValidation_LegitVsOutside verifies a file inside the log directory
// is accepted while a path outside it is rejected.
func TestLogPathValidation_LegitVsOutside(t *testing.T) {
	originalLogDir := GetLogDir()
	tempDir := t.TempDir()
	SetLogDir(tempDir)
	defer SetLogDir(originalLogDir)

	testLogFile := filepath.Join(tempDir, "test.log")
	if err := os.WriteFile(testLogFile, []byte("test log content"), 0600); err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}

	if _, err := ValidateLogPath(context.Background(), testLogFile, GetLogDir()); err != nil {
		t.Errorf("ValidateLogPath should accept a file inside the log directory: %v", err)
	}

	if _, err := ValidateLogPath(context.Background(), "/etc/passwd", GetLogDir()); err == nil {
		t.Errorf("ValidateLogPath should reject paths outside the log directory")
	}
}

// TestStreamLogFileRejectsTraversal verifies end to end that log reads route
// through ValidateLogPath: streaming a traversal path is rejected before any
// file is opened.
func TestStreamLogFileRejectsTraversal(t *testing.T) {
	lines, err := streamLogFile("../../../etc/passwd", LogReadConfig{BaseDir: t.TempDir()})
	if err == nil {
		t.Fatalf("expected traversal path to be rejected, got %d lines", len(lines))
	}
	if !containsAnyString(err.Error(), []string{
		"path traversal",
		"outside allowed directories",
	}) {
		t.Errorf("expected security-related error, got: %v", err)
	}
}

// containsAnyString reports whether s contains any of the given substrings.
func containsAnyString(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func BenchmarkLogPathSecurity(b *testing.B) {
	testPaths := []string{
		"/var/log/fail2ban.log",
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}
	ctx := context.Background()
	base := GetLogDir()

	b.ResetTimer()
	for b.Loop() {
		for _, path := range testPaths {
			_, _ = ValidateLogPath(ctx, path, base)
		}
	}
}
