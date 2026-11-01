// Security utility functions for input validation and threat detection: path
// traversal detection and dangerous command pattern identification.

package fail2ban

import (
	"path/filepath"
	"strings"
)

// ContainsPathTraversal validates paths using stdlib filepath canonicalization.
// Returns true if the path contains traversal attempts (e.g., .., absolute paths, encoded traversals, etc.)
func ContainsPathTraversal(input string) bool {
	// Check for URL-encoded or Unicode-encoded traversal attempts
	// These are suspicious in path/command contexts and should be rejected
	inputLower := strings.ToLower(input)
	suspiciousPatterns := []string{
		"%2e%2e", // URL encoded ..
		"%2f",    // URL encoded /
		"%5c",    // URL encoded \
		"\x00",   // Null byte
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	// Use filepath.IsLocal (Go 1.20+) to check if path is local and safe
	// Returns false for paths that:
	// - Are absolute (start with /)
	// - Contain .. that escape the current directory
	// - Are empty
	// - Contain invalid characters
	if !filepath.IsLocal(input) {
		return true
	}

	// Additional check: Clean the path and verify it doesn't start with ..
	// This catches cases where IsLocal might pass but the path still tries to escape
	cleaned := filepath.Clean(input)
	if strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned == ".." {
		return true
	}

	return false
}

// GetDangerousCommandPatterns returns the attack signatures ValidateCommand
// rejects before a command name reaches the allowlist check.
//
// Only real signatures belong here. The DANGEROUS_* placeholder names the
// injection tests use are test fixtures and live in the test files: shipping
// them made production validation depend on test data.
func GetDangerousCommandPatterns() []string {
	return []string{
		"rm -rf",                     // Destructive file operations
		"drop table",                 // SQL injection attempts
		"'; cat",                     // Command injection with file reads
		"/etc/passwd", "/etc/shadow", // Specific sensitive file access
	}
}
