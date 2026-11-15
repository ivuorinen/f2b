// Path traversal detection for input validation.

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

	return false
}
