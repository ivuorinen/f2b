// Package fail2ban provides security utility functions for input validation and threat detection.
// This module handles path traversal detection, dangerous command pattern identification,
// and other security-related checks to prevent injection attacks and unauthorized access.
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

// GetDangerousCommandPatterns returns patterns for log sanitization and threat detection.
//
// Purpose: This list is used for:
//   - Sanitizing/masking dangerous patterns in logs to prevent sensitive data leakage
//   - Detecting suspicious patterns in command outputs for monitoring/alerting
//
// NOT for: Input validation or injection prevention (use proper validation instead)
//
// The returned patterns include both production patterns (real attack signatures)
// and test sentinels (used exclusively in test fixtures for validation).
func GetDangerousCommandPatterns() []string {
	// Production patterns: Real command injection and SQL injection signatures
	productionPatterns := []string{
		"rm -rf",                     // Destructive file operations
		"drop table",                 // SQL injection attempts
		"'; cat",                     // Command injection with file reads
		"/etc/passwd", "/etc/shadow", // Specific sensitive file access
	}

	// Test sentinels: Markers used exclusively in test fixtures
	// These help verify pattern detection logic in tests
	testSentinels := []string{
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

	// Combine both lists for backward compatibility
	return append(productionPatterns, testSentinels...)
}
