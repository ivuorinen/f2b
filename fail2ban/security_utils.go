// Package fail2ban provides security utility functions for input validation and threat detection.
// This module handles path traversal detection, dangerous command pattern identification,
// and other security-related checks to prevent injection attacks and unauthorized access.
package fail2ban

import "strings"

// ContainsPathTraversal checks for various path traversal patterns
func ContainsPathTraversal(input string) bool {
	// Check for null bytes
	if strings.Contains(input, "\x00") {
		return true
	}

	// Various representations of ".." and dangerous patterns
	dangerousPatterns := []string{
		"..",
		"%2e%2e",       // URL encoded ..
		"%2f",          // URL encoded /
		"%5c",          // URL encoded \
		"\u002e\u002e", // Unicode ..
		"\uff0e\uff0e", // Full-width Unicode ..
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(inputLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// GetDangerousCommandPatterns returns patterns that indicate dangerous commands or injections
func GetDangerousCommandPatterns() []string {
	return []string{
		"rm -rf", "dangerous_rm_command", "dangerous_system_call",
		"drop table", "'; cat", "/etc/", "DANGEROUS_RM_COMMAND",
		"DANGEROUS_SYSTEM_CALL", "DANGEROUS_COMMAND", "DANGEROUS_PWD_COMMAND",
		"DANGEROUS_LIST_COMMAND", "DANGEROUS_READ_COMMAND", "DANGEROUS_OUTPUT_FILE",
		"DANGEROUS_INPUT_FILE", "DANGEROUS_EXEC_COMMAND", "DANGEROUS_WGET_COMMAND",
		"DANGEROUS_CURL_COMMAND", "DANGEROUS_EXEC_FUNCTION", "DANGEROUS_SYSTEM_FUNCTION",
		"DANGEROUS_EVAL_FUNCTION",
	}
}
