package fail2ban

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unicode"

	"github.com/hashicorp/go-version"
)

// Validation helpers

// ValidateIP validates an IP address string and returns an error if invalid
func ValidateIP(ip string) error {
	if ip == "" {
		return ErrIPRequiredError
	}
	// Check for valid IPv4 or IPv6 address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Don't include potentially malicious input in error message
		if containsCommandInjectionPatterns(ip) || len(ip) > 45 {
			return fmt.Errorf("invalid IP address format")
		}
		return NewInvalidIPError(ip)
	}
	return nil
}

// ValidateJail validates a jail name and returns an error if invalid
func ValidateJail(jail string) error {
	if jail == "" {
		return ErrJailRequiredError
	}
	// Jail names should be reasonable length
	if len(jail) > 64 {
		// Don't include potentially malicious input in error message
		if containsCommandInjectionPatterns(jail) {
			return fmt.Errorf("invalid jail name format")
		}
		return NewInvalidJailError(jail + " (too long)")
	}
	// First character should be alphanumeric
	if len(jail) > 0 {
		first := rune(jail[0])
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			// Don't include potentially malicious input in error message
			if containsCommandInjectionPatterns(jail) {
				return fmt.Errorf("invalid jail name format")
			}
			return NewInvalidJailError(jail + " (invalid format)")
		}
	}
	// Rest can be alphanumeric, dash, underscore, or dot
	for _, r := range jail {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			// Don't include potentially malicious input in error message
			if containsCommandInjectionPatterns(jail) {
				return fmt.Errorf("invalid jail name format")
			}
			return NewInvalidJailError(jail + " (invalid character)")
		}
	}
	return nil
}

// ValidateFilter validates a filter name and returns an error if invalid
func ValidateFilter(filter string) error {
	if filter == "" {
		return ErrFilterRequiredError
	}

	// Check length limits to prevent buffer overflow attacks
	if len(filter) > 255 {
		return NewInvalidFilterError(filter + " (too long)")
	}

	// Check for null bytes
	if strings.Contains(filter, "\x00") {
		return NewInvalidFilterError(filter + " (contains null bytes)")
	}

	// Enhanced path traversal detection
	if ContainsPathTraversal(filter) {
		return NewInvalidFilterError(filter + " (path traversal)")
	}

	// Character validation - only allow safe characters
	for _, r := range filter {
		if !isValidFilterChar(r) {
			return NewInvalidFilterError(filter + " (invalid characters)")
		}
	}

	// Additional validation: ensure filter doesn't start/end with dangerous patterns
	if strings.HasPrefix(filter, ".") || strings.HasSuffix(filter, ".") {
		// Allow single extension like ".conf" but not ".." or "..."
		if strings.Contains(filter, "..") {
			return NewInvalidFilterError(filter + " (invalid dot patterns)")
		}
	}

	return nil
}

// ValidateJailExists checks if a jail exists in the given list
func ValidateJailExists(jail string, jails []string) error {
	for _, j := range jails {
		if j == jail {
			return nil
		}
	}
	return NewJailNotFoundError(jail)
}

// Command execution helpers

// Parsing helpers

// ParseJailList parses the jail list output from fail2ban-client status
func ParseJailList(output string) ([]string, error) {
	// Optimized: Find "Jail list:" position directly instead of splitting all lines
	jailListPos := strings.Index(output, "Jail list:")
	if jailListPos == -1 {
		return nil, fmt.Errorf("failed to parse jails")
	}

	// Find the start of the jail list content (after "Jail list:")
	colonPos := strings.Index(output[jailListPos:], ":")
	if colonPos == -1 {
		return nil, fmt.Errorf("failed to parse jails")
	}

	// Find the end of the line
	start := jailListPos + colonPos + 1
	end := strings.Index(output[start:], "\n")
	if end == -1 {
		end = len(output) - start
	}

	jailList := strings.TrimSpace(output[start : start+end])
	if jailList == "" {
		return []string{}, nil // Return empty list for no jails
	}

	// Optimized: Use byte replacement instead of string replacement for single character
	if strings.Contains(jailList, ",") {
		jailList = strings.ReplaceAll(jailList, ",", " ")
	}

	return strings.Fields(jailList), nil
}

// ParseBracketedList parses bracketed output like "[jail1, jail2]"
func ParseBracketedList(output string) []string {
	// Optimized: Manual bracket removal instead of Trim to avoid checking both ends
	s := output
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if s == "" {
		return []string{}
	}

	// Optimized: Remove quotes first, then split to avoid multiple string operations
	if strings.Contains(s, "\"") {
		s = strings.ReplaceAll(s, "\"", "")
	}

	parts := strings.Split(s, ",")

	// Optimized: Trim in-place to avoid additional allocations
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}

	return parts
}

// Utility helpers

// CompareVersions compares two version strings
func CompareVersions(v1, v2 string) int {
	version1, err1 := version.NewVersion(v1)
	version2, err2 := version.NewVersion(v2)

	// If either version is invalid, fall back to string comparison
	if err1 != nil || err2 != nil {
		return strings.Compare(v1, v2)
	}

	return version1.Compare(version2)
}

// FormatDuration formats seconds into a human-readable duration string
func FormatDuration(sec int64) string {
	days := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, h, m, s)
}

// IsTestEnvironment returns true if running in a test environment
func IsTestEnvironment() bool {
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return false
}

// ContainsPathTraversal checks for various path traversal patterns
func ContainsPathTraversal(input string) bool {
	// Path separators and traversal patterns
	if strings.ContainsAny(input, "/\\") {
		return true
	}

	// Various representations of ".."
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

// ValidateCommand validates that a command is in the allowlist for security
func ValidateCommand(command string) error {
	// Allowlist of commands that f2b is permitted to execute
	allowedCommands := map[string]bool{
		"fail2ban-client": true,
		"fail2ban-regex":  true,
		"fail2ban-server": true,
		"service":         true,
		"systemctl":       true,
		"sudo":            true, // Only when used internally
	}

	if command == "" {
		return NewInvalidCommandError("command cannot be empty")
	}

	// Check for null bytes (command injection attempt)
	if strings.ContainsRune(command, '\x00') {
		// Don't include potentially malicious input in error message
		return fmt.Errorf("invalid command format")
	}

	// Check for path traversal in command name
	if ContainsPathTraversal(command) {
		// Don't include potentially malicious input in error message
		// Check for common dangerous patterns that shouldn't be in command names
		dangerousPatterns := []string{"rm -rf", "drop table", "'; cat", "/etc/"}
		cmdLower := strings.ToLower(command)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(cmdLower, pattern) {
				return fmt.Errorf("invalid command format")
			}
		}
		return NewInvalidCommandError(command + " (path traversal)")
	}

	// Additional security checks for command injection patterns
	if containsCommandInjectionPatterns(command) {
		// Don't include potentially malicious input in error message
		return fmt.Errorf("invalid command format")
	}

	// Validate against allowlist
	if !allowedCommands[command] {
		return NewCommandNotAllowedError(command)
	}

	return nil
}

// ValidateArguments validates command arguments for security
func ValidateArguments(args []string) error {
	for i, arg := range args {
		if err := validateSingleArgument(arg, i); err != nil {
			return fmt.Errorf("argument %d invalid: %w", i, err)
		}
	}
	return nil
}

// validateSingleArgument validates a single command argument
func validateSingleArgument(arg string, _ int) error {
	// Check for null bytes
	if strings.ContainsRune(arg, '\x00') {
		return NewInvalidArgumentError(arg + " (contains null byte)")
	}

	// Check length to prevent buffer overflow
	if len(arg) > 1024 {
		return NewInvalidArgumentError(fmt.Sprintf("%s (too long: %d chars)", arg, len(arg)))
	}

	// Check for command injection patterns
	if containsCommandInjectionPatterns(arg) {
		return NewInvalidArgumentError(arg + " (injection patterns)")
	}

	// For IP arguments, validate IP format
	if isLikelyIPArgument(arg) {
		if err := ValidateIP(arg); err != nil {
			return fmt.Errorf("invalid IP format: %w", err)
		}
	}

	return nil
}

// containsCommandInjectionPatterns detects common command injection patterns
func containsCommandInjectionPatterns(input string) bool {
	// Optimized: Check single characters first (fastest)
	for _, r := range input {
		switch r {
		case ';', '&', '|', '`', '$', '<', '>', '\n', '\r', '\t':
			return true
		}
	}

	// Optimized: Convert to lower case only once and check multi-character patterns
	inputLower := strings.ToLower(input)

	// Multi-character patterns - be specific to avoid false positives
	multiCharPatterns := []string{
		"$(", "${", "&&", "||", ">>", "<<",
		"exec ", "system(", "eval(",
	}

	for _, pattern := range multiCharPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	return false
}

// isLikelyIPArgument heuristically determines if an argument looks like an IP address
func isLikelyIPArgument(arg string) bool {
	// Simple heuristic: contains dots and digits
	return strings.Contains(arg, ".") && strings.ContainsAny(arg, "0123456789")
}

// Internal helper functions

// isValidFilterChar checks if a character is allowed in filter names
func isValidFilterChar(r rune) bool {
	// Allow letters, digits, and safe punctuation
	return unicode.IsLetter(r) ||
		unicode.IsDigit(r) ||
		r == '-' ||
		r == '_' ||
		r == '.' ||
		r == '@' || // Allow @ for email-like patterns
		r == '+' || // Allow + for variations
		r == '~' // Allow ~ for common naming
}
