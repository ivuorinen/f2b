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
		return fmt.Errorf("IP address cannot be empty")
	}
	// Check for valid IPv4 or IPv6 address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address format")
	}
	return nil
}

// ValidateJail validates a jail name and returns an error if invalid
func ValidateJail(jail string) error {
	if jail == "" {
		return fmt.Errorf("jail name cannot be empty")
	}
	// Jail names should be reasonable length
	if len(jail) > 64 {
		return fmt.Errorf("jail name too long")
	}
	// First character should be alphanumeric
	if len(jail) > 0 {
		first := rune(jail[0])
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			return fmt.Errorf("invalid jail name format")
		}
	}
	// Rest can be alphanumeric, dash, underscore, or dot
	for _, r := range jail {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return fmt.Errorf("invalid jail name format")
		}
	}
	return nil
}

// ValidateFilter validates a filter name and returns an error if invalid
func ValidateFilter(filter string) error {
	if filter == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	// Check length limits to prevent buffer overflow attacks
	if len(filter) > 255 {
		return fmt.Errorf("filter name too long")
	}

	// Check for null bytes
	if strings.Contains(filter, "\x00") {
		return fmt.Errorf("filter name contains null bytes")
	}

	// Enhanced path traversal detection
	if ContainsPathTraversal(filter) {
		return fmt.Errorf("filter name contains path traversal patterns")
	}

	// Character validation - only allow safe characters
	for _, r := range filter {
		if !isValidFilterChar(r) {
			return fmt.Errorf("filter name contains invalid characters")
		}
	}

	// Additional validation: ensure filter doesn't start/end with dangerous patterns
	if strings.HasPrefix(filter, ".") || strings.HasSuffix(filter, ".") {
		// Allow single extension like ".conf" but not ".." or "..."
		if strings.Contains(filter, "..") {
			return fmt.Errorf("filter name contains invalid dot patterns")
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
	return fmt.Errorf("jail '%s' not found", jail)
}

// Command execution helpers

// Parsing helpers

// ParseJailList parses the jail list output from fail2ban-client status
func ParseJailList(output string) ([]string, error) {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				return nil, fmt.Errorf("failed to parse jails")
			}
			jailList := strings.TrimSpace(parts[1])
			if jailList == "" {
				return []string{}, nil // Return empty list for no jails
			}
			return strings.Fields(strings.ReplaceAll(jailList, ",", " ")), nil
		}
	}
	return nil, fmt.Errorf("failed to parse jails")
}

// ParseBracketedList parses bracketed output like "[jail1, jail2]"
func ParseBracketedList(output string) []string {
	s := strings.Trim(output, "[]")
	if s == "" {
		return []string{}
	}
	parts := strings.Split(strings.ReplaceAll(s, "\"", ""), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
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
		return fmt.Errorf("command cannot be empty")
	}

	// Check for null bytes (command injection attempt)
	if strings.ContainsRune(command, '\x00') {
		return fmt.Errorf("command contains null byte")
	}

	// Check for path traversal in command name
	if ContainsPathTraversal(command) {
		return fmt.Errorf("command contains path traversal patterns")
	}

	// Validate against allowlist
	if !allowedCommands[command] {
		return fmt.Errorf("command not in allowlist: %s", command)
	}

	return nil
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
