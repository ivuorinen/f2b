package fail2ban

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/ivuorinen/f2b/constants"
)

// ValidateIP validates an IP address string and returns an error if invalid
func ValidateIP(ip string) error {
	if ip == "" {
		return ErrIPRequiredError
	}
	// Check for valid IPv4 or IPv6 address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Don't include potentially malicious input in error message
		if containsCommandInjectionPatterns(ip) || len(ip) > constants.MaxIPAddressLength {
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
	// reject returns a generic error when the input looks like a command
	// injection attempt (so malicious input is never echoed back), otherwise a
	// specific error describing the reason.
	reject := func(reason string) error {
		if containsCommandInjectionPatterns(jail) {
			return fmt.Errorf(constants.ErrInvalidJailFormat)
		}
		return NewInvalidJailError(jail + " " + reason)
	}
	// Jail names should be reasonable length
	if len(jail) > constants.MaxJailNameLength {
		return reject("(too long)")
	}
	// First character should be alphanumeric (jail is non-empty here)
	first := rune(jail[0])
	if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
		return reject("(invalid format)")
	}
	// Rest can be alphanumeric, dash, underscore, or dot
	for _, r := range jail {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return reject("(invalid character)")
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
	if len(filter) > constants.MaxFilterNameLength {
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

	// Check for command injection patterns (defense in depth)
	if containsCommandInjectionPatterns(filter) {
		return NewInvalidFilterError(filter + " (injection patterns)")
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

// trustedCommandDirs are the only directories an absolute command path may
// live in. fail2ban installs its binaries under the standard system prefixes
// (Homebrew's /opt/homebrew/bin included for macOS).
var trustedCommandDirs = map[string]bool{
	"/bin":              true,
	"/sbin":             true,
	"/usr/bin":          true,
	"/usr/sbin":         true,
	"/usr/local/bin":    true,
	"/usr/local/sbin":   true,
	"/opt/homebrew/bin": true,
}

// isTrustedCommandDir reports whether dir may hold f2b's external binaries.
// Besides the hardcoded FHS prefixes, the F2B_TRUSTED_BIN_DIR environment
// variable may name ONE additional directory (absolute and clean) so
// non-FHS installs (~/.local/bin, /snap/bin, NixOS store paths) keep working
// without giving up the PATH-hijack defense for everyone else.
func isTrustedCommandDir(dir string) bool {
	if trustedCommandDirs[dir] {
		return true
	}
	extra := os.Getenv("F2B_TRUSTED_BIN_DIR")
	return extra != "" && filepath.IsAbs(extra) && filepath.Clean(extra) == extra && dir == extra
}

// ValidateCommand validates that a command is in the allowlist for security
func ValidateCommand(command string) error {
	// Allowlist of commands that f2b is permitted to execute.
	// "sudo" is intentionally NOT allowlisted: the sudo prefix is only ever
	// prepended internally (fail2ban.go) AFTER the inner command was validated,
	// so allowlisting "sudo" here would let a caller run "sudo <anything>".
	allowedCommands := map[string]bool{
		constants.Fail2BanClientCommand: true,
		constants.Fail2BanRegexCommand:  true,
		constants.Fail2BanServerCommand: true,
		"service":                       true,
		"systemctl":                     true,
	}

	if command == "" {
		return NewInvalidCommandError("command cannot be empty")
	}

	// Check for null bytes (command injection attempt)
	if strings.ContainsRune(command, '\x00') {
		// Don't include potentially malicious input in error message
		return fmt.Errorf(constants.ErrInvalidCommandFormat)
	}

	// Check for dangerous patterns first (before including command in error messages)
	dangerousPatterns := GetDangerousCommandPatterns()
	cmdLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			// Don't include potentially dangerous command in error message
			return fmt.Errorf(constants.ErrInvalidCommandFormat)
		}
	}

	// Additional security checks for command injection patterns
	if containsCommandInjectionPatterns(command) {
		// Don't include potentially malicious input in error message
		return fmt.Errorf(constants.ErrInvalidCommandFormat)
	}

	// The command may arrive as an absolute path resolved via exec.LookPath
	// (e.g. /usr/bin/fail2ban-client). Accept it when it is a clean absolute
	// path — no ".." or "." segments — inside a trusted system directory and
	// whose base name is allowlisted; otherwise it must be a bare executable
	// name. Pinning the directory prevents a hostile PATH from steering
	// LookPath to an attacker-controlled binary that would later run under sudo.
	name := command
	if filepath.IsAbs(command) {
		if filepath.Clean(command) != command {
			return fmt.Errorf(constants.ErrInvalidCommandFormat)
		}
		if !isTrustedCommandDir(filepath.Dir(command)) {
			return NewCommandNotAllowedError(command + " (untrusted directory)")
		}
		name = filepath.Base(command)
	} else {
		if ContainsPathTraversal(command) {
			// Don't include potentially malicious input in error message
			return NewInvalidCommandError(command + " (path traversal)")
		}
		// A relative command must be a bare name (no paths or whitespace).
		if strings.ContainsAny(command, "/\\ \t") {
			return fmt.Errorf(constants.ErrInvalidCommandFormat)
		}
	}

	// Validate against allowlist (safe to include command name for allowed commands)
	if !allowedCommands[name] {
		return NewCommandNotAllowedError(name)
	}

	return nil
}

// ValidateArguments validates command arguments for security
func ValidateArguments(args []string) error {
	return ValidateArgumentsWithContext(context.Background(), args)
}

// ValidateArgumentsWithContext validates command arguments for security with context support
func ValidateArgumentsWithContext(ctx context.Context, args []string) error {
	for i, arg := range args {
		if err := validateSingleArgument(ctx, arg, i); err != nil {
			return fmt.Errorf("argument %d invalid: %w", i, err)
		}
	}
	return nil
}

// validateSingleArgument validates a single command argument
func validateSingleArgument(_ context.Context, arg string, _ int) error {
	// Check for null bytes
	if strings.ContainsRune(arg, '\x00') {
		return NewInvalidArgumentError(arg + " (contains null byte)")
	}

	// Check length to prevent buffer overflow
	if len(arg) > constants.MaxArgumentLength {
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

// isLikelyIPArgument heuristically determines if an argument looks like an IP
// address, so validateSingleArgument can force-validate it as one. The shape
// check is strict on purpose: hex-lettered jail names like "abc.def" or
// "cafe.db" are legal jail names (ValidateJail allows dots) and must NOT be
// classified as IPs, or the whole command gets rejected with a misleading
// "invalid IP format" error. Only two shapes qualify:
//   - IPv4: exactly four dot-separated groups of 1-3 decimal digits
//     (so "999.1.1.1" is still IP-shaped and rejected by net.ParseIP)
//   - IPv6: contains "::" or at least two colons
func isLikelyIPArgument(arg string) bool {
	if arg == "" {
		return false
	}
	// IPv6 shape: "::" or two-plus colons (jail names cannot contain colons).
	if strings.Contains(arg, "::") || strings.Count(arg, ":") >= 2 {
		return true
	}
	// IPv4 shape: four dotted all-decimal octets.
	parts := strings.Split(arg, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

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

// ValidateFilterName validates a filter name for path traversal prevention.
// Rejects: "..", "/", "\", absolute paths, drive letters
// Allows: letters, digits, dash, underscore only
func ValidateFilterName(filter string) error {
	filter = strings.TrimSpace(filter)

	if filter == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	// Check for path traversal
	if ContainsPathTraversal(filter) {
		return fmt.Errorf("filter name contains path traversal")
	}

	// Check for absolute paths
	if filepath.IsAbs(filter) {
		return fmt.Errorf("filter name cannot be an absolute path")
	}

	// Only allow safe characters (alphanumeric, dash, underscore)
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(filter) {
		return fmt.Errorf("filter name contains invalid characters")
	}

	return nil
}
