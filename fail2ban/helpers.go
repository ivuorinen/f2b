package fail2ban

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/hashicorp/go-version"

	"github.com/ivuorinen/f2b/shared"
)

func init() {
	// Configure logging for CI/test environments to reduce noise
	// This now comes from the logging_env module
}

// Validation constants

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
		if containsCommandInjectionPatterns(ip) || len(ip) > shared.MaxIPAddressLength {
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
	if len(jail) > shared.MaxJailNameLength {
		// Don't include potentially malicious input in error message
		if containsCommandInjectionPatterns(jail) {
			return fmt.Errorf(shared.ErrInvalidJailFormat)
		}
		return NewInvalidJailError(jail + " (too long)")
	}
	// First character should be alphanumeric
	if len(jail) > 0 {
		first := rune(jail[0])
		if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
			// Don't include potentially malicious input in error message
			if containsCommandInjectionPatterns(jail) {
				return fmt.Errorf(shared.ErrInvalidJailFormat)
			}
			return NewInvalidJailError(jail + " (invalid format)")
		}
	}
	// Rest can be alphanumeric, dash, underscore, or dot
	for _, r := range jail {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			// Don't include potentially malicious input in error message
			if containsCommandInjectionPatterns(jail) {
				return fmt.Errorf(shared.ErrInvalidJailFormat)
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
	if len(filter) > shared.MaxFilterNameLength {
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
		return nil, fmt.Errorf(shared.ErrFailedToParseJails)
	}

	// Find the start of the jail list content (after "Jail list:")
	colonPos := strings.Index(output[jailListPos:], ":")
	if colonPos == -1 {
		return nil, fmt.Errorf(shared.ErrFailedToParseJails)
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
var (
	fail2banVersionPattern = regexp.MustCompile(`(?i)fail2ban(?:-client)?[\s-]*v?([0-9]+(?:\.[0-9]+)*)(?:[-+].*)?`)
	versionNumberPattern   = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(?:[-+].*)?$`)
)

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

// ExtractFail2BanVersion extracts the semantic version from fail2ban-client -V output
func ExtractFail2BanVersion(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", fmt.Errorf("empty version output")
	}
	if match := fail2banVersionPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return match[1], nil
	}
	if match := versionNumberPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return match[1], nil
	}
	return "", fmt.Errorf("unable to parse version from %q", trimmed)
}

// FormatDuration formats seconds into a human-readable duration string
func FormatDuration(sec int64) string {
	days := sec / shared.SecondsPerDay
	h := (sec % shared.SecondsPerDay) / shared.SecondsPerHour
	m := (sec % shared.SecondsPerHour) / shared.SecondsPerMinute
	s := sec % shared.SecondsPerMinute
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, h, m, s)
}

// ValidateCommand validates that a command is in the allowlist for security
func ValidateCommand(command string) error {
	// Allowlist of commands that f2b is permitted to execute
	allowedCommands := map[string]bool{
		shared.Fail2BanClientCommand: true,
		shared.Fail2BanRegexCommand:  true,
		shared.Fail2BanServerCommand: true,
		"service":                    true,
		"systemctl":                  true,
		"sudo":                       true, // Only when used internally
	}

	if command == "" {
		return NewInvalidCommandError("command cannot be empty")
	}

	// Check for null bytes (command injection attempt)
	if strings.ContainsRune(command, '\x00') {
		// Don't include potentially malicious input in error message
		return fmt.Errorf(shared.ErrInvalidCommandFormat)
	}

	// Check for dangerous patterns first (before including command in error messages)
	dangerousPatterns := GetDangerousCommandPatterns()
	cmdLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			// Don't include potentially dangerous command in error message
			return fmt.Errorf(shared.ErrInvalidCommandFormat)
		}
	}

	// Check for path traversal in command name
	if ContainsPathTraversal(command) {
		// Don't include potentially malicious input in error message
		return NewInvalidCommandError(command + " (path traversal)")
	}

	// Additional security checks for command injection patterns
	if containsCommandInjectionPatterns(command) {
		// Don't include potentially malicious input in error message
		return fmt.Errorf(shared.ErrInvalidCommandFormat)
	}

	// Command must be a bare executable name (no paths or whitespace)
	if strings.ContainsAny(command, "/\\ \t") {
		return fmt.Errorf(shared.ErrInvalidCommandFormat)
	}

	// Validate against allowlist (safe to include command name for allowed commands)
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
	if len(arg) > shared.MaxArgumentLength {
		return NewInvalidArgumentError(fmt.Sprintf("%s (too long: %d chars)", arg, len(arg)))
	}

	// Check for command injection patterns
	if containsCommandInjectionPatterns(arg) {
		return NewInvalidArgumentError(arg + " (injection patterns)")
	}

	// For IP arguments, validate IP format
	if isLikelyIPArgument(arg) {
		if err := CachedValidateIP(arg); err != nil {
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

// Timing infrastructure for performance monitoring

// TimedOperation represents a timed operation with metadata
type TimedOperation struct {
	Name      string
	Command   string
	Args      []string
	StartTime time.Time
}

// NewTimedOperation creates a new timed operation and starts timing
func NewTimedOperation(name, command string, args ...string) *TimedOperation {
	return &TimedOperation{
		Name:      name,
		Command:   command,
		Args:      args,
		StartTime: time.Now(),
	}
}

// Finish completes the timed operation and logs the duration with context
func (t *TimedOperation) Finish(err error) {
	duration := time.Since(t.StartTime)

	fields := Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}

	if err != nil {
		getLogger().WithFields(fields).
			WithField(shared.LogFieldError, err.Error()).
			Warnf(shared.ErrOperationFailed, duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			getLogger().WithFields(fields).Warnf(shared.ErrSlowOperation, duration)
		} else {
			// Log fast operations at debug level to reduce noise
			getLogger().WithFields(fields).Debugf(shared.MsgOperationCompleted, duration)
		}
	}
}

// FinishWithContext completes the timed operation and logs the duration with context
func (t *TimedOperation) FinishWithContext(ctx context.Context, err error) {
	duration := time.Since(t.StartTime)

	// Get logger with context fields
	logger := LoggerFromContext(ctx)

	// Add timing-specific fields
	fields := Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}
	logger = logger.WithFields(fields)

	if err != nil {
		logger.WithField(shared.LogFieldError, err.Error()).Warnf(shared.ErrOperationFailed, duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			logger.Warnf(shared.ErrSlowOperation, duration)
		} else {
			// Log fast operations at debug level to reduce noise
			logger.Debugf(shared.MsgOperationCompleted, duration)
		}
	}
}

// Path helper functions for centralized path validation

// PathSecurityConfig holds configuration for path security validation
type PathSecurityConfig struct {
	AllowedBasePaths []string // List of allowed base directories
	MaxPathLength    int      // Maximum allowed path length (0 = unlimited)
	AllowSymlinks    bool     // Whether to allow symlinks
	ResolveSymlinks  bool     // Whether to resolve symlinks before validation
}

// GetLogAllowedPaths returns allowed paths for log directories
func GetLogAllowedPaths() []string {
	paths := []string{"/var/log", "/opt", "/usr/local", "/home"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// GetFilterAllowedPaths returns allowed paths for filter directories
func GetFilterAllowedPaths() []string {
	paths := []string{"/etc/fail2ban", "/usr/local/etc/fail2ban", "/opt/fail2ban", "/home"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// appendDevPathsIfAllowed adds development paths if ALLOW_DEV_PATHS is set
func appendDevPathsIfAllowed(paths []string) []string {
	if os.Getenv("ALLOW_DEV_PATHS") != "" {
		return append(paths, "/tmp", "/var/folders") // macOS temp dirs
	}
	return paths
}

// expandAllowedPaths adds resolved equivalents for allowed paths and removes duplicates
func expandAllowedPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths)*2)
	expanded := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; !ok {
			expanded = append(expanded, p)
			seen[p] = struct{}{}
		}
		if resolved, err := resolveAncestorSymlinks(p, true); err == nil && resolved != "" && resolved != p {
			if _, ok := seen[resolved]; !ok {
				expanded = append(expanded, resolved)
				seen[resolved] = struct{}{}
			}
		}
	}
	return expanded
}

// CreateLogPathConfig creates a standard PathSecurityConfig for log directories
func CreateLogPathConfig() PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: GetLogAllowedPaths(),
		MaxPathLength:    4096,
		AllowSymlinks:    true,
		ResolveSymlinks:  true,
	}
}

// CreateFilterPathConfig creates a standard PathSecurityConfig for filter directories
func CreateFilterPathConfig() PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: GetFilterAllowedPaths(),
		MaxPathLength:    4096,
		AllowSymlinks:    true,
		ResolveSymlinks:  true,
	}
}

// CreateSingleDirPathConfig creates a path config for a single directory (like log file validation)
func CreateSingleDirPathConfig(baseDir string) PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: []string{baseDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}
}

// ValidatePathWithSecurity performs comprehensive path security validation
func ValidatePathWithSecurity(path string, config PathSecurityConfig) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path not allowed")
	}

	// Check path length limits
	if config.MaxPathLength > 0 && len(path) > config.MaxPathLength {
		return "", fmt.Errorf("path too long: %d characters (max: %d)", len(path), config.MaxPathLength)
	}

	// Detect and prevent null byte injection
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("path contains null byte")
	}

	// Decode URL-encoded path traversal attempts (path semantics)
	if decodedPath, err := url.PathUnescape(path); err == nil && decodedPath != path {
		getLogger().Debug("Detected URL-encoded path; using decoded version for validation")
		path = decodedPath
	}

	// Normalize unicode characters to prevent bypass attempts
	path = normalizeUnicode(path)

	// Basic path traversal detection (before cleaning)
	if hasPathTraversal(path) {
		return "", fmt.Errorf("path contains path traversal patterns")
	}

	// Clean and resolve the path
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Additional check after cleaning (double-check for sophisticated attacks)
	if hasPathTraversal(cleanPath) {
		return "", fmt.Errorf("path contains path traversal patterns after normalization")
	}

	// Handle symlinks according to configuration
	finalPath, err := handleSymlinks(cleanPath, config)
	if err != nil {
		return "", err
	}

	// Validate against allowed base paths using Rel, not prefix
	if err := validateBasePath(finalPath, config.AllowedBasePaths); err != nil {
		return "", err
	}

	// Check if path points to a device file or other dangerous file types
	if err := validateFileType(finalPath); err != nil {
		return "", err
	}

	return finalPath, nil
}

// hasPathTraversal detects various path traversal patterns
func hasPathTraversal(path string) bool {
	// Check for various path traversal patterns
	dangerousPatterns := []string{
		"..",
		"./",
		".\\",
		"//",
		"\\\\",
		"/../",
		"\\..\\",
		"%2e%2e",       // URL encoded ..
		"%2f",          // URL encoded /
		"%5c",          // URL encoded \
		"\u002e\u002e", // Unicode ..
		"\u2024\u2024", // Unicode bullet points (can look like ..)
		"\uff0e\uff0e", // Full-width Unicode ..
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(pathLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// normalizeUnicode normalizes unicode characters to prevent bypass attempts
func normalizeUnicode(path string) string {
	// Replace various Unicode representations of dots and slashes
	replacements := map[string]string{
		"\u002e": ".",  // Unicode dot
		"\u2024": ".",  // Unicode bullet (one dot leader)
		"\uff0e": ".",  // Full-width dot
		"\u002f": "/",  // Unicode slash
		"\u2044": "/",  // Unicode fraction slash
		"\uff0f": "/",  // Full-width slash
		"\u005c": "\\", // Unicode backslash
		"\uff3c": "\\", // Full-width backslash
	}

	result := path
	for unicode, ascii := range replacements {
		result = strings.ReplaceAll(result, unicode, ascii)
	}

	return result
}

// handleSymlinks resolves or validates symlinks according to configuration
func handleSymlinks(path string, config PathSecurityConfig) (string, error) {
	// Check if the path is a symlink
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if !config.AllowSymlinks {
				return "", fmt.Errorf("symlinks not allowed: %s", path)
			}

			if config.ResolveSymlinks {
				resolved, err := filepath.EvalSymlinks(path)
				if err != nil {
					return "", fmt.Errorf(shared.ErrFailedToResolveSymlink, err)
				}
				return resolved, nil
			}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check file info: %w", err)
	}

	// If leaf doesn't exist, resolve symlinks in the deepest existing ancestor
	if config.ResolveSymlinks {
		return resolveAncestorSymlinks(path, config.AllowSymlinks)
	}
	return path, nil
}

// resolveAncestorSymlinks resolves symlinks in existing ancestor directories
func resolveAncestorSymlinks(path string, allowSymlinks bool) (string, error) {
	dir := path
	var tail []string
	for {
		d := filepath.Dir(dir)
		if d == dir {
			break
		}
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		tail = append([]string{filepath.Base(dir)}, tail...)
		dir = d
	}
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if !allowSymlinks {
			return "", fmt.Errorf("symlinks not allowed in path: %s", dir)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", fmt.Errorf(shared.ErrFailedToResolveSymlink, err)
		}
		return filepath.Join(append([]string{resolved}, tail...)...), nil
	}
	return path, nil
}

// validateBasePath ensures the path is within allowed base directories
func validateBasePath(path string, allowedBasePaths []string) error {
	if len(allowedBasePaths) == 0 {
		return nil // No restrictions if no base paths configured
	}

	for _, basePath := range allowedBasePaths {
		cleanBasePath, err := filepath.Abs(filepath.Clean(basePath))
		if err != nil {
			continue
		}

		rel, err := filepath.Rel(cleanBasePath, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}

	return fmt.Errorf("path outside allowed directories: %s", path)
}

// validateFileType checks for dangerous file types (devices, named pipes, etc.)
func validateFileType(path string) error {
	// Check if file exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // File doesn't exist yet, allow it
	}
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	mode := info.Mode()

	// Block device files
	if mode&os.ModeDevice != 0 {
		return fmt.Errorf("device files not allowed: %s", path)
	}

	// Block named pipes (FIFOs)
	if mode&os.ModeNamedPipe != 0 {
		return fmt.Errorf("named pipes not allowed: %s", path)
	}

	// Block socket files
	if mode&os.ModeSocket != 0 {
		return fmt.Errorf("socket files not allowed: %s", path)
	}

	// Block irregular files (anything that's not a regular file or directory)
	if !mode.IsRegular() && !mode.IsDir() {
		return fmt.Errorf("irregular file type not allowed: %s", path)
	}

	return nil
}

// ValidateLogPath validates and sanitizes a log file path using standard log directory config
// with context support for timeout/cancellation
func ValidateLogPath(_ context.Context, path string, logDir string) (string, error) {
	config := CreateSingleDirPathConfig(logDir)
	return ValidatePathWithSecurity(path, config)
}

// ValidateClientLogPath validates log directory path for client initialization
// with context support for timeout/cancellation
func ValidateClientLogPath(_ context.Context, logDir string) (string, error) {
	config := CreateLogPathConfig()
	return ValidatePathWithSecurity(logDir, config)
}

// ValidateClientFilterPath validates filter directory path for client initialization
// with context support for timeout/cancellation
func ValidateClientFilterPath(_ context.Context, filterDir string) (string, error) {
	config := CreateFilterPathConfig()
	return ValidatePathWithSecurity(filterDir, config)
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
