package fail2ban

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

// Validation constants
const (
	// MaxIPAddressLength is the maximum length for an IP address string (IPv6 with brackets and port)
	MaxIPAddressLength = 45
	// MaxJailNameLength is the maximum length for a jail name
	MaxJailNameLength = 64
	// MaxFilterNameLength is the maximum length for a filter name
	MaxFilterNameLength = 255
	// MaxArgumentLength is the maximum length for a command argument
	MaxArgumentLength = 1024
)

// Time constants for duration calculations
const (
	// SecondsPerMinute is the number of seconds in a minute
	SecondsPerMinute = 60
	// SecondsPerHour is the number of seconds in an hour
	SecondsPerHour = 3600
	// SecondsPerDay is the number of seconds in a day
	SecondsPerDay = 86400
	// DefaultBanDuration is the default fallback duration for bans when parsing fails
	DefaultBanDuration = 24 * time.Hour
)

// Fail2Ban status codes
const (
	// Fail2BanStatusSuccess indicates successful operation (ban/unban succeeded)
	Fail2BanStatusSuccess = "0"
	// Fail2BanStatusAlreadyProcessed indicates IP was already banned/unbanned
	Fail2BanStatusAlreadyProcessed = "1"
)

// Fail2Ban command names
const (
	// Fail2BanClientCommand is the standard fail2ban client command
	Fail2BanClientCommand = "fail2ban-client"
	// Fail2BanRegexCommand is the fail2ban regex testing command
	Fail2BanRegexCommand = "fail2ban-regex"
	// Fail2BanServerCommand is the fail2ban server command
	Fail2BanServerCommand = "fail2ban-server"
)

// File permission constants
const (
	// DefaultFilePermissions for log files and temporary files
	DefaultFilePermissions = 0600
	// DefaultDirectoryPermissions for created directories
	DefaultDirectoryPermissions = 0750
)

// Timeout limit constants
const (
	// MaxCommandTimeout is the maximum allowed timeout for commands
	MaxCommandTimeout = 10 * time.Minute
	// MaxFileTimeout is the maximum allowed timeout for file operations
	MaxFileTimeout = 5 * time.Minute
	// MaxParallelTimeout is the maximum allowed timeout for parallel operations
	MaxParallelTimeout = 30 * time.Minute
)

// Context key types for structured logging
type contextKey string

const (
	// ContextKeyRequestID is the context key for request IDs
	ContextKeyRequestID contextKey = "request_id"
	// ContextKeyOperation is the context key for operation names
	ContextKeyOperation contextKey = "operation"
	// ContextKeyJail is the context key for jail names
	ContextKeyJail contextKey = "jail"
	// ContextKeyIP is the context key for IP addresses
	ContextKeyIP contextKey = "ip"
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
		if containsCommandInjectionPatterns(ip) || len(ip) > MaxIPAddressLength {
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
	if len(jail) > MaxJailNameLength {
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
	if len(filter) > MaxFilterNameLength {
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
	days := sec / SecondsPerDay
	h := (sec % SecondsPerDay) / SecondsPerHour
	m := (sec % SecondsPerHour) / SecondsPerMinute
	s := sec % SecondsPerMinute
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
		Fail2BanClientCommand: true,
		Fail2BanRegexCommand:  true,
		Fail2BanServerCommand: true,
		"service":             true,
		"systemctl":           true,
		"sudo":                true, // Only when used internally
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
	if len(arg) > MaxArgumentLength {
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

// Context helpers for structured logging

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithOperation adds an operation name to the context
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, ContextKeyOperation, operation)
}

// WithJail adds a jail name to the context
func WithJail(ctx context.Context, jail string) context.Context {
	return context.WithValue(ctx, ContextKeyJail, jail)
}

// WithIP adds an IP address to the context
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ContextKeyIP, ip)
}

// LoggerFromContext creates a logrus Entry with fields from context
func LoggerFromContext(ctx context.Context) *logrus.Entry {
	fields := logrus.Fields{}

	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		fields["request_id"] = requestID
	}

	if operation, ok := ctx.Value(ContextKeyOperation).(string); ok && operation != "" {
		fields["operation"] = operation
	}

	if jail, ok := ctx.Value(ContextKeyJail).(string); ok && jail != "" {
		fields["jail"] = jail
	}

	if ip, ok := ctx.Value(ContextKeyIP).(string); ok && ip != "" {
		fields["ip"] = ip
	}

	return logrus.WithFields(fields)
}

// GenerateRequestID generates a simple request ID for tracing
func GenerateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
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

	fields := logrus.Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}

	if err != nil {
		logrus.WithFields(fields).WithField("error", err.Error()).Warnf("Operation failed after %v", duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			logrus.WithFields(fields).Warnf("Slow operation completed in %v", duration)
		} else {
			// Log fast operations at debug level to reduce noise
			logrus.WithFields(fields).Debugf("Operation completed in %v", duration)
		}
	}
}

// FinishWithContext completes the timed operation and logs the duration with context
func (t *TimedOperation) FinishWithContext(ctx context.Context, err error) {
	duration := time.Since(t.StartTime)

	// Get logger with context fields
	logger := LoggerFromContext(ctx)

	// Add timing-specific fields
	fields := logrus.Fields{
		"operation": t.Name,
		"command":   t.Command,
		"duration":  duration,
		"args":      strings.Join(t.Args, " "),
	}
	logger = logger.WithFields(fields)

	if err != nil {
		logger.WithField("error", err.Error()).Warnf("Operation failed after %v", duration)
	} else {
		if duration > time.Second {
			// Log slow operations as warnings for visibility
			logger.Warnf("Slow operation completed in %v", duration)
		} else {
			// Log fast operations at debug level to reduce noise
			logger.Debugf("Operation completed in %v", duration)
		}
	}
}

// Validation caching for performance optimization

// ValidationCache provides thread-safe caching for validation results
type ValidationCache struct {
	mu    sync.RWMutex
	cache map[string]error
}

// NewValidationCache creates a new validation cache
func NewValidationCache() *ValidationCache {
	return &ValidationCache{
		cache: make(map[string]error),
	}
}

// Get retrieves a cached validation result
func (vc *ValidationCache) Get(key string) (bool, error) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	result, exists := vc.cache[key]
	return exists, result
}

// Set stores a validation result in the cache
func (vc *ValidationCache) Set(key string, err error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.cache[key] = err
}

// Clear removes all cached entries
func (vc *ValidationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.cache = make(map[string]error)
}

// Size returns the number of cached entries
func (vc *ValidationCache) Size() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.cache)
}

// MetricsRecorder interface for recording validation metrics
type MetricsRecorder interface {
	RecordValidationCacheHit()
	RecordValidationCacheMiss()
}

// Global validation caches for frequently used validators
var (
	ipValidationCache      = NewValidationCache()
	jailValidationCache    = NewValidationCache()
	filterValidationCache  = NewValidationCache()
	commandValidationCache = NewValidationCache()

	// metricsRecorder is set by the cmd package to avoid circular dependencies
	metricsRecorder   MetricsRecorder
	metricsRecorderMu sync.RWMutex
)

// SetMetricsRecorder sets the metrics recorder for validation cache tracking
func SetMetricsRecorder(recorder MetricsRecorder) {
	metricsRecorderMu.Lock()
	defer metricsRecorderMu.Unlock()
	metricsRecorder = recorder
}

// getMetricsRecorder returns the current metrics recorder
func getMetricsRecorder() MetricsRecorder {
	metricsRecorderMu.RLock()
	defer metricsRecorderMu.RUnlock()
	return metricsRecorder
}

// CachedValidateIP validates an IP address with caching
func CachedValidateIP(ip string) error {
	cacheKey := "ip:" + ip
	if exists, result := ipValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateIP(ip)
	ipValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateJail validates a jail name with caching
func CachedValidateJail(jail string) error {
	cacheKey := "jail:" + jail
	if exists, result := jailValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateJail(jail)
	jailValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateFilter validates a filter name with caching
func CachedValidateFilter(filter string) error {
	cacheKey := "filter:" + filter
	if exists, result := filterValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateFilter(filter)
	filterValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateCommand validates a command with caching
func CachedValidateCommand(command string) error {
	cacheKey := "command:" + command
	if exists, result := commandValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateCommand(command)
	commandValidationCache.Set(cacheKey, err)
	return err
}

// ClearValidationCaches clears all validation caches
func ClearValidationCaches() {
	ipValidationCache.Clear()
	jailValidationCache.Clear()
	filterValidationCache.Clear()
	commandValidationCache.Clear()
}

// GetValidationCacheStats returns cache statistics
func GetValidationCacheStats() map[string]int {
	return map[string]int{
		"ip_cache_size":      ipValidationCache.Size(),
		"jail_cache_size":    jailValidationCache.Size(),
		"filter_cache_size":  filterValidationCache.Size(),
		"command_cache_size": commandValidationCache.Size(),
	}
}
