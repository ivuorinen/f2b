package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ivuorinen/f2b/fail2ban"
)

const (
	// DefaultCommandTimeout is the default timeout for individual fail2ban commands
	DefaultCommandTimeout = 30 * time.Second
	// DefaultFileTimeout is the default timeout for file operations
	DefaultFileTimeout = 10 * time.Second
	// DefaultParallelTimeout is the default timeout for parallel operations
	DefaultParallelTimeout = 60 * time.Second
)

// containsPathTraversal performs comprehensive path traversal detection
// including various encoding techniques and bypass attempts
func containsPathTraversal(path string) bool {
	if path == "" {
		return false
	}

	variations := createPathVariations(path)
	return checkPathVariationsForTraversal(variations)
}

// createPathVariations generates different encoded variations of the path to check
func createPathVariations(path string) []string {
	variations := []string{path}

	// URL decode the path (handle single and double encoding)
	if decoded, err := url.QueryUnescape(path); err == nil && decoded != path {
		variations = append(variations, decoded)
		// Check for double encoding
		if doubleDecoded, err := url.QueryUnescape(decoded); err == nil && doubleDecoded != decoded {
			variations = append(variations, doubleDecoded)
		}
	}

	return variations
}

// Cache compiled regex for performance
var overlongEncodingRegex = regexp.MustCompile(
	`\xc0[\x80-\xbf]|\xe0[\x80-\x9f][\x80-\xbf]|\xf0[\x80-\x8f][\x80-\xbf][\x80-\xbf]`,
)

// checkPathVariationsForTraversal checks all path variations against dangerous patterns
func checkPathVariationsForTraversal(variations []string) bool {
	allPatterns := getAllDangerousPatterns()

	for _, variant := range variations {
		if checkSingleVariantForTraversal(variant, allPatterns, overlongEncodingRegex) {
			return true
		}
	}

	return false
}

// getAllDangerousPatterns returns all dangerous path traversal patterns
func getAllDangerousPatterns() map[string][]string {
	return map[string][]string{
		"basic": {
			"..", "../", "..\\", "..%2f", "..%2F", "..%5c", "..%5C",
		},
		"urlEncoded": {
			"%2e%2e", "%2E%2E", "%2e%2E", "%2E%2e",
			"%252e%252e", "%252E%252E", "%25252e%25252e",
		},
		"unicode": {
			"\\u002e\\u002e", "\\u00002e\\u00002e", "..",
		},
		"mixed": {
			"..%00", ".%2e", "%2e.", "...//", "..;/", "..%3b",
		},
	}
}

// checkSingleVariantForTraversal checks a single path variant against all patterns
func checkSingleVariantForTraversal(variant string, patterns map[string][]string, overlongRegex *regexp.Regexp) bool {
	lowerVariant := strings.ToLower(variant)

	// Check all pattern categories
	for _, patternList := range patterns {
		for _, pattern := range patternList {
			if containsPattern(variant, lowerVariant, pattern) {
				return true
			}
		}
	}

	// Check for UTF-8 overlong encodings
	if overlongRegex.MatchString(variant) {
		return true
	}

	// Check for null byte injection combined with path traversal
	if containsNullByteInjection(variant, lowerVariant) {
		return true
	}

	// Check for invalid UTF-8 sequences
	if !utf8.ValidString(variant) {
		return true
	}

	return false
}

// containsPattern checks if a variant contains a dangerous pattern
func containsPattern(variant, lowerVariant, pattern string) bool {
	// For Unicode patterns, check both original and lowercase
	if strings.Contains(pattern, "\\u") || strings.Contains(pattern, "\\x") {
		return strings.Contains(variant, pattern) || strings.Contains(lowerVariant, strings.ToLower(pattern))
	}
	// For other patterns, use case-insensitive check
	return strings.Contains(lowerVariant, strings.ToLower(pattern))
}

// containsNullByteInjection checks for null byte injection with path traversal
func containsNullByteInjection(variant, lowerVariant string) bool {
	return strings.Contains(variant, "\x00") &&
		(strings.Contains(variant, "..") || strings.Contains(lowerVariant, "%2e"))
}

// validateConfigPath validates directory paths from configuration
func validateConfigPath(path, pathType string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path cannot be empty", pathType)
	}

	// Comprehensive path traversal detection
	if containsPathTraversal(path) {
		return "", fmt.Errorf("%s path contains path traversal: %s", pathType, path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("%s path contains null byte: %s", pathType, path)
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid %s path: %w", pathType, err)
	}

	// Check path length (reasonable limit)
	if len(absPath) > 4096 {
		return "", fmt.Errorf("%s path too long: %d characters", pathType, len(absPath))
	}

	// Validate that it's a reasonable system path
	if !isReasonableSystemPath(absPath, pathType) {
		return "", fmt.Errorf("%s path not in expected system location: %s", pathType, absPath)
	}

	return absPath, nil
}

// isReasonableSystemPath checks if a path is in a reasonable system location
func isReasonableSystemPath(path, pathType string) bool {
	// Allow common system directories based on path type
	var allowedPrefixes []string
	switch pathType {
	case "log":
		allowedPrefixes = fail2ban.GetLogAllowedPaths()
	case "filter":
		allowedPrefixes = fail2ban.GetFilterAllowedPaths()
	default:
		return false
	}

	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// NewConfigFromEnv builds Config from environment variables with defaults and validation.
func NewConfigFromEnv() Config {
	cfg := Config{}

	// Get and validate log directory
	logDir := os.Getenv("F2B_LOG_DIR")
	if logDir == "" {
		logDir = "/var/log"
	}

	validatedLogDir, err := validateConfigPath(logDir, "log")
	if err != nil {
		Logger.WithError(err).WithField("path", logDir).Error("Invalid log directory from environment")
		validatedLogDir = "/var/log" // Fallback to safe default
	}
	cfg.LogDir = validatedLogDir

	// Get and validate filter directory
	filterDir := os.Getenv("F2B_FILTER_DIR")
	if filterDir == "" {
		filterDir = "/etc/fail2ban/filter.d"
	}

	validatedFilterDir, err := validateConfigPath(filterDir, "filter")
	if err != nil {
		Logger.WithError(err).WithField("path", filterDir).Error("Invalid filter directory from environment")
		validatedFilterDir = "/etc/fail2ban/filter.d" // Fallback to safe default
	}
	cfg.FilterDir = validatedFilterDir

	// Configure timeouts from environment variables
	cfg.CommandTimeout = parseTimeoutFromEnv("F2B_COMMAND_TIMEOUT", DefaultCommandTimeout)
	cfg.FileTimeout = parseTimeoutFromEnv("F2B_FILE_TIMEOUT", DefaultFileTimeout)
	cfg.ParallelTimeout = parseTimeoutFromEnv("F2B_PARALLEL_TIMEOUT", DefaultParallelTimeout)

	cfg.Format = "plain"
	return cfg
}

// parseTimeoutFromEnv parses timeout duration from environment variable with fallback
func parseTimeoutFromEnv(envVar string, defaultTimeout time.Duration) time.Duration {
	envValue := os.Getenv(envVar)
	if envValue == "" {
		return defaultTimeout
	}

	// Try parsing as duration first (e.g., "30s", "1m30s")
	if duration, err := time.ParseDuration(envValue); err == nil {
		if duration <= 0 {
			Logger.WithField("env_var", envVar).WithField("value", envValue).
				Warn("Invalid timeout value, using default")
			return defaultTimeout
		}
		return duration
	}

	// Try parsing as seconds (for backward compatibility)
	if seconds, err := strconv.Atoi(envValue); err == nil {
		if seconds <= 0 {
			Logger.WithField("env_var", envVar).WithField("value", envValue).
				Warn("Invalid timeout value, using default")
			return defaultTimeout
		}
		return time.Duration(seconds) * time.Second
	}

	Logger.WithField("env_var", envVar).WithField("value", envValue).
		Warn("Failed to parse timeout value, using default")
	return defaultTimeout
}

// ValidateConfig performs comprehensive validation of the Config struct
func (c *Config) ValidateConfig() error {
	var errors []string

	// Validate LogDir
	if c.LogDir == "" {
		errors = append(errors, "log directory cannot be empty")
	} else if _, err := validateConfigPath(c.LogDir, "log"); err != nil {
		errors = append(errors, fmt.Sprintf("invalid log directory: %v", err))
	}

	// Validate FilterDir
	if c.FilterDir == "" {
		errors = append(errors, "filter directory cannot be empty")
	} else if _, err := validateConfigPath(c.FilterDir, "filter"); err != nil {
		errors = append(errors, fmt.Sprintf("invalid filter directory: %v", err))
	}

	// Validate Format
	validFormats := map[string]bool{"plain": true, "json": true}
	if !validFormats[c.Format] {
		errors = append(errors, fmt.Sprintf("invalid format '%s', must be 'plain' or 'json'", c.Format))
	}

	// Validate Timeouts
	if c.CommandTimeout <= 0 {
		errors = append(errors, "command timeout must be positive")
	} else if c.CommandTimeout > fail2ban.MaxCommandTimeout {
		errors = append(errors, "command timeout too large (max 10 minutes)")
	}

	if c.FileTimeout <= 0 {
		errors = append(errors, "file timeout must be positive")
	} else if c.FileTimeout > fail2ban.MaxFileTimeout {
		errors = append(errors, "file timeout too large (max 5 minutes)")
	}

	if c.ParallelTimeout <= 0 {
		errors = append(errors, "parallel timeout must be positive")
	} else if c.ParallelTimeout > fail2ban.MaxParallelTimeout {
		errors = append(errors, "parallel timeout too large (max 30 minutes)")
	}

	// Check timeout relationships
	if c.ParallelTimeout < c.CommandTimeout {
		errors = append(errors, "parallel timeout should be >= command timeout")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}
