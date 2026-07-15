// Package cmd provides configuration management and validation utilities.
// This package handles CLI configuration parsing, validation, and security
// checks to ensure safe operation of f2b commands.
package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
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

// checkPathVariationsForTraversal checks all path variations against dangerous patterns
func checkPathVariationsForTraversal(variations []string) bool {
	allPatterns := getAllDangerousPatterns()

	for _, variant := range variations {
		if checkSingleVariantForTraversal(variant, allPatterns) {
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
func checkSingleVariantForTraversal(variant string, patterns map[string][]string) bool {
	lowerVariant := strings.ToLower(variant)

	// Check all pattern categories
	for _, patternList := range patterns {
		for _, pattern := range patternList {
			if containsPattern(variant, lowerVariant, pattern) {
				return true
			}
		}
	}

	// Check for null byte injection combined with path traversal
	if containsNullByteInjection(variant, lowerVariant) {
		return true
	}

	// Check for invalid UTF-8 sequences. This already rejects every genuine
	// overlong UTF-8 encoding (they decode to U+FFFD and are not valid UTF-8);
	// a byte-pattern regex over a Go string matches decoded runes, not raw
	// bytes, so it never caught real overlong input and false-positived on
	// legitimate accented text.
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

// validateConfigPathWithFallback validates a config path and returns the fallback if validation fails.
// This consolidates the common pattern of validate-or-fallback-with-logging used for config paths.
func validateConfigPathWithFallback(path, pathType, defaultPath, errorMsg string) string {
	validated, err := validateConfigPath(path, pathType)
	if err != nil {
		Logger.WithError(err).WithField(constants.LogFieldPath, path).Error(errorMsg)
		return defaultPath
	}
	return validated
}

// resolveDirFromEnv resolves a directory from an environment variable. When the
// variable is unset it validates the default (which is always valid). When it
// is explicitly set but invalid, it records a fatal error into cfgErr instead
// of silently substituting the default, so the user's misconfiguration is not
// ignored.
func resolveDirFromEnv(envVar, defaultDir, pathType string, cfgErr *error) string {
	raw := os.Getenv(envVar)
	if raw == "" {
		return validateConfigPathWithFallback(defaultDir, pathType, defaultDir, "Invalid default directory")
	}
	validated, err := validateConfigPath(raw, pathType)
	if err != nil {
		*cfgErr = errors.Join(*cfgErr, fmt.Errorf("%s=%q is invalid: %w", envVar, raw, err))
		return defaultDir
	}
	return validated
}

// isReasonableSystemPath checks if a path is in a reasonable system location
func isReasonableSystemPath(path, pathType string) bool {
	// Allow common system directories based on path type
	var allowedPrefixes []string
	switch pathType {
	case constants.PathTypeLog:
		allowedPrefixes = fail2ban.GetLogAllowedPaths()
	case constants.PathTypeFilter:
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

	// Resolve the log and filter directories. An explicitly-set but invalid env
	// var is a fatal config error (surfaced by Execute) rather than a silent
	// fallback to the default, which would operate on the wrong directory.
	cfg.LogDir = resolveDirFromEnv("F2B_LOG_DIR", constants.DefaultLogDir, constants.PathTypeLog, &cfg.configErr)
	cfg.FilterDir = resolveDirFromEnv(
		"F2B_FILTER_DIR", constants.DefaultFilterDir, constants.PathTypeFilter, &cfg.configErr,
	)

	// Configure timeouts from environment variables (clamped to their maxima).
	cfg.CommandTimeout = parseTimeoutFromEnv(
		"F2B_COMMAND_TIMEOUT",
		constants.DefaultCommandTimeout,
		constants.MaxCommandTimeout,
	)
	cfg.FileTimeout = parseTimeoutFromEnv("F2B_FILE_TIMEOUT", constants.DefaultFileTimeout, constants.MaxFileTimeout)
	cfg.ParallelTimeout = parseTimeoutFromEnv(
		"F2B_PARALLEL_TIMEOUT", constants.DefaultParallelTimeout, constants.MaxParallelTimeout,
	)

	cfg.Format = PlainFormat
	return cfg
}

// parseTimeoutFromEnv parses timeout duration from environment variable with
// fallback, clamping any value above maxTimeout so an env override cannot
// exceed the configured ceiling (previously the Max* limits were unenforced).
func parseTimeoutFromEnv(envVar string, defaultTimeout, maxTimeout time.Duration) time.Duration {
	envValue := os.Getenv(envVar)
	if envValue == "" {
		return defaultTimeout
	}

	clamp := func(d time.Duration) time.Duration {
		if maxTimeout > 0 && d > maxTimeout {
			Logger.WithField(constants.LogFieldEnvVar, envVar).WithField(constants.LogFieldValue, envValue).
				Warnf("Timeout exceeds maximum %s, clamping", maxTimeout)
			return maxTimeout
		}
		return d
	}

	// Try parsing as duration first (e.g., "30s", "1m30s")
	if duration, err := time.ParseDuration(envValue); err == nil {
		if duration <= 0 {
			Logger.WithField(constants.LogFieldEnvVar, envVar).WithField(constants.LogFieldValue, envValue).
				Warn(constants.MsgInvalidTimeout)
			return defaultTimeout
		}
		return clamp(duration)
	}

	// Try parsing as seconds (for backward compatibility)
	if seconds, err := strconv.Atoi(envValue); err == nil {
		if seconds <= 0 {
			Logger.WithField(constants.LogFieldEnvVar, envVar).WithField(constants.LogFieldValue, envValue).
				Warn(constants.MsgInvalidTimeout)
			return defaultTimeout
		}
		// Guard the multiplication: a huge value overflows time.Duration to a
		// negative that would slip past clamp's upper bound and expire every
		// context instantly.
		if maxTimeout > 0 && int64(seconds) > int64(maxTimeout/time.Second) {
			return clamp(maxTimeout)
		}
		return clamp(time.Duration(seconds) * time.Second)
	}

	Logger.WithField(constants.LogFieldEnvVar, envVar).WithField(constants.LogFieldValue, envValue).
		Warn("Failed to parse timeout value, using default")
	return defaultTimeout
}

// ValidateConfig performs comprehensive validation of the Config struct
func (c *Config) ValidateConfig() error {
	var problems []string

	// Validate directories
	dirs := []struct {
		label    string
		value    string
		pathType string
	}{
		{"log", c.LogDir, constants.PathTypeLog},
		{"filter", c.FilterDir, constants.PathTypeFilter},
	}
	for _, d := range dirs {
		if d.value == "" {
			problems = append(problems, d.label+" directory cannot be empty")
			continue
		}
		if _, err := validateConfigPath(d.value, d.pathType); err != nil {
			problems = append(problems, fmt.Sprintf("invalid %s directory: %v", d.label, err))
		}
	}

	// Validate Format
	if c.Format != PlainFormat && c.Format != JSONFormat {
		problems = append(problems, fmt.Sprintf("invalid format '%s', must be 'plain' or 'json'", c.Format))
	}

	// Validate timeouts (each must be positive and within its ceiling)
	timeouts := []struct {
		name    string
		value   time.Duration
		max     time.Duration
		tooLong string
	}{
		{"command", c.CommandTimeout, constants.MaxCommandTimeout, "command timeout too large (max 10 minutes)"},
		{"file", c.FileTimeout, constants.MaxFileTimeout, "file timeout too large (max 5 minutes)"},
		{"parallel", c.ParallelTimeout, constants.MaxParallelTimeout, "parallel timeout too large (max 30 minutes)"},
	}
	for _, t := range timeouts {
		switch {
		case t.value <= 0:
			problems = append(problems, t.name+" timeout must be positive")
		case t.value > t.max:
			problems = append(problems, t.tooLong)
		}
	}

	// Check timeout relationships
	if c.ParallelTimeout < c.CommandTimeout {
		problems = append(problems, "parallel timeout should be >= command timeout")
	}

	if len(problems) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(problems, "; "))
	}

	return nil
}
