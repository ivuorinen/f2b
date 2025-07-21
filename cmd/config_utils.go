package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
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
	overlongRegex := regexp.MustCompile(
		`\xc0[\x80-\xbf]|\xe0[\x80-\x9f][\x80-\xbf]|\xf0[\x80-\x8f][\x80-\xbf][\x80-\xbf]`,
	)

	for _, variant := range variations {
		if checkSingleVariantForTraversal(variant, allPatterns, overlongRegex) {
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
	switch pathType {
	case "log":
		allowedPrefixes := []string{
			"/var/log",
			"/tmp",
			"/opt",
			"/usr/local",
			"/home",
		}
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	case "filter":
		allowedPrefixes := []string{
			"/etc/fail2ban",
			"/usr/local/etc/fail2ban",
			"/opt/fail2ban",
			"/home",
		}
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
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
		logrus.WithError(err).WithField("path", logDir).Error("Invalid log directory from environment")
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
		logrus.WithError(err).WithField("path", filterDir).Error("Invalid filter directory from environment")
		validatedFilterDir = "/etc/fail2ban/filter.d" // Fallback to safe default
	}
	cfg.FilterDir = validatedFilterDir

	cfg.Format = "plain"
	return cfg
}
