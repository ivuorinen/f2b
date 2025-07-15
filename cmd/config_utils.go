package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// validateConfigPath validates directory paths from configuration
func validateConfigPath(path, pathType string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path cannot be empty", pathType)
	}

	// Basic path traversal detection
	if strings.Contains(path, "..") {
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
