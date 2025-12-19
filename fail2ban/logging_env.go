// Package fail2ban provides logging and environment detection utilities.
// This module handles logger configuration, CI detection, and test environment setup
// for the fail2ban integration system.
package fail2ban

import (
	"os"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// logger holds the current logger instance in a thread-safe manner
var logger atomic.Value

func init() {
	// Initialize with default logger
	logger.Store(NewLogrusAdapter(logrus.StandardLogger()))
}

// LevelSetter interface for loggers that support setting log levels
type LevelSetter interface {
	SetLevel(level string)
}

// SetLogger allows the cmd package to set the logger instance (thread-safe)
func SetLogger(l LoggerInterface) {
	logger.Store(l)
}

// getLogger returns the current logger instance (thread-safe)
func getLogger() LoggerInterface {
	return logger.Load().(LoggerInterface)
}

// IsCI detects if we're running in a CI environment
func IsCI() bool {
	ciEnvVars := []string{
		"CI", "GITHUB_ACTIONS", "TRAVIS", "CIRCLECI", "JENKINS_URL",
		"BUILDKITE", "TF_BUILD", "GITLAB_CI",
	}

	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}
	return false
}

// ConfigureCITestLogging reduces log verbosity in CI and test environments
// This should be called explicitly during application initialization
func ConfigureCITestLogging() {
	if IsCI() || IsTestEnvironment() {
		// Try interface-based assertion first to support custom loggers
		currentLogger := getLogger()
		if l, ok := currentLogger.(interface{ SetLevel(logrus.Level) }); ok {
			l.SetLevel(logrus.WarnLevel)
		} else {
			// Log when we can't adjust level (observable for debugging)
			logrus.StandardLogger().Debug(
				"Non-standard logger in use; CI/test log level adjustment skipped",
			)
		}
	}
}

// IsTestEnvironment detects if we're running in a test environment
func IsTestEnvironment() bool {
	// Check for test-specific environment variables
	testEnvVars := []string{"GO_TEST", "F2B_TEST", "F2B_TEST_SUDO"}
	for _, envVar := range testEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	// Check command line arguments for test patterns
	for _, arg := range os.Args {
		if strings.Contains(arg, ".test") || strings.Contains(arg, "-test") {
			return true
		}
	}

	return false
}
