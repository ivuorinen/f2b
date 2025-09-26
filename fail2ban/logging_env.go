// Package fail2ban provides logging and environment detection utilities.
// This module handles logger configuration, CI detection, and test environment setup
// for the fail2ban integration system.
package fail2ban

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// logger holds the current logger instance - will be set by cmd package
var logger LoggerInterface = logrus.StandardLogger()

// SetLogger allows the cmd package to set the logger instance
func SetLogger(l LoggerInterface) {
	logger = l
}

// getLogger returns the current logger instance
func getLogger() LoggerInterface {
	return logger
}

func init() {
	// Configure logging for CI/test environments to reduce noise
	configureCITestLogging()
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

// configureCITestLogging reduces log verbosity in CI and test environments
func configureCITestLogging() {
	if IsCI() || IsTestEnvironment() {
		if stdLogger, ok := logger.(*logrus.Logger); ok {
			stdLogger.SetLevel(logrus.WarnLevel)
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
