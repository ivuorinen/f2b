// Package fail2ban provides logging and environment detection utilities.
// This module handles logger configuration, CI detection, and test environment setup
// for the fail2ban integration system.
package fail2ban

import (
	"flag"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
)

// loggerBox wraps a LoggerInterface so atomic.Value always stores the same
// concrete type. Storing bare LoggerInterface values panics with "store of
// inconsistently typed value" when the concrete type differs from the first
// store (e.g. a custom logger after the default *logrusAdapter).
type loggerBox struct{ l LoggerInterface }

// logger holds the current logger instance in a thread-safe manner
var logger atomic.Value

func init() {
	// Initialize with default logger
	logger.Store(loggerBox{NewSlogLogger(SlogText)})
}

// SetLogger allows the cmd package to set the logger instance (thread-safe)
func SetLogger(l LoggerInterface) {
	if l == nil {
		return
	}
	logger.Store(loggerBox{l})
}

// getLogger returns the current logger instance (thread-safe)
func getLogger() LoggerInterface {
	box, ok := logger.Load().(loggerBox)
	if !ok || box.l == nil {
		// Fallback to default logger if type assertion fails
		return NewSlogLogger(SlogText)
	}
	return box.l
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
		if l, ok := currentLogger.(interface{ SetLevel(slog.Level) }); ok {
			l.SetLevel(slog.LevelWarn)
		} else {
			// Log when we can't adjust level (observable for debugging)
			currentLogger.Debug(
				"Non-standard logger in use; CI/test log level adjustment skipped",
			)
		}
	}
}

// IsTestEnvironment detects if we're running in a test environment.
//
// It must NOT match on os.Args content: the previous substring scan for
// "-test"/".test" flipped security-relevant behavior (skipping sudo checks)
// whenever any argument happened to contain that substring, e.g. a jail named
// "sshd-test". Detection relies on the -test.v flag that the testing package
// registers when running under `go test` — this is present regardless of the
// test binary's name, so it also closes the renamed-binary bypass.
func IsTestEnvironment() bool {
	// Explicit opt-in via environment variables.
	testEnvVars := []string{"GO_TEST", "F2B_TEST", "F2B_TEST_SUDO"}
	for _, envVar := range testEnvVars {
		if os.Getenv(envVar) != "" {
			if flag.Lookup("test.v") == nil {
				// Outside `go test` these vars silently disable real sudo
				// probing, which later surfaces as confusing "service not
				// running" errors — say so once, loudly.
				warnTestEnvOutsideGoTest.Do(func() {
					getLogger().WithField("variable", envVar).
						Warn("Test-environment variable set outside `go test`; real sudo checks are disabled")
				})
			}
			return true
		}
	}

	// Precise Go-test-binary detection.
	return flag.Lookup("test.v") != nil
}

// IsGoTestBinary reports whether this process is a `go test` binary, using only
// the -test.v flag the testing package registers.
//
// Deliberately narrower than IsTestEnvironment, which also honors the
// GO_TEST/F2B_TEST/F2B_TEST_SUDO opt-in. Those variables are settable in any
// shell, so they must never gate anything that weakens command resolution:
// leaving fail2ban-client as a bare name defers the lookup to exec's own PATH
// search, which skips the trusted-directory pinning resolveCommandName applies
// to absolute paths — the pinning that stops a hostile PATH from steering a
// sudo-executed binary. Skipping sudo probing tolerates the env-var opt-in;
// path resolution does not.
func IsGoTestBinary() bool {
	return flag.Lookup("test.v") != nil
}

// warnTestEnvOutsideGoTest rate-limits the production-shell warning above to
// one occurrence per process.
var warnTestEnvOutsideGoTest sync.Once
