// CLI configuration parsing and validation.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// validateConfigPath validates a configured log or filter directory with the
// same fail2ban path policy the client applies at construction. cmd used to
// keep its own traversal detectors and a strings.HasPrefix allowlist check
// with no separator boundary, so /var/logx passed here and failed later in
// the client; one policy owner keeps the two from disagreeing.
func validateConfigPath(path, pathType string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path cannot be empty", pathType)
	}
	var validate func(string) (string, error)
	switch pathType {
	case constants.PathTypeLog:
		validate = fail2ban.ValidateClientLogPath
	case constants.PathTypeFilter:
		validate = fail2ban.ValidateClientFilterPath
	default:
		return "", fmt.Errorf("unknown path type %q", pathType)
	}
	validated, err := validate(path)
	if err != nil {
		return "", fmt.Errorf("invalid %s path %s: %w", pathType, path, err)
	}
	return validated, nil
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
