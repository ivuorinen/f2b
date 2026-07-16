package cmd

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfigureCIFriendlyLogging tests the configureCIFriendlyLogging function
func TestConfigureCIFriendlyLogging(t *testing.T) {
	tests := []struct {
		name          string
		envVars       map[string]string
		initialLevel  slog.Level
		expectedLevel slog.Level
		shouldChange  bool
	}{
		{
			name: "CI environment sets error level",
			envVars: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"F2B_LOG_LEVEL":     "",
				"F2B_VERBOSE_TESTS": "",
			},
			initialLevel:  slog.LevelInfo,
			expectedLevel: slog.LevelError,
			shouldChange:  true,
		},
		{
			name: "test environment sets error level",
			envVars: map[string]string{
				"F2B_TEST_SUDO":     "1",
				"F2B_LOG_LEVEL":     "",
				"F2B_VERBOSE_TESTS": "",
			},
			initialLevel:  slog.LevelInfo,
			expectedLevel: slog.LevelError,
			shouldChange:  true,
		},
		{
			name: "explicit log level prevents auto-config",
			envVars: map[string]string{
				"GITHUB_ACTIONS": "true",
				"F2B_LOG_LEVEL":  "debug",
			},
			initialLevel:  slog.LevelDebug,
			expectedLevel: slog.LevelDebug,
			shouldChange:  false,
		},
		{
			name: "verbose tests flag prevents auto-config",
			envVars: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"F2B_VERBOSE_TESTS": "true",
			},
			initialLevel:  slog.LevelInfo,
			expectedLevel: slog.LevelInfo,
			shouldChange:  false,
		},
		// Note: Cannot test "normal environment" case because IsTestEnvironment()
		// will always return true when running under go test
		{
			name: "CI with explicit warn level keeps warn",
			envVars: map[string]string{
				"CI":            "true",
				"F2B_LOG_LEVEL": "warn",
			},
			initialLevel:  slog.LevelWarn,
			expectedLevel: slog.LevelWarn,
			shouldChange:  false,
		},
		{
			name: "test environment with verbose flag keeps info",
			envVars: map[string]string{
				"F2B_TEST_SUDO":     "1",
				"F2B_VERBOSE_TESTS": "1",
			},
			initialLevel:  slog.LevelInfo,
			expectedLevel: slog.LevelInfo,
			shouldChange:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all environment variables first to prevent test pollution
			allKeys := []string{
				"GITHUB_ACTIONS", "CI", "TRAVIS", "CIRCLECI", "JENKINS_URL",
				"F2B_TEST_SUDO", "F2B_LOG_LEVEL", "F2B_VERBOSE_TESTS",
			}
			for _, key := range allKeys {
				t.Setenv(key, "")
			}

			// Set test-specific environment variables
			for key, value := range tt.envVars {
				if value != "" {
					t.Setenv(key, value)
				}
			}

			// Set initial log level
			Logger.SetLevel(tt.initialLevel)

			// Call the function
			configureCIFriendlyLogging()

			// Verify Logger level
			assert.Equal(t, tt.expectedLevel, Logger.GetLevel(),
				"Logger level should be %s", tt.expectedLevel)
		})
	}
}

// TestConfigureCIFriendlyLogging_Integration tests the integration behavior
func TestConfigureCIFriendlyLogging_Integration(t *testing.T) {
	// This test ensures the function works as part of the larger initialization
	t.Run("multiple calls are idempotent", func(t *testing.T) {
		// Clear environment
		t.Setenv("GITHUB_ACTIONS", "")
		t.Setenv("CI", "")
		t.Setenv("F2B_TEST_SUDO", "")
		t.Setenv("F2B_LOG_LEVEL", "")
		t.Setenv("F2B_VERBOSE_TESTS", "")

		// Set CI environment
		t.Setenv("GITHUB_ACTIONS", "true")

		// Set initial level
		Logger.SetLevel(slog.LevelInfo)

		// Call multiple times
		configureCIFriendlyLogging()
		firstLevel := Logger.GetLevel()

		configureCIFriendlyLogging()
		secondLevel := Logger.GetLevel()

		// Should be the same after multiple calls
		assert.Equal(t, firstLevel, secondLevel)
		assert.Equal(t, slog.LevelError, firstLevel)
	})

	t.Run("respects explicit environment variables", func(t *testing.T) {
		// Both CI flags set, but explicit override
		t.Setenv("GITHUB_ACTIONS", "true")
		t.Setenv("F2B_TEST_SUDO", "1")
		t.Setenv("F2B_LOG_LEVEL", "info")

		Logger.SetLevel(slog.LevelInfo)

		configureCIFriendlyLogging()

		// Should NOT change to error level due to explicit F2B_LOG_LEVEL
		assert.Equal(t, slog.LevelInfo, Logger.GetLevel())
	})
}
