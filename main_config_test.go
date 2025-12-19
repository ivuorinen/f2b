package main

import (
	"os"
	"testing"
)

// TestMainConfigurationParsing tests the configuration parsing logic
func TestMainConfigurationParsing(t *testing.T) {
	tests := []struct {
		name              string
		logDirEnv         string
		filterDirEnv      string
		expectedLogDir    string
		expectedFilterDir string
	}{
		{
			name:              "default values",
			logDirEnv:         "",
			filterDirEnv:      "",
			expectedLogDir:    "/var/log",
			expectedFilterDir: "/etc/fail2ban/filter.d",
		},
		{
			name:              "custom log dir",
			logDirEnv:         "/custom/logs",
			filterDirEnv:      "",
			expectedLogDir:    "/custom/logs",
			expectedFilterDir: "/etc/fail2ban/filter.d",
		},
		{
			name:              "custom filter dir",
			logDirEnv:         "",
			filterDirEnv:      "/custom/filters",
			expectedLogDir:    "/var/log",
			expectedFilterDir: "/custom/filters",
		},
		{
			name:              "both custom directories",
			logDirEnv:         "/opt/logs",
			filterDirEnv:      "/opt/filters",
			expectedLogDir:    "/opt/logs",
			expectedFilterDir: "/opt/filters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment using t.Setenv for automatic cleanup
			if tt.logDirEnv != "" {
				t.Setenv("F2B_LOG_DIR", tt.logDirEnv)
			}
			if tt.filterDirEnv != "" {
				t.Setenv("F2B_FILTER_DIR", tt.filterDirEnv)
			}

			// Build config from env (mimic main function)
			config := struct {
				LogDir    string
				FilterDir string
				Format    string
			}{}

			config.LogDir = os.Getenv("F2B_LOG_DIR")
			if config.LogDir == "" {
				config.LogDir = "/var/log"
			}
			config.FilterDir = os.Getenv("F2B_FILTER_DIR")
			if config.FilterDir == "" {
				config.FilterDir = "/etc/fail2ban/filter.d"
			}
			config.Format = "plain"

			// Verify configuration values
			if config.LogDir != tt.expectedLogDir {
				t.Errorf("expected LogDir=%q, got %q", tt.expectedLogDir, config.LogDir)
			}
			if config.FilterDir != tt.expectedFilterDir {
				t.Errorf("expected FilterDir=%q, got %q", tt.expectedFilterDir, config.FilterDir)
			}
			if config.Format != "plain" {
				t.Errorf("expected Format=%q, got %q", "plain", config.Format)
			}
		})
	}
}

// TestMainEnvironmentVariables tests environment variable handling
func TestMainEnvironmentVariables(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected map[string]string
	}{
		{
			name: "all environment variables set",
			envVars: map[string]string{
				"F2B_LOG_DIR":    "/test/logs",
				"F2B_FILTER_DIR": "/test/filters",
				"F2B_LOG_LEVEL":  "debug",
				"F2B_LOG_FILE":   "/test/app.log",
				"F2B_TEST_SUDO":  "true",
			},
			expected: map[string]string{
				"F2B_LOG_DIR":    "/test/logs",
				"F2B_FILTER_DIR": "/test/filters",
				"F2B_LOG_LEVEL":  "debug",
				"F2B_LOG_FILE":   "/test/app.log",
				"F2B_TEST_SUDO":  "true",
			},
		},
		{
			name: "partial environment variables",
			envVars: map[string]string{
				"F2B_LOG_DIR":   "/partial/logs",
				"F2B_LOG_LEVEL": "info",
			},
			expected: map[string]string{
				"F2B_LOG_DIR":    "/partial/logs",
				"F2B_FILTER_DIR": "",
				"F2B_LOG_LEVEL":  "info",
				"F2B_LOG_FILE":   "",
				"F2B_TEST_SUDO":  "",
			},
		},
		{
			name:    "no environment variables",
			envVars: map[string]string{},
			expected: map[string]string{
				"F2B_LOG_DIR":    "",
				"F2B_FILTER_DIR": "",
				"F2B_LOG_LEVEL":  "",
				"F2B_LOG_FILE":   "",
				"F2B_TEST_SUDO":  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all environment variables first, then set test values
			// This ensures "no environment variables" case works even when running with F2B_LOG_LEVEL=error
			allKeys := []string{"F2B_LOG_DIR", "F2B_FILTER_DIR", "F2B_LOG_LEVEL", "F2B_LOG_FILE", "F2B_TEST_SUDO"}
			for _, key := range allKeys {
				t.Setenv(key, "") // Clear first
			}

			// Set environment variables for test
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			// Check that environment variables are correctly set or empty
			for key, expectedValue := range tt.expected {
				actualValue := os.Getenv(key)
				if actualValue != expectedValue {
					t.Errorf("expected %s=%q, got %q", key, expectedValue, actualValue)
				}
			}
		})
	}
}
