package fail2ban

import (
	"testing"
)

func TestSetLogger(t *testing.T) {
	// Save original logger
	originalLogger := getLogger()
	defer SetLogger(originalLogger)

	// Create a test logger
	testLogger := NewSlogLogger(SlogText)

	// Set the logger
	SetLogger(testLogger)

	// Verify it was set
	retrievedLogger := getLogger()
	if retrievedLogger == nil {
		t.Fatal("Retrieved logger is nil")
	}

	// Test that the logger is actually used
	// We can't directly compare pointers, but we can verify it's not the original
	if retrievedLogger == originalLogger {
		t.Error("Logger was not updated")
	}
}

func TestSetLogger_Concurrent(t *testing.T) {
	// Save original logger
	originalLogger := getLogger()
	defer SetLogger(originalLogger)

	// Test concurrent access to SetLogger and getLogger
	done := make(chan bool)
	for range 10 {
		go func() {
			testLogger := NewSlogLogger(SlogText)
			SetLogger(testLogger)
			_ = getLogger()
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}

	// Verify we didn't panic and logger is set
	if getLogger() == nil {
		t.Error("Logger is nil after concurrent access")
	}
}

func TestIsCI(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "GitHub Actions",
			envVars:  map[string]string{"GITHUB_ACTIONS": "true"},
			expected: true,
		},
		{
			name:     "CI environment",
			envVars:  map[string]string{"CI": "true"},
			expected: true,
		},
		{
			name:     "Travis CI",
			envVars:  map[string]string{"TRAVIS": "true"},
			expected: true,
		},
		{
			name:     "CircleCI",
			envVars:  map[string]string{"CIRCLECI": "true"},
			expected: true,
		},
		{
			name:     "Jenkins",
			envVars:  map[string]string{"JENKINS_URL": "http://jenkins"},
			expected: true,
		},
		{
			name:     "GitLab CI",
			envVars:  map[string]string{"GITLAB_CI": "true"},
			expected: true,
		},
		{
			name:     "No CI",
			envVars:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all CI environment variables first using t.Setenv
			ciVars := []string{
				"CI",
				"GITHUB_ACTIONS",
				"TRAVIS",
				"CIRCLECI",
				"JENKINS_URL",
				"BUILDKITE",
				"TF_BUILD",
				"GITLAB_CI",
			}
			for _, v := range ciVars {
				t.Setenv(v, "")
			}

			// Set test environment variables using t.Setenv
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			result := IsCI()
			if result != tt.expected {
				t.Errorf("IsCI() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsTestEnvironment(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "GO_TEST set",
			envVars:  map[string]string{"GO_TEST": "true"},
			expected: true,
		},
		{
			name:     "F2B_TEST set",
			envVars:  map[string]string{"F2B_TEST": "true"},
			expected: true,
		},
		{
			name:     "F2B_TEST_SUDO set",
			envVars:  map[string]string{"F2B_TEST_SUDO": "true"},
			expected: true,
		},
		{
			name:     "No test environment",
			envVars:  map[string]string{},
			expected: true, // Will be true because we're running in test mode (os.Args contains -test)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear test environment variables using t.Setenv
			testVars := []string{"GO_TEST", "F2B_TEST", "F2B_TEST_SUDO"}
			for _, v := range testVars {
				t.Setenv(v, "")
			}

			// Set test environment variables using t.Setenv
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			result := IsTestEnvironment()
			if result != tt.expected {
				t.Errorf("IsTestEnvironment() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfigureCITestLogging(t *testing.T) {
	// Save original logger
	originalLogger := getLogger()
	defer SetLogger(originalLogger)

	tests := []struct {
		name  string
		isCI  bool
		setup func(t *testing.T)
	}{
		{
			name: "in CI environment",
			isCI: true,
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("CI", "true")
			},
		},
		{
			name: "not in CI environment",
			isCI: false,
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("CI", "")
				t.Setenv("GITHUB_ACTIONS", "")
				t.Setenv("TRAVIS", "")
				t.Setenv("CIRCLECI", "")
				t.Setenv("JENKINS_URL", "")
				t.Setenv("BUILDKITE", "")
				t.Setenv("TF_BUILD", "")
				t.Setenv("GITLAB_CI", "")
				t.Setenv("GO_TEST", "")
				t.Setenv("F2B_TEST", "")
				t.Setenv("F2B_TEST_SUDO", "")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			// Create a new logger to test with
			testLogger := NewSlogLogger(SlogText)
			SetLogger(testLogger)

			// Call ConfigureCITestLogging
			ConfigureCITestLogging()

			// The function should not panic - that's the main test
			// We can't easily verify the log level was changed without accessing internal state
			// but we can verify the function runs without error
		})
	}
}
