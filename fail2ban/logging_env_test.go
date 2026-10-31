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
			expected: true, // true: the go test binary registers -test.v (false case: TestDetectTestEnvironment)
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

// TestDetectTestEnvironment drives the detection with injected inputs so the
// production case is constructible: inside `go test` the -test.v flag is
// always registered, which made IsTestEnvironment true in every case and let
// a constant-true implementation pass.
func TestDetectTestEnvironment(t *testing.T) {
	envOf := func(vars map[string]string) func(string) string {
		return func(key string) string { return vars[key] }
	}
	tests := []struct {
		name         string
		env          map[string]string
		goTestBinary bool
		want         bool
	}{
		{name: "production: no env, not a test binary", env: nil, goTestBinary: false, want: false},
		{name: "unrelated env only", env: map[string]string{"CI": "true"}, goTestBinary: false, want: false},
		{name: "go test binary", env: nil, goTestBinary: true, want: true},
		{name: "GO_TEST opt-in", env: map[string]string{"GO_TEST": "1"}, goTestBinary: false, want: true},
		{name: "F2B_TEST opt-in", env: map[string]string{"F2B_TEST": "1"}, goTestBinary: false, want: true},
		{name: "F2B_TEST_SUDO opt-in", env: map[string]string{"F2B_TEST_SUDO": "1"}, goTestBinary: false, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectTestEnvironment(envOf(tt.env), tt.goTestBinary); got != tt.want {
				t.Errorf("detectTestEnvironment() = %v, want %v", got, tt.want)
			}
		})
	}
}
