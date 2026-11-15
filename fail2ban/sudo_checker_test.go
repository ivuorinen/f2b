package fail2ban

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRealSudoChecker_CanUseSudo_InTestEnvironment tests that CanUseSudo returns false in test environment
func TestRealSudoChecker_CanUseSudo_InTestEnvironment(t *testing.T) {
	// Set test environment
	t.Setenv("F2B_TEST_SUDO", "1")

	checker := &RealSudoChecker{}
	result := checker.CanUseSudo()

	// Should always return false in test environment (safety measure)
	assert.False(t, result, "CanUseSudo should return false in test environment")
}

// TestRealSudoChecker_CanUseSudo_TestEnvironmentDetection tests test environment detection
func TestRealSudoChecker_CanUseSudo_TestEnvironmentDetection(t *testing.T) {
	tests := []struct {
		name        string
		envVar      string
		envValue    string
		shouldBlock bool
	}{
		{
			name:        "F2B_TEST_SUDO set",
			envVar:      "F2B_TEST_SUDO",
			envValue:    "1",
			shouldBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envValue)

			checker := &RealSudoChecker{}
			result := checker.CanUseSudo()

			assert.False(t, result, "Should return false in test environment")
		})
	}
}
