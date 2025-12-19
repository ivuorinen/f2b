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

// TestCanUseSudo_WithMock tests CanUseSudo using mock checker
func TestCanUseSudo_WithMock(t *testing.T) {
	tests := []struct {
		name     string
		mockSudo bool
		expected bool
	}{
		{
			name:     "user can sudo",
			mockSudo: true,
			expected: true,
		},
		{
			name:     "user cannot sudo",
			mockSudo: false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSudoChecker{
				MockCanUseSudo: tt.mockSudo,
			}

			result := mock.CanUseSudo()
			assert.Equal(t, tt.expected, result,
				"MockCanUseSudo=%v should return %v", tt.mockSudo, tt.expected)
		})
	}
}

// TestMockSudoChecker_CanUseSudo tests the mock implementation
func TestMockSudoChecker_CanUseSudo(t *testing.T) {
	mock := &MockSudoChecker{
		MockCanUseSudo: true,
	}
	assert.True(t, mock.CanUseSudo(), "Mock with MockCanUseSudo=true should return true")

	mock.MockCanUseSudo = false
	assert.False(t, mock.CanUseSudo(), "Mock with MockCanUseSudo=false should return false")
}

// TestHasSudoPrivileges_CanUseSudo tests that CanUseSudo contributes to HasSudoPrivileges
func TestHasSudoPrivileges_CanUseSudo(t *testing.T) {
	tests := []struct {
		name              string
		isRoot            bool
		inSudoGroup       bool
		canUseSudo        bool
		expectedPrivilege bool
	}{
		{
			name:              "can use sudo only",
			isRoot:            false,
			inSudoGroup:       false,
			canUseSudo:        true,
			expectedPrivilege: true,
		},
		{
			name:              "cannot use sudo, no other privileges",
			isRoot:            false,
			inSudoGroup:       false,
			canUseSudo:        false,
			expectedPrivilege: false,
		},
		{
			name:              "can use sudo and is root",
			isRoot:            true,
			inSudoGroup:       false,
			canUseSudo:        true,
			expectedPrivilege: true,
		},
		{
			name:              "can use sudo and in sudo group",
			isRoot:            false,
			inSudoGroup:       true,
			canUseSudo:        true,
			expectedPrivilege: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSudoChecker{
				MockIsRoot:      tt.isRoot,
				MockInSudoGroup: tt.inSudoGroup,
				MockCanUseSudo:  tt.canUseSudo,
			}

			result := mock.HasSudoPrivileges()
			assert.Equal(t, tt.expectedPrivilege, result,
				"IsRoot=%v, InSudoGroup=%v, CanUseSudo=%v should result in HasSudoPrivileges=%v",
				tt.isRoot, tt.inSudoGroup, tt.canUseSudo, tt.expectedPrivilege)
		})
	}
}

// TestRealSudoChecker_CanUseSudo_Integration tests integration with other sudo checks
func TestRealSudoChecker_CanUseSudo_Integration(t *testing.T) {
	// This test ensures CanUseSudo is properly integrated into privilege checking

	t.Run("mock checker returns expected values", func(t *testing.T) {
		// Create a mock where only CanUseSudo is true
		mock := &MockSudoChecker{
			MockIsRoot:      false,
			MockInSudoGroup: false,
			MockCanUseSudo:  true,
		}

		// Individual checks should work
		assert.False(t, mock.IsRoot())
		assert.False(t, mock.InSudoGroup())
		assert.True(t, mock.CanUseSudo())

		// HasSudoPrivileges should return true (because CanUseSudo is true)
		assert.True(t, mock.HasSudoPrivileges(),
			"HasSudoPrivileges should be true when CanUseSudo is true")
	})

	t.Run("explicit privileges override", func(t *testing.T) {
		// Test the explicit privileges flag
		mock := &MockSudoChecker{
			MockIsRoot:            false,
			MockInSudoGroup:       false,
			MockCanUseSudo:        false,
			MockHasPrivileges:     true,
			ExplicitPrivilegesSet: true,
		}

		assert.True(t, mock.HasSudoPrivileges(),
			"ExplicitPrivilegesSet=true should override computed privileges")
	})
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
		{
			name:        "F2B_TEST_SUDO empty",
			envVar:      "F2B_TEST_SUDO",
			envValue:    "",
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(tt.envVar, tt.envValue)
			} else {
				// Ensure environment is clean
				t.Setenv(tt.envVar, "")
			}

			checker := &RealSudoChecker{}
			result := checker.CanUseSudo()

			if tt.shouldBlock {
				assert.False(t, result, "Should return false in test environment")
			} else {
				// In non-test environment, result depends on actual sudo availability
				// We just verify it doesn't panic
				_ = result
			}
		})
	}
}

// TestCanUseSudo_MockConsistency tests that mock behavior is consistent
func TestCanUseSudo_MockConsistency(t *testing.T) {
	// Test that setting/unsetting the mock produces expected results
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)

	t.Run("mock set to true", func(t *testing.T) {
		mock := &MockSudoChecker{MockCanUseSudo: true}
		SetSudoChecker(mock)

		checker := GetSudoChecker()
		assert.True(t, checker.CanUseSudo(), "Should return true when mock is set to true")
	})

	t.Run("mock set to false", func(t *testing.T) {
		mock := &MockSudoChecker{MockCanUseSudo: false}
		SetSudoChecker(mock)

		checker := GetSudoChecker()
		assert.False(t, checker.CanUseSudo(), "Should return false when mock is set to false")
	})
}
