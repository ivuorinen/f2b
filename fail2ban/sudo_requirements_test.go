package fail2ban_test

import (
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

func TestCheckSudoRequirements(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
		expectError   bool
	}{
		{
			name:          "with privileges",
			hasPrivileges: true,
			expectError:   false,
		},
		{
			name:          "without privileges",
			hasPrivileges: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modern standardized setup with automatic cleanup
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			err := fail2ban.CheckSudoRequirements()

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
		})
	}
}

func TestSetAndGetSudoChecker(t *testing.T) {
	// Modern standardized setup with automatic cleanup
	_, cleanup := fail2bantest.SetupMockEnvironment(t)
	defer cleanup()

	// Create a custom mock checker for this specific test
	mock := &fail2bantest.MockSudoChecker{
		MockIsRoot:      true,
		MockInSudoGroup: false,
		MockCanUseSudo:  false,
	}

	// Set and verify
	fail2ban.SetSudoChecker(mock)
	retrieved := fail2ban.GetSudoChecker()

	if retrieved != mock {
		t.Error("SetSudoChecker/GetSudoChecker did not work correctly")
	}

	// Verify it works
	if !retrieved.IsRoot() {
		t.Error("expected mock checker to report IsRoot() = true")
	}
}

func TestSudoCheckingIntegration(t *testing.T) {
	// Test the integration between different sudo checking components

	tests := []struct {
		name               string
		mockIsRoot         bool
		mockInSudoGroup    bool
		mockCanUseSudo     bool
		expectPrivileges   bool
		expectRequiresPass bool
	}{
		{
			name:               "root user passes all checks",
			mockIsRoot:         true,
			mockInSudoGroup:    false,
			mockCanUseSudo:     false,
			expectPrivileges:   true,
			expectRequiresPass: true,
		},
		{
			name:               "sudo group member passes",
			mockIsRoot:         false,
			mockInSudoGroup:    true,
			mockCanUseSudo:     false,
			expectPrivileges:   true,
			expectRequiresPass: true,
		},
		{
			name:               "sudo capable user passes",
			mockIsRoot:         false,
			mockInSudoGroup:    false,
			mockCanUseSudo:     true,
			expectPrivileges:   true,
			expectRequiresPass: true,
		},
		{
			name:               "regular user fails",
			mockIsRoot:         false,
			mockInSudoGroup:    false,
			mockCanUseSudo:     false,
			expectPrivileges:   false,
			expectRequiresPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modern standardized setup with automatic cleanup
			_, cleanup := fail2bantest.SetupMockEnvironment(t)
			defer cleanup()

			// Set custom mock checker for this test
			mock := &fail2bantest.MockSudoChecker{
				MockIsRoot:      tt.mockIsRoot,
				MockInSudoGroup: tt.mockInSudoGroup,
				MockCanUseSudo:  tt.mockCanUseSudo,
			}
			fail2ban.SetSudoChecker(mock)

			// Test individual methods
			if mock.HasSudoPrivileges() != tt.expectPrivileges {
				t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), tt.expectPrivileges)
			}

			// Test CheckSudoRequirements
			err := fail2ban.CheckSudoRequirements()
			if tt.expectRequiresPass && err != nil {
				t.Errorf("CheckSudoRequirements() failed when it should pass: %v", err)
			}
			if !tt.expectRequiresPass && err == nil {
				t.Error("CheckSudoRequirements() passed when it should fail")
			}
		})
	}
}

func BenchmarkSudoChecking(b *testing.B) {
	checker := &fail2ban.RealSudoChecker{}

	b.Run("IsRoot", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			checker.IsRoot()
		}
	})

	b.Run("InSudoGroup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			checker.InSudoGroup()
		}
	})

	b.Run("HasSudoPrivileges", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			checker.HasSudoPrivileges()
		}
	})

	b.Run("MockChecker", func(b *testing.B) {
		mock := &fail2bantest.MockSudoChecker{
			MockIsRoot:      false,
			MockInSudoGroup: true,
			MockCanUseSudo:  false,
		}
		for i := 0; i < b.N; i++ {
			mock.HasSudoPrivileges()
		}
	})
}
