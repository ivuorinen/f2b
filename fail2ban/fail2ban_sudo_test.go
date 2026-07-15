package fail2ban

import (
	"os"
	"testing"
)

func TestRealSudoChecker_IsRoot(t *testing.T) {
	checker := &RealSudoChecker{}

	// We can't easily test this without changing user, but we can verify it doesn't panic
	isRoot := checker.IsRoot()

	// Check that the result matches actual UID
	expectedRoot := os.Geteuid() == 0
	if isRoot != expectedRoot {
		t.Errorf("IsRoot() = %v, want %v", isRoot, expectedRoot)
	}
}

func TestRealSudoChecker_InSudoGroup(_ *testing.T) {
	checker := &RealSudoChecker{}

	// We can't easily test this without modifying groups, but we can verify it doesn't panic
	inSudoGroup := checker.InSudoGroup()

	// This is a basic smoke test - result depends on actual system configuration
	_ = inSudoGroup // Just ensure it doesn't panic
}

func TestRealSudoChecker_CanUseSudo(t *testing.T) {
	checker := &RealSudoChecker{}

	// In the test environment CanUseSudo must not shell out to real sudo and
	// deterministically returns false.
	if checker.CanUseSudo() {
		t.Error("CanUseSudo() should be false in the test environment")
	}
}

// HasSudoPrivileges is exercised via injected sub-checks in
// TestSudoCheckingIntegration / TestMockSudoChecker; a RealSudoChecker test
// that recomputes IsRoot()||InSudoGroup()||CanUseSudo() would only restate the
// implementation and pass for any consistent (even entirely broken) version.

func TestMockSudoChecker(t *testing.T) {
	tests := []struct {
		name               string
		isRoot             bool
		inSudoGroup        bool
		canUseSudo         bool
		expectedPrivileges bool
	}{
		{
			name:               "root user",
			isRoot:             true,
			inSudoGroup:        false,
			canUseSudo:         false,
			expectedPrivileges: true,
		},
		{
			name:               "sudo group member",
			isRoot:             false,
			inSudoGroup:        true,
			canUseSudo:         false,
			expectedPrivileges: true,
		},
		{
			name:               "can use sudo",
			isRoot:             false,
			inSudoGroup:        false,
			canUseSudo:         true,
			expectedPrivileges: true,
		},
		{
			name:               "no privileges",
			isRoot:             false,
			inSudoGroup:        false,
			canUseSudo:         false,
			expectedPrivileges: false,
		},
		{
			name:               "all privileges",
			isRoot:             true,
			inSudoGroup:        true,
			canUseSudo:         true,
			expectedPrivileges: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSudoChecker{
				MockIsRoot:      tt.isRoot,
				MockInSudoGroup: tt.inSudoGroup,
				MockCanUseSudo:  tt.canUseSudo,
			}

			if mock.IsRoot() != tt.isRoot {
				t.Errorf("IsRoot() = %v, want %v", mock.IsRoot(), tt.isRoot)
			}
			if mock.InSudoGroup() != tt.inSudoGroup {
				t.Errorf("InSudoGroup() = %v, want %v", mock.InSudoGroup(), tt.inSudoGroup)
			}
			if mock.CanUseSudo() != tt.canUseSudo {
				t.Errorf("CanUseSudo() = %v, want %v", mock.CanUseSudo(), tt.canUseSudo)
			}
			if mock.HasSudoPrivileges() != tt.expectedPrivileges {
				t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), tt.expectedPrivileges)
			}
		})
	}
}

func TestMockSudoCheckerWithPrivileges(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
	}{
		{
			name:          "has privileges",
			hasPrivileges: true,
		},
		{
			name:          "no privileges",
			hasPrivileges: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSudoChecker{
				MockHasPrivileges:     tt.hasPrivileges,
				ExplicitPrivilegesSet: true,
			}

			if mock.HasSudoPrivileges() != tt.hasPrivileges {
				t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), tt.hasPrivileges)
			}
		})
	}
}

func TestRequiresSudo(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		expected bool
	}{
		{
			name:     "fail2ban-client set command",
			command:  "fail2ban-client",
			args:     []string{"set", "sshd", "banip", "192.168.1.100"},
			expected: true,
		},
		{
			name:     "fail2ban-client get banip command",
			command:  "fail2ban-client",
			args:     []string{"get", "sshd", "banip"},
			expected: true,
		},
		{
			name:     "fail2ban-client get unbanip command",
			command:  "fail2ban-client",
			args:     []string{"get", "sshd", "unbanip"},
			expected: true,
		},
		{
			name:     "fail2ban-client get other command",
			command:  "fail2ban-client",
			args:     []string{"get", "sshd", "status"},
			expected: true, // all fail2ban-client subcommands need the root-only socket

		},
		{
			name:     "fail2ban-client reload command",
			command:  "fail2ban-client",
			args:     []string{"reload"},
			expected: true,
		},
		{
			name:     "fail2ban-client restart command",
			command:  "fail2ban-client",
			args:     []string{"restart"},
			expected: true,
		},
		{
			name:     "fail2ban-client start command",
			command:  "fail2ban-client",
			args:     []string{"start"},
			expected: true,
		},
		{
			name:     "fail2ban-client stop command",
			command:  "fail2ban-client",
			args:     []string{"stop"},
			expected: true,
		},
		{
			name:     "fail2ban-client status command",
			command:  "fail2ban-client",
			args:     []string{"status"},
			expected: true, // status queries the root-only server socket

		},
		{
			name:     "fail2ban-client ping command",
			command:  "fail2ban-client",
			args:     []string{"ping"},
			expected: true, // ping queries the root-only server socket

		},
		{
			name:     "service fail2ban command",
			command:  "service",
			args:     []string{"fail2ban", "start"},
			expected: true,
		},
		{
			name:     "service other command",
			command:  "service",
			args:     []string{"other", "start"},
			expected: false,
		},
		{
			name:     "systemctl start command",
			command:  "systemctl",
			args:     []string{"start", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl stop command",
			command:  "systemctl",
			args:     []string{"stop", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl restart command",
			command:  "systemctl",
			args:     []string{"restart", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl reload command",
			command:  "systemctl",
			args:     []string{"reload", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl enable command",
			command:  "systemctl",
			args:     []string{"enable", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl disable command",
			command:  "systemctl",
			args:     []string{"disable", "fail2ban"},
			expected: true,
		},
		{
			name:     "systemctl status command",
			command:  "systemctl",
			args:     []string{"status", "fail2ban"},
			expected: false,
		},
		{
			name:     "other command",
			command:  "echo",
			args:     []string{"hello"},
			expected: false,
		},
		{
			name:     "fail2ban-client with no args",
			command:  "fail2ban-client",
			args:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequiresSudo(tt.command, tt.args...)
			if result != tt.expected {
				t.Errorf("RequiresSudo(%q, %v) = %v, want %v", tt.command, tt.args, result, tt.expected)
			}
		})
	}
}

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
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			err := CheckSudoRequirements()

			AssertError(t, err, tt.expectError, tt.name)
		})
	}
}

func TestSetAndGetSudoChecker(t *testing.T) {
	// Modern standardized setup with automatic cleanup
	_, cleanup := SetupMockEnvironment(t)
	defer cleanup()

	// Create a custom mock checker for this specific test
	mock := &MockSudoChecker{
		MockIsRoot:      true,
		MockInSudoGroup: false,
		MockCanUseSudo:  false,
	}

	// Set and verify
	SetSudoChecker(mock)
	retrieved := GetSudoChecker()

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
			_, cleanup := SetupMockEnvironment(t)
			defer cleanup()

			// Set custom mock checker for this test
			mock := &MockSudoChecker{
				MockIsRoot:      tt.mockIsRoot,
				MockInSudoGroup: tt.mockInSudoGroup,
				MockCanUseSudo:  tt.mockCanUseSudo,
			}
			SetSudoChecker(mock)

			// Test individual methods
			if mock.HasSudoPrivileges() != tt.expectPrivileges {
				t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), tt.expectPrivileges)
			}

			// Test CheckSudoRequirements
			err := CheckSudoRequirements()
			if tt.expectRequiresPass && err != nil {
				t.Errorf("CheckSudoRequirements() failed when it should pass: %v", err)
			}
			if !tt.expectRequiresPass && err == nil {
				t.Error("CheckSudoRequirements() passed when it should fail")
			}
		})
	}
}

func TestMockSudoCheckerEdgeCases(t *testing.T) {
	// Test edge cases with explicit MockHasPrivileges override
	mock := &MockSudoChecker{
		MockIsRoot:            false,
		MockInSudoGroup:       false,
		MockCanUseSudo:        false,
		MockHasPrivileges:     true, // Override to true despite other fields being false
		ExplicitPrivilegesSet: true,
	}

	if !mock.HasSudoPrivileges() {
		t.Error("expected HasSudoPrivileges() to return true when MockHasPrivileges is true")
	}

	// Test the opposite
	mock2 := &MockSudoChecker{
		MockIsRoot:            true,
		MockInSudoGroup:       true,
		MockCanUseSudo:        true,
		MockHasPrivileges:     false, // Override to false despite other fields being true
		ExplicitPrivilegesSet: true,
	}

	if mock2.HasSudoPrivileges() {
		t.Error("expected HasSudoPrivileges() to return false when MockHasPrivileges is false")
	}
}

func TestRealSudoCheckerErrorHandling(t *testing.T) {
	checker := &RealSudoChecker{}

	// Test that methods don't panic even if user.Current() or other calls fail
	// We can't easily simulate these failures without complex mocking,
	// but we can at least verify the methods don't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RealSudoChecker method panicked: %v", r)
		}
	}()

	_ = checker.IsRoot()
	_ = checker.InSudoGroup()
	_ = checker.CanUseSudo()
	_ = checker.HasSudoPrivileges()
}

func BenchmarkSudoChecking(b *testing.B) {
	checker := &RealSudoChecker{}

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
		mock := &MockSudoChecker{
			MockIsRoot:      false,
			MockInSudoGroup: true,
			MockCanUseSudo:  false,
		}
		for i := 0; i < b.N; i++ {
			mock.HasSudoPrivileges()
		}
	})
}

func TestRequiresSudoEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		expected bool
	}{
		{
			name:     "empty command",
			command:  "",
			args:     []string{},
			expected: false,
		},
		{
			name:     "fail2ban-client with only one arg",
			command:  "fail2ban-client",
			args:     []string{"set"},
			expected: true,
		},
		{
			name:     "fail2ban-client get with only jail",
			command:  "fail2ban-client",
			args:     []string{"get", "sshd"},
			expected: true, // any get subcommand queries the root-only socket

		},
		{
			name:     "service with no args",
			command:  "service",
			args:     []string{},
			expected: false,
		},
		{
			name:     "systemctl with no args",
			command:  "systemctl",
			args:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequiresSudo(tt.command, tt.args...)
			if result != tt.expected {
				t.Errorf("RequiresSudo(%q, %v) = %v, want %v", tt.command, tt.args, result, tt.expected)
			}
		})
	}
}
