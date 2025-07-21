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

func TestRealSudoChecker_CanUseSudo(_ *testing.T) {
	checker := &RealSudoChecker{}

	// We can't easily test this without sudo configuration, but we can verify it doesn't panic
	canUseSudo := checker.CanUseSudo()

	// This is a basic smoke test - result depends on actual system configuration
	_ = canUseSudo // Just ensure it doesn't panic
}

func TestRealSudoChecker_HasSudoPrivileges(t *testing.T) {
	checker := &RealSudoChecker{}

	hasPrivileges := checker.HasSudoPrivileges()

	// Should be true if any of the individual checks are true
	expectedHasPrivileges := checker.IsRoot() || checker.InSudoGroup() || checker.CanUseSudo()
	if hasPrivileges != expectedHasPrivileges {
		t.Errorf("HasSudoPrivileges() = %v, want %v", hasPrivileges, expectedHasPrivileges)
	}
}

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
			mock := NewMockSudoChecker(tt.isRoot, tt.inSudoGroup, tt.canUseSudo)

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
			mock := NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)

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
			expected: false,
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
			expected: false,
		},
		{
			name:     "fail2ban-client ping command",
			command:  "fail2ban-client",
			args:     []string{"ping"},
			expected: false,
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
			// Set up mock environment with specified privileges
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			err := CheckSudoRequirements()

			AssertError(t, err, tt.expectError, tt.name)
		})
	}
}

func TestSetAndGetSudoChecker(t *testing.T) {
	// Save original checker
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)

	// Create a mock checker
	mock := NewMockSudoChecker(true, false, false)

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

func TestGetCurrentUserInfo(t *testing.T) {
	info := GetCurrentUserInfo()

	// Check that basic fields exist
	requiredFields := []string{
		"uid",
		"gid",
		"euid",
		"egid",
		"is_root",
		"in_sudo_group",
		"can_use_sudo",
		"has_sudo_privileges",
	}
	for _, field := range requiredFields {
		if _, exists := info[field]; !exists {
			t.Errorf("expected field %s to exist in user info", field)
		}
	}

	// Check that UID fields are integers
	if uid, ok := info["uid"].(int); !ok || uid < 0 {
		t.Errorf("expected uid to be a non-negative integer, got %v", info["uid"])
	}

	// Check that boolean fields are actually boolean
	boolFields := []string{"is_root", "in_sudo_group", "can_use_sudo", "has_sudo_privileges"}
	for _, field := range boolFields {
		if _, ok := info[field].(bool); !ok {
			t.Errorf("expected field %s to be boolean, got %T", field, info[field])
		}
	}
}

func TestGetCurrentUserInfoWithMockChecker(t *testing.T) {
	// Save original checker
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)

	// Set mock checker with known values
	mock := NewMockSudoChecker(true, true, true)
	SetSudoChecker(mock)

	info := GetCurrentUserInfo()

	// Verify mock values are reflected
	if info["is_root"] != true {
		t.Errorf("expected is_root to be true, got %v", info["is_root"])
	}
	if info["in_sudo_group"] != true {
		t.Errorf("expected in_sudo_group to be true, got %v", info["in_sudo_group"])
	}
	if info["can_use_sudo"] != true {
		t.Errorf("expected can_use_sudo to be true, got %v", info["can_use_sudo"])
	}
	if info["has_sudo_privileges"] != true {
		t.Errorf("expected has_sudo_privileges to be true, got %v", info["has_sudo_privileges"])
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
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set mock checker
			mock := NewMockSudoChecker(tt.mockIsRoot, tt.mockInSudoGroup, tt.mockCanUseSudo)
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

			// Test GetCurrentUserInfo reflects the mock
			info := GetCurrentUserInfo()
			if info["has_sudo_privileges"] != tt.expectPrivileges {
				t.Errorf("GetCurrentUserInfo()['has_sudo_privileges'] = %v, want %v",
					info["has_sudo_privileges"], tt.expectPrivileges)
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
		mock := NewMockSudoChecker(false, true, false)
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
			expected: false,
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
