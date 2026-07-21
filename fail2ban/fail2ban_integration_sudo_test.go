package fail2ban

import (
	"slices"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// setupMockRunnerForPrivilegedTest configures mock responses for privileged tests
func setupMockRunnerForPrivilegedTest(mockRunner *MockRunner) {
	// Use standard mock setup as the base
	StandardMockSetup(mockRunner)
}

// testClientOperations tests various client operations
func testClientOperations(t *testing.T, client Client, expectOperationErr bool) {
	t.Helper()
	testOperations := []struct {
		name string
		op   func() error
	}{
		{
			name: "ban IP",
			op: func() error {
				_, err := client.BanIP("192.168.1.100", "sshd")
				return err
			},
		},
		{
			name: "unban IP",
			op: func() error {
				_, err := client.UnbanIP("192.168.1.100", "sshd")
				return err
			},
		},
		{
			name: "check banned",
			op: func() error {
				_, err := client.BannedIn("192.168.1.100")
				return err
			},
		},
	}

	for _, testOp := range testOperations {
		t.Run(testOp.name, func(t *testing.T) {
			err := testOp.op()
			if expectOperationErr && err == nil {
				t.Errorf("expected operation %s to fail", testOp.name)
			}
			if !expectOperationErr && err != nil {
				t.Errorf("unexpected error in operation %s: %v", testOp.name, err)
			}
		})
	}
}

// TestSudoIntegrationWithClient tests the full integration of sudo checking with client operations
func TestSudoIntegrationWithClient(t *testing.T) {
	// Test normal client creation (in test environment, sudo checking is skipped)
	t.Run("normal client creation", func(t *testing.T) {
		// Modern standardized setup with automatic cleanup
		_, cleanup := SetupMockEnvironmentWithSudo(t, true)
		defer cleanup()

		// Get the mock runner and configure additional responses
		mockRunner := MustMockRunner(t)
		setupMockRunnerForPrivilegedTest(mockRunner)

		// Test client creation
		client, err := NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
		if err != nil {
			t.Fatalf("unexpected client creation error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}

		testClientOperations(t, client, false)
	})
}

func TestSudoRequirementsIntegration(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
		isRoot        bool
		expectError   bool
		description   string
	}{
		{
			name:          "root user has privileges",
			hasPrivileges: true,
			isRoot:        true,
			expectError:   false,
			description:   "root user should pass sudo requirements check",
		},
		{
			name:          "user with sudo privileges passes",
			hasPrivileges: true,
			isRoot:        false,
			expectError:   false,
			description:   "user in sudo group should pass sudo requirements check",
		},
		{
			name:          "regular user fails sudo check",
			hasPrivileges: false,
			isRoot:        false,
			expectError:   true,
			description:   "regular user should fail sudo requirements check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSudoRequirementsCase(t, tt.hasPrivileges, tt.isRoot, tt.expectError)
		})
	}
}

// assertSudoRequirementsCase runs a single TestSudoRequirementsIntegration case.
func assertSudoRequirementsCase(t *testing.T, hasPrivileges, isRoot, expectError bool) {
	t.Helper()

	// Modern standardized setup with automatic cleanup
	_, cleanup := SetupMockEnvironmentWithSudo(t, hasPrivileges)
	defer cleanup()

	// Get the mock sudo checker and configure based on test case
	mockChecker := MustMockSudoChecker(t)
	mockChecker.MockIsRoot = isRoot
	if isRoot {
		// Root user always has privileges
		mockChecker.MockHasPrivileges = true
	}

	// Test sudo requirements directly
	err := CheckSudoRequirements()

	if expectError {
		if err == nil {
			t.Fatal("expected sudo requirements check to fail")
		}
		if !strings.Contains(err.Error(), "fail2ban operations require sudo privileges") {
			t.Errorf("expected sudo privilege error, got: %v", err)
		}
		return
	}

	if err != nil {
		t.Fatalf("unexpected sudo requirements error: %v", err)
	}
}

// TestSudoCommandSelection tests that the right commands get sudo prefix
func TestSudoCommandSelection(t *testing.T) {
	tests := []struct {
		name            string
		isRoot          bool
		hasPrivileges   bool
		command         string
		args            []string
		expectedCommand string
		description     string
	}{
		{
			name:            "root user does not need sudo",
			isRoot:          true,
			hasPrivileges:   true,
			command:         "fail2ban-client",
			args:            []string{"set", "sshd", "banip", "192.168.1.100"},
			expectedCommand: "fail2ban-client set sshd banip 192.168.1.100",
			description:     "root user should run commands directly without sudo",
		},
		{
			name:            "privileged user uses sudo for sudo-required commands",
			isRoot:          false,
			hasPrivileges:   true,
			command:         "fail2ban-client",
			args:            []string{"set", "sshd", "banip", "192.168.1.100"},
			expectedCommand: "sudo fail2ban-client set sshd banip 192.168.1.100",
			description:     "non-root privileged user should use sudo for privileged commands",
		},
		{
			name:            "privileged user does not use sudo for read-only commands",
			isRoot:          false,
			hasPrivileges:   true,
			command:         "fail2ban-client",
			args:            []string{"status"},
			expectedCommand: "fail2ban-client status",
			description:     "non-root user should not use sudo for read-only commands",
		},
		{
			name:            "unprivileged user runs without sudo",
			isRoot:          false,
			hasPrivileges:   false,
			command:         "fail2ban-client",
			args:            []string{"set", "sshd", "banip", "192.168.1.100"},
			expectedCommand: "fail2ban-client set sshd banip 192.168.1.100",
			description:     "unprivileged user runs commands as-is (will likely fail)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modern standardized setup with automatic cleanup
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			// Set custom mock checker for this specific test
			mock := &MockSudoChecker{
				MockIsRoot:        tt.isRoot,
				MockInSudoGroup:   tt.hasPrivileges && !tt.isRoot,
				MockCanUseSudo:    tt.hasPrivileges && !tt.isRoot,
				MockHasPrivileges: tt.hasPrivileges,
			}
			SetSudoChecker(mock)

			// Get the mock runner and configure responses
			mockRunner := MustMockRunner(t)
			mockRunner.SetResponse(tt.expectedCommand, []byte("success"))

			// Test command selection logic using mock runner directly
			_, err := mockRunner.CombinedOutputWithSudo(tt.command, tt.args...)

			// The escalation decision is the whole point of this test: assert
			// the runner actually received the expected (possibly sudo-prefixed)
			// command, not merely log a mismatch.
			calls := mockRunner.GetCalls()
			if !slices.Contains(calls, tt.expectedCommand) {
				t.Errorf("expected command %q in runner calls, got %v", tt.expectedCommand, calls)
			}

			if err != nil {
				t.Logf("Command execution failed (expected in test): %v", err)
			}
		})
	}
}

// TestSudoErrorPropagation tests that sudo-related errors are properly propagated
func TestSudoErrorPropagation(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "insufficient privileges shows helpful error",
			hasPrivileges: false,
			expectError:   true,
			errorContains: "fail2ban operations require sudo privileges",
		},
		{
			name:          "sufficient privileges allow operation",
			hasPrivileges: true,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSudoErrorPropagationCase(t, tt.hasPrivileges, tt.expectError, tt.errorContains)
		})
	}
}

// assertSudoErrorPropagationCase runs a single TestSudoErrorPropagation case.
func assertSudoErrorPropagationCase(t *testing.T, hasPrivileges, expectError bool, errorContains string) {
	t.Helper()

	// Modern standardized setup with automatic cleanup
	_, cleanup := SetupMockEnvironmentWithSudo(t, hasPrivileges)
	defer cleanup()

	// Test CheckSudoRequirements directly
	err := CheckSudoRequirements()

	if expectError {
		if err == nil {
			t.Fatal("expected error but got none")
		}
		if errorContains != "" && !strings.Contains(err.Error(), errorContains) {
			t.Errorf("expected error to contain %q, got %q", errorContains, err.Error())
		}
	} else {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

// TestSudoWithDifferentCommands tests sudo behavior with various command types
func TestSudoWithDifferentCommands(t *testing.T) {
	// Modern standardized setup with sudo privileges (not root)
	_, cleanup := SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Set custom mock checker for this test (not root, but has sudo)
	mock := &MockSudoChecker{
		MockIsRoot:      false,
		MockInSudoGroup: true,
		MockCanUseSudo:  true,
	} // not root, but in sudo group and can sudo
	SetSudoChecker(mock)

	tests := []struct {
		name           string
		command        string
		args           []string
		expectsSudo    bool
		expectedPrefix string
	}{
		{
			name:           "fail2ban set command requires sudo",
			command:        "fail2ban-client",
			args:           []string{"set", "sshd", "banip", "1.2.3.4"},
			expectsSudo:    true,
			expectedPrefix: "sudo fail2ban-client",
		},
		{
			name:           "fail2ban status command requires sudo",
			command:        "fail2ban-client",
			args:           []string{"status"},
			expectsSudo:    true, // status queries the root-only server socket
			expectedPrefix: "sudo fail2ban-client",
		},
		{
			name:           "service command requires sudo",
			command:        "service",
			args:           []string{"fail2ban", "restart"},
			expectsSudo:    true,
			expectedPrefix: "sudo service",
		},
		{
			name:           "systemctl privileged command requires sudo",
			command:        "systemctl",
			args:           []string{"restart", "fail2ban"},
			expectsSudo:    true,
			expectedPrefix: "sudo systemctl",
		},
		{
			name:           "systemctl status does not require sudo",
			command:        "systemctl",
			args:           []string{"status", "fail2ban"},
			expectsSudo:    false,
			expectedPrefix: "systemctl",
		},
		{
			// fail2ban-server is allowlisted but has no RequiresSudo case, so
			// it exercises the default no-sudo branch (non-allowlisted
			// commands like `echo` never reach the runner at all).
			name:           "non-privileged command does not require sudo",
			command:        "fail2ban-server",
			args:           []string{"-V"},
			expectsSudo:    false,
			expectedPrefix: "fail2ban-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSudoCommandBehavior(t, tt.command, tt.args, tt.expectsSudo, tt.expectedPrefix)
		})
	}
}

// assertSudoCommandBehavior runs a single TestSudoWithDifferentCommands case.
func assertSudoCommandBehavior(t *testing.T, command string, args []string, expectsSudo bool, expectedPrefix string) {
	t.Helper()

	// Test RequiresSudo function
	requiresSudo := RequiresSudo(command, args...)
	if requiresSudo != expectsSudo {
		t.Errorf("RequiresSudo(%s, %v) = %v, want %v", command, args, requiresSudo, expectsSudo)
	}

	// Configure the mock runner with expected response
	// Note: Reusing outer mock environment to avoid nested cleanup issues
	mockRunner := MustMockRunner(t)
	expectedCall := expectedPrefix + " " + strings.Join(args, " ")
	mockRunner.SetResponse(expectedCall, []byte("mock response"))

	// Execute command using mock runner directly to avoid OSRunner
	_, err := mockRunner.CombinedOutputWithSudo(command, args...)

	// Check that the expected command was called
	calls := mockRunner.GetCalls()
	found := false
	for _, call := range calls {
		if strings.HasPrefix(call, expectedPrefix) {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected command with prefix %q, got calls: %v", expectedPrefix, calls)
	}

	if err != nil {
		t.Logf("Command execution resulted in error (may be expected): %v", err)
	}
}

// TestSudoPrivilegeEscalation tests that privilege escalation works correctly
func TestSudoPrivilegeEscalation(t *testing.T) {
	tests := []struct {
		name             string
		initialPrivs     bool
		targetCommand    string
		targetArgs       []string
		shouldEscalate   bool
		expectedBehavior string
	}{
		{
			name:             "unprivileged user cannot escalate for privileged command",
			initialPrivs:     false,
			targetCommand:    "fail2ban-client",
			targetArgs:       []string{"set", "sshd", "banip", "1.2.3.4"},
			shouldEscalate:   false,
			expectedBehavior: "run without sudo (will likely fail)",
		},
		{
			name:             "privileged user escalates for privileged command",
			initialPrivs:     true,
			targetCommand:    "fail2ban-client",
			targetArgs:       []string{"set", "sshd", "banip", "1.2.3.4"},
			shouldEscalate:   true,
			expectedBehavior: "run with sudo",
		},
		{
			name:             "privileged user escalates for status (root-only socket)",
			initialPrivs:     true,
			targetCommand:    "fail2ban-client",
			targetArgs:       []string{"status"},
			shouldEscalate:   true,
			expectedBehavior: "run with sudo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modern standardized setup with automatic cleanup
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.initialPrivs)
			defer cleanup()

			// Get the mock runner and configure responses
			mockRunner := MustMockRunner(t)

			// Set up responses for both sudo and non-sudo versions
			nonSudoCmd := tt.targetCommand + " " + strings.Join(tt.targetArgs, " ")
			sudoCmd := "sudo " + nonSudoCmd

			mockRunner.SetResponse(nonSudoCmd, []byte("non-sudo response"))
			mockRunner.SetResponse(sudoCmd, []byte("sudo response"))

			// Execute command using mock runner directly
			_, err := mockRunner.CombinedOutputWithSudo(tt.targetCommand, tt.targetArgs...)

			// Verify behavior
			calls := mockRunner.GetCalls()

			var sudoCalled bool
			if slices.Contains(calls, sudoCmd) {
				sudoCalled = true
			}

			if tt.shouldEscalate && !sudoCalled {
				t.Errorf("Expected sudo escalation, but sudo command was not called. Calls: %v", calls)
			}

			if !tt.shouldEscalate && sudoCalled {
				t.Errorf("Did not expect sudo escalation, but sudo command was called. Calls: %v", calls)
			}

			t.Logf("Test behavior: %s", tt.expectedBehavior)
			t.Logf("Actual calls: %v", calls)

			if err != nil {
				t.Logf("Command execution error (may be expected): %v", err)
			}
		})
	}
}

// TestSudoMockConsistency tests that mock behaviors are consistent
func TestSudoMockConsistency(t *testing.T) {
	tests := []struct {
		name               string
		isRoot             bool
		inSudoGroup        bool
		canUseSudo         bool
		expectedPrivileges bool
	}{
		{
			name:               "root has privileges",
			isRoot:             true,
			inSudoGroup:        false,
			canUseSudo:         false,
			expectedPrivileges: true,
		},
		{
			name:               "sudo group member has privileges",
			isRoot:             false,
			inSudoGroup:        true,
			canUseSudo:         false,
			expectedPrivileges: true,
		},
		{
			name:               "sudo capable user has privileges",
			isRoot:             false,
			inSudoGroup:        false,
			canUseSudo:         true,
			expectedPrivileges: true,
		},
		{
			name:               "regular user has no privileges",
			isRoot:             false,
			inSudoGroup:        false,
			canUseSudo:         false,
			expectedPrivileges: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSudoMockConsistencyCase(t, tt.isRoot, tt.inSudoGroup, tt.canUseSudo, tt.expectedPrivileges)
		})
	}
}

// assertSudoMockConsistencyCase runs a single TestSudoMockConsistency case.
func assertSudoMockConsistencyCase(t *testing.T, isRoot, inSudoGroup, canUseSudo, expectedPrivileges bool) {
	t.Helper()

	mock := &MockSudoChecker{
		MockIsRoot:      isRoot,
		MockInSudoGroup: inSudoGroup,
		MockCanUseSudo:  canUseSudo,
	}

	// Test individual methods
	if mock.IsRoot() != isRoot {
		t.Errorf("IsRoot() = %v, want %v", mock.IsRoot(), isRoot)
	}
	if mock.InSudoGroup() != inSudoGroup {
		t.Errorf("InSudoGroup() = %v, want %v", mock.InSudoGroup(), inSudoGroup)
	}
	if mock.CanUseSudo() != canUseSudo {
		t.Errorf("CanUseSudo() = %v, want %v", mock.CanUseSudo(), canUseSudo)
	}

	// Test combined method
	if mock.HasSudoPrivileges() != expectedPrivileges {
		t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), expectedPrivileges)
	}

	// Test that CheckSudoRequirements behaves consistently
	originalChecker := GetSudoChecker()
	SetSudoChecker(mock)

	err := CheckSudoRequirements()

	if expectedPrivileges && err != nil {
		t.Errorf("CheckSudoRequirements() failed when privileges expected: %v", err)
	}
	if !expectedPrivileges && err == nil {
		t.Error("CheckSudoRequirements() succeeded when no privileges expected")
	}

	SetSudoChecker(originalChecker)
}
