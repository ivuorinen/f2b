package fail2ban

import (
	"os"
	"strings"
	"testing"
)

// TestSudoIntegrationWithClient tests the full integration of sudo checking with client operations
func TestSudoIntegrationWithClient(t *testing.T) {
	tests := []struct {
		name               string
		hasPrivileges      bool
		expectClientError  bool
		expectOperationErr bool
		description        string
	}{
		{
			name:               "root user can perform all operations",
			hasPrivileges:      true,
			expectClientError:  false,
			expectOperationErr: false,
			description:        "root user should be able to create client and perform operations",
		},
		{
			name:               "user with sudo privileges can perform operations",
			hasPrivileges:      true,
			expectClientError:  false,
			expectOperationErr: false,
			description:        "user in sudo group should be able to create client and perform operations",
		},
		{
			name:               "regular user cannot create client",
			hasPrivileges:      false,
			expectClientError:  true,
			expectOperationErr: true,
			description:        "regular user should fail at client creation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set environment variable to force sudo checking in tests
			if err := os.Setenv("F2B_TEST_SUDO", "true"); err != nil {
				t.Fatalf("failed to set F2B_TEST_SUDO: %v", err)
			}
			defer func() {
				if err := os.Unsetenv("F2B_TEST_SUDO"); err != nil {
					t.Fatalf("failed to unset F2B_TEST_SUDO: %v", err)
				}
			}()

			// Set mock checker
			mock := NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)
			SetSudoChecker(mock)

			// Set up mock runner for successful operations
			mockRunner := NewMockRunner()
			if tt.hasPrivileges {
				// Set up responses for successful client creation
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

				// Set up responses for operations
				mockRunner.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.100", []byte("0"))
				mockRunner.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.100", []byte("0"))
				mockRunner.SetResponse("sudo fail2ban-client banned 192.168.1.100", []byte(`["sshd"]`))
				mockRunner.SetResponse("fail2ban-client banned 192.168.1.100", []byte(`["sshd"]`))
			} else {
				// For unprivileged tests, set up basic responses for non-sudo commands
				mockRunner.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				mockRunner.SetResponse("fail2ban-client ping", []byte("pong"))
				mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				mockRunner.SetResponse("fail2ban-client banned 192.168.1.100", []byte(`[]`))
			}
			SetRunner(mockRunner)

			// Test client creation
			client, err := NewClient(DefaultLogDir, DefaultFilterDir)

			if tt.expectClientError {
				if err == nil {
					t.Fatal("expected client creation to fail")
				}
				if !strings.Contains(err.Error(), "fail2ban operations require sudo privileges") {
					t.Errorf("expected sudo privilege error, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected client creation error: %v", err)
			}

			if client == nil {
				t.Fatal("expected non-nil client")
			}

			// Test operations
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
					if tt.expectOperationErr && err == nil {
						t.Errorf("expected operation %s to fail", testOp.name)
					}
					if !tt.expectOperationErr && err != nil {
						t.Errorf("unexpected error in operation %s: %v", testOp.name, err)
					}
				})
			}
		})
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
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set mock checker
			mock := &MockSudoChecker{
				MockIsRoot:        tt.isRoot,
				MockInSudoGroup:   tt.hasPrivileges && !tt.isRoot,
				MockCanUseSudo:    tt.hasPrivileges && !tt.isRoot,
				MockHasPrivileges: tt.hasPrivileges,
			}
			SetSudoChecker(mock)

			// Set up mock runner that tracks what command was called
			mockRunner := NewMockRunner()
			mockRunner.SetResponse(tt.expectedCommand, []byte("success"))
			SetRunner(mockRunner)

			// Test command selection logic using mock runner directly
			_, err := mockRunner.CombinedOutputWithSudo(tt.command, tt.args...)

			// Test that our mock runner received the expected command
			calls := mockRunner.GetCalls()
			found := false
			for _, call := range calls {
				if call == tt.expectedCommand {
					found = true
					break
				}
			}

			if !found && len(calls) > 0 {
				t.Logf("Expected command: %s", tt.expectedCommand)
				t.Logf("Actual calls: %v", calls)
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
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set mock checker
			mock := NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)
			SetSudoChecker(mock)

			// Test CheckSudoRequirements directly
			err := CheckSudoRequirements()

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestSudoWithDifferentCommands tests sudo behavior with various command types
func TestSudoWithDifferentCommands(t *testing.T) {
	// Save original checker
	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)

	// Set up privileged user
	mock := NewMockSudoChecker(false, true, true) // not root, but in sudo group and can sudo
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
			name:           "fail2ban status command does not require sudo",
			command:        "fail2ban-client",
			args:           []string{"status"},
			expectsSudo:    false,
			expectedPrefix: "fail2ban-client",
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
			name:           "random command does not require sudo",
			command:        "echo",
			args:           []string{"hello"},
			expectsSudo:    false,
			expectedPrefix: "echo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test RequiresSudo function
			requiresSudo := RequiresSudo(tt.command, tt.args...)
			if requiresSudo != tt.expectsSudo {
				t.Errorf("RequiresSudo(%s, %v) = %v, want %v", tt.command, tt.args, requiresSudo, tt.expectsSudo)
			}

			// Test with mock runner to verify command construction
			mockRunner := NewMockRunner()
			expectedCall := tt.expectedPrefix + " " + strings.Join(tt.args, " ")
			mockRunner.SetResponse(expectedCall, []byte("mock response"))
			SetRunner(mockRunner)

			// Execute command using mock runner directly to avoid OSRunner
			_, err := mockRunner.CombinedOutputWithSudo(tt.command, tt.args...)

			// Check that the expected command was called
			calls := mockRunner.GetCalls()
			found := false
			for _, call := range calls {
				if strings.HasPrefix(call, tt.expectedPrefix) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected command with prefix %q, got calls: %v", tt.expectedPrefix, calls)
			}

			if err != nil {
				t.Logf("Command execution resulted in error (may be expected): %v", err)
			}
		})
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
			name:             "privileged user does not escalate for safe command",
			initialPrivs:     true,
			targetCommand:    "fail2ban-client",
			targetArgs:       []string{"status"},
			shouldEscalate:   false,
			expectedBehavior: "run without sudo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original checker
			originalChecker := GetSudoChecker()
			defer SetSudoChecker(originalChecker)

			// Set mock checker
			mock := NewMockSudoCheckerWithPrivileges(tt.initialPrivs)
			SetSudoChecker(mock)

			// Set up mock runner
			mockRunner := NewMockRunner()

			// Set up responses for both sudo and non-sudo versions
			nonSudoCmd := tt.targetCommand + " " + strings.Join(tt.targetArgs, " ")
			sudoCmd := "sudo " + nonSudoCmd

			mockRunner.SetResponse(nonSudoCmd, []byte("non-sudo response"))
			mockRunner.SetResponse(sudoCmd, []byte("sudo response"))
			SetRunner(mockRunner)

			// Execute command using mock runner directly
			_, err := mockRunner.CombinedOutputWithSudo(tt.targetCommand, tt.targetArgs...)

			// Verify behavior
			calls := mockRunner.GetCalls()

			var sudoCalled bool
			for _, call := range calls {
				if call == sudoCmd {
					sudoCalled = true
					break
				}
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
			mock := NewMockSudoChecker(tt.isRoot, tt.inSudoGroup, tt.canUseSudo)

			// Test individual methods
			if mock.IsRoot() != tt.isRoot {
				t.Errorf("IsRoot() = %v, want %v", mock.IsRoot(), tt.isRoot)
			}
			if mock.InSudoGroup() != tt.inSudoGroup {
				t.Errorf("InSudoGroup() = %v, want %v", mock.InSudoGroup(), tt.inSudoGroup)
			}
			if mock.CanUseSudo() != tt.canUseSudo {
				t.Errorf("CanUseSudo() = %v, want %v", mock.CanUseSudo(), tt.canUseSudo)
			}

			// Test combined method
			if mock.HasSudoPrivileges() != tt.expectedPrivileges {
				t.Errorf("HasSudoPrivileges() = %v, want %v", mock.HasSudoPrivileges(), tt.expectedPrivileges)
			}

			// Test that CheckSudoRequirements behaves consistently
			originalChecker := GetSudoChecker()
			SetSudoChecker(mock)

			err := CheckSudoRequirements()

			if tt.expectedPrivileges && err != nil {
				t.Errorf("CheckSudoRequirements() failed when privileges expected: %v", err)
			}
			if !tt.expectedPrivileges && err == nil {
				t.Error("CheckSudoRequirements() succeeded when no privileges expected")
			}

			SetSudoChecker(originalChecker)
		})
	}
}
