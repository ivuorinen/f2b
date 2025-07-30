package fail2ban

import (
	"strings"
	"testing"
)

func TestNewClientPathTraversalProtection(t *testing.T) {
	// Enable test mode
	t.Setenv("F2B_TEST_SUDO", "true")

	// Mock sudo privileges
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	// Mock runner for version check
	mock := NewMockRunner()
	SetRunner(mock)
	mock.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail:      1\n`- Jail list:   sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail:      1\n`- Jail list:   sshd"))

	tests := []struct {
		name          string
		logDir        string
		filterDir     string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid paths",
			logDir:      "/var/log",
			filterDir:   "/etc/fail2ban/filter.d",
			expectError: false,
		},
		{
			name:          "path traversal in logDir",
			logDir:        "/var/log/../../../etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "path traversal in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/../../../etc/passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "URL encoded path traversal in logDir",
			logDir:        "/var/log/%2e%2e/%2e%2e/etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "null byte in logDir",
			logDir:        "/var/log\x00/malicious",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "null byte in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/filter.d\x00/malicious",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "non-allowed base path for logDir",
			logDir:        "/etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "non-allowed base path for filterDir",
			logDir:        "/var/log",
			filterDir:     "/var/log/filter.d", // filter dir should be in /etc/fail2ban
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:        "allowed alternative paths",
			logDir:      "/opt/myapp/logs",
			filterDir:   "/opt/fail2ban/filters",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.logDir, tt.filterDir)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNewClientDefaultPathValidation(t *testing.T) {
	// Enable test mode
	t.Setenv("F2B_TEST_SUDO", "true")

	// Mock sudo privileges
	mockChecker := NewMockSudoCheckerWithPrivileges(true)
	SetSudoChecker(mockChecker)

	// Mock runner for version check
	mock := NewMockRunner()
	SetRunner(mock)
	mock.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail:      1\n`- Jail list:   sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail:      1\n`- Jail list:   sshd"))

	// Test with empty paths (should use defaults and validate them)
	client, err := NewClient("", "")
	if err != nil {
		t.Fatalf("unexpected error with default paths: %v", err)
	}

	// Verify defaults were applied
	if client.LogDir != DefaultLogDir {
		t.Errorf("expected LogDir to be %s, got %s", DefaultLogDir, client.LogDir)
	}

	if client.FilterDir != DefaultFilterDir {
		t.Errorf("expected FilterDir to be %s, got %s", DefaultFilterDir, client.FilterDir)
	}
}
