package fail2ban

import (
	"strings"
	"testing"
)

func TestNewClientPathTraversalProtection(t *testing.T) {
	// Enable test mode
	t.Setenv("F2B_TEST_SUDO", "true")

	// Set up mock environment
	_, cleanup := SetupMockEnvironment(t)
	defer cleanup()

	// Get the mock runner and configure additional responses
	mock := GetRunner().(*MockRunner)
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

	// Set up mock environment
	_, cleanup := SetupMockEnvironment(t)
	defer cleanup()

	// Get the mock runner and configure additional responses
	mock := GetRunner().(*MockRunner)
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

func TestArgumentValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		{
			name:        "ValidArguments",
			args:        []string{"status", "sshd"},
			expectError: false,
			description: "Valid arguments should pass",
		},
		{
			name:        "ArgumentWithNullByte",
			args:        []string{"status", "jail\x00name"},
			expectError: true,
			description: "Arguments with null bytes should be rejected",
		},
		{
			name:        "ArgumentTooLong",
			args:        []string{strings.Repeat("A", 1025)},
			expectError: true,
			description: "Very long arguments should be rejected",
		},
		{
			name:        "CommandInjectionSemicolon",
			args:        []string{"status", "jail; rm -rf /"},
			expectError: true,
			description: "Command injection with semicolon should be rejected",
		},
		{
			name:        "CommandInjectionPipe",
			args:        []string{"status", "jail | cat /etc/passwd"},
			expectError: true,
			description: "Command injection with pipe should be rejected",
		},
		{
			name:        "CommandInjectionBacktick",
			args:        []string{"status", "jail`whoami`"},
			expectError: true,
			description: "Command injection with backtick should be rejected",
		},
		{
			name:        "ValidIPArgument",
			args:        []string{"set", "sshd", "banip", "192.168.1.100"},
			expectError: false,
			description: "Valid IP in arguments should pass",
		},
		{
			name:        "InvalidIPArgument",
			args:        []string{"set", "sshd", "banip", "999.999.999.999"},
			expectError: true,
			description: "Invalid IP in arguments should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArguments(tt.args)

			if tt.expectError && err == nil {
				t.Errorf("%s: Expected error for args %v, but got none", tt.description, tt.args)
			}

			if !tt.expectError && err != nil {
				t.Errorf("%s: Expected no error for args %v, but got: %v", tt.description, tt.args, err)
			}
		})
	}
}

func TestCommandValidationEnhanced(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		expectError bool
		description string
	}{
		{
			name:        "ValidCommand",
			command:     "fail2ban-client",
			expectError: false,
			description: "Valid command should pass",
		},
		{
			name:        "CommandWithInjection",
			command:     "fail2ban-client; rm -rf /",
			expectError: true,
			description: "Command with injection should be rejected",
		},
		{
			name:        "CommandNotInAllowlist",
			command:     "rm",
			expectError: true,
			description: "Command not in allowlist should be rejected",
		},
		{
			name:        "EmptyCommand",
			command:     "",
			expectError: true,
			description: "Empty command should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)

			if tt.expectError && err == nil {
				t.Errorf("%s: Expected error for command %q, but got none", tt.description, tt.command)
			}

			if !tt.expectError && err != nil {
				t.Errorf("%s: Expected no error for command %q, but got: %v", tt.description, tt.command, err)
			}
		})
	}
}
