package fail2ban

import (
	"strings"
	"testing"
)

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
			args:        []string{"status", "jail; DANGEROUS_RM_COMMAND"},
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
			command:     "fail2ban-client; DANGEROUS_RM_COMMAND",
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
