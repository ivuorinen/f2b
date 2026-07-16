package fail2ban

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid fail2ban-client command",
			command: "fail2ban-client",
			wantErr: false,
		},
		{
			name:    "valid fail2ban-regex command",
			command: "fail2ban-regex",
			wantErr: false,
		},
		{
			name:    "valid service command",
			command: "service",
			wantErr: false,
		},
		{
			name:    "valid systemctl command",
			command: "systemctl",
			wantErr: false,
		},
		{
			// "sudo" must NOT be allowlisted as a command: the sudo prefix is
			// only ever added internally after the inner command is validated.
			name:    "sudo command not allowed",
			command: "sudo",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "empty command",
			command: "",
			wantErr: true,
			errMsg:  "command cannot be empty",
		},
		{
			name:    "command with null byte",
			command: "fail2ban-client\x00",
			wantErr: true,
			errMsg:  "invalid command format",
		},
		{
			name:    "command with path traversal",
			command: "../../../bin/bash",
			wantErr: true,
			errMsg:  "path traversal",
		},
		{
			name:    "command not in allowlist",
			command: "rm",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "dangerous command - bash",
			command: "bash",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "dangerous command - sh",
			command: "sh",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "dangerous command - nc",
			command: "nc",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "URL encoded path traversal",
			command: "fail2ban%2e%2e%2fclient",
			wantErr: true,
			errMsg:  "path traversal",
		},
		{
			name:    "absolute path in trusted directory",
			command: "/usr/bin/fail2ban-client",
			wantErr: false,
		},
		{
			name:    "absolute path outside trusted directories",
			command: "/tmp/fail2ban-client",
			wantErr: true,
			errMsg:  "command not allowed:",
		},
		{
			name:    "unclean absolute path",
			command: "/usr/bin/../bin/fail2ban-client",
			wantErr: true,
			errMsg:  "invalid command format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateCommand() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCommand() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCommand() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestValidateCommandSecurityPatterns(t *testing.T) {
	// Test various injection attempts
	maliciousCommands := []string{
		"fail2ban-client; DANGEROUS_RM_COMMAND",
		"fail2ban-client && DANGEROUS_RM_COMMAND",
		"fail2ban-client | DANGEROUS_RM_COMMAND",
		"fail2ban-client $(DANGEROUS_RM_COMMAND)",
		"fail2ban-client `DANGEROUS_RM_COMMAND`",
		"/bin/bash",
		"/usr/bin/env bash",
		"python3 -c 'DANGEROUS_SYSTEM_CALL'",
		"perl -e 'DANGEROUS_SYSTEM_CALL'",
		"ruby -e 'DANGEROUS_SYSTEM_CALL'",
	}

	for _, cmd := range maliciousCommands {
		t.Run("malicious_"+cmd, func(t *testing.T) {
			err := ValidateCommand(cmd)
			if err == nil {
				t.Errorf("ValidateCommand() should reject malicious command: %s", cmd)
			}
		})
	}
}

func TestValidateCommandConcurrency(t *testing.T) {
	// Test concurrent access to ValidateCommand
	concurrency := 10
	iterations := 100

	errChan := make(chan error, concurrency*iterations)
	done := make(chan bool, concurrency)

	for range concurrency {
		go func() {
			defer func() { done <- true }()
			for range iterations {
				// Test with valid commands
				if err := ValidateCommand("fail2ban-client"); err != nil {
					errChan <- err
					return
				}
				// Test with invalid commands
				if err := ValidateCommand("malicious"); err == nil {
					errChan <- fmt.Errorf("ValidateCommand should have rejected malicious command")
					return
				}
			}
		}()
	}

	// Wait for all goroutines to complete
	for range concurrency {
		<-done
	}

	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			t.Errorf("Concurrent ValidateCommand() failed: %v", err)
		}
	}
}

func BenchmarkValidateCommand(b *testing.B) {
	commands := []string{
		"fail2ban-client",
		"fail2ban-regex",
		"service",
		"systemctl",
		"malicious-command",
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		cmd := commands[i%len(commands)]
		_ = ValidateCommand(cmd) // Ignore error in benchmark
	}
}
