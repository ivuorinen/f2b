package fail2ban

import (
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
			name:    "valid sudo command",
			command: "sudo",
			wantErr: false,
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
			errMsg:  "command contains null byte",
		},
		{
			name:    "command with path traversal",
			command: "../../../bin/bash",
			wantErr: true,
			errMsg:  "command contains path traversal patterns",
		},
		{
			name:    "command not in allowlist",
			command: "rm",
			wantErr: true,
			errMsg:  "command not in allowlist",
		},
		{
			name:    "dangerous command - bash",
			command: "bash",
			wantErr: true,
			errMsg:  "command not in allowlist",
		},
		{
			name:    "dangerous command - sh",
			command: "sh",
			wantErr: true,
			errMsg:  "command not in allowlist",
		},
		{
			name:    "dangerous command - nc",
			command: "nc",
			wantErr: true,
			errMsg:  "command not in allowlist",
		},
		{
			name:    "URL encoded path traversal",
			command: "fail2ban%2e%2e%2fclient",
			wantErr: true,
			errMsg:  "command contains path traversal patterns",
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
		"fail2ban-client; rm -rf /",
		"fail2ban-client && rm -rf /",
		"fail2ban-client | rm -rf /",
		"fail2ban-client $(rm -rf /)",
		"fail2ban-client `rm -rf /`",
		"/bin/bash",
		"/usr/bin/env bash",
		"python3 -c 'import os; os.system(\"rm -rf /\")'",
		"perl -e 'system(\"rm -rf /\")'",
		"ruby -e 'system(\"rm -rf /\")'",
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

	for i := 0; i < concurrency; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < iterations; j++ {
				// Test with valid commands
				if err := ValidateCommand("fail2ban-client"); err != nil {
					errChan <- err
					return
				}
				// Test with invalid commands
				if err := ValidateCommand("malicious"); err == nil {
					errChan <- err
					return
				}
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
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
	for i := 0; i < b.N; i++ {
		cmd := commands[i%len(commands)]
		_ = ValidateCommand(cmd) // Ignore error in benchmark
	}
}
