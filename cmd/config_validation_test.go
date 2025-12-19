package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ivuorinen/f2b/shared"
)

// TestValidateConfig tests the ValidateConfig method
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty log directory",
			config: &Config{
				LogDir:          "",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: true,
			errorMsg:    "log directory cannot be empty",
		},
		{
			name: "empty filter directory",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: true,
			errorMsg:    "filter directory cannot be empty",
		},
		{
			name: "invalid format",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          "invalid",
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: true,
			errorMsg:    "invalid format",
		},
		{
			name: "negative command timeout",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  -1 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: true,
			errorMsg:    "command timeout must be positive",
		},
		{
			name: "command timeout too large",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  shared.MaxCommandTimeout + time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: shared.MaxCommandTimeout + time.Second + 1,
			},
			expectError: true,
			errorMsg:    "command timeout too large",
		},
		{
			name: "negative file timeout",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     -1 * time.Second,
				ParallelTimeout: 10 * time.Second,
			},
			expectError: true,
			errorMsg:    "file timeout must be positive",
		},
		{
			name: "file timeout too large",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     shared.MaxFileTimeout + time.Second,
				ParallelTimeout: shared.MaxFileTimeout + time.Second + 1,
			},
			expectError: true,
			errorMsg:    "file timeout too large",
		},
		{
			name: "negative parallel timeout",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: -1 * time.Second,
			},
			expectError: true,
			errorMsg:    "parallel timeout must be positive",
		},
		{
			name: "parallel timeout too large",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  5 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: shared.MaxParallelTimeout + time.Second,
			},
			expectError: true,
			errorMsg:    "parallel timeout too large",
		},
		{
			name: "parallel timeout less than command timeout",
			config: &Config{
				LogDir:          "/var/log/fail2ban",
				FilterDir:       "/etc/fail2ban/filter.d",
				Format:          PlainFormat,
				CommandTimeout:  10 * time.Second,
				FileTimeout:     3 * time.Second,
				ParallelTimeout: 5 * time.Second,
			},
			expectError: true,
			errorMsg:    "parallel timeout should be >= command timeout",
		},
		{
			name: "multiple validation errors",
			config: &Config{
				LogDir:          "",
				FilterDir:       "",
				Format:          "invalid",
				CommandTimeout:  -1 * time.Second,
				FileTimeout:     -1 * time.Second,
				ParallelTimeout: -1 * time.Second,
			},
			expectError: true,
			errorMsg:    "configuration validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateConfig()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
