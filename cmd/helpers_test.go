package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestRequireNonEmptyArgument(t *testing.T) {
	tests := []struct {
		name        string
		arg         string
		argName     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "non-empty argument",
			arg:         "test-value",
			argName:     "testArg",
			expectError: false,
		},
		{
			name:        "empty string argument",
			arg:         "",
			argName:     "testArg",
			expectError: true,
			errorMsg:    "testArg cannot be empty",
		},
		{
			name:        "whitespace-only argument",
			arg:         "   ",
			argName:     "testArg",
			expectError: true,
			errorMsg:    "testArg cannot be empty",
		},
		{
			name:        "tab-only argument",
			arg:         "\t",
			argName:     "testArg",
			expectError: true,
			errorMsg:    "testArg cannot be empty",
		},
		{
			name:        "newline-only argument",
			arg:         "\n",
			argName:     "testArg",
			expectError: true,
			errorMsg:    "testArg cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireNonEmptyArgument(tt.arg, tt.argName)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error to contain %q, got: %v", tt.errorMsg, err)
			}
		})
	}
}

func TestFormatBannedResult(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		jails    []string
		expected string
	}{
		{
			name:     "no jails - not banned",
			ip:       "192.168.1.100",
			jails:    []string{},
			expected: "IP 192.168.1.100 is not banned",
		},
		{
			name:     "nil jails - not banned",
			ip:       "192.168.1.100",
			jails:    nil,
			expected: "IP 192.168.1.100 is not banned",
		},
		{
			name:     "single jail",
			ip:       "192.168.1.100",
			jails:    []string{"sshd"},
			expected: "IP 192.168.1.100 is banned in: [sshd]",
		},
		{
			name:     "multiple jails",
			ip:       "192.168.1.100",
			jails:    []string{"sshd", "apache", "nginx"},
			expected: "IP 192.168.1.100 is banned in: [sshd apache nginx]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatBannedResult(tt.ip, tt.jails)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		context      string
		expectedMsg  string
		expectNilErr bool
	}{
		{
			name:         "nil error returns nil",
			err:          nil,
			context:      "test context",
			expectNilErr: true,
		},
		{
			name:        "wraps error with context",
			err:         errors.New("original error"),
			context:     "command execution",
			expectedMsg: "command execution failed:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.err, tt.context)

			if tt.expectNilErr {
				if result != nil {
					t.Errorf("expected nil error, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Error("expected wrapped error, got nil")
				return
			}

			if tt.expectedMsg != "" && !strings.Contains(result.Error(), tt.expectedMsg) {
				t.Errorf("expected error to contain %q, got: %v", tt.expectedMsg, result)
			}
		})
	}
}

func TestNewContextualCommand(t *testing.T) {
	// Simple test handler
	testHandler := func(_ context.Context, _ *cobra.Command, _ []string) error {
		return nil
	}

	tests := []struct {
		name         string
		use          string
		short        string
		aliases      []string
		config       *Config
		expectFields bool
	}{
		{
			name:         "creates command with all fields",
			use:          "test",
			short:        "Test command",
			aliases:      []string{"t"},
			config:       &Config{},
			expectFields: true,
		},
		{
			name:         "creates command with minimal fields",
			use:          "minimal",
			short:        "Minimal",
			aliases:      nil,
			config:       &Config{},
			expectFields: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewContextualCommand(tt.use, tt.short, tt.aliases, tt.config, testHandler)

			if cmd == nil {
				t.Fatal("expected command to be created, got nil")
			}

			if tt.expectFields {
				if cmd.Use != tt.use {
					t.Errorf("expected Use to be %q, got %q", tt.use, cmd.Use)
				}
				if cmd.Short != tt.short {
					t.Errorf("expected Short to be %q, got %q", tt.short, cmd.Short)
				}
			}
		})
	}
}

func TestAddWatchFlags(t *testing.T) {
	tests := []struct {
		name     string
		command  *cobra.Command
		interval time.Duration
	}{
		{
			name:     "adds watch flags to command",
			command:  &cobra.Command{Use: "test"},
			interval: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function modifies the command by adding flags
			// We can test that it doesn't panic and the command is still valid
			AddWatchFlags(tt.command, &tt.interval)

			// Check that the interval flag was added
			flag := tt.command.Flags().Lookup("interval")
			if flag == nil {
				t.Error("expected 'interval' flag to be added")
			}
		})
	}
}
