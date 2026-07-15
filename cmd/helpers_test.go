package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/constants"
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

// TestCreateTimeoutContext verifies the base-context and timeout resolution
// rules of createTimeoutContext.
func TestCreateTimeoutContext(t *testing.T) {
	tests := []struct {
		name    string
		nilBase bool
		config  *Config
		timeout time.Duration
	}{
		{
			name:    "nil base and nil config use background and default timeout",
			nilBase: true,
			config:  nil,
			timeout: constants.DefaultCommandTimeout,
		},
		{
			name:    "zero CommandTimeout falls back to default",
			config:  &Config{CommandTimeout: 0},
			timeout: constants.DefaultCommandTimeout,
		},
		{
			name:    "custom CommandTimeout is honored",
			config:  &Config{CommandTimeout: 5 * time.Second},
			timeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var base context.Context
			if !tt.nilBase {
				base = context.Background()
			}
			before := time.Now()
			ctx, cancel := createTimeoutContext(base, tt.config)
			defer cancel()

			if ctx == nil {
				t.Fatal("expected non-nil context")
			}
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("expected context to have a deadline")
			}
			expected := before.Add(tt.timeout)
			if diff := deadline.Sub(expected); diff < -time.Second || diff > time.Second {
				t.Errorf("deadline %v not within 1s of expected %v", deadline, expected)
			}
		})
	}
}
