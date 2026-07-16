package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// TestGetJailsFromArgs tests jail extraction from arguments
func TestGetJailsFromArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		startIndex  int
		expectJails []string
		expectError bool
	}{
		{
			name:        "jail provided in args",
			args:        []string{"192.168.1.1", "SSHD"},
			startIndex:  1,
			expectJails: []string{"SSHD"}, // jail names are case-sensitive; passed through verbatim
			expectError: false,
		},
		{
			name:        "no jail in args - list from client",
			args:        []string{"192.168.1.1"},
			startIndex:  1,
			expectJails: []string{"apache", "sshd"}, // MockClient default jails (sorted)
			expectError: false,
		},
		{
			name:        "empty args - list from client",
			args:        []string{},
			startIndex:  0,
			expectJails: []string{"apache", "sshd"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := fail2ban.NewMockClient()
			jails, err := GetJailsFromArgsWithContext(context.Background(), mockClient, tt.args, tt.startIndex)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectJails, jails)
			}
		})
	}
}

// TestHandlePermissionError tests permission error handling
func TestHandlePermissionError(t *testing.T) {
	tests := []struct {
		name           string
		inputErr       error
		expectNil      bool
		expectContains string
	}{
		{
			name:      "nil error returns nil",
			inputErr:  nil,
			expectNil: true,
		},
		{
			name:           "permission denied error",
			inputErr:       errors.New("permission denied"),
			expectNil:      false,
			expectContains: "permission denied",
		},
		{
			name:           "sudo error",
			inputErr:       errors.New("sudo required"),
			expectNil:      false,
			expectContains: "sudo",
		},
		{
			name:           "generic error gets categorized",
			inputErr:       errors.New("generic error"),
			expectNil:      false,
			expectContains: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HandlePermissionError(tt.inputErr)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				if tt.expectContains != "" {
					assert.Contains(t, result.Error(), tt.expectContains)
				}
			}
		})
	}
}

// TestOutputResults tests result output formatting
func TestOutputResults(t *testing.T) {
	tests := []struct {
		name        string
		results     any
		format      string
		wantContain []string
	}{
		{
			name:        "json format output",
			results:     map[string]string{"status": "ok"},
			format:      JSONFormat,
			wantContain: []string{`"status"`, `"ok"`},
		},
		{
			name:        "plain format output",
			results:     "plain text output",
			format:      PlainFormat,
			wantContain: []string{"plain text output"},
		},
		{
			name:        "nil config uses plain format",
			results:     "test output",
			format:      "",
			wantContain: []string{"test output"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command with output buffer
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			var config *Config
			if tt.format != "" {
				config = &Config{Format: tt.format}
			}

			OutputResults(cmd, tt.results, config)

			// Assert the rendered content, not merely that something was written.
			output := buf.String()
			for _, want := range tt.wantContain {
				assert.Contains(t, output, want)
			}
		})
	}
}

// TestProcessUnbanOperation tests unban operation processing
func TestProcessUnbanOperation(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		jails       []string
		setupMock   func(*fail2ban.MockClient)
		expectError bool
		expectCount int
	}{
		{
			name:  "successful unban single jail",
			ip:    "192.168.1.1",
			jails: []string{"sshd"},
			setupMock: func(_ *fail2ban.MockClient) {
				// MockClient returns 0 by default (successful unban)
			},
			expectError: false,
			expectCount: 1,
		},
		{
			name:  "successful unban multiple jails",
			ip:    "192.168.1.1",
			jails: []string{"sshd", "apache"},
			setupMock: func(_ *fail2ban.MockClient) {
				// MockClient handles both jails
			},
			expectError: false,
			expectCount: 2,
		},
		{
			name:  "unban returns already unbanned status",
			ip:    "192.168.1.1",
			jails: []string{"sshd"},
			setupMock: func(m *fail2ban.MockClient) {
				// Configure mock to return code 1 (already unbanned)
				m.UnbanResults = map[string]map[string]int{
					"sshd": {"192.168.1.1": 1},
				}
			},
			expectError: false,
			expectCount: 1,
		},
		{
			name:  "unban fails with error",
			ip:    "192.168.1.1",
			jails: []string{"sshd"},
			setupMock: func(m *fail2ban.MockClient) {
				// Configure mock to return an error
				m.UnbanErrors = map[string]map[string]error{
					"sshd": {"192.168.1.1": errors.New("unban failed")},
				}
			},
			expectError: true,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := fail2ban.NewMockClient()
			tt.setupMock(mockClient)

			results, err := ProcessUnbanOperation(mockClient, tt.ip, tt.jails)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, results)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, tt.expectCount)

				// Verify result structure
				for _, result := range results {
					assert.Equal(t, tt.ip, result.IP)
					assert.NotEmpty(t, result.Jail)
					assert.NotEmpty(t, result.Status)
				}
			}
		})
	}
}

// TestTrimmedOutput tests output trimming
func TestTrimmedOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "trims leading whitespace",
			input:    []byte("  output"),
			expected: "output",
		},
		{
			name:     "trims trailing whitespace",
			input:    []byte("output  "),
			expected: "output",
		},
		{
			name:     "trims both sides",
			input:    []byte("  output  "),
			expected: "output",
		},
		{
			name:     "trims newlines",
			input:    []byte("\noutput\n"),
			expected: "output",
		},
		{
			name:     "empty input",
			input:    []byte(""),
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    []byte("   \n\t  "),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimmedOutput(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateServiceAction tests service action validation
func TestValidateServiceAction(t *testing.T) {
	tests := []struct {
		name        string
		action      string
		expectError bool
	}{
		{"valid start action", "start", false},
		{"valid stop action", "stop", false},
		{"valid restart action", "restart", false},
		{"valid status action", "status", false},
		{"valid reload action", "reload", false},
		{"valid enable action", "enable", false},
		{"valid disable action", "disable", false},
		{"invalid action", "invalid", true},
		{"empty action", "", true},
		{"uppercase action", "START", true}, // Should be lowercase
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceAction(tt.action)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestInterpretBanStatus tests ban status interpretation
func TestInterpretBanStatus(t *testing.T) {
	tests := []struct {
		name      string
		code      int
		operation string
		expected  string
	}{
		{"ban operation code 0", 0, constants.MetricsBan, "Banned"},
		{"ban operation code 1", 1, constants.MetricsBan, "Already banned"},
		{"unban operation code 0", 0, constants.MetricsUnban, "Unbanned"},
		{"unban operation code 1", 1, constants.MetricsUnban, "Already unbanned"},
		{"unknown operation", 0, "unknown", "Unknown"},
		{"unknown operation code 1", 1, "unknown", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretBanStatus(tt.code, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHelperStringUtilities tests string utility functions
func TestHelperStringUtilities(t *testing.T) {
	t.Run("IsEmptyString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected bool
		}{
			{"", true},
			{"   ", true},
			{"\n\t", true},
			{"test", false},
			{"  test  ", false},
		}

		for _, tt := range tests {
			result := IsEmptyString(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})
}
