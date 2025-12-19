package cmd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// TestIsSkipCommand tests command skip detection
func TestIsSkipCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{"service command skipped", "service", true},
		{"version command skipped", "version", true},
		{"test-filter command skipped", "test-filter", true},
		{"completion command skipped", "completion", true},
		{"help command skipped", "help", true},
		{"ban command not skipped", "ban", false},
		{"unban command not skipped", "unban", false},
		{"status command not skipped", "status", false},
		{"empty command not skipped", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSkipCommand(tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

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
			expectJails: []string{"sshd"}, // Should be lowercased
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
			jails, err := GetJailsFromArgs(mockClient, tt.args, tt.startIndex)

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

// TestHandleErrorWithContext tests automatic error categorization
func TestHandleErrorWithContext(t *testing.T) {
	tests := []struct {
		name      string
		inputErr  error
		expectNil bool
	}{
		{
			name:      "nil error returns nil",
			inputErr:  nil,
			expectNil: true,
		},
		{
			name:      "validation error detected",
			inputErr:  errors.New("invalid input provided"),
			expectNil: false,
		},
		{
			name:      "permission error detected",
			inputErr:  errors.New("permission denied"),
			expectNil: false,
		},
		{
			name:      "system error detected",
			inputErr:  errors.New("service not found"),
			expectNil: false,
		},
		{
			name:      "generic error handled",
			inputErr:  errors.New("unknown error"),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HandleErrorWithContext(tt.inputErr)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

// TestOutputResults tests result output formatting
func TestOutputResults(t *testing.T) {
	tests := []struct {
		name    string
		results interface{}
		format  string
	}{
		{
			name:    "json format output",
			results: map[string]string{"status": "ok"},
			format:  JSONFormat,
		},
		{
			name:    "plain format output",
			results: "plain text output",
			format:  PlainFormat,
		},
		{
			name:    "nil config uses plain format",
			results: "test output",
			format:  "",
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

			// Should not panic
			OutputResults(cmd, tt.results, config)

			// Verify output was written
			output := buf.String()
			assert.NotEmpty(t, output, "Expected output to be written")
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

// TestWrapErrorf tests formatted error wrapping
func TestWrapErrorf(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		format         string
		args           []interface{}
		expectNil      bool
		expectContains string
	}{
		{
			name:      "nil error returns nil",
			err:       nil,
			format:    "operation %s",
			args:      []interface{}{"test"},
			expectNil: true,
		},
		{
			name:           "wraps error with formatted message",
			err:            errors.New("original error"),
			format:         "operation %s failed",
			args:           []interface{}{"ban"},
			expectNil:      false,
			expectContains: "operation ban failed",
		},
		{
			name:           "wraps error with multiple format args",
			err:            errors.New("connection timeout"),
			format:         "jail %s operation %s",
			args:           []interface{}{"sshd", "status"},
			expectNil:      false,
			expectContains: "jail sshd operation status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapErrorf(tt.err, tt.format, tt.args...)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Contains(t, result.Error(), tt.expectContains)
				assert.Contains(t, result.Error(), tt.err.Error())
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
		{"ban operation code 0", 0, shared.MetricsBan, "Banned"},
		{"ban operation code 1", 1, shared.MetricsBan, "Already banned"},
		{"unban operation code 0", 0, shared.MetricsUnban, "Unbanned"},
		{"unban operation code 1", 1, shared.MetricsUnban, "Already unbanned"},
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
	t.Run("TrimmedString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"  test  ", "test"},
			{"\ntest\n", "test"},
			{"test", "test"},
			{"", ""},
			{"   ", ""},
		}

		for _, tt := range tests {
			result := TrimmedString(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})

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

	t.Run("NonEmptyString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected bool
		}{
			{"", false},
			{"   ", false},
			{"\n\t", false},
			{"test", true},
			{"  test  ", true},
		}

		for _, tt := range tests {
			result := NonEmptyString(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})
}
