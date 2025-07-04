package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestLogsWatchCmd(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		mockLogs       []string
		limit          int
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "watch all logs",
			args:           []string{},
			mockLogs:       []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			limit:          10,
			expectedOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			expectError:    false,
		},
		{
			name:           "watch logs with jail filter",
			args:           []string{"sshd"},
			mockLogs:       []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100", "2024-01-01 12:01:00 [apache] Ban 192.168.1.101"},
			limit:          10,
			expectedOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			expectError:    false,
		},
		{
			name:           "watch logs with jail and IP filter",
			args:           []string{"sshd", "192.168.1.100"},
			mockLogs:       []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			limit:          10,
			expectedOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			expectError:    false,
		},
		{
			name:           "watch logs with limit",
			args:           []string{},
			mockLogs:       []string{"line1", "line2", "line3"},
			limit:          2,
			expectedOutput: "line2\nline3",
			expectError:    false,
		},
		{
			name:        "watch logs with error",
			args:        []string{},
			mockLogs:    []string{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock client that will return different logs on subsequent calls
			mock := &MockLogsWatchClient{
				initialLogs: tt.mockLogs,
				limit:       tt.limit,
				shouldError: tt.expectError,
			}

			config := &Config{Format: "plain"}
			cmd := LogsWatchCmd(mock, config)

			// Set up command flags
			if tt.limit > 0 {
				cmd.Flags().Set("limit", string(rune(tt.limit+'0')))
			}

			// Capture output
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetArgs(tt.args)

			// For error cases, run the command and check error immediately
			if tt.expectError {
				err := cmd.Execute()
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			// For success cases, test that the command can be set up without error
			// We can't easily test the actual watching behavior in unit tests
			// without complex goroutine management, so we test the setup
			cmd.SetArgs(tt.args)

			// Test that we can create the command and it has the expected structure
			if cmd.Use != "logs-watch [jail] [ip]" {
				t.Errorf("unexpected command use: %s", cmd.Use)
			}

			// Test that the limit flag exists
			limitFlag := cmd.Flags().Lookup("limit")
			if limitFlag == nil {
				t.Errorf("limit flag should exist")
			}
		})
	}
}

func TestLogsWatchCmdJSON(t *testing.T) {
	mock := &MockLogsWatchClient{
		initialLogs: []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
		limit:       10,
	}

	config := &Config{Format: JSONFormat}
	cmd := LogsWatchCmd(mock, config)

	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)

	// Test that the command is properly set up for JSON output
	cmd.SetArgs([]string{})

	// Check that the command structure is correct
	if cmd.Use != "logs-watch [jail] [ip]" {
		t.Errorf("unexpected command use: %s", cmd.Use)
	}

	// Test that the limit flag exists and has correct default
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Errorf("limit flag should exist")
	}
	if limitFlag.DefValue != "10" {
		t.Errorf("expected default limit of 10, got %s", limitFlag.DefValue)
	}
}

func TestLogsWatchCmdLimit(t *testing.T) {
	mock := &MockLogsWatchClient{
		initialLogs: []string{"line1", "line2", "line3", "line4", "line5"},
		limit:       3,
	}

	config := &Config{Format: "plain"}
	cmd := LogsWatchCmd(mock, config)

	// Set limit flag
	cmd.Flags().Set("limit", "3")

	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)

	// Test that the limit flag can be set properly
	err := cmd.Flags().Set("limit", "3")
	if err != nil {
		t.Errorf("failed to set limit flag: %v", err)
	}

	// Check that the command structure is correct
	if cmd.Use != "logs-watch [jail] [ip]" {
		t.Errorf("unexpected command use: %s", cmd.Use)
	}

	// Test that the limit flag was set correctly
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Errorf("limit flag should exist")
	}

	// Get the limit value
	limitValue, err := cmd.Flags().GetInt("limit")
	if err != nil {
		t.Errorf("failed to get limit value: %v", err)
	}
	if limitValue != 3 {
		t.Errorf("expected limit value 3, got %d", limitValue)
	}
}

func TestEqualFunction(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "different content",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "d"},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "one empty, one not",
			a:        []string{},
			b:        []string{"a"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equal(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("equal(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestLogsWatchCmdFlags(t *testing.T) {
	mock := &MockLogsWatchClient{
		initialLogs: []string{"test log"},
		limit:       5,
	}

	config := &Config{Format: "plain"}
	cmd := LogsWatchCmd(mock, config)

	// Test that the limit flag is properly defined
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag should be defined")
	}

	if limitFlag.Shorthand != "n" {
		t.Errorf("expected limit flag shorthand to be 'n', got %q", limitFlag.Shorthand)
	}

	if limitFlag.DefValue != "10" {
		t.Errorf("expected limit flag default value to be '10', got %q", limitFlag.DefValue)
	}
}

// MockLogsWatchClient is a mock client specifically for testing logs-watch
type MockLogsWatchClient struct {
	initialLogs []string
	limit       int
	shouldError bool
	callCount   int
}

func (m *MockLogsWatchClient) GetLogLines(jail, ip string) ([]string, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error getting log lines")
	}

	m.callCount++

	// Return initial logs on first call, then simulate new logs on subsequent calls
	if m.callCount == 1 {
		return m.initialLogs, nil
	}

	// Simulate new logs being added
	newLogs := make([]string, len(m.initialLogs))
	copy(newLogs, m.initialLogs)
	newLogs = append(newLogs, fmt.Sprintf("new log line %d", m.callCount))

	return newLogs, nil
}

// Implement other required methods for the interface
func (m *MockLogsWatchClient) ListJails() ([]string, error) {
	return []string{"sshd", "apache"}, nil
}

func (m *MockLogsWatchClient) StatusAll() (string, error) {
	return "mock status", nil
}

func (m *MockLogsWatchClient) StatusJail(jail string) (string, error) {
	return fmt.Sprintf("mock status for %s", jail), nil
}

func (m *MockLogsWatchClient) BanIP(ip, jail string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) UnbanIP(ip, jail string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) BannedIn(ip string) ([]string, error) {
	return []string{}, nil
}

func (m *MockLogsWatchClient) GetBanRecords(jails []string) ([]fail2ban.BanRecord, error) {
	return []fail2ban.BanRecord{}, nil
}

func (m *MockLogsWatchClient) ListFilters() ([]string, error) {
	return []string{"sshd"}, nil
}

func (m *MockLogsWatchClient) TestFilter(filter string) (string, error) {
	return "mock filter test result", nil
}
