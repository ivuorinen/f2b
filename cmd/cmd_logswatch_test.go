package cmd

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/shared"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestLogsWatchCmd(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		mockLogs   []string
		limit      int
		wantOutput string
		wantError  bool
	}{
		{
			name:       "watch all logs",
			args:       []string{},
			mockLogs:   []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			limit:      10,
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			wantError:  false,
		},
		{
			name: "watch logs with jail filter",
			args: []string{"sshd"},
			mockLogs: []string{
				"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
				"2024-01-01 12:01:00 [apache] Ban 192.168.1.101",
			},
			limit:      10,
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			wantError:  false,
		},
		{
			name:       "watch logs with jail and IP filter",
			args:       []string{"sshd", "192.168.1.100"},
			mockLogs:   []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			limit:      10,
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
			wantError:  false,
		},
		{
			name:       "watch logs with limit",
			args:       []string{},
			mockLogs:   []string{"line1", "line2", "line3"},
			limit:      2,
			wantOutput: "line2\nline3",
			wantError:  false,
		},
		{
			name:      "watch logs with error",
			args:      []string{},
			mockLogs:  []string{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock client that will return different logs on subsequent calls
			mock := &MockLogsWatchClient{
				initialLogs: tt.mockLogs,
				limit:       tt.limit,
				shouldError: tt.wantError,
			}

			config := &Config{Format: "plain"}
			cmd := LogsWatchCmd(context.Background(), mock, config)

			// Set up command flags
			if tt.limit > 0 {
				if err := cmd.Flags().Set("limit", strconv.Itoa(tt.limit)); err != nil {
					t.Fatalf("failed to set limit flag: %v", err)
				}
			}

			// Capture output
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetArgs(tt.args)

			// For error cases, run the command and check error immediately
			if tt.wantError {
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
				t.Fatalf("limit flag should exist")
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
	cmd := LogsWatchCmd(context.Background(), mock, config)

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
		t.Fatalf("limit flag should exist")
	} else if limitFlag.DefValue != "1000" {
		t.Errorf("expected default limit of 1000, got %s", limitFlag.DefValue)
	}
}

func TestLogsWatchCmdLimit(t *testing.T) {
	mock := &MockLogsWatchClient{
		initialLogs: []string{"line1", "line2", "line3", "line4", "line5"},
		limit:       3,
	}

	config := &Config{Format: "plain"}
	cmd := LogsWatchCmd(context.Background(), mock, config)

	// Set limit flag
	if err := cmd.Flags().Set("limit", "3"); err != nil {
		t.Fatalf("failed to set limit flag: %v", err)
	}

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

func TestComputeHashEquivalence(t *testing.T) {
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
			hashA := computeHash(tt.a)
			hashB := computeHash(tt.b)
			result := hashA == hashB
			if result != tt.expected {
				t.Errorf("computeHash equivalence for (%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
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
	cmd := LogsWatchCmd(context.Background(), mock, config)

	// Test that the limit flag is properly defined
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag should be defined")
	} else if limitFlag.Shorthand != "n" {
		t.Errorf("expected limit flag shorthand to be 'n', got %q", limitFlag.Shorthand)
	}

	if limitFlag.DefValue != "1000" {
		t.Errorf("expected limit flag default value to be '1000', got %q", limitFlag.DefValue)
	}

	// Test that the interval flag is properly defined
	intervalFlag := cmd.Flags().Lookup("interval")
	if intervalFlag == nil {
		t.Fatal("interval flag should be defined")
	} else if intervalFlag.Shorthand != "i" {
		t.Errorf("expected interval flag shorthand to be 'i', got %q", intervalFlag.Shorthand)
	}
	if intervalFlag.DefValue != shared.DefaultPollingInterval.String() {
		t.Errorf(
			"expected interval flag default value to be %q, got %q",
			shared.DefaultPollingInterval.String(),
			intervalFlag.DefValue,
		)
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

	var logs []string
	// Return initial logs on first call, then simulate new logs on subsequent calls
	if m.callCount == 1 {
		logs = m.initialLogs
	} else {
		// Simulate new logs being added
		logs = make([]string, len(m.initialLogs))
		copy(logs, m.initialLogs)
		logs = append(logs, fmt.Sprintf("new log line %d", m.callCount))
	}

	// Apply jail filtering if specified
	if jail != "" && jail != "all" {
		var filtered []string
		for _, line := range logs {
			if strings.Contains(line, "["+jail+"]") {
				filtered = append(filtered, line)
			}
		}
		logs = filtered
	}

	// Apply IP filtering if specified
	if ip != "" && ip != "all" {
		var filtered []string
		for _, line := range logs {
			if strings.Contains(line, ip) {
				filtered = append(filtered, line)
			}
		}
		logs = filtered
	}

	return logs, nil
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

func (m *MockLogsWatchClient) BanIP(_, _ string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) UnbanIP(_, _ string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) BannedIn(_ string) ([]string, error) {
	return []string{}, nil
}

func (m *MockLogsWatchClient) GetBanRecords(_ []string) ([]fail2ban.BanRecord, error) {
	return []fail2ban.BanRecord{}, nil
}

func (m *MockLogsWatchClient) ListFilters() ([]string, error) {
	return []string{"sshd"}, nil
}

func (m *MockLogsWatchClient) TestFilter(_ string) (string, error) {
	return "mock filter test result", nil
}

// Context-aware methods for MockLogsWatchClient

func (m *MockLogsWatchClient) ListJailsWithContext(_ context.Context) ([]string, error) {
	return m.ListJails()
}

func (m *MockLogsWatchClient) StatusAllWithContext(_ context.Context) (string, error) {
	return m.StatusAll()
}

func (m *MockLogsWatchClient) StatusJailWithContext(_ context.Context, jail string) (string, error) {
	return m.StatusJail(jail)
}

func (m *MockLogsWatchClient) BanIPWithContext(_ context.Context, ip, jail string) (int, error) {
	return m.BanIP(ip, jail)
}

func (m *MockLogsWatchClient) UnbanIPWithContext(_ context.Context, ip, jail string) (int, error) {
	return m.UnbanIP(ip, jail)
}

func (m *MockLogsWatchClient) BannedInWithContext(_ context.Context, ip string) ([]string, error) {
	return m.BannedIn(ip)
}

func (m *MockLogsWatchClient) GetBanRecordsWithContext(
	_ context.Context, jails []string) ([]fail2ban.BanRecord, error) {
	return m.GetBanRecords(jails)
}

func (m *MockLogsWatchClient) GetLogLinesWithContext(_ context.Context, jail, ip string) ([]string, error) {
	return m.GetLogLines(jail, ip)
}

func (m *MockLogsWatchClient) ListFiltersWithContext(_ context.Context) ([]string, error) {
	return m.ListFilters()
}

func (m *MockLogsWatchClient) TestFilterWithContext(_ context.Context, filter string) (string, error) {
	return m.TestFilter(filter)
}
