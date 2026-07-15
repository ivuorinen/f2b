package cmd

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"

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

			// Success cases: run the command with an already-canceled context so
			// it prints the initial (jail/IP-filtered, limit-tailed) lines and
			// then exits the watch loop at <-ctx.Done() instead of blocking.
			watchCtx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := cmd.ExecuteContext(watchCtx); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := strings.TrimRight(outBuf.String(), "\n")
			if got != tt.wantOutput {
				t.Errorf("output = %q, want %q", got, tt.wantOutput)
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
	cmd.SetArgs([]string{})

	// Run to completion with a canceled context; assert the initial line is
	// actually emitted in JSON form (quoted), not merely that the flag exists.
	watchCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cmd.ExecuteContext(watchCtx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := outBuf.String()
	if !strings.Contains(out, "192.168.1.100") {
		t.Errorf("JSON output missing log line content: %q", out)
	}
	if !strings.Contains(out, "\"") {
		t.Errorf("JSON output is not quoted/serialized: %q", out)
	}

	// Default limit flag is still asserted.
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatalf("limit flag should exist")
		return
	}
	if limitFlag.DefValue != fmt.Sprintf("%d", constants.DefaultLogLinesLimit) {
		t.Errorf("expected default limit of %d, got %s", constants.DefaultLogLinesLimit, limitFlag.DefValue)
	}
}

func TestLogsWatchCmdLimit(t *testing.T) {
	mock := &MockLogsWatchClient{
		initialLogs: []string{"line1", "line2", "line3", "line4", "line5"},
		limit:       3,
	}

	config := &Config{Format: "plain"}
	cmd := LogsWatchCmd(context.Background(), mock, config)

	if err := cmd.Flags().Set("limit", "3"); err != nil {
		t.Fatalf("failed to set limit flag: %v", err)
	}

	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{})

	// Run to completion; with a limit of 3 over 5 lines, the command must emit
	// exactly the last three lines — this asserts the tailing behavior, not the
	// flag round-trip.
	watchCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cmd.ExecuteContext(watchCtx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.TrimRight(outBuf.String(), "\n")
	if want := "line3\nline4\nline5"; got != want {
		t.Errorf("limited output = %q, want %q", got, want)
	}
}

func TestNewTailLines(t *testing.T) {
	tests := []struct {
		name     string
		prev     []string
		curr     []string
		expected []string
	}{
		{
			name:     "one appended line",
			prev:     []string{"a", "b", "c"},
			curr:     []string{"a", "b", "c", "d"},
			expected: []string{"d"},
		},
		{
			name:     "tail window shifted by two",
			prev:     []string{"a", "b", "c"},
			curr:     []string{"c", "d", "e"},
			expected: []string{"d", "e"},
		},
		{
			name:     "no change",
			prev:     []string{"a", "b", "c"},
			curr:     []string{"a", "b", "c"},
			expected: []string{},
		},
		{
			name:     "empty prev returns all",
			prev:     []string{},
			curr:     []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "no overlap (rotation) returns all",
			prev:     []string{"a", "b"},
			curr:     []string{"x", "y"},
			expected: []string{"x", "y"},
		},
		{
			// fail2ban repeats identical lines: a bare last-line match would
			// anchor on the new copy of "L" and silently drop "A" and "L".
			name:     "appended duplicate of last line",
			prev:     []string{"a", "b", "L"},
			curr:     []string{"a", "b", "L", "A", "L"},
			expected: []string{"A", "L"},
		},
		{
			name:     "duplicate last line in shifted window",
			prev:     []string{"b", "c", "L"},
			curr:     []string{"c", "L", "A", "L"},
			expected: []string{"A", "L"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newTailLines(tt.prev, tt.curr)
			if strings.Join(got, "\n") != strings.Join(tt.expected, "\n") {
				t.Errorf("newTailLines(%v, %v) = %v, want %v", tt.prev, tt.curr, got, tt.expected)
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
		return
	}
	if limitFlag.Shorthand != "n" {
		t.Errorf("expected limit flag shorthand to be 'n', got %q", limitFlag.Shorthand)
	}
	if limitFlag.DefValue != fmt.Sprintf("%d", constants.DefaultLogLinesLimit) {
		t.Errorf(
			"expected limit flag default value to be %d, got %q",
			constants.DefaultLogLinesLimit,
			limitFlag.DefValue,
		)
	}

	// Test that the interval flag is properly defined
	intervalFlag := cmd.Flags().Lookup("interval")
	if intervalFlag == nil {
		t.Fatal("interval flag should be defined")
		return
	}
	if intervalFlag.Shorthand != "i" {
		t.Errorf("expected interval flag shorthand to be 'i', got %q", intervalFlag.Shorthand)
	}
	if intervalFlag.DefValue != constants.DefaultPollingInterval.String() {
		t.Errorf(
			"expected interval flag default value to be %q, got %q",
			constants.DefaultPollingInterval.String(),
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
		logs = make([]string, len(m.initialLogs), len(m.initialLogs)+1)
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
