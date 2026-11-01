package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
			assertLogsWatchCase(t, tt.args, tt.mockLogs, tt.limit, tt.wantOutput, tt.wantError)
		})
	}
}

// assertLogsWatchCase builds a LogsWatchCmd around a mock client and verifies
// its output (success) or that it errors (wantError) for a single case.
func assertLogsWatchCase(
	t *testing.T,
	args, mockLogs []string,
	limit int,
	wantOutput string,
	wantError bool,
) {
	t.Helper()

	// Create a mock client that will return different logs on subsequent calls
	mock := &MockLogsWatchClient{
		initialLogs: mockLogs,
		limit:       limit,
		shouldError: wantError,
	}

	config := &Config{Format: "plain"}
	cmd := LogsWatchCmd(mock, config)

	// Set up command flags
	if limit > 0 {
		if err := cmd.Flags().Set("limit", strconv.Itoa(limit)); err != nil {
			t.Fatalf("failed to set limit flag: %v", err)
		}
	}

	// Capture output
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetArgs(args)

	// For error cases, run the command and check error immediately
	if wantError {
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
	if got != wantOutput {
		t.Errorf("output = %q, want %q", got, wantOutput)
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
	cmd := LogsWatchCmd(mock, config)

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
	// The limit is applied by the client at read time, not trimmed afterwards.
	if mock.lastLimit != mock.limit {
		t.Errorf("forwarded limit = %d, want %d", mock.lastLimit, mock.limit)
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
	cmd := LogsWatchCmd(mock, config)

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

// MockLogsWatchClient is a mock client specifically for testing logs-watch.
// It applies the requested line limit itself, like the real client, and
// records it in lastLimit.
type MockLogsWatchClient struct {
	initialLogs []string
	limit       int
	lastLimit   int
	shouldError bool
	callCount   int
}

func (m *MockLogsWatchClient) GetLogLinesWithLimitContext(
	_ context.Context, jail, ip string, maxLines int,
) ([]string, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error getting log lines")
	}

	m.callCount++
	m.lastLimit = maxLines

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

	// Apply jail then IP filtering if specified
	logs = mockGetLogLinesFiltered(logs, jail, "["+jail+"]")
	logs = mockGetLogLinesFiltered(logs, ip, ip)

	if maxLines > 0 && len(logs) > maxLines {
		logs = logs[len(logs)-maxLines:]
	}
	return logs, nil
}

// mockGetLogLinesFiltered returns logs unchanged when value is empty or "all",
// otherwise keeps only lines containing substr.
func mockGetLogLinesFiltered(logs []string, value, substr string) []string {
	if value == "" || value == "all" {
		return logs
	}
	var filtered []string
	for _, line := range logs {
		if strings.Contains(line, substr) {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

// The remaining fail2ban.Client methods are stubs logs-watch never calls.

func (m *MockLogsWatchClient) ListJailsWithContext(_ context.Context) ([]string, error) {
	return []string{"sshd", "apache"}, nil
}

func (m *MockLogsWatchClient) StatusAllWithContext(_ context.Context) (string, error) {
	return "mock status", nil
}

func (m *MockLogsWatchClient) StatusJailWithContext(_ context.Context, jail string) (string, error) {
	return fmt.Sprintf("mock status for %s", jail), nil
}

func (m *MockLogsWatchClient) BanIPWithContext(_ context.Context, _, _ string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) UnbanIPWithContext(_ context.Context, _, _ string) (int, error) {
	return 0, nil
}

func (m *MockLogsWatchClient) BannedInWithContext(_ context.Context, _ string) ([]string, error) {
	return []string{}, nil
}

func (m *MockLogsWatchClient) GetBanRecordsWithContext(_ context.Context, _ []string) ([]fail2ban.BanRecord, error) {
	return []fail2ban.BanRecord{}, nil
}

func (m *MockLogsWatchClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return m.GetLogLinesWithLimitContext(ctx, jail, ip, constants.DefaultLogLinesLimit)
}

func (m *MockLogsWatchClient) ListFiltersWithContext(_ context.Context) ([]string, error) {
	return []string{"sshd"}, nil
}

func (m *MockLogsWatchClient) TestFilterWithContext(_ context.Context, _ string) (string, error) {
	return "mock filter test result", nil
}

// TestLogsWatchCmdCreation checks the command's shape and flags.
func TestLogsWatchCmdCreation(t *testing.T) {
	cmd := LogsWatchCmd(&MockLogsWatchClient{}, &Config{Format: PlainFormat})
	if cmd == nil || cmd.Use != "logs-watch [jail] [ip]" || cmd.Short == "" || cmd.RunE == nil {
		t.Fatalf("unexpected logs-watch command: %+v", cmd)
	}
	// jail and ip are positional args, not flags
	for _, name := range []string{"limit", "interval"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q missing", name)
		}
	}
}

// TestGetLogLinesWithLimitAndContextReadsRealClient pins one poll against the
// real client: the exact filtered, limited lines, and an error once the
// per-read timeout has expired.
func TestGetLogLinesWithLimitAndContextReadsRealClient(t *testing.T) {
	dir := t.TempDir()
	content := "a [sshd] Ban 192.168.1.1\nb [apache] Ban 192.168.1.2\nc [sshd] Ban 192.168.1.3\n"
	if err := os.WriteFile(filepath.Join(dir, "fail2ban.log"), []byte(content), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	client := &fail2ban.RealClient{LogDir: dir}
	ctx := context.Background()

	tests := []struct {
		name     string
		jail, ip string
		maxLines int
		want     []string
	}{
		{name: "no filters", maxLines: 10, want: []string{
			"a [sshd] Ban 192.168.1.1", "b [apache] Ban 192.168.1.2", "c [sshd] Ban 192.168.1.3",
		}},
		{name: "jail filter", jail: "sshd", maxLines: 10, want: []string{
			"a [sshd] Ban 192.168.1.1", "c [sshd] Ban 192.168.1.3",
		}},
		{name: "ip filter", ip: "192.168.1.2", maxLines: 10, want: []string{"b [apache] Ban 192.168.1.2"}},
		{name: "limit keeps the newest", maxLines: 1, want: []string{"c [sshd] Ban 192.168.1.3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getLogLinesWithLimitAndContext(ctx, client, tt.jail, tt.ip, tt.maxLines, 5*time.Second)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("lines = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("expired timeout", func(t *testing.T) {
		_, err := getLogLinesWithLimitAndContext(ctx, client, "", "", 10, time.Nanosecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want context.DeadlineExceeded", err)
		}
	})
}
