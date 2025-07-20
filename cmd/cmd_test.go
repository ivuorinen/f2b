package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMain(m *testing.M) {
	Logger.SetOutput(io.Discard)

	// Set up mock sudo checker with privileges for all tests
	originalChecker := fail2ban.GetSudoChecker()
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	code := m.Run()

	// Restore original checker
	fail2ban.SetSudoChecker(originalChecker)

	os.Exit(code)
}

// Type alias for the enhanced MockClient from fail2ban package
type MockClient = fail2ban.MockClient

// NewMockClient creates a new MockClient for testing
func NewMockClient() *MockClient {
	return fail2ban.NewMockClient()
}

// Helper function to set jails for the enhanced MockClient
func setMockJails(mock *MockClient, jails []string) {
	mock.Jails = make(map[string]struct{})
	for _, jail := range jails {
		mock.Jails[jail] = struct{}{}
	}
}

// Context-aware methods for MockClient

// Use centralized validation functions from fail2ban package
// No need for duplicate validation logic here

// Helper function to capture command output
func executeCommand(client fail2ban.Client, args ...string) (string, error) {
	// Suppress logrus output during tests
	oldLoggerOut := Logger.Out
	Logger.SetOutput(io.Discard)
	defer Logger.SetOutput(oldLoggerOut)

	// Ensure mock sudo checker is set for commands that need it
	originalChecker := fail2ban.GetSudoChecker()
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)
	defer fail2ban.SetSudoChecker(originalChecker)

	rootCmd := &cobra.Command{Use: "f2b"}
	config := Config{Format: "plain"}
	rootCmd.AddCommand(ListJailsCmd(client))
	rootCmd.AddCommand(StatusCmd(client, &config))
	rootCmd.AddCommand(BanCmd(client, &config))
	rootCmd.AddCommand(UnbanCmd(client, &config))
	rootCmd.AddCommand(TestIPCmd(client, "plain"))
	rootCmd.AddCommand(LogsCmd(client, &config))
	rootCmd.AddCommand(BannedCmd(client, "plain"))
	rootCmd.AddCommand(VersionCmd("plain"))
	rootCmd.AddCommand(TestFilterCmd(client, &config))

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()

	// Filter out logrus lines (starting with "time="), but keep "Error:" lines for error output tests
	lines := strings.Split(buf.String(), "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "time=") {
			filtered = append(filtered, line)
		}
	}
	// Remove trailing empty lines
	for len(filtered) > 0 && filtered[len(filtered)-1] == "" {
		filtered = filtered[:len(filtered)-1]
	}
	return strings.Join(filtered, "\n") + "\n", err
}

// Helper function to set up commands (mimics the real cmd package)

func TestListJailsCommand(t *testing.T) {
	tests := []struct {
		name        string
		jails       []string
		expectedOut string
		expectError bool
	}{
		{
			name:        "list single jail",
			jails:       []string{"sshd"},
			expectedOut: "sshd\n",
			expectError: false,
		},
		{
			name:        "list multiple jails",
			jails:       []string{"sshd", "apache", "nginx"},
			expectedOut: "apache nginx sshd\n", // alphabetical order
			expectError: false,
		},
		{
			name:        "list no jails",
			jails:       []string{},
			expectedOut: "\n",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, tt.jails)

			output, err := executeCommand(mock, "list-jails")

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if output != tt.expectedOut {
				t.Errorf("expected output %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestStatusCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		jails       []string
		statusAll   string
		statusJail  map[string]string
		expectedOut string
		expectError bool
	}{
		{
			name:        "status all",
			args:        []string{"status", "all"},
			jails:       []string{"sshd"},
			statusAll:   "Status for all jails\n",
			expectedOut: "Status for all jails\n",
			expectError: false,
		},
		{
			name:        "status specific jail",
			args:        []string{"status", "sshd"},
			jails:       []string{"sshd"},
			statusJail:  map[string]string{"sshd": "Status for sshd jail\n"},
			expectedOut: "Status for sshd jail\n",
			expectError: false,
		},
		{
			name:        "status nonexistent jail",
			args:        []string{"status", "nonexistent"},
			jails:       []string{"sshd"},
			expectedOut: "Error: jail 'nonexistent' not found",
			expectError: true,
		},
		{
			name:  "status no args shows usage",
			args:  []string{"status"},
			jails: []string{"sshd"},
			expectedOut: "Usage: f2b status all   (show all jails)\n" +
				"       f2b status <jail> (show specific jail)\nAvailable jails: sshd\n",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, tt.jails)
			mock.StatusAllData = tt.statusAll
			mock.StatusJailData = tt.statusJail

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, tt.expectedOut) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestBannedCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		banRecords  []fail2ban.BanRecord
		expectedOut string
		expectError bool
	}{
		{
			name: "show banned IPs",
			args: []string{"banned"},
			banRecords: []fail2ban.BanRecord{
				{Jail: "sshd", IP: "192.168.1.100", Remaining: "01:30:00"},
				{Jail: "apache", IP: "192.168.1.101", Remaining: "02:15:30"},
			},
			expectedOut: "sshd | 192.168.1.100 | 01:30:00 remaining\napache | 192.168.1.101 | 02:15:30 remaining\n",
			expectError: false,
		},
		{
			name:        "show banned IPs with specific jail",
			args:        []string{"banned", "sshd"},
			banRecords:  []fail2ban.BanRecord{},
			expectedOut: "\n",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			mock.BanRecords = tt.banRecords

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if output != tt.expectedOut {
				t.Errorf("expected output %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestBanCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		jails       []string
		banResults  map[string]map[string]int
		setupBanned bool
		expectedOut string
		expectError bool
	}{
		{
			name:        "ban IP without jail specified",
			args:        []string{"ban", "192.168.1.100"},
			jails:       []string{"sshd", "apache"},
			banResults:  map[string]map[string]int{"192.168.1.100": {"sshd": 0, "apache": 0}},
			expectedOut: "Banned 192.168.1.100 in apache\nBanned 192.168.1.100 in sshd\n", // alphabetical order
			expectError: false,
		},
		{
			name:        "ban IP with specific jail",
			args:        []string{"ban", "192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			banResults:  map[string]map[string]int{"192.168.1.100": {"sshd": 0}},
			expectedOut: "Banned 192.168.1.100 in sshd\n",
			expectError: false,
		},
		{
			name:        "ban IP already banned",
			args:        []string{"ban", "192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: true,
			expectedOut: "Already banned 192.168.1.100 in sshd\n",
			expectError: false,
		},
		{
			name:        "ban command without IP",
			args:        []string{"ban"},
			expectedOut: "Error: IP address required",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, tt.jails)
			mock.BanResults = tt.banResults

			// Set up initial banned state if needed
			if tt.setupBanned {
				// Pre-ban the IP so it's already banned
				_, _ = mock.BanIP("192.168.1.100", "sshd")
			}

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, tt.expectedOut) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestUnbanCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		jails       []string
		banResults  map[string]map[string]int
		setupBanned bool
		expectedOut string
		expectError bool
	}{
		{
			name:        "unban IP with specific jail",
			args:        []string{"unban", "192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: true,
			expectedOut: "Unbanned 192.168.1.100 in sshd\n",
			expectError: false,
		},
		{
			name:        "unban IP already unbanned",
			args:        []string{"unban", "192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: false,
			expectedOut: "Already unbanned 192.168.1.100 in sshd\n",
			expectError: false,
		},
		{
			name:        "unban command without IP",
			args:        []string{"unban"},
			expectedOut: "Error: IP address required",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			setMockJails(mock, tt.jails)
			mock.BanResults = tt.banResults

			// Set up initial banned state
			if tt.setupBanned {
				// Use the enhanced MockClient's BanIP method to set up banned state
				_, _ = mock.BanIP("192.168.1.100", "sshd")
			}

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, tt.expectedOut) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestTestIPCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		setupBans   map[string][]string // jail -> IPs to ban
		expectedOut string
		expectError bool
	}{
		{
			name:        "test IP not banned",
			args:        []string{"test", "192.168.1.100"},
			setupBans:   map[string][]string{}, // no bans
			expectedOut: "IP 192.168.1.100 is not banned",
			expectError: false,
		},
		{
			name:        "test IP banned in one jail",
			args:        []string{"test", "192.168.1.100"},
			setupBans:   map[string][]string{"sshd": {"192.168.1.100"}},
			expectedOut: "IP 192.168.1.100 is banned in: [sshd]\n",
			expectError: false,
		},
		{
			name:        "test IP banned in multiple jails",
			args:        []string{"test", "192.168.1.100"},
			setupBans:   map[string][]string{"sshd": {"192.168.1.100"}, "apache": {"192.168.1.100"}},
			expectedOut: "IP 192.168.1.100 is banned in: [apache sshd]\n", // alphabetical order
			expectError: false,
		},
		{
			name:        "test command without IP",
			args:        []string{"test"},
			expectedOut: "Error: IP address required",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()

			// Set up bans
			for jail, ips := range tt.setupBans {
				for _, ip := range ips {
					_, _ = mock.BanIP(ip, jail)
				}
			}

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, tt.expectedOut) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestLogsCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		logLines    []string
		expectedOut string
		expectError bool
	}{
		{
			name: "show all logs",
			args: []string{"logs"},
			logLines: []string{
				"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
				"2024-01-01 12:01:00 [apache] Ban 192.168.1.101",
			},
			expectedOut: "[2024-01-01 12:00:00 [sshd] Ban 192.168.1.100 2024-01-01 12:01:00 [apache] Ban 192.168.1.101]",
			expectError: false,
		},
		{
			name:        "show logs with jail filter",
			args:        []string{"logs", "sshd"},
			logLines:    []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			expectedOut: "[2024-01-01 12:00:00 [sshd] Ban 192.168.1.100]",
			expectError: false,
		},
		{
			name:        "show logs with jail and IP filter",
			args:        []string{"logs", "sshd", "192.168.1.100"},
			logLines:    []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			expectedOut: "[2024-01-01 12:00:00 [sshd] Ban 192.168.1.100]",
			expectError: false,
		},
		{
			name:        "show logs when no logs exist",
			args:        []string{"logs"},
			logLines:    []string{}, // Explicitly set empty slice
			expectedOut: "[]",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			// Set LogLines to control the behavior explicitly
			mock.LogLines = tt.logLines

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, tt.expectedOut) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestTestFilterCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		filters     []string
		filterTests map[string]string
		expectedOut string
		expectError bool
	}{
		{
			name:        "test existing filter",
			args:        []string{"test-filter", "sshd"},
			filters:     []string{"sshd", "apache"},
			filterTests: map[string]string{"sshd": "Filter test results for sshd\n"},
			expectedOut: "Filter test results for sshd\n",
			expectError: false,
		},
		{
			name:        "test nonexistent filter",
			args:        []string{"test-filter", "nonexistent"},
			filters:     []string{"sshd", "apache"},
			filterTests: map[string]string{},
			expectedOut: "\n",
			expectError: true,
		},
		{
			name:        "test-filter command without filter shows available filters",
			args:        []string{"test-filter"},
			filters:     []string{"sshd", "apache"},
			expectedOut: "Available filters: sshd, apache\n",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			mock.Filters = tt.filters
			mock.FilterTests = tt.filterTests

			output, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(output, strings.TrimSpace(tt.expectedOut)) && tt.expectedOut != "" {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, output)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	mock := NewMockClient()

	output, err := executeCommand(mock, "version")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedOut := fmt.Sprintf("f2b version %s\n", version)
	if output != expectedOut {
		t.Errorf("expected output %q, got %q", expectedOut, output)
	}
}

func TestCommandErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		setupMock     func(*MockClient)
		expectError   bool
		expectedError string
	}{
		{
			name: "ban IP error",
			args: []string{"ban", "192.168.1.100", "sshd"},
			setupMock: func(m *MockClient) {
				setMockJails(m, []string{"sshd"})
				m.SetBanError("sshd", "192.168.1.100", fmt.Errorf("ban failed"))
			},
			expectError:   true,
			expectedError: "ban failed",
		},
		{
			name: "unban IP error",
			args: []string{"unban", "192.168.1.100", "sshd"},
			setupMock: func(m *MockClient) {
				setMockJails(m, []string{"sshd"})
				m.SetUnbanError("sshd", "192.168.1.100", fmt.Errorf("unban failed"))
			},
			expectError:   true,
			expectedError: "unban failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			tt.setupMock(mock)

			_, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectError && tt.expectedError != "" {
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain %q, got %q", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestCommandInvalidArguments tests commands with invalid arguments
func TestCommandInvalidArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "ban without IP",
			args:        []string{"ban"},
			expectError: true,
		},
		{
			name:        "unban without IP",
			args:        []string{"unban"},
			expectError: true,
		},
		{
			name:        "test without IP",
			args:        []string{"test"},
			expectError: true,
		},
		{
			name:        "test-filter without filter",
			args:        []string{"test-filter"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			mock.Filters = []string{"sshd", "apache"}

			_, err := executeCommand(mock, tt.args...)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
