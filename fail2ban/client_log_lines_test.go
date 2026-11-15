package fail2ban_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

func TestGetLogLines(t *testing.T) {
	// Create a temporary test log directory
	tempDir := t.TempDir()
	client := &fail2ban.RealClient{LogDir: tempDir}

	// Create test log files
	logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100 - 2024-01-01 12:00:00
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101 - 2024-01-01 12:02:00`

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	mock := fail2bantest.NewMockRunner()
	fail2bantest.StandardMockSetup(mock)
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))

	tests := []struct {
		name          string
		jail          string
		ip            string
		expectedLines int
	}{
		{
			name:          "all logs",
			jail:          "",
			ip:            "",
			expectedLines: 3,
		},
		{
			name:          "filter by jail",
			jail:          "sshd",
			ip:            "",
			expectedLines: 2,
		},
		{
			name:          "filter by IP",
			jail:          "",
			ip:            "192.168.1.100",
			expectedLines: 2,
		},
		{
			name:          "filter by jail and IP",
			jail:          "sshd",
			ip:            "192.168.1.100",
			expectedLines: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := client.GetLogLinesWithContext(context.Background(), tt.jail, tt.ip)
			fail2bantest.AssertError(t, err, false, "get log lines")

			if len(lines) != tt.expectedLines {
				t.Errorf("expected %d lines, got %d", tt.expectedLines, len(lines))
			}
		})
	}
}

func TestGetLogLinesWithLimitPrefersRecent(t *testing.T) {
	logDir := t.TempDir()
	oldPath := filepath.Join(logDir, "fail2ban.log.1")
	newPath := filepath.Join(logDir, "fail2ban.log")

	// Older rotated log with more entries than the requested limit
	oldContent := "old-entry-1\nold-entry-2\nold-entry-3\n"
	if err := os.WriteFile(oldPath, []byte(oldContent), 0o600); err != nil {
		t.Fatalf("failed to create rotated log: %v", err)
	}

	// Current log with the most recent entries
	newContent := "new-entry-1\nnew-entry-2\n"
	if err := os.WriteFile(newPath, []byte(newContent), 0o600); err != nil {
		t.Fatalf("failed to create current log: %v", err)
	}

	expected := []string{"new-entry-1", "new-entry-2"}

	client := &fail2ban.RealClient{LogDir: logDir}
	clientLines, err := client.GetLogLinesWithLimitContext(context.Background(), "", "", 2)
	if err != nil {
		t.Fatalf("RealClient.GetLogLinesWithLimitContext returned error: %v", err)
	}

	if !reflect.DeepEqual(clientLines, expected) {
		t.Fatalf("client expected %v, got %v", expected, clientLines)
	}

	// A window wider than the current log reaches back into the rotated log
	// and stays chronological.
	clientLines, err = client.GetLogLinesWithLimitContext(context.Background(), "", "", 4)
	if err != nil {
		t.Fatalf("RealClient.GetLogLinesWithLimitContext returned error: %v", err)
	}
	expected = []string{"old-entry-2", "old-entry-3", "new-entry-1", "new-entry-2"}
	if !reflect.DeepEqual(clientLines, expected) {
		t.Fatalf("client expected %v, got %v", expected, clientLines)
	}
}

func TestGetLogLinesMethod(t *testing.T) {
	// Test that real client's GetLogLines method exists
	// Create a temporary directory for the test
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	tmpDir := t.TempDir()

	// Set up test environment
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, false)
	defer cleanup()
	fail2bantest.StandardMockSetup(fail2bantest.MustMockRunner(t)) // NewClient's version check needs a response

	// NewClient with valid temp dirs must succeed in the test environment;
	// a skip here would hide a real NewClient regression.
	client, err := fail2ban.NewClient(tmpDir, tmpDir)
	if err != nil {
		t.Fatalf("NewClient with valid temp dirs failed: %v", err)
	}

	// A directory holding no fail2ban log is an error, not an empty result.
	if lines, err := client.GetLogLinesWithContext(context.Background(), "sshd", "192.168.1.1"); err == nil {
		t.Fatalf("GetLogLinesWithContext on empty dir returned no error, lines=%v", lines)
	}
}
