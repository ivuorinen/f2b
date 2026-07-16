package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGetLogLinesErrorHandling tests actual error handling in log line retrieval functions
func TestGetLogLinesErrorHandling(t *testing.T) {
	// Test with non-existent log directory
	t.Run("invalid_log_directory", func(t *testing.T) {
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		// Set log directory to non-existent path
		SetLogDir("/nonexistent/path/that/should/not/exist")

		lines, err := GetLogLines(context.Background(), "sshd", "")
		if err != nil {
			t.Logf("Correctly handled non-existent log directory: %v", err)
		}

		// Should return empty slice for missing directory, not error
		if len(lines) != 0 {
			t.Errorf("Expected empty lines for non-existent directory, got %d lines", len(lines))
		}
	})

	t.Run("empty_log_directory", func(t *testing.T) {
		// Create temporary directory with no log files
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		lines, err := GetLogLines(context.Background(), "sshd", "192.168.1.100")
		if err != nil {
			t.Errorf("Should not error on empty directory, got: %v", err)
		}

		if len(lines) != 0 {
			t.Errorf("Expected no lines from empty directory, got %d", len(lines))
		}
	})

	t.Run("valid_log_with_jail_filter", func(t *testing.T) {
		assertLogFilter(t, "sshd", "", "sshd", 2)
	})

	t.Run("valid_log_with_ip_filter", func(t *testing.T) {
		assertLogFilter(t, "", "192.168.1.100", "192.168.1.100", 2)
	})
}

// assertLogFilter writes the standard test log to a temp dir, calls GetLogLines
// with the given jail/ip filter, and asserts the result count and that every
// line contains want. Centralizing the log content avoids duplicating it (and
// the setup) across filter cases.
func assertLogFilter(t *testing.T, jail, ip, want string, wantCount int) {
	t.Helper()
	setupLogDir(t, `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101`)

	lines, err := GetLogLines(context.Background(), jail, ip)
	if err != nil {
		t.Errorf("GetLogLines should not error with valid log: %v", err)
	}
	if len(lines) != wantCount {
		t.Errorf("expected %d lines, got %d", wantCount, len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, want) {
			t.Errorf("expected %q in line, got: %s", want, line)
		}
	}
}

// TestGetLogLinesWithLimitErrorHandling tests error handling with memory limits
func TestGetLogLinesWithLimitErrorHandling(t *testing.T) {
	t.Run("zero_limit", func(t *testing.T) {
		setupLogDir(t, `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100`)

		lines, err := GetLogLinesWithLimit(context.Background(), "sshd", "", 0)
		if err != nil {
			t.Errorf("GetLogLinesWithLimit should not error with zero limit: %v", err)
		}
		if len(lines) != 0 {
			t.Errorf("Expected no lines with zero limit, got %d", len(lines))
		}
	})

	t.Run("negative_limit", func(t *testing.T) {
		setupLogDir(t, `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100`)

		_, err := GetLogLinesWithLimit(context.Background(), "sshd", "", -1)
		if err == nil {
			t.Error("GetLogLinesWithLimit should error with negative limit")
		} else if !strings.Contains(err.Error(), "must be non-negative") {
			t.Errorf("Expected validation error for negative limit, got: %v", err)
		}
	})

	t.Run("small_limit", func(t *testing.T) {
		setupLogDir(t, `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.101
2024-01-01 12:03:00,012 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.101`)

		lines, err := GetLogLinesWithLimit(context.Background(), "sshd", "", 2)
		if err != nil {
			t.Errorf("GetLogLinesWithLimit should not error: %v", err)
		}
		if len(lines) != 2 {
			t.Errorf("Expected 2 lines due to limit, got %d", len(lines))
		}
	})
}

// setupLogDir points GetLogDir at a fresh temp dir containing a fail2ban.log
// with the given content, restoring the original dir on cleanup.
func setupLogDir(t *testing.T, content string) {
	t.Helper()
	tempDir := t.TempDir()
	original := GetLogDir()
	t.Cleanup(func() { SetLogDir(original) })
	SetLogDir(tempDir)
	if err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test log file: %v", err)
	}
}
