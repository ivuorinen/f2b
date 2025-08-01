package fail2ban

import (
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

		lines, err := GetLogLines("sshd", "")
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

		lines, err := GetLogLines("sshd", "192.168.1.100")
		if err != nil {
			t.Errorf("Should not error on empty directory, got: %v", err)
		}

		if len(lines) != 0 {
			t.Errorf("Expected no lines from empty directory, got %d", len(lines))
		}
	})

	t.Run("valid_log_with_jail_filter", func(t *testing.T) {
		// Create temporary log directory with test data
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		// Create test log file with sshd entries
		logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101`

		err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test filtering by jail
		lines, err := GetLogLines("sshd", "")
		if err != nil {
			t.Errorf("GetLogLines should not error with valid log: %v", err)
		}

		expectedSSHLines := 2 // Two sshd entries
		if len(lines) != expectedSSHLines {
			t.Errorf("Expected %d sshd lines, got %d", expectedSSHLines, len(lines))
		}

		// Verify content
		for _, line := range lines {
			if !strings.Contains(line, "sshd") {
				t.Errorf("Expected sshd in line, got: %s", line)
			}
		}
	})

	t.Run("valid_log_with_ip_filter", func(t *testing.T) {
		// Create temporary log directory with test data
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [apache] Found 192.168.1.101`

		err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test filtering by IP
		lines, err := GetLogLines("", "192.168.1.100")
		if err != nil {
			t.Errorf("GetLogLines should not error with valid log: %v", err)
		}

		expectedIPLines := 2 // Two entries for 192.168.1.100
		if len(lines) != expectedIPLines {
			t.Errorf("Expected %d lines for IP, got %d", expectedIPLines, len(lines))
		}

		// Verify content
		for _, line := range lines {
			if !strings.Contains(line, "192.168.1.100") {
				t.Errorf("Expected IP in line, got: %s", line)
			}
		}
	})
}

// TestGetLogLinesWithLimitErrorHandling tests error handling with memory limits
func TestGetLogLinesWithLimitErrorHandling(t *testing.T) {
	t.Run("zero_limit", func(t *testing.T) {
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100`

		err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test with zero limit
		lines, err := GetLogLinesWithLimit("sshd", "", 0)
		if err != nil {
			t.Errorf("GetLogLinesWithLimit should not error with zero limit: %v", err)
		}

		// Should return empty due to limit
		if len(lines) != 0 {
			t.Errorf("Expected no lines with zero limit, got %d", len(lines))
		}
	})

	t.Run("negative_limit", func(t *testing.T) {
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100`

		err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test with negative limit (should be treated as unlimited)
		lines, err := GetLogLinesWithLimit("sshd", "", -1)
		if err != nil {
			t.Errorf("GetLogLinesWithLimit should not error with negative limit: %v", err)
		}

		// Should return available lines
		if len(lines) == 0 {
			t.Error("Expected lines with negative limit (unlimited)")
		}
	})

	t.Run("small_limit", func(t *testing.T) {
		tempDir := t.TempDir()
		originalDir := GetLogDir()
		defer SetLogDir(originalDir)

		SetLogDir(tempDir)

		// Create log with multiple entries
		logContent := `2024-01-01 12:00:00,123 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:02:00,789 fail2ban.filter [1234]: INFO [sshd] Found 192.168.1.101
2024-01-01 12:03:00,012 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.101`

		err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
		if err != nil {
			t.Fatalf("Failed to create test log file: %v", err)
		}

		// Test with limit of 2
		lines, err := GetLogLinesWithLimit("sshd", "", 2)
		if err != nil {
			t.Errorf("GetLogLinesWithLimit should not error: %v", err)
		}

		// Should respect the limit
		if len(lines) != 2 {
			t.Errorf("Expected 2 lines due to limit, got %d", len(lines))
		}
	})
}
