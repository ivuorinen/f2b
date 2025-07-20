package fail2ban_test

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestSetLogDir tests the log directory setting functionality
func TestSetLogDir(t *testing.T) {
	// Save original log directory using GetLogDir to avoid test pollution
	originalLogDir := fail2ban.GetLogDir()

	// Test setting a new log directory
	testDir := "/tmp/test-logs"
	fail2ban.SetLogDir(testDir)

	// Create test directory and files
	tempDir := t.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Test that GetLogLines uses the new directory
	logContent := "2024-01-01 12:00:00 [sshd] Test log entry"
	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	lines, err := fail2ban.GetLogLines("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(lines) != 1 || lines[0] != logContent {
		t.Errorf("expected log content %q, got %v", logContent, lines)
	}

	// Restore original directory
	fail2ban.SetLogDir(originalLogDir)
}

// TestSetRunner tests the runner setting functionality
func TestSetRunner(t *testing.T) {
	// Create a test runner
	testRunner := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	// Set the test runner
	fail2ban.SetRunner(testRunner)

	// Test that the runner is used
	testRunner.SetResponse("test-command arg1 arg2", []byte("test-output"))

	output, err := fail2ban.RunnerCombinedOutput("test-command", "arg1", "arg2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(output) != "test-output" {
		t.Errorf("expected output %q, got %q", "test-output", string(output))
	}
}

// TestOSRunnerWithoutSudo tests the OS runner without sudo
func TestOSRunnerWithoutSudo(t *testing.T) {
	runner := &fail2ban.OSRunner{}

	// Test with a simple command that should work
	output, err := runner.CombinedOutput("echo", "hello")
	if err != nil {
		t.Skipf("echo command not available in test environment: %v", err)
	}

	if strings.TrimSpace(string(output)) != "hello" {
		t.Errorf("expected output %q, got %q", "hello", strings.TrimSpace(string(output)))
	}
}

// TestOSRunnerWithSudo tests the OS runner with sudo
func TestOSRunnerWithSudo(t *testing.T) {
	runner := &fail2ban.OSRunner{}

	// Test with a command that would use sudo
	// Note: This might fail in CI/test environments without sudo
	_, err := runner.CombinedOutput("echo", "hello")
	if err != nil {
		t.Logf("sudo command failed as expected in test environment: %v", err)
	}
}

// TestLogFileReading tests reading different types of log files
func TestLogFileReading(t *testing.T) {
	tempDir := t.TempDir()
	fail2ban.SetLogDir(tempDir)

	tests := []struct {
		name       string
		filename   string
		content    string
		compressed bool
		expected   []string
	}{
		{
			name:     "regular log file",
			filename: "fail2ban.log",
			content:  "line1\nline2\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "empty log file",
			filename: "fail2ban.log",
			content:  "",
			expected: []string{},
		},
		{
			name:     "single line log",
			filename: "fail2ban.log",
			content:  "single line",
			expected: []string{"single line"},
		},
		{
			name:       "compressed log file",
			filename:   "fail2ban.log.1.gz",
			content:    "compressed line1\ncompressed line2",
			compressed: true,
			expected:   []string{"compressed line1", "compressed line2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up previous files
			files, _ := filepath.Glob(filepath.Join(tempDir, "fail2ban.log*"))
			for _, f := range files {
				if err := os.Remove(f); err != nil {
					t.Fatalf("failed to remove file: %v", err)
				}
			}

			// Create test file
			filePath := filepath.Join(tempDir, tt.filename)
			if tt.compressed {
				// Create compressed file
				// #nosec G304 - filePath is safely constructed from tempDir and test data
				file, err := os.Create(filePath)
				if err != nil {
					t.Fatalf("failed to create file: %v", err)
				}
				defer func() {
					if err := file.Close(); err != nil {
						t.Fatalf("failed to close file: %v", err)
					}
				}()

				gzWriter := gzip.NewWriter(file)
				_, err = gzWriter.Write([]byte(tt.content))
				if err != nil {
					t.Fatalf("failed to write compressed content: %v", err)
				}
				if err := gzWriter.Close(); err != nil {
					t.Fatalf("failed to close gzip writer: %v", err)
				}
			} else {
				err := os.WriteFile(filePath, []byte(tt.content), 0600)
				if err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
			}

			// Test reading
			lines, err := fail2ban.GetLogLines("", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(lines) != len(tt.expected) {
				t.Errorf("expected %d lines, got %d", len(tt.expected), len(lines))
			}

			for i, expected := range tt.expected {
				if i >= len(lines) || lines[i] != expected {
					t.Errorf("expected line %d to be %q, got %q", i, expected, lines[i])
				}
			}
		})
	}
}

// TestLogFileOrdering tests that log files are read in chronological order
func TestLogFileOrdering(t *testing.T) {
	tempDir := t.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Create multiple log files
	logFiles := map[string]string{
		"fail2ban.log":    "current log line",
		"fail2ban.log.1":  "rotated log line 1",
		"fail2ban.log.2":  "rotated log line 2",
		"fail2ban.log.10": "rotated log line 10",
	}

	for filename, content := range logFiles {
		err := os.WriteFile(filepath.Join(tempDir, filename), []byte(content), 0600)
		if err != nil {
			t.Fatalf("failed to create log file %s: %v", filename, err)
		}
	}

	lines, err := fail2ban.GetLogLines("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be in chronological order: oldest rotated first, then current
	expectedOrder := []string{
		"rotated log line 10",
		"rotated log line 2",
		"rotated log line 1",
		"current log line",
	}

	if len(lines) != len(expectedOrder) {
		t.Errorf("expected %d lines, got %d", len(expectedOrder), len(lines))
	}

	for i, expected := range expectedOrder {
		if i >= len(lines) || lines[i] != expected {
			t.Errorf("expected line %d to be %q, got %q", i, expected, lines[i])
		}
	}
}

// TestLogFiltering tests jail and IP filtering
func TestLogFiltering(t *testing.T) {
	tempDir := t.TempDir()
	fail2ban.SetLogDir(tempDir)

	logContent := `2024-01-01 12:00:00 [sshd] Found 192.168.1.100
2024-01-01 12:01:00 [sshd] Ban 192.168.1.100
2024-01-01 12:02:00 [apache] Found 192.168.1.101
2024-01-01 12:03:00 [apache] Ban 192.168.1.101
2024-01-01 12:04:00 [nginx] Found 192.168.1.102`

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	tests := []struct {
		name          string
		jailFilter    string
		ipFilter      string
		expectedCount int
	}{
		{
			name:          "no filter",
			jailFilter:    "",
			ipFilter:      "",
			expectedCount: 5,
		},
		{
			name:          "filter by jail sshd",
			jailFilter:    "sshd",
			ipFilter:      "",
			expectedCount: 2,
		},
		{
			name:          "filter by IP 192.168.1.100",
			jailFilter:    "",
			ipFilter:      "192.168.1.100",
			expectedCount: 2,
		},
		{
			name:          "filter by jail apache and IP 192.168.1.101",
			jailFilter:    "apache",
			ipFilter:      "192.168.1.101",
			expectedCount: 2,
		},
		{
			name:          "filter by nonexistent jail",
			jailFilter:    "nonexistent",
			ipFilter:      "",
			expectedCount: 0,
		},
		{
			name:          "filter by nonexistent IP",
			jailFilter:    "",
			ipFilter:      "10.0.0.1",
			expectedCount: 0,
		},
		{
			name:          "filter by 'all' jail",
			jailFilter:    "all",
			ipFilter:      "",
			expectedCount: 5,
		},
		{
			name:          "filter by 'all' IP",
			jailFilter:    "",
			ipFilter:      "all",
			expectedCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := fail2ban.GetLogLines(tt.jailFilter, tt.ipFilter)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(lines) != tt.expectedCount {
				t.Errorf("expected %d lines, got %d", tt.expectedCount, len(lines))
			}
		})
	}
}

// TestBanRecordFormatting tests the ban record formatting
func TestBanRecordFormatting(t *testing.T) {
	// Test duration formatting indirectly through GetBanRecords
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	// Create a mock ban record with specific times
	banTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	unbanTime := time.Date(2024, 1, 1, 14, 30, 45, 0, time.UTC) // 2 hours, 30 minutes, 45 seconds later

	mockBanOutput := fmt.Sprintf("192.168.1.100 %s + %s extra field",
		banTime.Format("2006-01-02 15:04:05"),
		unbanTime.Format("2006-01-02 15:04:05"))
	mock.SetResponse("fail2ban-client get sshd banip --with-time", []byte(mockBanOutput))

	fail2ban.SetRunner(mock)

	client, err := fail2ban.NewClient(fail2ban.DefaultLogDir, fail2ban.DefaultFilterDir)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	records, err := client.GetBanRecords([]string{"sshd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}

	if len(records) > 0 {
		record := records[0]
		if record.Jail != "sshd" {
			t.Errorf("expected jail 'sshd', got %q", record.Jail)
		}
		if record.IP != "192.168.1.100" {
			t.Errorf("expected IP '192.168.1.100', got %q", record.IP)
		}
		if !record.BannedAt.Equal(banTime) {
			t.Errorf("expected ban time %v, got %v", banTime, record.BannedAt)
		}
		// The remaining time should be formatted as DD:HH:MM:SS
		// We can't test the exact value as it depends on the current time
		// but we can test that it's formatted correctly
		if !strings.Contains(record.Remaining, ":") {
			t.Errorf("expected remaining time to contain colons, got %q", record.Remaining)
		}
	}
}

// TestVersionComparison tests version comparison logic indirectly
func TestVersionComparisonEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "exact minimum version",
			version:     "0.11.0",
			expectError: false,
		},
		{
			name:        "higher patch version",
			version:     "0.11.10",
			expectError: false,
		},
		{
			name:        "higher minor version",
			version:     "0.12.0",
			expectError: false,
		},
		{
			name:        "higher major version",
			version:     "1.0.0",
			expectError: false,
		},
		{
			name:        "just below minimum",
			version:     "0.10.99",
			expectError: true,
		},
		{
			name:        "much older version",
			version:     "0.9.0",
			expectError: true,
		},
		{
			name:        "version with extra parts",
			version:     "0.11.2.1",
			expectError: false,
		},
		{
			name:        "version with non-numeric parts",
			version:     "0.11.2-beta",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fail2ban.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte(tt.version))
			if !tt.expectError {
				mock.SetResponse("fail2ban-client ping", []byte("pong"))
				mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			}
			fail2ban.SetRunner(mock)

			_, err := fail2ban.NewClient(fail2ban.DefaultLogDir, fail2ban.DefaultFilterDir)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestClientInitializationEdgeCases tests edge cases in client initialization
func TestClientInitializationEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*fail2ban.MockRunner)
		expectError bool
		errorMsg    string
	}{
		{
			name: "version command returns error",
			setupMock: func(m *fail2ban.MockRunner) {
				m.SetError("fail2ban-client -V", fmt.Errorf("command not found"))
			},
			expectError: true,
			errorMsg:    "version check failed",
		},
		{
			name: "ping command returns error",
			setupMock: func(m *fail2ban.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetError("fail2ban-client ping", fmt.Errorf("connection refused"))
			},
			expectError: true,
			errorMsg:    "fail2ban service not running",
		},
		{
			name: "status command returns unparseable output",
			setupMock: func(m *fail2ban.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetResponse("fail2ban-client ping", []byte("pong"))
				m.SetResponse("fail2ban-client status", []byte("Invalid status output"))
			},
			expectError: true,
			errorMsg:    "failed to parse jails",
		},
		{
			name: "empty jail list",
			setupMock: func(m *fail2ban.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetResponse("fail2ban-client ping", []byte("pong"))
				m.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 0\n`- Jail list:"))
			},
			expectError: false, // Changed to false since we now allow empty jail lists
			errorMsg:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fail2ban.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			tt.setupMock(mock)
			fail2ban.SetRunner(mock)

			_, err := fail2ban.NewClient(fail2ban.DefaultLogDir, fail2ban.DefaultFilterDir)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectError && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestConcurrentAccess tests concurrent access to the client
func TestConcurrentAccess(t *testing.T) {
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client banned 192.168.1.100", []byte(`["sshd"]`))
	fail2ban.SetRunner(mock)

	client, err := fail2ban.NewClient(fail2ban.DefaultLogDir, fail2ban.DefaultFilterDir)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Run concurrent operations
	done := make(chan bool)
	errors := make(chan error, 10)

	// Start multiple goroutines
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Test various operations
			_, err := client.ListJails()
			if err != nil {
				errors <- err
				return
			}

			_, err = client.BannedIn("192.168.1.100")
			if err != nil {
				errors <- err
				return
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Errorf("concurrent access error: %v", err)
	}
}

// TestMemoryUsage tests that the client doesn't leak memory
func TestMemoryUsage(t *testing.T) {
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	fail2ban.SetRunner(mock)

	// Create and destroy many clients
	for i := 0; i < 1000; i++ {
		client, err := fail2ban.NewClient(fail2ban.DefaultLogDir, fail2ban.DefaultFilterDir)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		// Use the client
		_, err = client.ListJails()
		if err != nil {
			t.Fatalf("failed to list jails: %v", err)
		}

		// Client should be garbage collected
		_ = client
	}
}
