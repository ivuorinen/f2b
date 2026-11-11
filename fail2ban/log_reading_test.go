// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// cleanupLogFiles removes existing log files from temp directory
func cleanupLogFiles(t *testing.T, tempDir string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(tempDir, "fail2ban.log*"))
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			t.Fatalf("failed to remove file: %v", err)
		}
	}
}

// createCompressedTestFile creates a gzip compressed test file
func createCompressedTestFile(t *testing.T, filePath, content string) {
	t.Helper()
	// #nosec G304 - filePath is safely constructed from tempDir and test data
	file, err := os.Create(filePath)
	require.NoError(t, err, "create compressed file")
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("failed to close file: %v", err)
		}
	}()

	gzWriter := gzip.NewWriter(file)
	_, err = gzWriter.Write([]byte(content))
	if err != nil {
		t.Fatalf("failed to write compressed content: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
}

// validateLogLines validates that the read lines match expected lines
func validateLogLines(t *testing.T, lines []string, expected []string, _ string) {
	t.Helper()
	if len(lines) != len(expected) {
		t.Errorf("expected %d lines, got %d", len(expected), len(lines))
	}

	for i, expectedLine := range expected {
		if i >= len(lines) {
			t.Errorf("expected line %d to be %q, but only got %d lines", i, expectedLine, len(lines))
		} else if lines[i] != expectedLine {
			t.Errorf("expected line %d to be %q, got %q", i, expectedLine, lines[i])
		}
	}
}

// TestLogFileReading tests reading different types of log files
func TestLogFileReading(t *testing.T) {
	tempDir := t.TempDir()
	SetLogDir(tempDir)

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
			cleanupLogFiles(t, tempDir)

			// Create test file
			filePath := filepath.Join(tempDir, tt.filename)
			if tt.compressed {
				createCompressedTestFile(t, filePath, tt.content)
			} else {
				err := os.WriteFile(filePath, []byte(tt.content), 0600)
				require.NoError(t, err, "write regular file")
			}

			// Test reading
			lines, err := readLogs(context.Background(), "", "")
			require.NoError(t, err, tt.name)

			validateLogLines(t, lines, tt.expected, tt.name)
		})
	}
}

// TestLogFileOrdering tests that log files are read in chronological order
func TestLogFileOrdering(t *testing.T) {
	tempDir := t.TempDir()
	SetLogDir(tempDir)

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

	lines, err := readLogs(context.Background(), "", "")
	require.NoError(t, err, "GetLogLines ordering test")

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
	SetLogDir(tempDir)

	logContent := `2024-01-01 12:00:00 [sshd] Found 192.168.1.100
2024-01-01 12:01:00 [sshd] Ban 192.168.1.100
2024-01-01 12:02:00 [apache] Found 192.168.1.101
2024-01-01 12:03:00 [apache] Ban 192.168.1.101
2024-01-01 12:04:00 [nginx] Found 192.168.1.102`

	err := os.WriteFile(filepath.Join(tempDir, "fail2ban.log"), []byte(logContent), 0600)
	require.NoError(t, err, "create test log file for filtering")

	tests := []struct {
		name          string
		jailFilter    string
		ipFilter      string
		expectedCount int
	}{
		{name: "no filter", expectedCount: 5},
		{name: "filter by jail sshd", jailFilter: "sshd", expectedCount: 2},
		{name: "filter by IP 192.168.1.100", ipFilter: "192.168.1.100", expectedCount: 2},
		{
			name:          "filter by jail apache and IP 192.168.1.101",
			jailFilter:    "apache",
			ipFilter:      "192.168.1.101",
			expectedCount: 2,
		},
		{name: "filter by nonexistent jail", jailFilter: "nonexistent", expectedCount: 0},
		{name: "filter by nonexistent IP", ipFilter: "10.0.0.1", expectedCount: 0},
		{name: "filter by 'all' jail", jailFilter: "all", expectedCount: 5},
		{name: "filter by 'all' IP", ipFilter: "all", expectedCount: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := readLogs(context.Background(), tt.jailFilter, tt.ipFilter)
			require.NoError(t, err, tt.name)

			if len(lines) != tt.expectedCount {
				t.Errorf("expected %d lines, got %d", tt.expectedCount, len(lines))
			}
		})
	}
}
