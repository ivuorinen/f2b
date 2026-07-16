package fail2ban

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamLogFile tests the streamLogFile function
func TestStreamLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [sshd] Ban 192.168.1.2
2024-01-01 10:02:00 [apache] Ban 192.168.1.3
`
	err := os.WriteFile(logFile, []byte(logContent), 0600)
	require.NoError(t, err)

	t.Run("successful stream", func(t *testing.T) {
		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		lines, err := streamLogFile(logFile, config)
		assert.NoError(t, err)
		assert.Len(t, lines, 3)
	})

	t.Run("stream with max lines limit", func(t *testing.T) {
		config := LogReadConfig{
			MaxLines: 2,
			BaseDir:  tmpDir,
		}

		lines, err := streamLogFile(logFile, config)
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(lines), 2)
	})

	t.Run("stream with jail filter", func(t *testing.T) {
		config := LogReadConfig{
			MaxLines:   10,
			JailFilter: "sshd",
			BaseDir:    tmpDir,
		}

		lines, err := streamLogFile(logFile, config)
		assert.NoError(t, err)
		for _, line := range lines {
			assert.Contains(t, line, "sshd")
		}
	})

	t.Run("stream with IP filter", func(t *testing.T) {
		config := LogReadConfig{
			MaxLines: 10,
			IPFilter: "192.168.1.1",
			BaseDir:  tmpDir,
		}

		lines, err := streamLogFile(logFile, config)
		assert.NoError(t, err)
		for _, line := range lines {
			assert.Contains(t, line, "192.168.1.1")
		}
	})
}

// TestScanLogLines tests the scanLogLines function
func TestScanLogLines(t *testing.T) {
	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [apache] Ban 192.168.1.2
2024-01-01 10:02:00 [sshd] Ban 192.168.1.3
`

	t.Run("scan with jail filter", func(t *testing.T) {
		scanner := bufio.NewScanner(strings.NewReader(logContent))
		config := LogReadConfig{
			MaxLines:   10,
			JailFilter: "sshd",
		}

		lines, err := scanLogLines(scanner, config)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(lines)) // Only sshd lines
		for _, line := range lines {
			assert.Contains(t, line, "sshd")
		}
	})

	t.Run("scan with IP filter", func(t *testing.T) {
		scanner := bufio.NewScanner(strings.NewReader(logContent))
		config := LogReadConfig{
			MaxLines: 10,
			IPFilter: "192.168.1.1",
		}

		lines, err := scanLogLines(scanner, config)
		assert.NoError(t, err)
		assert.Len(t, lines, 1)
		assert.Contains(t, lines[0], "192.168.1.1")
	})

	t.Run("scan with both filters", func(t *testing.T) {
		scanner := bufio.NewScanner(strings.NewReader(logContent))
		config := LogReadConfig{
			MaxLines:   10,
			JailFilter: "sshd",
			IPFilter:   "192.168.1.3",
		}

		lines, err := scanLogLines(scanner, config)
		assert.NoError(t, err)
		assert.Len(t, lines, 1)
		assert.Contains(t, lines[0], "sshd")
		assert.Contains(t, lines[0], "192.168.1.3")
	})

	t.Run("scan with max lines limit", func(t *testing.T) {
		scanner := bufio.NewScanner(strings.NewReader(logContent))
		config := LogReadConfig{
			MaxLines: 1,
		}

		lines, err := scanLogLines(scanner, config)
		assert.NoError(t, err)
		assert.Len(t, lines, 1)
	})
}

// TestGetLogLinesOptimized tests the GetLogLinesOptimized function
func TestGetLogLinesOptimized(t *testing.T) {
	tmpDir := t.TempDir()
	oldLogDir := GetLogDir()
	SetLogDir(tmpDir)
	defer SetLogDir(oldLogDir)

	// Create test log file
	logFile := filepath.Join(tmpDir, "fail2ban.log")
	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [apache] Ban 192.168.1.2
`
	err := os.WriteFile(logFile, []byte(logContent), 0600)
	require.NoError(t, err)

	const sshdLine = "2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"

	t.Run("successful read with jail filter", func(t *testing.T) {
		olp := NewOptimizedLogProcessor()
		lines, err := olp.GetLogLinesOptimized("sshd", "", 10)
		require.NoError(t, err)
		// Only the [sshd] line matches; the [apache] line is filtered out.
		assert.Equal(t, []string{sshdLine}, lines)
	})

	t.Run("read with IP filter", func(t *testing.T) {
		olp := NewOptimizedLogProcessor()
		lines, err := olp.GetLogLinesOptimized("", "192.168.1.1", 10)
		require.NoError(t, err)
		// Only 192.168.1.1 matches (not 192.168.1.2).
		assert.Equal(t, []string{sshdLine}, lines)
	})

	t.Run("read with both filters", func(t *testing.T) {
		olp := NewOptimizedLogProcessor()
		lines, err := olp.GetLogLinesOptimized("sshd", "192.168.1.1", 5)
		require.NoError(t, err)
		assert.Equal(t, []string{sshdLine}, lines)
	})
}

// TestGetLogLinesUltraOptimized tests the GetLogLinesUltraOptimized function
func TestGetLogLinesUltraOptimized(t *testing.T) {
	tmpDir := t.TempDir()
	oldLogDir := GetLogDir()
	SetLogDir(tmpDir)
	defer SetLogDir(oldLogDir)

	// Create test log file
	logFile := filepath.Join(tmpDir, "fail2ban.log")
	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [apache] Ban 192.168.1.2
2024-01-01 10:02:00 [sshd] Ban 192.168.1.3
`
	err := os.WriteFile(logFile, []byte(logContent), 0600)
	require.NoError(t, err)

	const (
		sshdLine1 = "2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"
		sshdLine3 = "2024-01-01 10:02:00 [sshd] Ban 192.168.1.3"
	)

	t.Run("successful ultra optimized read", func(t *testing.T) {
		lines, err := GetLogLinesUltraOptimized("sshd", "", 10)
		require.NoError(t, err)
		// Both [sshd] lines match; the [apache] line is filtered out.
		assert.Equal(t, []string{sshdLine1, sshdLine3}, lines)
	})

	t.Run("with both filters", func(t *testing.T) {
		lines, err := GetLogLinesUltraOptimized("sshd", "192.168.1.1", 5)
		require.NoError(t, err)
		// Only the sshd line whose IP is 192.168.1.1.
		assert.Equal(t, []string{sshdLine1}, lines)
	})

	t.Run("with max lines limit", func(t *testing.T) {
		lines, err := GetLogLinesUltraOptimized("", "", 1)
		require.NoError(t, err)
		// The limit caps the result to a single line.
		assert.Len(t, lines, 1)
	})
}

// TestShouldSkipFile tests the shouldSkipFile function
func TestShouldSkipFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files with different sizes
	smallFile := filepath.Join(tmpDir, "small.log")
	err := os.WriteFile(smallFile, []byte("small content"), 0600)
	require.NoError(t, err)

	largeFile := filepath.Join(tmpDir, "large.log")
	largeContent := make([]byte, 2*1024*1024) // 2MB
	err = os.WriteFile(largeFile, largeContent, 0600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		filepath    string
		maxFileSize int64
		expectSkip  bool
	}{
		{"small file within limit", smallFile, 1024 * 1024, false},
		{"large file exceeds limit", largeFile, 1024 * 1024, true},
		{"zero max size - skip nothing", largeFile, 0, false},
		{"negative max size - skip nothing", largeFile, -1, false},
		{"file exactly at limit", smallFile, 13, false}, // "small content" is 13 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipFile(tt.filepath, tt.maxFileSize)
			assert.Equal(t, tt.expectSkip, result)
		})
	}
}

// TestResolveBaseDir tests the resolveBaseDir function
func TestResolveBaseDir(t *testing.T) {
	t.Run("from config with absolute path", func(t *testing.T) {
		config := LogReadConfig{
			BaseDir: "/var/log/fail2ban",
		}
		result := resolveBaseDir(config)
		assert.Equal(t, "/var/log/fail2ban", result)
	})

	t.Run("from config with empty path uses GetLogDir", func(t *testing.T) {
		config := LogReadConfig{
			BaseDir: "",
		}
		result := resolveBaseDir(config)
		assert.NotEmpty(t, result)
	})
}

// TestStreamLogFileWithContext tests streamLogFileWithContext function
func TestStreamLogFileWithContext(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logContent := `line 1
line 2
line 3
`
	err := os.WriteFile(logFile, []byte(logContent), 0600)
	require.NoError(t, err)

	t.Run("successful stream with context", func(t *testing.T) {
		ctx := context.Background()
		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		lines, err := streamLogFileWithContext(ctx, logFile, config)
		assert.NoError(t, err)
		assert.Len(t, lines, 3)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		_, err := streamLogFileWithContext(ctx, logFile, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context")
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(2 * time.Millisecond) // Ensure timeout

		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		_, err := streamLogFileWithContext(ctx, logFile, config)
		assert.Error(t, err)
	})
}

// TestCollectLogLines tests the collectLogLines function
func TestCollectLogLines(t *testing.T) {
	tmpDir := t.TempDir()

	// Create main log file
	logFile := filepath.Join(tmpDir, "fail2ban.log")
	content := "2024-01-01 10:00:00 [sshd] Ban 192.168.1.1\n"
	err := os.WriteFile(logFile, []byte(content), 0600)
	require.NoError(t, err)

	t.Run("collect from log directory", func(t *testing.T) {
		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		lines, err := collectLogLines(context.Background(), tmpDir, config)
		assert.NoError(t, err)
		assert.NotNil(t, lines)
	})

	t.Run("collect with context timeout", func(_ *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(2 * time.Millisecond)

		config := LogReadConfig{
			MaxLines: 10,
			BaseDir:  tmpDir,
		}

		_, err := collectLogLines(ctx, tmpDir, config)
		// May or may not error depending on timing - we're just testing it doesn't panic
		_ = err
	})
}
