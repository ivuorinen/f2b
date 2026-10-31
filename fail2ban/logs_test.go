package fail2ban

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamLogFileWithContext covers per-file streaming: limits, filters and
// cancellation.
func TestStreamLogFileWithContext(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [sshd] Ban 192.168.1.2
2024-01-01 10:02:00 [apache] Ban 192.168.1.3
`
	require.NoError(t, os.WriteFile(logFile, []byte(logContent), 0600))

	t.Run("successful stream", func(t *testing.T) {
		lines, err := streamLogFileWithContext(
			context.Background(),
			logFile,
			LogReadConfig{MaxLines: 10, BaseDir: tmpDir},
		)
		require.NoError(t, err)
		assert.Len(t, lines, 3)
	})

	t.Run("stream with max lines limit", func(t *testing.T) {
		lines, err := streamLogFileWithContext(
			context.Background(),
			logFile,
			LogReadConfig{MaxLines: 2, BaseDir: tmpDir},
		)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"2024-01-01 10:00:00 [sshd] Ban 192.168.1.1",
			"2024-01-01 10:01:00 [sshd] Ban 192.168.1.2",
		}, lines)
	})

	t.Run("stream with jail filter", func(t *testing.T) {
		config := LogReadConfig{MaxLines: 10, JailFilter: "sshd", BaseDir: tmpDir}
		lines, err := streamLogFileWithContext(context.Background(), logFile, config)
		require.NoError(t, err)
		assert.Len(t, lines, 2)
		for _, line := range lines {
			assert.Contains(t, line, "[sshd]")
		}
	})

	t.Run("stream with IP filter", func(t *testing.T) {
		config := LogReadConfig{MaxLines: 10, IPFilter: "192.168.1.1", BaseDir: tmpDir}
		lines, err := streamLogFileWithContext(context.Background(), logFile, config)
		require.NoError(t, err)
		assert.Equal(t, []string{"2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"}, lines)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := streamLogFileWithContext(ctx, logFile, LogReadConfig{MaxLines: 10, BaseDir: tmpDir})
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(2 * time.Millisecond) // Ensure timeout
		_, err := streamLogFileWithContext(ctx, logFile, LogReadConfig{MaxLines: 10, BaseDir: tmpDir})
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

// TestScanLogLinesWithContext covers the line scanner's filters and limit.
func TestScanLogLinesWithContext(t *testing.T) {
	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [apache] Ban 192.168.1.2
2024-01-01 10:02:00 [sshd] Ban 192.168.1.3
`
	scan := func(t *testing.T, config LogReadConfig) []string {
		t.Helper()
		scanner := bufio.NewScanner(strings.NewReader(logContent))
		lines, err := scanLogLinesWithContext(context.Background(), scanner, prepareLogFilters(config))
		require.NoError(t, err)
		return lines
	}

	t.Run("scan with jail filter", func(t *testing.T) {
		lines := scan(t, LogReadConfig{MaxLines: 10, JailFilter: "sshd"})
		assert.Len(t, lines, 2)
		for _, line := range lines {
			assert.Contains(t, line, "[sshd]")
		}
	})

	t.Run("scan with IP filter", func(t *testing.T) {
		lines := scan(t, LogReadConfig{MaxLines: 10, IPFilter: "192.168.1.1"})
		assert.Equal(t, []string{"2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"}, lines)
	})

	t.Run("scan with both filters", func(t *testing.T) {
		lines := scan(t, LogReadConfig{MaxLines: 10, JailFilter: "sshd", IPFilter: "192.168.1.3"})
		assert.Equal(t, []string{"2024-01-01 10:02:00 [sshd] Ban 192.168.1.3"}, lines)
	})

	t.Run("scan with max lines limit", func(t *testing.T) {
		lines := scan(t, LogReadConfig{MaxLines: 1})
		assert.Equal(t, []string{"2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"}, lines)
	})
}

// TestRealClientLogFilters reads through the client entry point, the only
// production log read, and checks the jail/IP filters and the line limit.
func TestRealClientLogFilters(t *testing.T) {
	tmpDir := t.TempDir()
	logContent := `2024-01-01 10:00:00 [sshd] Ban 192.168.1.1
2024-01-01 10:01:00 [apache] Ban 192.168.1.2
2024-01-01 10:02:00 [sshd] Ban 192.168.1.3
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fail2ban.log"), []byte(logContent), 0600))
	client := &RealClient{LogDir: tmpDir}

	const (
		sshdLine1 = "2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"
		sshdLine3 = "2024-01-01 10:02:00 [sshd] Ban 192.168.1.3"
	)

	tests := []struct {
		name     string
		jail, ip string
		maxLines int
		want     []string
	}{
		{name: "jail filter", jail: "sshd", maxLines: 10, want: []string{sshdLine1, sshdLine3}},
		{name: "IP filter", ip: "192.168.1.1", maxLines: 10, want: []string{sshdLine1}},
		{name: "both filters", jail: "sshd", ip: "192.168.1.1", maxLines: 5, want: []string{sshdLine1}},
		{name: "limit keeps the newest line", maxLines: 1, want: []string{sshdLine3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := client.GetLogLinesWithLimitContext(context.Background(), tt.jail, tt.ip, tt.maxLines)
			require.NoError(t, err)
			assert.Equal(t, tt.want, lines)
		})
	}
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
		assert.Equal(t, GetLogDir(), result)
	})
}

// writeLogLines writes n numbered lines tagged with name to dir/name.
func writeLogLines(t *testing.T, dir, name string, n int) []string {
	t.Helper()
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("2024-01-01 10:00:%02d [sshd] Ban 192.168.1.1 %s#%d", i, name, i)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0600))
	return lines
}

// TestCollectLogLines pins the collector's result shape and context handling.
func TestCollectLogLines(t *testing.T) {
	tmpDir := t.TempDir()
	content := "2024-01-01 10:00:00 [sshd] Ban 192.168.1.1\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "fail2ban.log"), []byte(content), 0600))

	t.Run("collect from log directory", func(t *testing.T) {
		lines, err := collectLogLines(context.Background(), tmpDir, LogReadConfig{MaxLines: 10, BaseDir: tmpDir})
		require.NoError(t, err)
		assert.Equal(t, []string{"2024-01-01 10:00:00 [sshd] Ban 192.168.1.1"}, lines)
	})

	t.Run("collect with context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(2 * time.Millisecond)

		lines, err := collectLogLines(ctx, tmpDir, LogReadConfig{MaxLines: 10, BaseDir: tmpDir})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, lines)
	})

	t.Run("no matches returns an empty non-nil slice", func(t *testing.T) {
		// JSON output encodes this slice: nil printed null instead of [].
		config := LogReadConfig{MaxLines: 10, BaseDir: tmpDir, IPFilter: "9.9.9.9"}
		lines, err := collectLogLines(context.Background(), tmpDir, config)
		require.NoError(t, err)
		require.NotNil(t, lines)
		assert.Empty(t, lines)
	})
}

// TestCollectLogLinesNewestFirstAcrossRotatedLogs pins the chronological
// result when the window spans the current log and rotated logs.
func TestCollectLogLinesNewestFirstAcrossRotatedLogs(t *testing.T) {
	dir := t.TempDir()
	oldest := writeLogLines(t, dir, "fail2ban.log.2", 2)
	older := writeLogLines(t, dir, "fail2ban.log.1", 2)
	current := writeLogLines(t, dir, "fail2ban.log", 2)

	lines, err := collectLogLines(context.Background(), dir, LogReadConfig{MaxLines: 5, BaseDir: dir})
	require.NoError(t, err)

	want := append(append(append([]string{}, oldest[1:]...), older...), current...)
	assert.Equal(t, want, lines)
}

// TestCollectLogLinesStopsOnceCurrentLogSuffices pins the early stop: a
// window the current log fills must not open the rotated archives. The
// rotated file here is a corrupt gzip, so reading it would log a failure.
func TestCollectLogLinesStopsOnceCurrentLogSuffices(t *testing.T) {
	dir := t.TempDir()
	current := writeLogLines(t, dir, "fail2ban.log", 3)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fail2ban.log.1.gz"), []byte("not gzip"), 0600))
	buf := captureFail2banLog(t)

	lines, err := collectLogLines(context.Background(), dir, LogReadConfig{MaxLines: 2, BaseDir: dir})
	require.NoError(t, err)
	assert.Equal(t, current[1:], lines)
	assert.NotContains(
		t,
		buf.String(),
		"Failed to read log file",
		"rotated log was read although the current log sufficed",
	)

	// Control: a window larger than the current log does reach the rotated log.
	lines, err = collectLogLines(context.Background(), dir, LogReadConfig{MaxLines: 10, BaseDir: dir})
	require.NoError(t, err)
	assert.Equal(t, current, lines)
	assert.Contains(t, buf.String(), "Failed to read log file")
}

// TestCollectLogLinesReturnsErrorWhenNoFileReadable pins that "nothing could
// be read" is an error, not an empty success that looks like "no matches".
func TestCollectLogLinesReturnsErrorWhenNoFileReadable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fail2ban.log.1.gz"), []byte("not gzip"), 0600))

	lines, err := collectLogLines(context.Background(), dir, LogReadConfig{MaxLines: 10, BaseDir: dir})
	require.Error(t, err)
	assert.Nil(t, lines)

	// One readable file is enough: the unreadable one is logged and skipped.
	current := writeLogLines(t, dir, "fail2ban.log", 1)
	lines, err = collectLogLines(context.Background(), dir, LogReadConfig{MaxLines: 10, BaseDir: dir})
	require.NoError(t, err)
	assert.Equal(t, current, lines)
}

// TestCollectLogLinesTailsOversizedCurrentLog pins the oversized-log path:
// the active log is tailed to its newest MaxFileSize bytes with the first
// (partial) line discarded, while an oversized rotated log is skipped.
func TestCollectLogLinesTailsOversizedCurrentLog(t *testing.T) {
	dir := t.TempDir()
	writeLogLines(t, dir, "fail2ban.log.1", 50)
	current := writeLogLines(t, dir, "fail2ban.log", 50)

	const maxFileSize = 200
	data, err := os.ReadFile(filepath.Join(dir, "fail2ban.log")) // #nosec G304 -- test temp file
	require.NoError(t, err)
	tail := string(data[len(data)-maxFileSize:])
	// The complete lines inside the last maxFileSize bytes: everything after
	// the first newline of the tail.
	want := strings.Split(strings.TrimSpace(tail[strings.IndexByte(tail, '\n')+1:]), "\n")
	require.NotEmpty(t, want)
	require.Less(t, len(want), len(current))

	lines, err := collectLogLines(context.Background(), dir,
		LogReadConfig{MaxLines: 1000, MaxFileSize: maxFileSize, BaseDir: dir})
	require.NoError(t, err)
	assert.Equal(t, want, lines)
	assert.Equal(t, current[len(current)-len(want):], lines)
}
