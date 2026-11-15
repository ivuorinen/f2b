package fail2ban

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureFail2banLog routes the package logger to a buffer for the test.
func captureFail2banLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	l := NewSlogLogger(SlogText)
	l.SetOutput(&buf)
	l.SetLevel(slog.LevelDebug)
	previous := getLogger()
	SetLogger(l)
	t.Cleanup(func() { SetLogger(previous) })
	return &buf
}

// TestParseBanRecordsWarnsOnSkippedLines pins that unparseable lines beside
// readable ones are reported rather than dropped silently. Blank lines are
// not counted.
func TestParseBanRecordsWarnsOnSkippedLines(t *testing.T) {
	input := "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining\n" +
		"\n" +
		"ticket-42 2025-07-20 14:36:59 + 2025-07-20 14:46:59 remaining\n" +
		"not-an-ip\n"

	t.Run("skipped lines are counted and logged", func(t *testing.T) {
		buf := captureFail2banLog(t)
		records, err := ParseBanRecords(input, "sshd")
		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Contains(t, buf.String(), "Skipped unparseable ban record lines")
		assert.Contains(t, buf.String(), "skipped=2")
		assert.Contains(t, buf.String(), "jail=sshd")
	})

	t.Run("clean input logs no warning", func(t *testing.T) {
		buf := captureFail2banLog(t)
		records, err := ParseBanRecords(benchmarkBanRecordOutput, "sshd")
		require.NoError(t, err)
		require.Len(t, records, len(benchmarkBanRecordData))
		assert.NotContains(t, buf.String(), "Skipped unparseable")
	})
}
