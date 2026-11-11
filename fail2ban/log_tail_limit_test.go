package fail2ban

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
)

// scanLines runs the line scanner over numbered lines "line0".."lineN-1".
func scanLines(t *testing.T, count int, config LogReadConfig) []string {
	t.Helper()
	var input strings.Builder
	for i := range count {
		fmt.Fprintf(&input, "line%d\n", i)
	}
	scanner := bufio.NewScanner(strings.NewReader(input.String()))
	lines, err := scanLogLinesWithContext(context.Background(), scanner, prepareLogFilters(config))
	require.NoError(t, err)
	return lines
}

// TestFileReadTailsToTheRequestedLimit pins the wiring: a per-file read returns
// at most the limit, the newest lines, so the buffer never holds the whole file.
func TestFileReadTailsToTheRequestedLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fail2ban.log")
	require.NoError(t, os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0600))

	lines, err := readLogLinesFromFile(context.Background(), path, LogReadConfig{MaxLines: 2, BaseDir: dir}, true)

	require.NoError(t, err)
	assert.Equal(t, []string{"two", "three"}, lines)
}

func TestScanLogLinesKeepsOnlyTheNewestWhenTailing(t *testing.T) {
	assert.Equal(t, []string{"line8", "line9"}, scanLines(t, 10, LogReadConfig{TailLines: 2}))
}

func TestScanLogLinesReturnsEverythingBelowTheTailLimit(t *testing.T) {
	assert.Equal(t, []string{"line0", "line1"}, scanLines(t, 2, LogReadConfig{TailLines: 5}))
}

// TestScanLogLinesBoundsMemoryWhenTailing pins why tailing exists: a read of 10
// lines used to hold every matching line of a 100 MB log in memory.
func TestScanLogLinesBoundsMemoryWhenTailing(t *testing.T) {
	lines := scanLines(t, 10000, LogReadConfig{TailLines: 2})

	require.Len(t, lines, 2)
	assert.Less(t, cap(lines), 64, "the retained buffer grew with the file, not the limit")
}

// TestSalvageKeepsLinesReadBeforeARecoverableDefect pins that one oversized
// line or a truncated gzip keeps the lines already read.
func TestSalvageKeepsLinesReadBeforeARecoverableDefect(t *testing.T) {
	recoverable := map[string]error{
		"oversized line": bufio.ErrTooLong,
		"truncated gzip": io.ErrUnexpectedEOF,
		"bad gzip body":  gzip.ErrChecksum,
		"bad gzip head":  gzip.ErrHeader,
	}
	for name, defect := range recoverable {
		t.Run(name, func(t *testing.T) {
			lines, err := salvageScannedLines([]string{"kept"}, defect)
			require.NoError(t, err)
			assert.Equal(t, []string{"kept"}, lines)
		})
	}
}

func TestSalvageReportsARealReadFailure(t *testing.T) {
	lines, err := salvageScannedLines([]string{"kept"}, errors.New("input/output error"))

	require.Error(t, err)
	assert.Nil(t, lines)
}

// TestGzipReaderStopsAtTheDecompressionCap pins the gzip-bomb guard at its
// boundary, starting the counter next to the cap so no 100 MB stream is needed.
func TestGzipReaderStopsAtTheDecompressionCap(t *testing.T) {
	reader := &gzipFileReader{reader: strings.NewReader("abc"), read: constants.DefaultMaxFileSize - 1, path: "x.gz"}
	buf := make([]byte, 8)

	n, err := reader.Read(buf)

	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, "a", string(buf[:n]))
}

func TestGzipReaderPassesThroughBelowTheCap(t *testing.T) {
	reader := &gzipFileReader{reader: strings.NewReader("abc"), read: constants.DefaultMaxFileSize - 3, path: "x.gz"}
	buf := make([]byte, 8)

	n, err := reader.Read(buf)

	require.NoError(t, err)
	assert.Equal(t, "abc", string(buf[:n]))
}
