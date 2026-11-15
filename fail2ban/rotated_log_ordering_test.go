package fail2ban

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractLogNumberOrdersRotatedNames pins the key that decides which log is
// read first: a higher key is older, so dated names are negated to make a later
// date sort as newer.
func TestExtractLogNumberOrdersRotatedNames(t *testing.T) {
	tests := []struct {
		name string
		key  int
		ok   bool
	}{
		{"fail2ban.log.1", 1, true},
		{"fail2ban.log.2.gz", 2, true},
		{"fail2ban.log.gz", 0, true},
		{"fail2ban.log.20240131", -20240131, true},
		{"fail2ban.log.20240131.gz", -20240131, true},
		{"fail2ban.log.99999999", 99999999, true}, // eight digits, but no such date
		{"fail2ban.log-20240131", -20240131, true},
		{"fail2ban.log-20240131.gz", -20240131, true},
		{"fail2ban.log-rotated", 0, false},
		{"fail2ban.log.old", 0, false},
		{"auth.log", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok := extractLogNumber(tt.name)
			assert.Equal(t, tt.key, key)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

// TestCollectLogLinesReturnsNothingWithoutALimit uses an empty directory, which
// is an error once a read is actually attempted.
func TestCollectLogLinesReturnsNothingWithoutALimit(t *testing.T) {
	lines, err := collectLogLines(context.Background(), t.TempDir(), LogReadConfig{MaxLines: 0})

	require.NoError(t, err)
	assert.Empty(t, lines)
}

func TestCollectLogLinesReportsAMalformedLogDirectory(t *testing.T) {
	_, err := collectLogLines(context.Background(), "[", LogReadConfig{MaxLines: 5})

	require.ErrorIs(t, err, filepath.ErrBadPattern)
}

func TestShouldSkipFileKeepsAMissingFile(t *testing.T) {
	assert.False(t, shouldSkipFile(filepath.Join(t.TempDir(), "missing"), 10))
}
