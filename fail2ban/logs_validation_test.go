package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
)

func TestGetLogLinesWithLimit_ValidatesNegativeMaxLines(t *testing.T) {
	_, err := GetLogLinesWithLimit(context.Background(), "", "", -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-negative")
}

func TestGetLogLinesWithLimit_ValidatesExcessiveMaxLines(t *testing.T) {
	_, err := GetLogLinesWithLimit(context.Background(), "", "", constants.MaxLogLinesLimit+1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed value")
}

func TestGetLogLinesWithLimit_AcceptsValidMaxLines(t *testing.T) {
	// Use an existing fixture (testdata/fail2ban.log does not exist, which made
	// this test silently skip).
	cleanup := setupTestLogEnvironment(t, "testdata/fail2ban_sample.log")
	defer cleanup()

	// A valid maxLines returns the fixture's lines without error.
	lines, err := GetLogLinesWithLimit(context.Background(), "", "", 10)
	require.NoError(t, err)
	assert.NotEmpty(t, lines, "the sample fixture should yield log lines")
}

func TestGetLogLinesOptimized_ValidatesNegativeMaxLines(t *testing.T) {
	olp := &OptimizedLogProcessor{}
	_, err := olp.GetLogLinesOptimized("", "", -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-negative")
}

func TestGetLogLinesOptimized_ValidatesExcessiveMaxLines(t *testing.T) {
	olp := &OptimizedLogProcessor{}
	_, err := olp.GetLogLinesOptimized("", "", constants.MaxLogLinesLimit+1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed value")
}

func TestGetLogLinesWithLimit_AcceptsZeroMaxLines(t *testing.T) {
	// Should return empty slice for zero maxLines
	lines, err := GetLogLinesWithLimit(context.Background(), "", "", 0)
	assert.NoError(t, err)
	assert.Empty(t, lines)
}

func TestGetLogLinesWithLimit_SanitizesFilters(t *testing.T) {
	cleanup := setupTestLogEnvironment(t, "testdata/fail2ban_sample.log")
	defer cleanup()

	ctx := context.Background()

	// A whitespace-padded filter must be trimmed and behave identically to the
	// clean filter. If it were not trimmed, the jail pattern "[  sshd  ]" would
	// match nothing (empty result) and the padded IP would fail net.ParseIP.
	padded, err := GetLogLinesWithLimit(ctx, "  sshd  ", "  192.168.1.100  ", 10)
	require.NoError(t, err)
	clean, err := GetLogLinesWithLimit(ctx, "sshd", "192.168.1.100", 10)
	require.NoError(t, err)

	assert.NotEmpty(t, clean, "the sshd/192.168.1.100 filter should match the fixture")
	assert.Equal(t, clean, padded, "whitespace-padded filters must behave like trimmed filters")
}
