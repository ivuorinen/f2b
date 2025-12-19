package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/shared"
)

func TestGetLogLinesWithLimit_ValidatesNegativeMaxLines(t *testing.T) {
	_, err := GetLogLinesWithLimit(context.Background(), "", "", -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-negative")
}

func TestGetLogLinesWithLimit_ValidatesExcessiveMaxLines(t *testing.T) {
	_, err := GetLogLinesWithLimit(context.Background(), "", "", shared.MaxLogLinesLimit+1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed value")
}

func TestGetLogLinesWithLimit_AcceptsValidMaxLines(t *testing.T) {
	// Setup test environment with mock data
	cleanup := setupTestLogEnvironment(t, "testdata/fail2ban.log")
	defer cleanup()

	// Should not error with valid values
	_, err := GetLogLinesWithLimit(context.Background(), "", "", 10)
	assert.NoError(t, err)
}

func TestGetLogLinesOptimized_ValidatesNegativeMaxLines(t *testing.T) {
	olp := &OptimizedLogProcessor{}
	_, err := olp.GetLogLinesOptimized("", "", -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-negative")
}

func TestGetLogLinesOptimized_ValidatesExcessiveMaxLines(t *testing.T) {
	olp := &OptimizedLogProcessor{}
	_, err := olp.GetLogLinesOptimized("", "", shared.MaxLogLinesLimit+1)
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
	cleanup := setupTestLogEnvironment(t, "testdata/fail2ban.log")
	defer cleanup()

	// Filters with whitespace should be sanitized
	_, err := GetLogLinesWithLimit(context.Background(), "  sshd  ", "  192.168.1.1  ", 10)
	assert.NoError(t, err)
}
