package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// fixedWindowClient returns one log window, or an error, for every read.
type fixedWindowClient struct {
	fail2ban.Client
	window []string
	err    error
}

func (c *fixedWindowClient) GetLogLinesWithLimitContext(
	context.Context, string, string, int,
) ([]string, error) {
	return c.window, c.err
}

// watchOver returns a watch reading client, printing to out in format.
func watchOver(client fail2ban.Client, out *bytes.Buffer, format string) logWatch {
	return logWatch{
		out:      out,
		client:   client,
		maxLines: 10,
		config:   &Config{Format: format, FileTimeout: time.Second},
	}
}

func TestPollOncePrintsOnlyNewLinesAndCarriesTheWindow(t *testing.T) {
	var out bytes.Buffer
	watch := watchOver(&fixedWindowClient{window: []string{"a", "b"}}, &out, PlainFormat)

	window, err := watch.pollOnce(context.Background(), []string{"a"})

	require.NoError(t, err)
	assert.Equal(t, "b\n", out.String())
	assert.Equal(t, []string{"a", "b"}, window, "the next poll must compare against the new window")
}

func TestPollOncePrintsNothingForAnUnchangedWindow(t *testing.T) {
	var out bytes.Buffer
	watch := watchOver(&fixedWindowClient{window: []string{"a"}}, &out, PlainFormat)

	_, err := watch.pollOnce(context.Background(), []string{"a"})

	require.NoError(t, err)
	assert.Empty(t, out.String())
}

// TestPollOnceKeepsPollingAfterAFetchError pins that a transient read failure
// keeps the previous window instead of ending the watch.
func TestPollOnceKeepsPollingAfterAFetchError(t *testing.T) {
	var out bytes.Buffer
	watch := watchOver(&fixedWindowClient{err: errors.New("rotating")}, &out, PlainFormat)

	window, err := watch.pollOnce(context.Background(), []string{"a"})

	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, window)
	assert.Empty(t, out.String())
}

// TestPollOnceStopsWhenTheOutputIsGone pins that a write failure ends the
// watch; polling forever into a closed pipe would never stop.
func TestPollOnceStopsWhenTheOutputIsGone(t *testing.T) {
	watch := logWatch{
		out:      failingWriter{},
		client:   &fixedWindowClient{window: []string{"a", "b"}},
		maxLines: 10,
		config:   &Config{Format: PlainFormat, FileTimeout: time.Second},
	}

	_, err := watch.pollOnce(context.Background(), []string{"a"})

	require.Error(t, err)
}

// TestPollOnceEmitsTheSameJSONShapeAsLogs pins that --format json gives
// logs-watch the array of lines `logs` prints, not one string of joined lines.
func TestPollOnceEmitsTheSameJSONShapeAsLogs(t *testing.T) {
	var out bytes.Buffer
	watch := watchOver(&fixedWindowClient{window: []string{"a", "b", "c"}}, &out, JSONFormat)

	_, err := watch.pollOnce(context.Background(), []string{"a"})
	require.NoError(t, err)

	var lines []string
	require.NoError(t, json.Unmarshal(out.Bytes(), &lines), "output was %q", out.String())
	assert.Equal(t, []string{"b", "c"}, lines)
}
