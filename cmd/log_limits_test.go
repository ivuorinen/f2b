package cmd

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestLogsAppliesTheLimitCeiling pins that a limit in range reaches the client
// unchanged and a larger one is clamped: the fail2ban layer rejects anything
// above the ceiling, so the flag would otherwise error.
func TestLogsAppliesTheLimitCeiling(t *testing.T) {
	tests := map[string]struct{ limit, want int }{
		"in range":  {5, 5},
		"oversized": {constants.MaxLogLinesLimit + 1, constants.MaxLogLinesLimit},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := fail2bantest.NewMockClient()
			args := []string{"--" + constants.FlagLimit, strconv.Itoa(tt.limit)}

			_, err := executeForOutput(LogsCmd(client, failureTestConfig()), args...)

			require.NoError(t, err)
			assert.Equal(t, tt.want, client.LastLogLimit)
		})
	}
}

func TestResolveMaxLines(t *testing.T) {
	tests := map[string]struct{ limit, want int }{
		"unset":     {0, constants.DefaultLogLinesLimit},
		"negative":  {-1, constants.DefaultLogLinesLimit},
		"in range":  {5, 5},
		"at max":    {constants.MaxLogLinesLimit, constants.MaxLogLinesLimit},
		"above max": {constants.MaxLogLinesLimit + 1, constants.MaxLogLinesLimit},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveMaxLines(tt.limit))
		})
	}
}

// TestLogWatchRunAcceptsAZeroInterval pins the default: time.NewTicker panics
// on an interval that is not positive.
func TestLogWatchRunAcceptsAZeroInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, logWatch{}.run(ctx, nil, 0))
}

// TestLogWatchRunStopsWhenAPollCannotWrite pins that the loop ends on a dead
// output. Without that, the run returns nil only when the context expires.
func TestLogWatchRunStopsWhenAPollCannotWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	watch := logWatch{
		out:      failingWriter{},
		client:   &fixedWindowClient{window: []string{"a", "b"}},
		maxLines: 10,
		config:   &Config{Format: PlainFormat, FileTimeout: time.Second},
	}

	require.Error(t, watch.run(ctx, []string{"a"}, time.Millisecond))
}

// TestLogsWatchPrintsNothingForAnEmptyLog uses JSON, where printing an empty
// window would emit a stray "null" or "[]" before the first real lines.
func TestLogsWatchPrintsNothingForAnEmptyLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	cmd := LogsWatchCmd(&fixedWindowClient{}, &Config{Format: JSONFormat, FileTimeout: time.Second})
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.ExecuteContext(ctx))

	assert.Empty(t, out.String())
}

func TestLogsWatchReportsAFailedFirstWrite(t *testing.T) {
	cmd := LogsWatchCmd(
		&fixedWindowClient{window: []string{"a"}},
		&Config{Format: PlainFormat, FileTimeout: time.Second},
	)
	cmd.SetOut(failingWriter{})
	cmd.SetArgs([]string{})

	require.ErrorContains(t, cmd.ExecuteContext(context.Background()), "no space left")
}

func TestParseTimeoutFromEnvTreatsBareNumbersAsSeconds(t *testing.T) {
	const (
		fallback = 7 * time.Second
		ceiling  = time.Minute
	)
	tests := map[string]time.Duration{
		"30": 30 * time.Second,
		"-5": fallback,
		// Just past 2^63 nanoseconds, so the multiplication wraps to a negative
		// value that would pass the ceiling check and expire every context.
		"9223372037": ceiling,
	}
	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("F2B_TEST_TIMEOUT", value)
			assert.Equal(t, want, parseTimeoutFromEnv("F2B_TEST_TIMEOUT", fallback, ceiling))
		})
	}
}

// TestValidateConfigNamesADirectoryOutsideTheAllowlist pins the fail-fast for
// --log-dir: the directory is what root is pointed at.
func TestValidateConfigNamesADirectoryOutsideTheAllowlist(t *testing.T) {
	config := Config{LogDir: "/root/secrets", FilterDir: constants.DefaultFilterDir, Format: PlainFormat}

	require.ErrorContains(t, config.ValidateConfig(), "invalid log directory")
}
