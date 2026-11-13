package cmd

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// captureTerminalStderr runs fn with os.Stderr and every log record on one
// pipe, as on a terminal where main points the fail2ban logger at Logger, and
// returns what reached stderr.
func captureTerminalStderr(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	origStderr, origOutput, origLevel := os.Stderr, Logger.Output(), Logger.GetLevel()
	os.Stderr = writer
	Logger.SetOutput(writer)
	Logger.SetLevel(slog.LevelInfo)
	fail2ban.SetLogger(Logger)
	t.Cleanup(func() {
		os.Stderr = origStderr
		Logger.SetOutput(origOutput)
		Logger.SetLevel(origLevel)
		fail2ban.SetLogger(fail2ban.NewSlogLogger(fail2ban.SlogText))
		assert.NoError(t, reader.Close())
	})

	fn()
	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	return string(output)
}

// TestPrintErrorReportsOnceOnTheTerminal pins that a failure reaches a terminal
// user as one line. With logs on stderr, the structured record and the Error:
// line used to print the same failure twice.
func TestPrintErrorReportsOnceOnTheTerminal(t *testing.T) {
	output := captureTerminalStderr(t, func() { PrintError(errors.New("boom")) })
	assert.Equal(t, 1, strings.Count(output, "boom"), "stderr was %q", output)
}

// TestPrintErrorKeepsTheRecordInALogFile pins the other half: with a --log-file
// sink the structured record is the only copy that survives the run.
func TestPrintErrorKeepsTheRecordInALogFile(t *testing.T) {
	var sink bytes.Buffer
	origOutput := Logger.Output()
	Logger.SetOutput(&sink)
	t.Cleanup(func() { Logger.SetOutput(origOutput) })

	PrintError(errors.New("boom"))

	assert.Contains(t, sink.String(), "boom")
}

// TestServiceFailureReportsOnceOnTheTerminal pins one copy of a failed service
// action on stderr: the timer's failure record and a "Service action failed"
// record used to repeat the Error: line.
func TestServiceFailureReportsOnceOnTheTerminal(t *testing.T) {
	_, cleanup := fail2bantest.SetupMockEnvironment(t)
	t.Cleanup(cleanup)
	fail2bantest.MustMockRunner(t).SetError("sudo service fail2ban restart", &testServiceError{"restart exploded"})

	output := captureTerminalStderr(t, func() {
		cmd := ServiceCmd(fail2ban.GetRunner(), &Config{Format: PlainFormat})
		cmd.SetArgs([]string{"restart"})
		assert.Error(t, cmd.Execute())
	})
	assert.Equal(t, 1, strings.Count(output, "restart exploded"), "stderr was %q", output)
}

// TestIPOperationFailureReportsOnceOnTheTerminal pins one copy of a failed ban
// on stderr: LogOperation's "Operation failed" record repeated the Error: line.
func TestIPOperationFailureReportsOnceOnTheTerminal(t *testing.T) {
	validationErr := fail2ban.ValidateBanTarget("999.1.1.1")
	require.Error(t, validationErr)
	config := validTestConfig(PlainFormat)

	output := captureTerminalStderr(t, func() {
		cmd := BanCmd(fail2bantest.NewMockClient(), &config)
		cmd.SetArgs([]string{"999.1.1.1"})
		assert.Error(t, cmd.Execute())
	})
	assert.Equal(t, 1, strings.Count(output, validationErr.Error()), "stderr was %q", output)
}
