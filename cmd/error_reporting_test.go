package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrintErrorReportsOnceOnTheTerminal pins that a failure reaches a terminal
// user as one line. With logs on stderr, the structured record and the Error:
// line used to print the same failure twice.
func TestPrintErrorReportsOnceOnTheTerminal(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	origStderr, origOutput := os.Stderr, Logger.Output()
	os.Stderr = writer
	Logger.SetOutput(writer)
	t.Cleanup(func() {
		os.Stderr = origStderr
		Logger.SetOutput(origOutput)
	})

	PrintError(errors.New("boom"))
	require.NoError(t, writer.Close())

	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(output), "boom"), "stderr was %q", output)
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
