package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCLI runs the CLI with args and returns its exit code and stderr. None of
// the args used here reach a client, so no fail2ban or sudo process starts.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	origArgs, origStderr := os.Args, os.Stderr
	t.Cleanup(func() { os.Args, os.Stderr = origArgs, origStderr })

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	os.Args = append([]string{"f2b"}, args...)
	os.Stderr = writer

	code := run()

	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	return code, string(output)
}

// TestRunExitCodes pins the contract scripts rely on, and that an error is
// shown exactly once: cobra's errors are printed by run, and a command's own
// errors are printed by its handler.
func TestRunExitCodes(t *testing.T) {
	tests := map[string]struct {
		args       []string
		wantCode   int
		wantErrors int
	}{
		"success":            {[]string{"version"}, 0, 0},
		"unknown flag":       {[]string{"--no-such-flag"}, 1, 1},
		"handled validation": {[]string{"ban", "not-an-ip"}, 1, 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			code, stderr := runCLI(t, tt.args...)

			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantErrors, strings.Count(stderr, "Error:"), "stderr: %s", stderr)
		})
	}
}
