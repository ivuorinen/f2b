package cmd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestExecuteRestoresStderrLoggingAfterALogFileRun pins that closing the
// --log-file hands Logger back to stderr. Execute supports later runs in the
// same process, and Logger kept writing to the closed file, so every log line
// of those runs was lost.
func TestExecuteRestoresStderrLoggingAfterALogFileRun(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	logFile := filepath.Join(t.TempDir(), "f2b.log")
	logFileFlag := rootCmd.PersistentFlags().Lookup(constants.FlagLogFile)
	require.NotNil(t, logFileFlag)

	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	origStdout, origStderr, origArgs, origCfg := os.Stdout, os.Stderr, os.Args, cfg
	origOutput, origLevel := Logger.Output(), Logger.GetLevel()
	os.Stdout, os.Stderr = devNull, stderrW
	t.Cleanup(func() {
		os.Stdout, os.Stderr, os.Args, cfg = origStdout, origStderr, origArgs, origCfg
		Logger.SetOutput(origOutput)
		Logger.SetLevel(origLevel)
		Logger.Reconfigure(fail2ban.SlogText)
		assert.NoError(t, logFileFlag.Value.Set(logFileFlag.DefValue))
		if err := stderrW.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close stderr pipe writer: %v", err)
		}
		assert.NoError(t, stderrR.Close())
		assert.NoError(t, devNull.Close())
	})

	run := func(args ...string) {
		t.Helper()
		os.Args = append([]string{"f2b"}, args...)
		require.NoError(t, Execute(fail2bantest.NewMockClient(), validTestConfig(PlainFormat)))
	}
	run("--"+constants.FlagLogFile, logFile, "version")
	// Flag values outlive a run; clear it so the second run has no --log-file.
	require.NoError(t, logFileFlag.Value.Set(""))
	run("version")

	assert.True(t, writesToStderr(Logger.Output()), "Logger still writes to the closed log file")
	Logger.Info("after the second run")
	require.NoError(t, stderrW.Close())
	output, err := io.ReadAll(stderrR)
	require.NoError(t, err)
	assert.Contains(t, string(output), "after the second run")
}
