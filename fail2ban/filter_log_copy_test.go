package fail2ban_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// logCopyArg stands in, in MockRunner response keys, for the log copy
// TestFilterWithContext hands fail2ban-regex: its directory name is random.
const logCopyArg = "LOGCOPY"

// logCopyRunner records the log argument fail2ban-regex is given and that
// file's content while the command runs, then forwards the command to
// MockRunner with the argument replaced by logCopyArg.
type logCopyRunner struct {
	*fail2bantest.MockRunner
	logArg  string
	content string
}

func (r *logCopyRunner) CombinedOutputWithSudoContext(
	ctx context.Context, name string, args ...string,
) ([]byte, error) {
	if name != constants.Fail2BanRegexCommand || len(args) == 0 {
		return r.MockRunner.CombinedOutputWithSudoContext(ctx, name, args...)
	}
	if err := fail2ban.ValidateArguments(args); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return nil, err
	}
	r.logArg, r.content = args[0], string(data)
	return r.MockRunner.CombinedOutputWithSudoContext(ctx, name, append([]string{logCopyArg}, args[1:]...)...)
}

// allowedLog writes content to a log in a temp directory, which
// ALLOW_DEV_PATHS admits to the log allowlist, and returns its resolved path.
func allowedLog(t *testing.T, content string) string {
	t.Helper()
	t.Setenv("ALLOW_DEV_PATHS", "true")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(dir, "auth.log")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// newRootFilterClient is newFilterClient for f2b running as root, such as
// `sudo f2b`, with the runner wrapped to record the log fail2ban-regex gets.
func newRootFilterClient(t *testing.T, body string) (*fail2ban.RealClient, *logCopyRunner, string) {
	t.Helper()
	client, mock, path := newFilterClient(t, body)
	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(
		&fail2bantest.MockSudoChecker{MockIsRoot: true, MockHasPrivileges: true, ExplicitPrivilegesSet: true},
	)
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })
	runner := &logCopyRunner{MockRunner: mock}
	t.Cleanup(fail2bantest.WithTestRunner(t, runner))
	return client, runner, path
}

// TestFilterAsRootHandsRegexAPrivateCopyOfTheLog pins that when f2b runs as
// root, fail2ban-regex never gets the validated path, which a user who can
// write a directory on it could swap for a symlink, but a copy that is removed
// when the command returns. It holds for a log the caller names and for the
// logpath the filter declares.
func TestFilterAsRootHandsRegexAPrivateCopyOfTheLog(t *testing.T) {
	const content = "Failed password for root from 192.0.2.1\n"
	for name, declared := range map[string]bool{"named by the caller": false, "declared by the filter": true} {
		t.Run(name, func(t *testing.T) {
			logPath := allowedLog(t, content)
			body, logFile := stockFilter, logPath
			if declared {
				body, logFile = stockFilter+"logpath = "+logPath+"\n", ""
			}
			client, runner, filterPath := newRootFilterClient(t, body)
			runner.SetResponse("fail2ban-regex "+logCopyArg+" "+filterPath, []byte(regexOutput))

			got, err := client.TestFilterWithContext(context.Background(), "sshd", logFile)

			require.NoError(t, err)
			assert.Equal(t, regexOutput, got)
			assert.NotEqual(t, logPath, runner.logArg, "fail2ban-regex was given a path the caller can still change")
			assert.Equal(t, content, runner.content)
			assert.NoDirExists(t, filepath.Dir(runner.logArg), "the log copy outlived the command")
		})
	}
}

// TestFilterAsRootRefusesALogThatIsNotARegularFile pins that, as root, the log
// is opened and checked before fail2ban-regex runs: path validation lets a
// directory through.
func TestFilterAsRootRefusesALogThatIsNotARegularFile(t *testing.T) {
	dir := filepath.Dir(allowedLog(t, "x\n"))
	client, runner, _ := newRootFilterClient(t, stockFilter)

	_, err := client.TestFilterWithContext(context.Background(), "sshd", dir)

	require.ErrorContains(t, err, "not a regular file")
	assert.Empty(t, runner.GetCalls(), "fail2ban-regex ran against a directory")
}

// TestFilterAsOrdinaryUserPassesTheValidatedPath pins that when f2b runs as an
// ordinary user and escalates per command, fail2ban-regex gets the validated
// path itself: that user may already run `sudo fail2ban-regex <file>`, so
// there is no boundary to protect, and f2b reading the log with the user's
// own privileges would refuse logs only root can read.
func TestFilterAsOrdinaryUserPassesTheValidatedPath(t *testing.T) {
	logPath := allowedLog(t, "x\n")
	client, mock, filterPath := newFilterClient(t, stockFilter)
	mock.SetResponse("sudo fail2ban-regex "+logPath+" "+filterPath, []byte(regexOutput))

	got, err := client.TestFilterWithContext(context.Background(), "sshd", logPath)

	require.NoError(t, err)
	assert.Equal(t, regexOutput, got)
}
