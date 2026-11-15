package fail2ban_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

const (
	// stockFilter has the shape fail2ban ships: failregex and no logpath.
	stockFilter = "[Definition]\nfailregex = ^.* from <HOST>\n"
	// regexOutput stands in for fail2ban-regex's report.
	regexOutput = "Lines: 1 lines"
)

// newFilterClient returns a client over a filter directory holding sshd.conf
// with body, for a non-root user who may use sudo, plus the filter's path.
// The mock is installed as the global runner, which a RealClient built
// without NewClient falls back to.
func newFilterClient(t *testing.T, body string) (*fail2ban.RealClient, *fail2bantest.MockRunner, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd.conf")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))

	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(&fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true})
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

	mock := fail2bantest.NewMockRunner()
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))
	return &fail2ban.RealClient{Path: "fail2ban-client", FilterDir: dir}, mock, path
}

// TestFilterAgainstGivenLogFileRunsThroughSudo pins the case stock filters
// depend on: they declare no logpath, so the caller names the log, and only
// the sudo form is registered because the log is typically root-only.
func TestFilterAgainstGivenLogFileRunsThroughSudo(t *testing.T) {
	client, mock, path := newFilterClient(t, stockFilter)
	logFile := allowedLog(t, "")
	mock.SetResponse("sudo fail2ban-regex "+logFile+" "+path, []byte(regexOutput))

	got, err := client.TestFilterWithContext(context.Background(), "sshd", logFile)

	require.NoError(t, err)
	assert.Equal(t, regexOutput, got)
}

// TestFilterGivenLogFileOverridesDeclaredLogpath pins precedence: an explicit
// log file wins over the filter's own logpath.
func TestFilterGivenLogFileOverridesDeclaredLogpath(t *testing.T) {
	client, mock, path := newFilterClient(t, stockFilter+"logpath = /var/log/declared.log\n")
	logFile := allowedLog(t, "")
	mock.SetResponse("sudo fail2ban-regex "+logFile+" "+path, []byte(regexOutput))

	got, err := client.TestFilterWithContext(context.Background(), "sshd", logFile)

	require.NoError(t, err)
	assert.Equal(t, regexOutput, got)
}

// TestFilterRefusesLogOutsideAllowlist pins the read-as-root guard for both
// sources of the log path: a filter file naming /etc/shadow and a caller
// naming it. The side effect is what matters, so the assertion is that
// fail2ban-regex was never invoked.
func TestFilterRefusesLogOutsideAllowlist(t *testing.T) {
	tests := map[string]struct {
		body    string
		logFile string
	}{
		"logpath declared by the filter": {body: stockFilter + "logpath = /etc/shadow\n"},
		"log file named by the caller":   {body: stockFilter, logFile: "/etc/shadow"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, mock, path := newFilterClient(t, tt.body)
			mock.SetResponse("sudo fail2ban-regex /etc/shadow "+path, []byte(regexOutput))

			_, err := client.TestFilterWithContext(context.Background(), "sshd", tt.logFile)

			require.Error(t, err)
			assert.Empty(t, mock.GetCalls(), "fail2ban-regex ran against a log outside the allowlist")
		})
	}
}

// TestFilterRefusesALogThatIsNotAFile pins that, for an ordinary user too, a
// log that is missing or not a regular file stops before fail2ban-regex runs:
// fail2ban-regex reads any path that is not a file as one literal log line and
// reports success without testing a file.
func TestFilterRefusesALogThatIsNotAFile(t *testing.T) {
	tests := map[string]struct {
		log  func(dir string) string
		want string
	}{
		"missing log":   {func(dir string) string { return filepath.Join(dir, "typo.log") }, "does not exist"},
		"log directory": {func(dir string) string { return dir }, "not a regular file"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, mock, path := newFilterClient(t, stockFilter)
			logFile := tt.log(filepath.Dir(allowedLog(t, "")))
			mock.SetResponse("sudo fail2ban-regex "+logFile+" "+path, []byte(regexOutput))

			_, err := client.TestFilterWithContext(context.Background(), "sshd", logFile)

			require.ErrorContains(t, err, tt.want)
			assert.Empty(t, mock.GetCalls(), "fail2ban-regex ran against a log that is not a file")
		})
	}
}

// TestFilterLeavesAnAuditRecord pins that the one command designed around a
// read-as-root concern records which filter and log it read.
func TestFilterLeavesAnAuditRecord(t *testing.T) {
	client, mock, path := newFilterClient(t, stockFilter)
	logFile := allowedLog(t, "")
	mock.SetResponse("sudo fail2ban-regex "+logFile+" "+path, []byte(regexOutput))
	sink := captureLog(t, slog.LevelInfo)

	_, err := client.TestFilterWithContext(context.Background(), "sshd", logFile)

	require.NoError(t, err)
	assert.Contains(t, sink.String(), "sshd")
	assert.Contains(t, sink.String(), logFile)
}
