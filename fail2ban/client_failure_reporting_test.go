package fail2ban_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

var errSocketRefused = errors.New("socket refused")

// clientOverMockRunner returns a client for root, so fail2ban-client commands
// reach the mock runner without the sudo prefix. The mock is installed as the
// global runner, which a RealClient built without NewClient falls back to.
func clientOverMockRunner(t *testing.T, jails ...string) (*fail2ban.RealClient, *fail2bantest.MockRunner) {
	t.Helper()
	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(
		&fail2bantest.MockSudoChecker{MockIsRoot: true, MockHasPrivileges: true, ExplicitPrivilegesSet: true},
	)
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

	mock := fail2bantest.NewMockRunner()
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))
	return &fail2ban.RealClient{Path: "fail2ban-client", Jails: jails}, mock
}

// TestGetBanRecordsSelectsJails pins which jails a request reaches. `f2b banned
// all` depends on the expansion: without it, a list naming "all" queried a jail
// literally called all and a nil list reported no bans.
func TestGetBanRecordsSelectsJails(t *testing.T) {
	everyJail := []string{"nginx", "sshd"}
	tests := map[string]struct{ requested, want []string }{
		"nil list":             {nil, everyJail},
		"empty list":           {[]string{}, everyJail},
		"all":                  {[]string{"all"}, everyJail},
		"blank":                {[]string{""}, everyJail},
		"all among named":      {[]string{"sshd", "all"}, everyJail},
		"one named jail":       {[]string{"sshd"}, []string{"sshd"}},
		"two named jails only": {[]string{"nginx", "sshd"}, everyJail},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, mock := clientOverMockRunner(t, "sshd", "nginx")
			record := []byte("192.0.2.1 2030-01-01 10:00:00 + 600 = 2030-01-01 10:10:00")
			for _, jail := range everyJail {
				mock.SetResponse("fail2ban-client get "+jail+" banip --with-time", record)
			}

			records, err := client.GetBanRecordsWithContext(context.Background(), tt.requested)

			require.NoError(t, err)
			got := make([]string, 0, len(records))
			for _, r := range records {
				got = append(got, r.Jail)
			}
			slices.Sort(got)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestBanRejectsUnrecognizedOutput pins that output which is not a count is an
// error: reading it as success would report a ban that may not exist.
func TestBanRejectsUnrecognizedOutput(t *testing.T) {
	client, mock := clientOverMockRunner(t, "sshd")
	mock.SetResponse("fail2ban-client set sshd banip 192.0.2.1", []byte("something odd"))

	_, err := client.BanIPWithContext(context.Background(), "192.0.2.1", "sshd")

	require.Error(t, err)
}

func TestBannedInReportsARunnerFailure(t *testing.T) {
	client, mock := clientOverMockRunner(t, "sshd")
	mock.SetError("fail2ban-client banned 192.0.2.1", errSocketRefused)

	_, err := client.BannedInWithContext(context.Background(), "192.0.2.1")

	require.ErrorIs(t, err, errSocketRefused)
}

func TestListFiltersReportsAMissingDirectory(t *testing.T) {
	client := &fail2ban.RealClient{FilterDir: filepath.Join(t.TempDir(), "missing")}

	_, err := client.ListFiltersWithContext(context.Background())

	require.Error(t, err)
}

func TestListJailsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	jails, err := (&fail2ban.RealClient{Jails: []string{"sshd"}}).ListJailsWithContext(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, jails)
}

func TestNewClientReportsAFailedJailListing(t *testing.T) {
	mock := fail2bantest.NewMockRunner()
	restore := fail2bantest.WithTestRunner(t, mock)
	defer restore()
	fail2bantest.StandardMockSetup(mock)
	mock.SetError("fail2ban-client status", errSocketRefused)
	mock.SetError("sudo fail2ban-client status", errSocketRefused)

	_, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")

	require.ErrorIs(t, err, errSocketRefused)
}

// TestFilterWithoutFailregexIsRefused pins that a file with no failregex stops
// before fail2ban-regex runs, since the tool runs as root against a log.
func TestFilterWithoutFailregexIsRefused(t *testing.T) {
	client, mock, _ := newFilterClient(t, "[Definition]\nignoreregex =\n")

	_, err := client.TestFilterWithContext(context.Background(), "sshd", "/var/log/auth.log")

	require.ErrorContains(t, err, "failregex")
	assert.Empty(t, mock.GetCalls())
}

func TestFilterNameCannotLeaveTheFilterDirectory(t *testing.T) {
	client, mock, _ := newFilterClient(t, stockFilter)

	_, err := client.TestFilterWithContext(context.Background(), "../sshd", "/var/log/auth.log")

	require.Error(t, err)
	assert.Empty(t, mock.GetCalls())
}
