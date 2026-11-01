package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// setInvalidTestCfg points the global cfg at a traversal path so any real
// client construction fails, and restores the original cfg on cleanup.
func setInvalidTestCfg(t *testing.T) {
	t.Helper()
	originalCfg := cfg
	t.Cleanup(func() { cfg = originalCfg })
	cfg = Config{
		LogDir:    "../../../etc",
		FilterDir: "../../../etc",
		Format:    PlainFormat,
	}
}

// setValidMockedTestCfg sets up a mock runner/sudo checker with standard
// responses and points cfg at the default directories, restoring on cleanup.
func setValidMockedTestCfg(t *testing.T) {
	t.Helper()
	originalCfg := cfg
	t.Cleanup(func() { cfg = originalCfg })
	_, cleanup := fail2ban.SetupMockEnvironmentWithStandardResponses(t)
	t.Cleanup(cleanup)
	cfg = Config{
		LogDir:    constants.DefaultLogDir,
		FilterDir: constants.DefaultFilterDir,
		Format:    PlainFormat,
	}
}

// TestNewLazyClientDefersConstruction verifies that NewLazyClient does not
// construct the underlying client eagerly: with an invalid cfg.LogDir no error
// surfaces until the first client method call.
func TestNewLazyClientDefersConstruction(t *testing.T) {
	setInvalidTestCfg(t)

	// Construction must succeed even though cfg is invalid.
	client := NewLazyClient()
	require.NotNil(t, client)

	// The first method call resolves the real client and surfaces the error.
	jails, err := client.ListJailsWithContext(context.Background())
	require.Error(t, err)
	assert.Nil(t, jails)
}

// TestLazyClientResolvesUnderCallerContext pins that construction runs under
// the triggering operation's context: building under context.Background() ran
// -V/ping/status past the command's timeout and Ctrl-C.
func TestLazyClientResolvesUnderCallerContext(t *testing.T) {
	setValidMockedTestCfg(t)
	runner := fail2ban.MustMockRunner(t)
	before := len(runner.GetCalls())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewLazyClient().ListJailsWithContext(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Len(t, runner.GetCalls(), before, "construction ran fail2ban-client despite a canceled context")
}

// TestLazyClientCachesConstructionError verifies the sync.Once error caching:
// a second call returns the identical error without re-resolving, even after
// cfg has been fixed and a working mock environment installed.
func TestLazyClientCachesConstructionError(t *testing.T) {
	setInvalidTestCfg(t)

	client := NewLazyClient()
	_, err1 := client.ListJailsWithContext(context.Background())
	require.Error(t, err1)

	// Fix the environment: valid cfg plus a mock runner that would let
	// construction succeed. The cached error must still be returned.
	setValidMockedTestCfg(t)

	_, err2 := client.StatusAllWithContext(context.Background())
	require.Error(t, err2)
	assert.Equal(t, err1, err2, "second call must return the cached construction error")
}

// TestLazyClientDelegatesEachOperation pins each context operation of the
// production client wrapper to the fail2ban-client command it must issue. The
// cmd tests inject MockClient directly, so a lazyClient delegator calling the
// wrong method (an unban that bans) passed every other test.
func TestLazyClientDelegatesEachOperation(t *testing.T) {
	setValidMockedTestCfg(t)
	runner := fail2ban.MustMockRunner(t)
	client := NewLazyClient()
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "ban",
			call: func() error { _, err := client.BanIPWithContext(ctx, "192.168.1.100", "sshd"); return err },
			want: "fail2ban-client set sshd banip 192.168.1.100",
		},
		{
			name: "unban",
			call: func() error { _, err := client.UnbanIPWithContext(ctx, "192.168.1.100", "sshd"); return err },
			want: "fail2ban-client set sshd unbanip 192.168.1.100",
		},
		{
			name: "status jail",
			call: func() error { _, err := client.StatusJailWithContext(ctx, "sshd"); return err },
			want: "fail2ban-client status sshd",
		},
		{
			name: "status all",
			call: func() error { _, err := client.StatusAllWithContext(ctx); return err },
			want: "fail2ban-client status",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(runner.GetCalls())
			require.NoError(t, tt.call())
			calls := runner.GetCalls()[before:]
			require.NotEmpty(t, calls)
			assert.True(t, strings.HasSuffix(calls[len(calls)-1], tt.want),
				"last command %q must end with %q", calls[len(calls)-1], tt.want)
		})
	}
}

// TestLazyClientForwardsLineLimit pins the NIT-33 fix: the requested line
// limit must reach the real client's read, not be capped at the default.
func TestLazyClientForwardsLineLimit(t *testing.T) {
	setValidMockedTestCfg(t)
	t.Setenv("ALLOW_DEV_PATHS", "1")
	dir := t.TempDir()
	content := "a [sshd] Ban 1.1.1.1\nb [sshd] Ban 1.1.1.2\nc [sshd] Ban 1.1.1.3\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fail2ban.log"), []byte(content), 0o600))
	cfg.LogDir = dir

	lines, err := NewLazyClient().GetLogLinesWithLimitContext(context.Background(), "", "", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"c [sshd] Ban 1.1.1.3"}, lines)
}

// TestLazyClientResolvesAndDelegates verifies that with a valid mocked
// environment the lazy client resolves on first use and delegates calls to the
// real client.
func TestLazyClientResolvesAndDelegates(t *testing.T) {
	setValidMockedTestCfg(t)

	client := NewLazyClient()

	jails, err := client.ListJailsWithContext(context.Background())
	require.NoError(t, err)
	assert.Contains(t, jails, "sshd")

	// Subsequent calls reuse the already-resolved client.
	status, err := client.StatusAllWithContext(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, status)
}
