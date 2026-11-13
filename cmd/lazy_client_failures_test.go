package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestLazyClientReportsConstructionFailureFromEveryOperation pins each
// delegator's guard: with construction failed there is no client, so a missing
// check is a nil-pointer panic on the first command.
func TestLazyClientReportsConstructionFailureFromEveryOperation(t *testing.T) {
	setInvalidTestCfg(t)
	client := NewLazyClient()
	ctx := context.Background()

	operations := map[string]func() error{
		"list jails":  func() error { _, err := client.ListJailsWithContext(ctx); return err },
		"status all":  func() error { _, err := client.StatusAllWithContext(ctx); return err },
		"status jail": func() error { _, err := client.StatusJailWithContext(ctx, "sshd"); return err },
		"ban":         func() error { _, err := client.BanIPWithContext(ctx, "192.0.2.1", "sshd"); return err },
		"unban":       func() error { _, err := client.UnbanIPWithContext(ctx, "192.0.2.1", "sshd"); return err },
		"banned in":   func() error { _, err := client.BannedInWithContext(ctx, "192.0.2.1"); return err },
		"ban records": func() error { _, err := client.GetBanRecordsWithContext(ctx, nil); return err },
		"log lines":   func() error { _, err := client.GetLogLinesWithContext(ctx, "", ""); return err },
		"list filters": func() error {
			_, err := client.ListFiltersWithContext(ctx)
			return err
		},
		"test filter": func() error {
			_, err := client.TestFilterWithContext(ctx, "sshd", "")
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			require.Error(t, operation())
		})
	}
}

// TestLazyClientForwardsReadCommands extends the write-side delegation test to
// the read operations, pinning each to the command it must issue.
func TestLazyClientForwardsReadCommands(t *testing.T) {
	setValidMockedTestCfg(t)
	runner := fail2bantest.MustMockRunner(t)
	client := NewLazyClient()
	ctx := context.Background()
	for _, prefix := range []string{"", "sudo "} {
		runner.SetResponse(prefix+"fail2ban-client banned 192.0.2.1", []byte("['sshd']"))
		runner.SetResponse(prefix+"fail2ban-client get sshd banip --with-time", []byte(""))
	}

	tests := map[string]struct {
		call func() error
		want string
	}{
		"banned in": {
			func() error { _, err := client.BannedInWithContext(ctx, "192.0.2.1"); return err },
			"fail2ban-client banned 192.0.2.1",
		},
		"ban records": {
			func() error { _, err := client.GetBanRecordsWithContext(ctx, []string{"sshd"}); return err },
			"fail2ban-client get sshd banip --with-time",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := len(runner.GetCalls())
			require.NoError(t, tt.call())
			calls := runner.GetCalls()[before:]
			require.NotEmpty(t, calls)
			last := calls[len(calls)-1]
			assert.True(t, strings.HasSuffix(last, tt.want), "last command %q must end with %q", last, tt.want)
		})
	}
}

// TestLazyClientForwardsFileOperations covers the operations that read files
// rather than run fail2ban-client, using real directories.
func TestLazyClientForwardsFileOperations(t *testing.T) {
	setValidMockedTestCfg(t)
	t.Setenv("ALLOW_DEV_PATHS", "1")
	logDir, filterDir := t.TempDir(), t.TempDir()
	logLine := "x [sshd] Ban 192.0.2.1"
	require.NoError(t, os.WriteFile(filepath.Join(logDir, "fail2ban.log"), []byte(logLine+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(filterDir, "sshd.conf"), []byte("[Definition]\n"), 0o600))
	cfg.LogDir, cfg.FilterDir = logDir, filterDir
	client := NewLazyClient()
	ctx := context.Background()

	lines, err := client.GetLogLinesWithContext(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{logLine}, lines)

	filters, err := client.ListFiltersWithContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"sshd"}, filters)

	_, err = client.TestFilterWithContext(ctx, "nosuchfilter", "")
	require.ErrorContains(t, err, "filter not found")
}
