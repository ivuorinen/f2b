package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

var errBackendDown = errors.New("backend down")

// brokenClient fails one named operation and serves the rest from a MockClient.
type brokenClient struct {
	*fail2bantest.MockClient
	broken string
}

func (c *brokenClient) failure(op string) error {
	if c.broken == op {
		return errBackendDown
	}
	return nil
}

func (c *brokenClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	if err := c.failure("list-jails"); err != nil {
		return nil, err
	}
	return c.MockClient.ListJailsWithContext(ctx)
}

func (c *brokenClient) StatusAllWithContext(ctx context.Context) (string, error) {
	if err := c.failure("status-all"); err != nil {
		return "", err
	}
	return c.MockClient.StatusAllWithContext(ctx)
}

func (c *brokenClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	if err := c.failure("status-jail"); err != nil {
		return "", err
	}
	return c.MockClient.StatusJailWithContext(ctx, jail)
}

func (c *brokenClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	if err := c.failure("banned-in"); err != nil {
		return nil, err
	}
	return c.MockClient.BannedInWithContext(ctx, ip)
}

func (c *brokenClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]fail2ban.BanRecord, error) {
	if err := c.failure("ban-records"); err != nil {
		return nil, err
	}
	return c.MockClient.GetBanRecordsWithContext(ctx, jails)
}

func (c *brokenClient) GetLogLinesWithLimitContext(
	ctx context.Context, jail, ip string, maxLines int,
) ([]string, error) {
	if err := c.failure("log-lines"); err != nil {
		return nil, err
	}
	return c.MockClient.GetLogLinesWithLimitContext(ctx, jail, ip, maxLines)
}

func (c *brokenClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	if err := c.failure("list-filters"); err != nil {
		return nil, err
	}
	return c.MockClient.ListFiltersWithContext(ctx)
}

func failureTestConfig() *Config {
	return &Config{
		Format:          PlainFormat,
		CommandTimeout:  time.Second,
		FileTimeout:     time.Second,
		ParallelTimeout: time.Second,
	}
}

// executeForOutput runs cmd with args and returns what it printed and its error.
func executeForOutput(cmd *cobra.Command, args ...string) (string, error) {
	var out bytes.Buffer
	cmd.SetOut(&out)
	// A nil slice would make cobra fall back to the test binary's os.Args.
	cmd.SetArgs(append([]string{}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestCommandsReportClientFailures pins that a failed client call ends the
// command with that error, already shown to the user, and no success output.
func TestCommandsReportClientFailures(t *testing.T) {
	config := failureTestConfig()
	var (
		listJails = func(c fail2ban.Client) *cobra.Command { return ListJailsCmd(c, config) }
		status    = func(c fail2ban.Client) *cobra.Command { return StatusCmd(c, config) }
		banned    = func(c fail2ban.Client) *cobra.Command { return BannedCmd(c, config) }
		testIP    = func(c fail2ban.Client) *cobra.Command { return TestIPCmd(c, config) }
		logs      = func(c fail2ban.Client) *cobra.Command { return LogsCmd(c, config) }
		filter    = func(c fail2ban.Client) *cobra.Command { return TestFilterCmd(c, config) }
		ban       = func(c fail2ban.Client) *cobra.Command { return BanCmd(c, config) }
	)
	tests := map[string]struct {
		build  func(fail2ban.Client) *cobra.Command
		args   []string
		broken string
	}{
		"list-jails":           {listJails, nil, "list-jails"},
		"status all":           {status, []string{"all"}, "status-all"},
		"status jail lookup":   {status, []string{"sshd"}, "list-jails"},
		"status jail":          {status, []string{"sshd"}, "status-jail"},
		"banned jail lookup":   {banned, []string{"sshd"}, "list-jails"},
		"banned records":       {banned, []string{"all"}, "ban-records"},
		"test ip":              {testIP, []string{"192.0.2.1"}, "banned-in"},
		"logs":                 {logs, []string{"sshd"}, "log-lines"},
		"filter listing":       {filter, nil, "list-filters"},
		"ban with jail lookup": {ban, []string{"192.0.2.1"}, "list-jails"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := &brokenClient{MockClient: fail2bantest.NewMockClient(), broken: tt.broken}

			out, err := executeForOutput(tt.build(client), tt.args...)

			require.ErrorIs(t, err, errBackendDown)
			assert.True(t, IsPrinted(err), "the error must already be reported to the user")
			assert.Empty(t, out)
		})
	}
}

// TestBannedRefusesJailsItCannotQuery pins that a typo'd or invalid name is an
// error before any ban records are read, not an empty ban list.
func TestBannedRefusesJailsItCannotQuery(t *testing.T) {
	for _, jail := range []string{"nosuchjail", "bad;jail"} {
		t.Run(jail, func(t *testing.T) {
			client := fail2bantest.NewMockClient()

			_, err := executeForOutput(BannedCmd(client, failureTestConfig()), jail)

			require.Error(t, err)
			assert.Nil(t, client.LastBanRecordsJails)
		})
	}
}

// TestCommandsReportAFailedWrite pins the exit status when the output is gone,
// such as a closed pipe or a full disk.
func TestCommandsReportAFailedWrite(t *testing.T) {
	config := failureTestConfig()
	client := fail2bantest.NewMockClient()
	commands := map[string]*cobra.Command{
		"list-jails":     ListJailsCmd(client, config),
		"status usage":   StatusCmd(client, config),
		"filter listing": TestFilterCmd(client, config),
	}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			cmd.SetOut(failingWriter{})
			cmd.SetArgs([]string{})

			require.ErrorContains(t, cmd.ExecuteContext(context.Background()), "no space left")
		})
	}
}

// TestStatusUsageSurvivesAJailListFailure pins that help text still prints when
// fail2ban is unreachable, which is when a user is most likely to ask for it.
func TestStatusUsageSurvivesAJailListFailure(t *testing.T) {
	client := &brokenClient{MockClient: fail2bantest.NewMockClient(), broken: "list-jails"}

	out, err := executeForOutput(StatusCmd(client, failureTestConfig()))

	require.NoError(t, err)
	assert.Contains(t, out, "Usage:")
}
