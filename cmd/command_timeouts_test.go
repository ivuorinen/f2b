package cmd

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// deadlineClient records how long each ban call was allowed to run.
type deadlineClient struct {
	fail2ban.Client
	mu        sync.Mutex
	remaining []time.Duration
	unbounded int
}

func (c *deadlineClient) BanIPWithContext(ctx context.Context, _, _ string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok {
		c.unbounded++
		return 0, nil
	}
	c.remaining = append(c.remaining, time.Until(deadline))
	return 0, nil
}

// TestParallelBanAppliesTheInjectedTimeoutPerJail pins two things: every jail
// runs under a deadline, so one hung invocation cannot stall the batch, and
// that deadline comes from the command's own Config. The global default is 30s
// and the injected value 1s, so a read of the global fails the bound.
func TestParallelBanAppliesTheInjectedTimeoutPerJail(t *testing.T) {
	client := &deadlineClient{}
	jails := []string{"sshd", "apache"}

	_, err := ProcessBanOperationParallelWithContext(
		context.Background(), client, "192.0.2.1", jails, &Config{CommandTimeout: time.Second},
	)

	require.NoError(t, err)
	assert.Zero(t, client.unbounded, "a jail ran with no deadline")
	require.Len(t, client.remaining, len(jails))
	for _, remaining := range client.remaining {
		assert.LessOrEqual(t, remaining, time.Second)
	}
}

// deadlineRunner records the deadline of the command it was asked to run.
type deadlineRunner struct {
	fail2ban.Runner
	deadline    time.Time
	hasDeadline bool
}

func (r *deadlineRunner) CombinedOutputWithSudoContext(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	r.deadline, r.hasDeadline = ctx.Deadline()
	return []byte("active"), nil
}

// TestServiceCmdBoundsTheServiceCall pins that a hung service manager cannot
// block an unattended run forever. The default command timeout is deliberately
// not used, because a restart can legitimately take longer.
func TestServiceCmdBoundsTheServiceCall(t *testing.T) {
	runner := &deadlineRunner{}
	cmd := ServiceCmd(runner, &Config{Format: PlainFormat, CommandTimeout: time.Second})
	cmd.SetArgs([]string{"status"})

	require.NoError(t, cmd.ExecuteContext(context.Background()))

	require.True(t, runner.hasDeadline, "the service call ran with no deadline")
	remaining := time.Until(runner.deadline)
	assert.Greater(t, remaining, time.Second, "a restart must not be held to the per-command timeout")
	assert.LessOrEqual(t, remaining, constants.MaxCommandTimeout)
}
