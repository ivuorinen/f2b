package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestBanShowsResultsBeforeReportingAPartialFailure pins that a ban which
// worked in one jail is still shown when another jail fails: the firewall
// changed, so the user has to see where.
func TestBanShowsResultsBeforeReportingAPartialFailure(t *testing.T) {
	client := fail2bantest.NewMockClient()
	client.SetBanError("apache", "192.0.2.1", errBackendDown)

	out, err := executeForOutput(BanCmd(client, failureTestConfig()), "192.0.2.1")

	require.ErrorIs(t, err, errBackendDown)
	assert.Contains(t, out, "Banned 192.0.2.1 in sshd")
	assert.Contains(t, out, "192.0.2.1 in apache")
}

// TestBanRefusesToRunWithNoJails pins the guard against a silent no-op: with no
// jails the per-jail loop never runs, and the command would report success.
func TestBanRefusesToRunWithNoJails(t *testing.T) {
	client := fail2bantest.NewMockClient()
	client.Jails = map[string]struct{}{}

	_, err := executeForOutput(BanCmd(client, failureTestConfig()), "192.0.2.1")

	require.ErrorContains(t, err, "no jails configured")
	assert.Empty(t, client.Banned)
}

func TestResolveOutputFormatPrefersTheFlag(t *testing.T) {
	flagged := func(value string) *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().String(constants.FlagFormat, value, "")
		return cmd
	}

	assert.Equal(t, JSONFormat, resolveOutputFormat(&Config{Format: PlainFormat}, flagged(JSONFormat)))
	assert.Equal(t, PlainFormat, resolveOutputFormat(&Config{Format: PlainFormat}, flagged("")))
	assert.Equal(t, JSONFormat, resolveOutputFormat(nil, flagged(JSONFormat)))
	assert.Empty(t, resolveOutputFormat(nil, flagged("")))
}

// TestJoinOperationErrorsReportsACancellationOnce pins the dedupe: a canceled
// run fails every remaining jail with the same context error.
func TestJoinOperationErrorsReportsACancellationOnce(t *testing.T) {
	err := joinOperationErrors(
		[]error{context.Canceled, nil, errBackendDown, context.DeadlineExceeded, context.Canceled},
	)

	require.ErrorIs(t, err, errBackendDown)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, strings.Count(err.Error(), "context canceled"))
	assert.NotContains(t, err.Error(), "deadline exceeded", "only the last context error is kept")

	assert.NoError(t, joinOperationErrors([]error{nil, nil}))
}

// TestRunJailOperationSkipsTheClientOnceCanceled pins that a canceled run does
// not start another fail2ban-client and reports why the jail was skipped.
func TestRunJailOperationSkipsTheClientOnceCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	operation := OperationType{
		Operation: constants.OpBan,
		OperationCtx: func(context.Context, fail2ban.Client, string, string) (int, error) {
			calls++
			return 0, nil
		},
	}

	result, err := runJailOperation(
		ctx, fail2bantest.NewMockClient(), "192.0.2.1", "sshd", operation, GetContextualLogger(), failureTestConfig(),
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, "context canceled", result.Status)
	assert.Zero(t, calls)
}

// TestProcessWithValidationStopsBeforeTheOperation pins that bad input never
// reaches the operation that changes firewall state.
func TestProcessWithValidationStopsBeforeTheOperation(t *testing.T) {
	tests := map[string]struct {
		ip    string
		jails []string
	}{
		"invalid ip":          {"not-an-ip", []string{"sshd"}},
		"invalid second jail": {"192.0.2.1", []string{"sshd", "bad;jail"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			operation := func(context.Context, fail2ban.Client, string, []string) ([]OperationResult, error) {
				called = true
				return nil, nil
			}

			_, err := processWithValidation(
				context.Background(),
				fail2bantest.NewMockClient(),
				tt.ip,
				tt.jails,
				operation,
			)

			require.Error(t, err)
			assert.False(t, called)
		})
	}
}

// TestHandleValidationErrorKeepsItsRemediation pins that an error which already
// carries a hint is not rewrapped by the keyword match, which replaces the hint.
func TestHandleValidationErrorKeepsItsRemediation(t *testing.T) {
	err := HandleValidationError(fail2ban.NewValidationError("invalid thing", "the specific hint"))

	assert.True(t, IsPrinted(err))
	var contextual *fail2ban.ContextualError
	require.True(t, errors.As(err, &contextual))
	assert.Equal(t, "the specific hint", contextual.GetRemediation())
}

func TestErrorHandlersPassNilThrough(t *testing.T) {
	require.NoError(t, HandleClientError(nil))
	require.NoError(t, HandleValidationError(nil))
}
