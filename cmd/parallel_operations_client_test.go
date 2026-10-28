package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// newParallelTestClient builds a RealClient over a mock runner that answers a
// successful (count "1") response for `set <jail> <action> 192.168.1.1` on each
// given jail. Shared by the parallel ban/unban tests.
func newParallelTestClient(t *testing.T, action string, jails ...string) fail2ban.Client {
	t.Helper()
	mockRunner := fail2ban.NewMockRunner()
	t.Cleanup(fail2ban.WithTestRunner(t, mockRunner))
	fail2ban.StandardMockSetup(mockRunner)
	for _, jail := range jails {
		cmd := "fail2ban-client set " + jail + " " + action + " 192.168.1.1"
		mockRunner.SetResponse(cmd, []byte("1"))
		mockRunner.SetResponse("sudo "+cmd, []byte("1"))
	}
	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)
	return client
}

// assertParallelResults checks each per-jail outcome, not just the slice
// length — a regression that fails every jail while still returning a
// populated slice must fail these tests.
func assertParallelResults(t *testing.T, results []OperationResult, ip, wantStatus string, jails ...string) {
	t.Helper()
	assert.Len(t, results, len(jails))
	seen := map[string]bool{}
	for _, r := range results {
		assert.Equal(t, ip, r.IP)
		assert.Equal(t, wantStatus, r.Status, "jail %s", r.Jail)
		seen[r.Jail] = true
	}
	for _, jail := range jails {
		assert.True(t, seen[jail], "no result for jail %s", jail)
	}
}

// TestProcessBanOperationParallelMultiJail covers the concurrent multi-jail ban path.
func TestProcessBanOperationParallelMultiJail(t *testing.T) {
	client := newParallelTestClient(t, "banip", "sshd", "apache")
	results, err := ProcessBanOperationParallelWithContext(
		context.Background(), client, "192.168.1.1", []string{"sshd", "apache"})
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Banned", "sshd", "apache")
}

// TestProcessUnbanOperationParallelMultiJail covers the concurrent multi-jail unban path.
func TestProcessUnbanOperationParallelMultiJail(t *testing.T) {
	client := newParallelTestClient(t, "unbanip", "sshd", "apache")
	results, err := ProcessUnbanOperationParallelWithContext(
		context.Background(), client, "192.168.1.1", []string{"sshd", "apache"})
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Unbanned", "sshd", "apache")
}

// TestProcessBanOperationParallelWithContext covers the single-jail ban path.
func TestProcessBanOperationParallelWithContext(t *testing.T) {
	client := newParallelTestClient(t, "banip", "sshd")
	results, err := ProcessBanOperationParallelWithContext(
		context.Background(),
		client,
		"192.168.1.1",
		[]string{"sshd"},
	)
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Banned", "sshd")
}

// TestProcessUnbanOperationParallelWithContext covers the single-jail unban path.
func TestProcessUnbanOperationParallelWithContext(t *testing.T) {
	client := newParallelTestClient(t, "unbanip", "sshd")
	results, err := ProcessUnbanOperationParallelWithContext(
		context.Background(),
		client,
		"192.168.1.1",
		[]string{"sshd"},
	)
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Unbanned", "sshd")
}

// TestProcessOperationWithContextKeepsPartialResults pins that a failure on a
// later jail still returns the jails already changed: dropping them hid that
// firewall state had been modified.
func TestProcessOperationWithContextKeepsPartialResults(t *testing.T) {
	mock := fail2ban.NewMockClient()
	results, err := ProcessOperationWithContext(
		context.Background(), mock, "192.168.1.1", []string{"sshd", "nosuchjail"}, BanOperationType)
	require.Error(t, err)
	require.Len(t, results, 1, "the jail banned before the failure must be reported")
	assert.Equal(t, OperationResult{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"}, results[0])
}
