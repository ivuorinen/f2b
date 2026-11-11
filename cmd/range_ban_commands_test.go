package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestBanAndUnbanAcceptARange pins the CLI side of range bans: the range
// reaches the client as typed and is reported back.
func TestBanAndUnbanAcceptARange(t *testing.T) {
	const target = "198.51.100.0/24"
	client := fail2bantest.NewMockClient()

	out, err := executeForOutput(BanCmd(client, failureTestConfig()), target, "sshd")
	require.NoError(t, err)
	assert.Contains(t, out, target)
	assert.Contains(t, client.Banned["sshd"], target)

	_, err = executeForOutput(UnbanCmd(client, failureTestConfig()), target, "sshd")
	require.NoError(t, err)
	assert.NotContains(t, client.Banned["sshd"], target)
}

// TestTestIPRefusesARange pins that `test` stays address-only: fail2ban's
// `banned` matches the exact ban entry, so a range would report an address
// inside it as not banned.
func TestTestIPRefusesARange(t *testing.T) {
	_, err := executeForOutput(TestIPCmd(fail2bantest.NewMockClient(), failureTestConfig()), "198.51.100.0/24")

	require.Error(t, err)
}
