package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockForBannedInTest sets up mock responses for BannedIn tests
func setupMockForBannedInTest(ip, mockResponse string) *MockRunner {
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client banned "+ip, []byte(mockResponse))
	mock.SetResponse("sudo fail2ban-client banned "+ip, []byte(mockResponse))
	return mock
}

// newBannedInClient builds a client whose banned query for ip returns response.
func newBannedInClient(t *testing.T, ip, response string) *RealClient {
	t.Helper()
	t.Cleanup(WithTestRunner(t, setupMockForBannedInTest(ip, response)))
	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	require.NoError(t, err)
	return client
}

func TestBannedInWithContext(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     []string
	}{
		{name: "single jail", response: `["sshd"]`, want: []string{"sshd"}},
		{name: "multiple jails", response: `["sshd", "apache"]`, want: []string{"sshd", "apache"}},
		{name: "not banned", response: `[]`, want: []string{}},
		{
			// Combined output carries stderr too; only the last line is the
			// jail list, so sudo's warning must not become a jail name.
			name:     "stderr noise before the jail list",
			response: "sudo: unable to resolve host h: Name or service not known\n['sshd']\n",
			want:     []string{"sshd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newBannedInClient(t, "192.168.1.100", tt.response)
			got, err := client.BannedInWithContext(context.Background(), "192.168.1.100")
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBannedInWithContext_InvalidIP(t *testing.T) {
	client := newBannedInClient(t, "invalid-ip", "")
	_, err := client.BannedInWithContext(context.Background(), "invalid-ip")
	require.Error(t, err)
}

// TestBanIPParsesLastOutputLine pins that the ban/unban count is read from the
// last output line: a stderr line before fail2ban-client's count turned a
// successful ban into "unexpected output".
func TestBanIPParsesLastOutputLine(t *testing.T) {
	mock := setupMockForBannedInTest("192.168.1.100", `[]`)
	noisy := []byte("sudo: unable to resolve host h: Name or service not known\n1\n")
	mock.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.100", noisy)
	mock.SetResponse("fail2ban-client set sshd banip 192.168.1.100", noisy)
	mock.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.100", []byte("warning\n0\n"))
	mock.SetResponse("fail2ban-client set sshd unbanip 192.168.1.100", []byte("warning\n0\n"))
	t.Cleanup(WithTestRunner(t, mock))
	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	code, err := client.BanIPWithContext(context.Background(), "192.168.1.100", "sshd")
	require.NoError(t, err)
	assert.Equal(t, 0, code, "count 1 means newly banned")

	code, err = client.UnbanIPWithContext(context.Background(), "192.168.1.100", "sshd")
	require.NoError(t, err)
	assert.Equal(t, 1, code, "count 0 means already unbanned")
}
