package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFail2banLog writes lines as dir/fail2ban.log.
func writeFail2banLog(t *testing.T, dir string, lines ...string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fail2ban.log"), []byte(content), 0o600))
}

// TestGetLogLinesWithContextDefaultLimit checks that the default-limit read
// returns the matching lines and validates its filters like the limited read.
func TestGetLogLinesWithContextDefaultLimit(t *testing.T) {
	dir := t.TempDir()
	writeFail2banLog(t, dir,
		"2025-01-01 10:00:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
		"2025-01-01 10:01:00 fail2ban.actions [1]: NOTICE [apache] Ban 192.168.1.1",
		"2025-01-01 10:02:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.10",
	)
	client := &RealClient{LogDir: dir}

	lines, err := client.GetLogLinesWithContext(context.Background(), "sshd", "192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"2025-01-01 10:00:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1"}, lines)

	_, err = client.GetLogLinesWithContext(context.Background(), "bad jail;rm", "")
	require.Error(t, err, "an invalid jail filter must be rejected, not silently match nothing")
	_, err = client.GetLogLinesWithContext(context.Background(), "", "not-an-ip")
	require.Error(t, err, "an invalid IP filter must be rejected, not silently match nothing")
}

// TestBanIPWithContext tests the BanIPWithContext function
func TestBanIPWithContext(t *testing.T) {
	restoreRunner := WithTestRunner(t, GetRunner())
	defer restoreRunner()

	tests := []struct {
		name        string
		setupMock   func(*MockRunner)
		ip          string
		jail        string
		expectError bool
	}{
		{
			name: "successful ban",
			setupMock: func(m *MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
				m.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
				m.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
				m.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
				m.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				m.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				m.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
				m.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
			},
			ip:          "192.168.1.1",
			jail:        "sshd",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRunner := NewMockRunner()
			tt.setupMock(mockRunner)
			SetRunner(mockRunner)

			client, err := NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
			require.NoError(t, err)

			ctx := context.Background()
			count, err := client.BanIPWithContext(ctx, tt.ip, tt.jail)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, count, 0, "Count should be 0 (new ban) or 1 (already banned)")
			}
		})
	}
}

// TestGetLogLinesWithLimitContextOutcomes pins the exact result of the
// limited read: the newest maxLines matching lines, nothing for a zero limit,
// and the context error for an expired deadline.
func TestGetLogLinesWithLimitContextOutcomes(t *testing.T) {
	dir := t.TempDir()
	writeFail2banLog(t, dir,
		"2025-01-01 10:00:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
		"2025-01-01 10:01:00 fail2ban.actions [1]: NOTICE [apache] Ban 192.168.1.1",
		"2025-01-01 10:02:00 fail2ban.actions [1]: NOTICE [sshd] Unban 192.168.1.1",
		"2025-01-01 10:03:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
	)
	client := &RealClient{LogDir: dir}

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	tests := []struct {
		name     string
		expired  bool
		maxLines int
		want     []string
		wantErr  error
	}{
		{
			name:     "limit keeps the newest matching lines",
			maxLines: 2,
			want: []string{
				"2025-01-01 10:02:00 fail2ban.actions [1]: NOTICE [sshd] Unban 192.168.1.1",
				"2025-01-01 10:03:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
			},
		},
		{
			name:     "limit above the match count returns every match",
			maxLines: 10,
			want: []string{
				"2025-01-01 10:00:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
				"2025-01-01 10:02:00 fail2ban.actions [1]: NOTICE [sshd] Unban 192.168.1.1",
				"2025-01-01 10:03:00 fail2ban.actions [1]: NOTICE [sshd] Ban 192.168.1.1",
			},
		},
		{
			name:     "zero max lines returns an empty slice",
			maxLines: 0,
			want:     []string{},
		},
		{
			name:     "expired context returns the deadline error",
			expired:  true,
			maxLines: 10,
			wantErr:  context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.expired {
				ctx = expired
			}
			lines, err := client.GetLogLinesWithLimitContext(ctx, "sshd", "192.168.1.1", tt.maxLines)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, lines)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, lines)
		})
	}
}
