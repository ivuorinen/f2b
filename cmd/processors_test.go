package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestUnbanParallelOperation tests the multi-jail parallel unban path.
func TestUnbanParallelOperation(t *testing.T) {
	mockRunner := fail2bantest.NewMockRunner()
	restoreRunner := fail2bantest.WithTestRunner(t, mockRunner)
	defer restoreRunner()
	fail2bantest.StandardMockSetup(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("fail2ban-client set apache unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set apache unbanip 192.168.1.1", []byte("1"))

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name        string
		ip          string
		jails       []string
		expectError bool
	}{
		{
			name:        "successful parallel unban",
			ip:          "192.168.1.1",
			jails:       []string{"sshd", "apache"},
			expectError: false,
		},
		{
			name:        "single jail unban",
			ip:          "192.168.1.1",
			jails:       []string{"sshd"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := processWithValidation(
				ctx,
				client,
				tt.ip,
				tt.jails,
				func(ctx context.Context, c fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
					return ProcessUnbanOperationParallelWithContext(ctx, c, ip, jails, nil)
				},
			)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, len(tt.jails))
			}
		})
	}
}
