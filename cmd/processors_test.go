package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestUnbanProcessorProcessParallel tests the ProcessParallel method
func TestUnbanProcessorProcessParallel(t *testing.T) {
	mockRunner := fail2ban.NewMockRunner()
	defer fail2ban.WithTestRunner(t, mockRunner)()
	fail2ban.StandardMockSetup(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("fail2ban-client set apache unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set apache unbanip 192.168.1.1", []byte("1"))

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	processor := &UnbanProcessor{}
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
			results, err := processor.ProcessParallel(ctx, client, tt.ip, tt.jails)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, len(tt.jails))
			}
		})
	}
}
