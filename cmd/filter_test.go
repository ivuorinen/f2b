package cmd

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestTestFilterCmdCreation tests TestFilterCmd command creation
func TestTestFilterCmdCreation(t *testing.T) {
	mockRunner := fail2ban.NewMockRunner()
	restoreRunner := fail2ban.WithTestRunner(t, mockRunner)
	defer restoreRunner()
	fail2ban.StandardMockSetup(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	config := &Config{
		Format:      PlainFormat,
		FileTimeout: 5 * time.Second,
	}

	cmd := TestFilterCmd(client, config)

	// Verify command structure
	assert.NotNil(t, cmd)
	assert.Equal(t, "test-filter <filter>", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

// TestTestFilterCmdExecution tests TestFilterCmd execution
func TestTestFilterCmdExecution(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*fail2ban.MockClient)
		args        []string
		expectError bool
		wantOutput  string
	}{
		{
			name: "successful filter test",
			setup: func(m *fail2ban.MockClient) {
				m.SetFilterTest("sshd", "Filter sshd: 3 matches in /var/log/auth.log")
			},
			args:        []string{"sshd"},
			expectError: false,
			wantOutput:  "Filter sshd: 3 matches in /var/log/auth.log",
		},
		{
			name:        "no filter provided - lists available",
			setup:       func(_ *fail2ban.MockClient) {},
			args:        []string{},
			expectError: true, // Should error saying filter required
		},
		{
			name:        "invalid filter name (path traversal)",
			setup:       func(_ *fail2ban.MockClient) {},
			args:        []string{"../../../etc/passwd"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A MockClient makes the success path deterministic: its
			// TestFilterWithContext returns the configured output, so the
			// happy path can assert real output without a filesystem fixture.
			client := fail2ban.NewMockClient()
			tt.setup(client)

			config := &Config{
				Format:      PlainFormat,
				FileTimeout: 5 * time.Second,
			}

			cmd := TestFilterCmd(client, config)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Contains(t, out.String(), tt.wantOutput)
		})
	}
}
