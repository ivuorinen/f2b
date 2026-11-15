package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestCommandsRejectSurplusArguments pins the arity of every command: a user
// naming two jails used to get results for the first with exit 0 and no
// warning. ValidateArgs is the check cobra runs before the command body.
func TestCommandsRejectSurplusArguments(t *testing.T) {
	client := fail2bantest.NewMockClient()
	config := &Config{Format: PlainFormat}

	tests := map[string]struct {
		cmd      *cobra.Command
		accepted []string
		surplus  []string
	}{
		"list-jails": {ListJailsCmd(client, config), nil, []string{"extra"}},
		"version":    {VersionCmd(config), nil, []string{"extra"}},
		"status":     {StatusCmd(client, config), []string{"sshd"}, []string{"sshd", "extra"}},
		"banned":     {BannedCmd(client, config), []string{"sshd"}, []string{"sshd", "nginx"}},
		"test":       {TestIPCmd(client, config), []string{"192.0.2.1"}, []string{"192.0.2.1", "extra"}},
		"test-filter": {
			TestFilterCmd(client, config),
			[]string{"sshd", "/var/log/auth.log"},
			[]string{"sshd", "/var/log/auth.log", "extra"},
		},
		"logs": {LogsCmd(client, config), []string{"sshd", "192.0.2.1"}, []string{"sshd", "192.0.2.1", "extra"}},
		"logs-watch": {
			LogsWatchCmd(client, config),
			[]string{"sshd", "192.0.2.1"},
			[]string{"sshd", "192.0.2.1", "extra"},
		},
		"service": {ServiceCmd(fail2bantest.NewMockRunner(), config), []string{"status"}, []string{"status", "extra"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, tt.cmd.ValidateArgs(tt.accepted))
			require.Error(t, tt.cmd.ValidateArgs(tt.surplus))
		})
	}
}
