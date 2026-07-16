package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// UnbanCmd returns the unban command with injected client and config
func UnbanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewIPCommand(client, config, IPCommandConfig{
		CommandName:   "unban",
		Usage:         "unban <ip> [jail]",
		Description:   "Unban an IP address",
		Aliases:       []string{"unbanip", "ub"},
		OperationName: "unban_command",
		SingleOp:      ProcessUnbanOperationWithContext,
		ParallelOp:    ProcessUnbanOperationParallelWithContext,
	})
}
