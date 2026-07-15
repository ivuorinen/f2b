package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BanCmd returns the ban command with injected client and config
func BanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewIPCommand(client, config, IPCommandConfig{
		CommandName:   "ban",
		Usage:         "ban <ip> [jail]",
		Description:   "Ban an IP address",
		Aliases:       []string{"banip", "b"},
		OperationName: "ban_command",
		SingleOp:      ProcessBanOperationWithContext,
		ParallelOp:    ProcessBanOperationParallelWithContext,
	})
}
