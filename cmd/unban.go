package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// UnbanCmd returns the unban command with injected client and config
func UnbanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewIPCommand(client, config, IPCommandConfig{
		CommandName:   "unban",
		Usage:         "unban <ip|cidr> [jail]",
		Description:   "Unban an IP address or CIDR range",
		Aliases:       []string{"unbanip", "ub"},
		OperationName: "unban_command",
		SingleOp:      ProcessUnbanOperationWithContext,
		ParallelOp: func(ctx context.Context, c fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
			return ProcessUnbanOperationParallelWithContext(ctx, c, ip, jails, config)
		},
	})
}
