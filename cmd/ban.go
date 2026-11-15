package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BanCmd returns the ban command with injected client and config
func BanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewIPCommand(client, config, IPCommandConfig{
		CommandName:   "ban",
		Usage:         "ban <ip|cidr> [jail]",
		Description:   "Ban an IP address or CIDR range",
		Aliases:       []string{"banip", "b"},
		OperationName: "ban_command",
		SingleOp:      ProcessBanOperationWithContext,
		ParallelOp: func(ctx context.Context, c fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
			return ProcessBanOperationParallelWithContext(ctx, c, ip, jails, config)
		},
	})
}
