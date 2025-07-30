package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BannedCmd returns the banned command with injected client and config
func BannedCmd(client interface {
	GetBanRecordsWithContext(context.Context, []string) ([]fail2ban.BanRecord, error)
}, config *Config) *cobra.Command {
	return NewCommand(
		"banned [all|<jail>]",
		"List banned IPs with remaining time",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for banned operation
			ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
			defer cancel()

			target := "all"
			if len(args) > 0 {
				target = strings.ToLower(args[0])
			}

			records, err := client.GetBanRecordsWithContext(ctx, []string{target})
			if err != nil {
				return HandleClientError(err)
			}

			if config.Format == JSONFormat {
				PrintOutputTo(GetCmdOutput(cmd), records, config.Format)
			} else {
				for _, r := range records {
					PrintOutputTo(GetCmdOutput(cmd),
						r.Jail+" | "+r.IP+" | "+r.Remaining+" remaining",
						config.Format,
					)
				}
			}
			return nil
		})
}
