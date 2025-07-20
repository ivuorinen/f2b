package cmd

import (
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// BannedCmd returns the banned command with injected client and config
func BannedCmd(client interface {
	GetBanRecords([]string) ([]fail2ban.BanRecord, error)
}, format string) *cobra.Command {
	return NewCommand("banned [all|<jail>]", "List banned IPs with remaining time", nil, func(cmd *cobra.Command, args []string) error {
		target := "all"
		if len(args) > 0 {
			target = strings.ToLower(args[0])
		}

		records, err := client.GetBanRecords([]string{target})
		if err != nil {
			return HandleClientError(err)
		}

		if format == JSONFormat {
			PrintOutputTo(GetCmdOutput(cmd), records, format)
		} else {
			for _, r := range records {
				PrintOutputTo(GetCmdOutput(cmd),
					r.Jail+" | "+r.IP+" | "+r.Remaining+" remaining",
					format,
				)
			}
		}
		return nil
	})
}
