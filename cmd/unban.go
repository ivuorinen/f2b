package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// UnbanCmd returns the unban command with injected client and config
func UnbanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "unban <ip> [jail]",
		Short:   "Unban an IP address",
		Aliases: []string{"unbanip", "ub"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				err := fmt.Errorf("IP address required")
				PrintError(err)
				return err
			}
			ip := args[0]
			var jails []string
			if len(args) > 1 {
				jails = []string{strings.ToLower(args[1])}
			} else {
				var err error
				jails, err = client.ListJails()
				if err != nil {
					PrintError(err)
					return err
				}
			}
			// result represents the output of an unban operation for JSON output.
			type result struct {
				Status string `json:"status"`
				IP     string `json:"ip"`
				Jail   string `json:"jail"`
			}
			var results []result
			for _, jail := range jails {
				code, err := client.UnbanIP(ip, jail)
				if err != nil {
					PrintError(err)
					return err
				}
				status := "Unbanned"
				if code == 1 {
					status = "Already unbanned"
				}
				results = append(results, result{Status: status, IP: ip, Jail: jail})
			}
			if config != nil && config.Format == JSONFormat {
				PrintOutputTo(GetCmdOutput(cmd), results, config.Format)
			} else {
				for _, r := range results {
					fmt.Fprintf(GetCmdOutput(cmd), "%s %s in %s\n", r.Status, r.IP, r.Jail)
				}
			}
			return nil
		},
	}
	return cmd
}
