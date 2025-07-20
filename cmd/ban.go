// Package cmd contains the command packages for the f2b tool.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BanCmd returns the ban command with injected client and config
func BanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand("ban <ip> [jail]", "Ban an IP address", []string{"banip", "b"},
		func(cmd *cobra.Command, args []string) error {
			// Validate IP argument
			ip, err := ValidateIPArgument(args)
			if err != nil {
				return PrintErrorAndReturn(err)
			}

			// Get jails from arguments or client
			jails, err := GetJailsFromArgs(client, args, 1)
			if err != nil {
				return HandleClientError(err)
			}

			// Process ban operation
			results, err := ProcessBanOperation(client, ip, jails)
			if err != nil {
				return HandleClientError(err)
			}

			// Output results
			if config != nil && config.Format == JSONFormat {
				PrintOutputTo(GetCmdOutput(cmd), results, JSONFormat)
			} else {
				for _, r := range results {
					if _, err := fmt.Fprintf(GetCmdOutput(cmd), "%s %s in %s\n", r.Status, r.IP, r.Jail); err != nil {
						return err
					}
				}
			}
			return nil
		})
}
