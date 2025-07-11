package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// ListJailsCmd returns the list-jails command with injected client
func ListJailsCmd(client fail2ban.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list-jails",
		Short:   "List all jails",
		Aliases: []string{"ls-jails", "jails"},
		RunE: func(cmd *cobra.Command, args []string) error {
			jails, err := client.ListJails()
			if err != nil {
				if _, ferr := fmt.Fprintln(GetCmdError(cmd), "Error:", err); ferr != nil {
					return ferr
				}
				return err
			}
			if _, err := fmt.Fprintln(GetCmdOutput(cmd), strings.Join(jails, " ")); err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}
