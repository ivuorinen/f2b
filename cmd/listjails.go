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
				fmt.Fprintln(GetCmdError(cmd), "Error:", err)
				return err
			}
			fmt.Fprintln(GetCmdOutput(cmd), strings.Join(jails, " "))
			return nil
		},
	}
	return cmd
}
