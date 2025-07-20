package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// ListJailsCmd returns the list-jails command with injected client
func ListJailsCmd(client fail2ban.Client) *cobra.Command {
	return NewCommand("list-jails", "List all jails", []string{"ls-jails", "jails"}, func(cmd *cobra.Command, args []string) error {
		jails, err := client.ListJails()
		if err != nil {
			return HandleClientError(err)
		}

		if _, err := fmt.Fprintln(GetCmdOutput(cmd), strings.Join(jails, " ")); err != nil {
			return err
		}
		return nil
	})
}
