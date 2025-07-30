package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// ListJailsCmd returns the list-jails command with injected client and config
func ListJailsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"list-jails",
		"List all jails",
		[]string{"ls-jails", "jails"},
		func(cmd *cobra.Command, _ []string) error {
			// Create timeout context for listing jails
			ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
			defer cancel()

			jails, err := client.ListJailsWithContext(ctx)
			if err != nil {
				return HandleClientError(err)
			}

			if _, err := fmt.Fprintln(GetCmdOutput(cmd), strings.Join(jails, " ")); err != nil {
				return err
			}
			return nil
		})
}
