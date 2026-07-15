package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// ListJailsCmd returns the list-jails command with injected client and config
func ListJailsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		constants.CLICmdListJails,
		"List all jails",
		[]string{"ls-jails", "jails"},
		func(cmd *cobra.Command, _ []string) error {
			// Create timeout context for listing jails
			ctx, cancel := createTimeoutContext(cmd.Context(), config)
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
