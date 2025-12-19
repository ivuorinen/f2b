package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// StatusCmd returns the status command with injected client and config
func StatusCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"status [all|<jail>]",
		"Show status of all jails or a specific jail",
		[]string{"st", "stat", "show-status"},
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for the entire status operation
			ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
			defer cancel()

			if len(args) == 0 {
				jails, err := client.ListJailsWithContext(ctx)
				if err != nil {
					// Log error but continue with empty jail list for help display
					Logger.WithError(err).Warn("Failed to fetch jails for help display")
					jails = []string{}
				}
				PrintOutputTo(
					GetCmdOutput(cmd),
					"Usage: "+cmd.Root().Use+" status all   (show all jails)",
					config.Format,
				)
				PrintOutputTo(
					GetCmdOutput(cmd),
					"       "+cmd.Root().Use+" status <jail> (show specific jail)",
					config.Format,
				)
				PrintOutputTo(GetCmdOutput(cmd), "Available jails: "+strings.Join(jails, " "), config.Format)
				return nil
			}

			target := strings.ToLower(args[0])
			if target == shared.AllFilter {
				out, err := client.StatusAllWithContext(ctx)
				if err != nil {
					return HandleClientError(err)
				}
				status := FormatStatusResult("", out)
				PrintOutputTo(GetCmdOutput(cmd), status, config.Format)
				return nil
			}

			// Check if jail exists (with timeout context)
			jails, err := client.ListJailsWithContext(ctx)
			if err != nil {
				return HandleClientError(err)
			}
			jailExists := false
			for _, j := range jails {
				if j == target {
					jailExists = true
					break
				}
			}

			if !jailExists {
				return HandleClientError(fail2ban.NewJailNotFoundError(target))
			}

			out, err := client.StatusJailWithContext(ctx, target)
			if err != nil {
				return HandleClientError(err)
			}

			status := FormatStatusResult(target, out)
			PrintOutputTo(GetCmdOutput(cmd), status, config.Format)
			return nil
		})
}
