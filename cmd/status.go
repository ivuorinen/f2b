package cmd

import (
	"context"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// StatusCmd returns the status command with injected client and config
func StatusCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"status [all|<jail>]",
		"Show status of all jails or a specific jail",
		[]string{"st", "stat", "show-status"},
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for the entire status operation
			ctx, cancel := createTimeoutContext(cmd.Context(), config)
			defer cancel()

			if len(args) == 0 {
				return printStatusUsage(ctx, cmd, client, config)
			}

			// Jail names are case-sensitive; keep the argument verbatim and
			// only treat the special "all" selector case-insensitively.
			target := args[0]
			if strings.EqualFold(target, constants.AllFilter) {
				out, err := client.StatusAllWithContext(ctx)
				if err != nil {
					return HandleClientError(err)
				}
				return PrintOutputTo(GetCmdOutput(cmd), FormatStatusResult("", out), config.Format)
			}

			// Check if jail exists (with timeout context)
			jails, err := client.ListJailsWithContext(ctx)
			if err != nil {
				return HandleClientError(err)
			}
			jailExists := slices.Contains(jails, target)

			if !jailExists {
				return HandleClientError(fail2ban.NewJailNotFoundError(target))
			}

			out, err := client.StatusJailWithContext(ctx, target)
			if err != nil {
				return HandleClientError(err)
			}

			return PrintOutputTo(GetCmdOutput(cmd), FormatStatusResult(target, out), config.Format)
		})
}

// printStatusUsage prints the status command usage help, listing the currently
// available jails. A jail-list error is non-fatal here: it degrades to an
// empty list so the help still prints.
func printStatusUsage(ctx context.Context, cmd *cobra.Command, client fail2ban.Client, config *Config) error {
	jails, err := client.ListJailsWithContext(ctx)
	if err != nil {
		Logger.WithError(err).Warn("Failed to fetch jails for help display")
		jails = []string{}
	}
	out := GetCmdOutput(cmd)
	for _, line := range []string{
		"Usage: " + cmd.Root().Use + " status all   (show all jails)",
		"       " + cmd.Root().Use + " status <jail> (show specific jail)",
		"Available jails: " + strings.Join(jails, " "),
	} {
		if err := PrintOutputTo(out, line, config.Format); err != nil {
			return err
		}
	}
	return nil
}
