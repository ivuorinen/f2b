package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// LogsCmd returns the logs command with injected client and config
func LogsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := NewCommand(
		"logs [jail] [ip]",
		"Show Fail2Ban logs (optionally filtered by jail and/or IP)",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for log reading (use file timeout)
			ctx, cancel := context.WithTimeout(context.Background(), config.FileTimeout)
			defer cancel()

			// Parse optional arguments
			parsedArgs := ParseOptionalArgs(args, 2)
			jail := parsedArgs[0]
			ip := parsedArgs[1]

			limit, _ := cmd.Flags().GetInt("limit")
			if limit < 0 {
				limit = 0
			}
			lines, err := client.GetLogLinesWithContext(ctx, jail, ip)
			if err != nil {
				return HandleClientError(err)
			}

			if limit > 0 && len(lines) > limit {
				lines = lines[len(lines)-limit:]
			}

			PrintOutputTo(GetCmdOutput(cmd), lines, config.Format)
			return nil
		})

	AddLogFlags(cmd)
	return cmd
}
