package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// LogsCmd returns the logs command with injected client and config
func LogsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := NewCommand(
		"logs [jail] [ip]",
		"Show Fail2Ban logs (optionally filtered by jail and/or IP)",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Derive from cmd.Context() so SIGINT cancels the read instead of
			// waiting out the file timeout.
			ctx, cancel := context.WithTimeout(cmd.Context(), config.FileTimeout)
			defer cancel()

			// Parse optional arguments
			parsedArgs := ParseOptionalArgs(args, 2)
			jail := parsedArgs[0]
			ip := parsedArgs[1]

			limit, _ := cmd.Flags().GetInt(constants.FlagLimit)
			switch {
			case limit <= 0:
				limit = constants.DefaultLogLinesLimit
			case limit > constants.MaxLogLinesLimit:
				Logger.WithField("limit", limit).
					Warnf("limit exceeds maximum, clamping to %d", constants.MaxLogLinesLimit)
				limit = constants.MaxLogLinesLimit
			}

			lines, err := client.GetLogLinesWithLimitContext(ctx, jail, ip, limit)
			if err != nil {
				return HandleClientError(err)
			}

			return printLogLines(cmd, lines, config.Format)
		})

	AddLogFlags(cmd)
	return cmd
}

// printLogLines writes log lines one per line in plain mode, so `f2b logs |
// wc -l` counts matches, and as a JSON array otherwise. Printing the slice
// through the generic plain path rendered every match space-joined inside
// "[ ]" on a single line.
func printLogLines(cmd *cobra.Command, lines []string, format string) error {
	if format == JSONFormat {
		return PrintOutputTo(GetCmdOutput(cmd), lines, format)
	}
	if len(lines) == 0 {
		return nil
	}
	return PrintOutputTo(GetCmdOutput(cmd), strings.Join(lines, "\n"), format)
}
