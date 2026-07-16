package cmd

import (
	"context"

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
			base := cmd.Context()
			if base == nil {
				base = context.Background()
			}
			ctx, cancel := context.WithTimeout(base, config.FileTimeout)
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

			// Read-time limit when available (see logLinesLimiter): the
			// fallback path caps at the fail2ban layer's default, so -n above
			// that would silently truncate.
			var lines []string
			var err error
			if lc, ok := client.(logLinesLimiter); ok {
				lines, err = lc.GetLogLinesWithLimitContext(ctx, jail, ip, limit)
			} else {
				lines, err = client.GetLogLinesWithContext(ctx, jail, ip)
				if err == nil && limit > 0 && len(lines) > limit {
					lines = lines[len(lines)-limit:]
				}
			}
			if err != nil {
				return HandleClientError(err)
			}

			PrintOutputTo(GetCmdOutput(cmd), lines, config.Format)
			return nil
		})

	AddLogFlags(cmd)
	return cmd
}
