package cmd

import (
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// LogsCmd returns the logs command with injected client and config
func LogsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := NewCommand("logs [jail] [ip]", "Show Fail2Ban logs (optionally filtered by jail and/or IP)", nil, func(cmd *cobra.Command, args []string) error {
		// Parse optional arguments
		parsedArgs := ParseOptionalArgs(args, 2)
		jail := parsedArgs[0]
		ip := parsedArgs[1]

		limit, _ := cmd.Flags().GetInt("limit")
		lines, err := client.GetLogLines(jail, ip)
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
