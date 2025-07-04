package cmd

import (
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// LogsCmd returns the logs command with injected client and config
func LogsCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs [jail] [ip]",
		Short: "Show Fail2Ban logs (optionally filtered by jail and/or IP)",
		RunE: func(cmd *cobra.Command, args []string) error {
			jail := ""
			ip := ""
			if len(args) > 0 {
				jail = args[0]
			}
			if len(args) > 1 {
				ip = args[1]
			}
			limit, _ := cmd.Flags().GetInt("limit")
			lines, err := client.GetLogLines(jail, ip)
			if err != nil {
				PrintError(err)
				return err
			}
			if limit > 0 && len(lines) > limit {
				lines = lines[len(lines)-limit:]
			}
			PrintOutputTo(GetCmdOutput(cmd), lines, config.Format)
			return nil
		},
	}
	cmd.Flags().IntP("limit", "n", 0, "Show only the last N log lines")
	return cmd
}
