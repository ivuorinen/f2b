package cmd

import (
	"fmt"
	"strings"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// StatusCmd returns the status command with injected client and config
func StatusCmd(client fail2ban.Client, config *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status [all|<jail>]",
		Short:   "Show status of all jails or a specific jail",
		Aliases: []string{"st", "stat", "show-status"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				jails, _ := client.ListJails()
				PrintOutputTo(GetCmdOutput(cmd), "Usage: "+cmd.Root().Use+" status all   (show all jails)", config.Format)
				PrintOutputTo(GetCmdOutput(cmd), "       "+cmd.Root().Use+" status <jail> (show specific jail)", config.Format)
				PrintOutputTo(GetCmdOutput(cmd), "Available jails: "+strings.Join(jails, " "), config.Format)
				return nil
			}
			target := strings.ToLower(args[0])
			if target == "all" {
				out, err := client.StatusAll()
				if err != nil {
					PrintError(err)
					return err
				}
				PrintOutputTo(GetCmdOutput(cmd), out, config.Format)
				return nil
			}
			jails, _ := client.ListJails()
			for _, j := range jails {
				if j == target {
					out, err := client.StatusJail(target)
					if err != nil {
						PrintError(err)
						return err
					}
					PrintOutputTo(GetCmdOutput(cmd), out, config.Format)
					return nil
				}
			}
			err := fmt.Errorf("jail '%s' not found", target)
			PrintError(err)
			return err
		},
	}
	return cmd
}
