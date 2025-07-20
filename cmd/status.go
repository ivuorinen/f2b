package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// StatusCmd returns the status command with injected client and config
func StatusCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"status [all|<jail>]",
		"Show status of all jails or a specific jail",
		[]string{"st", "stat", "show-status"},
		func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				jails, _ := client.ListJails()
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
			if target == "all" {
				out, err := client.StatusAll()
				if err != nil {
					return HandleClientError(err)
				}
				status := FormatStatusResult("", out)
				PrintOutputTo(GetCmdOutput(cmd), status, config.Format)
				return nil
			}

			// Check if jail exists
			jails, _ := client.ListJails()
			jailExists := false
			for _, j := range jails {
				if j == target {
					jailExists = true
					break
				}
			}

			if !jailExists {
				return PrintErrorAndReturn(fmt.Errorf("jail '%s' not found", target))
			}

			out, err := client.StatusJail(target)
			if err != nil {
				return HandleClientError(err)
			}

			status := FormatStatusResult(target, out)
			PrintOutputTo(GetCmdOutput(cmd), status, config.Format)
			return nil
		})
}
