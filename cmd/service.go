package cmd

import (
	"fmt"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/spf13/cobra"
)

// ServiceCmd returns the service command with injected config
func ServiceCmd(config *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "service [start|stop|restart|status|reload|enable|disable]",
		Short: "Manage the Fail2Ban service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				PrintError(fmt.Errorf("action required: start|stop|restart|status|reload|enable|disable"))
				return nil
			}
			action := args[0]

			// Validate action to prevent command injection
			validActions := map[string]bool{
				"start":   true,
				"stop":    true,
				"restart": true,
				"status":  true,
				"reload":  true,
				"enable":  true,
				"disable": true,
			}

			if !validActions[action] {
				PrintError(fmt.Errorf("invalid service action: %s. Valid actions: start, stop, restart, status, reload, enable, disable", action))
				return nil
			}

			out, err := fail2ban.RunnerCombinedOutputWithSudo("service", "fail2ban", action)
			if err != nil {
				PrintError(err)
				return err
			}
			PrintOutput(string(out), config.Format)
			return nil
		},
	}
}
