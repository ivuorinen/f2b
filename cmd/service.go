package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// ServiceCmd returns the service command with injected config
func ServiceCmd(config *Config) *cobra.Command {
	return NewCommand(
		"service [start|stop|restart|status|reload|enable|disable]",
		"Manage the Fail2Ban service",
		nil,
		func(_ *cobra.Command, args []string) error {
			// Validate service action argument
			if err := RequireArguments(args, 1, "action required: start|stop|restart|status|reload|enable|disable"); err != nil {
				PrintError(err)
				return nil
			}

			action := args[0]
			if err := ValidateServiceAction(action); err != nil {
				PrintError(err)
				return nil
			}

			out, err := fail2ban.RunnerCombinedOutputWithSudo("service", "fail2ban", action)
			if err != nil {
				return HandleClientError(err)
			}

			PrintOutput(string(out), config.Format)
			return nil
		})
}
