package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/shared"
)

// ServiceCmd returns the service command with injected config
func ServiceCmd(config *Config) *cobra.Command {
	return NewCommand(
		"service [start|stop|restart|status|reload|enable|disable]",
		"Manage the Fail2Ban service",
		nil,
		func(_ *cobra.Command, args []string) error {
			// Validate service action argument
			if err := RequireArguments(
				args,
				1,
				"action required: start|stop|restart|status|reload|enable|disable",
			); err != nil {
				return HandleValidationError(err)
			}

			action := args[0]
			if err := ValidateServiceAction(action); err != nil {
				return HandleValidationError(err)
			}

			out, err := fail2ban.RunnerCombinedOutputWithSudo(shared.ServiceCommand, shared.ServiceFail2ban, action)
			if err != nil {
				return HandleSystemError(err)
			}

			PrintOutput(string(out), config.Format)
			return nil
		})
}
