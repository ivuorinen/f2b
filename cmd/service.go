package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
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

			// enable/disable are systemd concepts that service(8) does not
			// forward to systemctl, so invoke systemctl directly for them.
			var out []byte
			var err error
			if action == "enable" || action == "disable" {
				out, err = fail2ban.RunnerCombinedOutputWithSudo("systemctl", action, constants.ServiceFail2ban)
			} else {
				out, err = fail2ban.RunnerCombinedOutputWithSudo(
					constants.ServiceCommand,
					constants.ServiceFail2ban,
					action,
				)
			}
			if err != nil {
				// Surface the underlying diagnostic output (from systemctl or
				// the init script) instead of only the generic exec error.
				if trimmed := TrimmedOutput(out); trimmed != "" {
					return HandleSystemError(fmt.Errorf("%w: %s", err, trimmed))
				}
				return HandleSystemError(err)
			}

			PrintOutput(string(out), config.Format)
			return nil
		})
}
