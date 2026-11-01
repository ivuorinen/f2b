package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// ServiceCmd returns the service command with injected config
func ServiceCmd(config *Config) *cobra.Command {
	actions := strings.Join(serviceActions, "|")
	return NewCommand(
		"service ["+actions+"]",
		"Manage the Fail2Ban service",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Validate service action argument
			if err := RequireArguments(args, 1, "action required: "+actions); err != nil {
				return HandleValidationError(err)
			}

			action := args[0]
			if err := ValidateServiceAction(action); err != nil {
				return HandleValidationError(err)
			}

			// cmd.Context() carries Ctrl-C/SIGTERM cancellation. No
			// CommandTimeout is applied: a service restart can legitimately
			// take longer than the per-command default.
			ctx := cmd.Context()

			// enable/disable are systemd concepts that service(8) does not
			// forward to systemctl, so invoke systemctl directly for them.
			// The runner folds the command's own diagnostic output into a
			// failure's error, so it is not appended again here.
			var out []byte
			var err error
			if action == "enable" || action == "disable" {
				out, err = fail2ban.RunnerCombinedOutputWithSudoContext(
					ctx,
					"systemctl",
					action,
					constants.ServiceFail2ban,
				)
			} else {
				out, err = fail2ban.RunnerCombinedOutputWithSudoContext(
					ctx,
					constants.ServiceCommand,
					constants.ServiceFail2ban,
					action,
				)
			}
			if err != nil {
				Logger.WithField("action", action).WithError(err).Error("Service action failed")
				return HandleSystemError(err)
			}

			// A privileged state change (stop/disable/restart) must leave an
			// audit record like ban/unban do, not only stdout output.
			Logger.WithField("action", action).Info("Service action completed")
			return PrintOutput(string(out), config.Format)
		})
}
