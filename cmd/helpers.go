package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// Command creation helpers

// NewCommand creates a new cobra command with standard setup
func NewCommand(use, short string, aliases []string, runE func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Aliases: aliases,
		RunE:    runE,
	}
}

// AddLogFlags adds common log-related flags to a command
func AddLogFlags(cmd *cobra.Command) {
	cmd.Flags().IntP("limit", "n", 0, "Show only the last N log lines")
}

// IsSkipCommand returns true if the command doesn't require a fail2ban client
func IsSkipCommand(command string) bool {
	skipCommands := []string{
		"service",
		"version",
		"test-filter",
		"completion",
		"help",
	}

	for _, skip := range skipCommands {
		if command == skip {
			return true
		}
	}
	return false
}

// AddWatchFlags adds common watch-related flags to a command
func AddWatchFlags(cmd *cobra.Command, interval *time.Duration) {
	cmd.Flags().DurationVarP(interval, "interval", "i", 5*time.Second, "Polling interval")
}

// Validation helpers

// ValidateIPArgument validates that an IP address is provided in args
func ValidateIPArgument(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("IP address required")
	}
	ip := args[0]
	// Validate the IP address
	if err := fail2ban.ValidateIP(ip); err != nil {
		return "", err
	}
	return ip, nil
}

// ValidateServiceAction validates that a service action is valid
func ValidateServiceAction(action string) error {
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
		return fmt.Errorf(
			"invalid service action: %s. Valid actions: start, stop, restart, status, reload, enable, disable",
			action,
		)
	}
	return nil
}

// GetJailsFromArgs gets jail list from arguments or client
func GetJailsFromArgs(client fail2ban.Client, args []string, startIndex int) ([]string, error) {
	if len(args) > startIndex {
		return []string{strings.ToLower(args[startIndex])}, nil
	}

	jails, err := client.ListJails()
	if err != nil {
		return nil, err
	}
	return jails, nil
}

// ParseOptionalArgs parses optional arguments up to a given count
func ParseOptionalArgs(args []string, count int) []string {
	result := make([]string, count)
	for i := 0; i < count && i < len(args); i++ {
		result[i] = args[i]
	}
	return result
}

// Error handling helpers

// HandleClientError handles client errors with consistent formatting
func HandleClientError(err error) error {
	if err != nil {
		PrintError(err)
		return err
	}
	return nil
}

// PrintErrorAndReturn prints an error and returns it
func PrintErrorAndReturn(err error) error {
	PrintError(err)
	return err
}

// Output helpers

// OutputResults outputs results in the specified format
func OutputResults(cmd *cobra.Command, results interface{}, config *Config) {
	if config != nil && config.Format == JSONFormat {
		PrintOutputTo(GetCmdOutput(cmd), results, JSONFormat)
	} else {
		PrintOutputTo(GetCmdOutput(cmd), results, "plain")
	}
}

// InterpretBanStatus interprets ban operation status codes
func InterpretBanStatus(code int, operation string) string {
	switch operation {
	case "ban":
		if code == 1 {
			return "Already banned"
		}
		return "Banned"
	case "unban":
		if code == 1 {
			return "Already unbanned"
		}
		return "Unbanned"
	default:
		return "Unknown"
	}
}

// Operation result types

// OperationResult represents the result of a jail operation
type OperationResult struct {
	IP     string `json:"ip"`
	Jail   string `json:"jail"`
	Status string `json:"status"`
}

// ProcessBanOperation processes ban operations across multiple jails
func ProcessBanOperation(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		code, err := client.BanIP(ip, jail)
		if err != nil {
			return nil, err
		}

		status := InterpretBanStatus(code, "ban")
		Logger.WithFields(map[string]interface{}{
			"ip":     ip,
			"jail":   jail,
			"status": status,
		}).Info("Ban result")

		results = append(results, OperationResult{
			IP:     ip,
			Jail:   jail,
			Status: status,
		})
	}

	return results, nil
}

// ProcessUnbanOperation processes unban operations across multiple jails
func ProcessUnbanOperation(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		code, err := client.UnbanIP(ip, jail)
		if err != nil {
			return nil, err
		}

		status := InterpretBanStatus(code, "unban")
		Logger.WithFields(map[string]interface{}{
			"ip":     ip,
			"jail":   jail,
			"status": status,
		}).Info("Unban result")

		results = append(results, OperationResult{
			IP:     ip,
			Jail:   jail,
			Status: status,
		})
	}

	return results, nil
}

// Argument validation helpers

// RequireArguments checks that at least n arguments are provided
func RequireArguments(args []string, n int, errorMsg string) error {
	if len(args) < n {
		return errors.New(errorMsg)
	}
	return nil
}

// RequireNonEmptyArgument checks that an argument is not empty
func RequireNonEmptyArgument(arg, name string) error {
	if strings.TrimSpace(arg) == "" {
		return fmt.Errorf("%s cannot be empty", name)
	}
	return nil
}

// Status output helpers

// FormatBannedResult formats banned IP results for output
func FormatBannedResult(ip string, jails []string) string {
	if len(jails) == 0 {
		return fmt.Sprintf("IP %s is not banned", ip)
	}
	return fmt.Sprintf("IP %s is banned in: %v", ip, jails)
}

// FormatStatusResult formats status results for output
func FormatStatusResult(jail, status string) string {
	if jail == "" {
		return status
	}
	return fmt.Sprintf("Status for %s:\n%s", jail, status)
}
