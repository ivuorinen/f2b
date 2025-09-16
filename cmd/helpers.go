package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

const (
	// DefaultPollingInterval is the default interval for polling operations
	DefaultPollingInterval = 5 * time.Second
)

// IsCI detects if we're running in a CI environment
func IsCI() bool {
	return fail2ban.IsCI()
}

// IsTestEnvironment detects if we're running in a test environment
func IsTestEnvironment() bool {
	return fail2ban.IsTestEnvironment()
}

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

// NewContextualCommand creates a command with standardized context and logging setup
func NewContextualCommand(
	use, short string,
	aliases []string,
	config *Config,
	handler func(context.Context, *cobra.Command, []string) error,
) *cobra.Command {
	return NewCommand(use, short, aliases, func(cmd *cobra.Command, args []string) error {
		// Get the contextual logger
		logger := GetContextualLogger()

		// Base on Cobra's context so signals/cancellations propagate
		base := cmd.Context()
		if base == nil {
			base = context.Background()
		}
		// Create timeout context for the entire operation
		timeout := time.Minute
		if config != nil && config.CommandTimeout > 0 {
			timeout = config.CommandTimeout
		}
		ctx, cancel := context.WithTimeout(base, timeout)
		defer cancel()

		// Extract command name from use string (first word)
		cmdName := use
		if spaceIndex := strings.Index(use, " "); spaceIndex != -1 {
			cmdName = use[:spaceIndex]
		}

		// Add command context
		ctx = WithCommand(ctx, cmdName)

		// Log operation with timing
		return logger.LogOperation(ctx, cmdName+"_command", func() error {
			return handler(ctx, cmd, args)
		})
	})
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
	cmd.Flags().DurationVarP(interval, "interval", "i", DefaultPollingInterval, "Polling interval")
}

// Validation helpers

// ValidateIPArgument validates that an IP address is provided in args
func ValidateIPArgument(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("IP address required")
	}
	ip := args[0]
	// Validate the IP address
	if err := fail2ban.CachedValidateIP(ip); err != nil {
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

// GetJailsFromArgsWithContext gets jail list from arguments or client with timeout context
func GetJailsFromArgsWithContext(
	ctx context.Context,
	client fail2ban.Client,
	args []string,
	startIndex int,
) ([]string, error) {
	if len(args) > startIndex {
		return []string{strings.ToLower(args[startIndex])}, nil
	}

	jails, err := client.ListJailsWithContext(ctx)
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

// HandleValidationError specifically handles validation errors with clearer messaging
func HandleValidationError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's a contextual validation error
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) && contextErr.GetCategory() == fail2ban.ErrorCategoryValidation {
		PrintError(err) // PrintError already handles contextual errors well
		return err
	}

	// For non-contextual validation errors, wrap them for better messaging
	if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") {
		validationErr := fail2ban.NewValidationError(
			err.Error(),
			"Check your input parameters and try again. Use --help for usage information.",
		)
		PrintError(validationErr)
		return validationErr
	}

	return HandleClientError(err)
}

// HandlePermissionError specifically handles permission/sudo errors with helpful hints
func HandlePermissionError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's already a contextual permission error
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) && contextErr.GetCategory() == fail2ban.ErrorCategoryPermission {
		PrintError(err)
		return err
	}

	// Check for common permission-related error patterns
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "sudo") {
		permErr := fail2ban.NewPermissionError(
			err.Error(),
			"Try running with sudo privileges or check that fail2ban service is running.",
		)
		PrintError(permErr)
		return permErr
	}

	return HandleClientError(err)
}

// HandleSystemError specifically handles system-level errors with diagnostic hints
func HandleSystemError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's already a contextual system error
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) && contextErr.GetCategory() == fail2ban.ErrorCategorySystem {
		PrintError(err)
		return err
	}

	// Check for common system error patterns
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "command not found") {
		sysErr := fail2ban.NewSystemError(
			err.Error(),
			"Ensure fail2ban is installed and fail2ban-client is in your PATH.",
			err,
		)
		PrintError(sysErr)
		return sysErr
	}

	if strings.Contains(errMsg, "not running") || strings.Contains(errMsg, "connection refused") {
		sysErr := fail2ban.NewSystemError(
			err.Error(),
			"Start the fail2ban service: sudo systemctl start fail2ban",
			err,
		)
		PrintError(sysErr)
		return sysErr
	}

	return HandleClientError(err)
}

// HandleErrorWithContext automatically chooses the appropriate error handler based on error context
func HandleErrorWithContext(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's already a contextual error and route accordingly
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) {
		switch contextErr.GetCategory() {
		case fail2ban.ErrorCategoryValidation:
			return HandleValidationError(err)
		case fail2ban.ErrorCategoryPermission:
			return HandlePermissionError(err)
		case fail2ban.ErrorCategorySystem:
			return HandleSystemError(err)
		default:
			return HandleClientError(err)
		}
	}

	// For non-contextual errors, try to infer the type
	errMsg := strings.ToLower(err.Error())

	// Validation error patterns
	if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") ||
		strings.Contains(errMsg, "malformed") || strings.Contains(errMsg, "format") {
		return HandleValidationError(err)
	}

	// Permission error patterns
	if strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "sudo") ||
		strings.Contains(errMsg, "unauthorized") || strings.Contains(errMsg, "forbidden") {
		return HandlePermissionError(err)
	}

	// System error patterns
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "not running") ||
		strings.Contains(errMsg, "connection") || strings.Contains(errMsg, "timeout") {
		return HandleSystemError(err)
	}

	// Default to generic client error handling
	return HandleClientError(err)
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

// ProcessBanOperationWithContext processes ban operations across multiple jails with timeout context
func ProcessBanOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	logger := GetContextualLogger()
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		// Add jail to context for this operation
		jailCtx := WithJail(ctx, jail)

		// Time the ban operation
		start := time.Now()
		code, err := client.BanIPWithContext(jailCtx, ip, jail)
		duration := time.Since(start)

		if err != nil {
			// Log the failed operation with timing
			logger.LogBanOperation(jailCtx, "ban", ip, jail, false, duration)
			return nil, err
		}

		status := InterpretBanStatus(code, "ban")

		// Log the successful operation with timing
		logger.LogBanOperation(jailCtx, "ban", ip, jail, true, duration)

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

// ProcessUnbanOperationWithContext processes unban operations across multiple jails with timeout context
func ProcessUnbanOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	logger := GetContextualLogger()
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		// Add jail to context for this operation
		jailCtx := WithJail(ctx, jail)

		// Time the unban operation
		start := time.Now()
		code, err := client.UnbanIPWithContext(jailCtx, ip, jail)
		duration := time.Since(start)

		if err != nil {
			// Log the failed operation with timing
			logger.LogBanOperation(jailCtx, "unban", ip, jail, false, duration)
			return nil, err
		}

		status := InterpretBanStatus(code, "unban")

		// Log the successful operation with timing
		logger.LogBanOperation(jailCtx, "unban", ip, jail, true, duration)

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
