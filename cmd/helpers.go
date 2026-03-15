// Package cmd provides common helper functions and utilities for CLI commands.
// This package contains shared functionality used across multiple f2b commands,
// including argument validation, error handling, and output formatting helpers.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/shared"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// createTimeoutContext creates a context with the configured command timeout.
// This helper consolidates the duplicate timeout handling pattern.
// If base is nil, context.Background() is used.
func createTimeoutContext(base context.Context, config *Config) (context.Context, context.CancelFunc) {
	if base == nil {
		base = context.Background()
	}
	timeout := shared.DefaultCommandTimeout
	if config != nil && config.CommandTimeout > 0 {
		timeout = config.CommandTimeout
	}
	// #nosec G118 -- cancel is returned to callers who are responsible for calling it
	return context.WithTimeout(base, timeout)
}

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

		// Create timeout context based on Cobra's context so signals/cancellations propagate
		ctx, cancel := createTimeoutContext(cmd.Context(), config)
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
	cmd.Flags().IntP(shared.FlagLimit, "n", 0, "Show only the last N log lines")
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
	cmd.Flags().DurationVarP(interval, shared.FlagInterval, "i", shared.DefaultPollingInterval, "Polling interval")
}

// Validation helpers

// ValidateIPArgument validates that an IP address is provided in args
func ValidateIPArgument(args []string) (string, error) {
	return ValidateIPArgumentWithContext(context.Background(), args)
}

// ValidateIPArgumentWithContext validates that an IP address is provided in args with context support
func ValidateIPArgumentWithContext(ctx context.Context, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("IP address required")
	}
	ip := args[0]
	// Validate the IP address
	if err := fail2ban.CachedValidateIP(ctx, ip); err != nil {
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

// errorPatternMatch defines a pattern and its associated remediation message
type errorPatternMatch struct {
	patterns    []string
	remediation string
}

// errorTypePattern maps error message patterns to their corresponding handler function
type errorTypePattern struct {
	patterns []string
	handler  func(error) error
}

// errorTypePatterns defines patterns for inferring error types from non-contextual errors
var errorTypePatterns = []errorTypePattern{
	{
		patterns: []string{"invalid", "required", "malformed", "format"},
		handler:  HandleValidationError,
	},
	{
		patterns: []string{"permission", "sudo", "unauthorized", "forbidden"},
		handler:  HandlePermissionError,
	},
	{
		patterns: []string{"not found", "not running", "connection", "timeout"},
		handler:  HandleSystemError,
	},
}

// handleCategorizedError is a shared helper for handling categorized errors with pattern matching
func handleCategorizedError(
	err error,
	category fail2ban.ErrorCategory,
	patternMatches []errorPatternMatch,
	createError func(error, string) error,
) error {
	if err == nil {
		return nil
	}

	// Check if it's already a contextual error of this category
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) && contextErr.GetCategory() == category {
		PrintError(err)
		return err
	}

	// Check for pattern matches
	errMsg := strings.ToLower(err.Error())
	for _, pm := range patternMatches {
		for _, pattern := range pm.patterns {
			if strings.Contains(errMsg, pattern) {
				newErr := createError(err, pm.remediation)
				PrintError(newErr)
				return newErr
			}
		}
	}

	return HandleClientError(err)
}

// HandleValidationError specifically handles validation errors with clearer messaging
func HandleValidationError(err error) error {
	return handleCategorizedError(
		err,
		fail2ban.ErrorCategoryValidation,
		[]errorPatternMatch{
			{
				patterns:    []string{"invalid", "required"},
				remediation: "Check your input parameters and try again. Use --help for usage information.",
			},
		},
		func(err error, remediation string) error {
			return fail2ban.NewValidationError(err.Error(), remediation)
		},
	)
}

// HandlePermissionError specifically handles permission/sudo errors with helpful hints
func HandlePermissionError(err error) error {
	return handleCategorizedError(
		err,
		fail2ban.ErrorCategoryPermission,
		[]errorPatternMatch{
			{
				patterns:    []string{"permission denied", "sudo"},
				remediation: "Try running with sudo privileges or check that fail2ban service is running.",
			},
		},
		func(err error, remediation string) error {
			return fail2ban.NewPermissionError(err.Error(), remediation)
		},
	)
}

// HandleSystemError specifically handles system-level errors with diagnostic hints
func HandleSystemError(err error) error {
	return handleCategorizedError(
		err,
		fail2ban.ErrorCategorySystem,
		[]errorPatternMatch{
			{
				patterns:    []string{"not found", "command not found"},
				remediation: "Ensure fail2ban is installed and fail2ban-client is in your PATH.",
			},
			{
				patterns:    []string{"not running", "connection refused"},
				remediation: "Start the fail2ban service: sudo systemctl start fail2ban",
			},
		},
		func(err error, remediation string) error {
			return fail2ban.NewSystemError(err.Error(), remediation, err)
		},
	)
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

	// For non-contextual errors, try to infer the type from patterns
	errMsg := strings.ToLower(err.Error())
	for _, ep := range errorTypePatterns {
		for _, pattern := range ep.patterns {
			if strings.Contains(errMsg, pattern) {
				return ep.handler(err)
			}
		}
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
		PrintOutputTo(GetCmdOutput(cmd), results, PlainFormat)
	}
}

// InterpretBanStatus interprets ban operation status codes
func InterpretBanStatus(code int, operation string) string {
	switch operation {
	case shared.MetricsBan:
		if code == 1 {
			return "Already banned"
		}
		return "Banned"
	case shared.MetricsUnban:
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

// OperationType defines a ban or unban operation with its associated metadata
type OperationType struct {
	// MetricsType is the metrics key for this operation (e.g., shared.MetricsBan)
	MetricsType string
	// Message is the log message for this operation (e.g., shared.MsgBanResult)
	Message string
	// Operation is the function to execute without context
	Operation func(client fail2ban.Client, ip, jail string) (int, error)
	// OperationCtx is the function to execute with context
	OperationCtx func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error)
}

// BanOperationType defines the ban operation
var BanOperationType = OperationType{
	MetricsType: shared.MetricsBan,
	Message:     shared.MsgBanResult,
	Operation: func(c fail2ban.Client, ip, jail string) (int, error) {
		return c.BanIP(ip, jail)
	},
	OperationCtx: func(ctx context.Context, c fail2ban.Client, ip, jail string) (int, error) {
		return c.BanIPWithContext(ctx, ip, jail)
	},
}

// UnbanOperationType defines the unban operation
var UnbanOperationType = OperationType{
	MetricsType: shared.MetricsUnban,
	Message:     shared.MsgUnbanResult,
	Operation: func(c fail2ban.Client, ip, jail string) (int, error) {
		return c.UnbanIP(ip, jail)
	},
	OperationCtx: func(ctx context.Context, c fail2ban.Client, ip, jail string) (int, error) {
		return c.UnbanIPWithContext(ctx, ip, jail)
	},
}

// ProcessOperation processes operations across multiple jails using the specified operation type
func ProcessOperation(
	client fail2ban.Client,
	ip string,
	jails []string,
	opType OperationType,
) ([]OperationResult, error) {
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		code, err := opType.Operation(client, ip, jail)
		if err != nil {
			return nil, err
		}

		status := InterpretBanStatus(code, opType.MetricsType)
		Logger.WithFields(map[string]interface{}{
			"ip":     ip,
			"jail":   jail,
			"status": status,
		}).Info(opType.Message)

		results = append(results, OperationResult{
			IP:     ip,
			Jail:   jail,
			Status: status,
		})
	}

	return results, nil
}

// ProcessOperationWithContext processes operations across multiple jails with timeout context
func ProcessOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
	opType OperationType,
) ([]OperationResult, error) {
	logger := GetContextualLogger()
	results := make([]OperationResult, 0, len(jails))

	for _, jail := range jails {
		// Add jail to context for this operation
		jailCtx := WithJail(ctx, jail)

		// Time the operation
		start := time.Now()
		code, err := opType.OperationCtx(jailCtx, client, ip, jail)
		duration := time.Since(start)

		if err != nil {
			// Log the failed operation with timing
			logger.LogBanOperation(jailCtx, opType.MetricsType, ip, jail, false, duration)
			return nil, err
		}

		status := InterpretBanStatus(code, opType.MetricsType)

		// Log the successful operation with timing
		logger.LogBanOperation(jailCtx, opType.MetricsType, ip, jail, true, duration)

		// Log the operation-specific message (ban vs unban)
		Logger.WithFields(map[string]interface{}{
			"ip":     ip,
			"jail":   jail,
			"status": status,
		}).Info(opType.Message)

		results = append(results, OperationResult{
			IP:     ip,
			Jail:   jail,
			Status: status,
		})
	}

	return results, nil
}

// ProcessBanOperation processes ban operations across multiple jails
func ProcessBanOperation(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	return ProcessOperation(client, ip, jails, BanOperationType)
}

// ProcessBanOperationWithContext processes ban operations across multiple jails with timeout context
func ProcessBanOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return ProcessOperationWithContext(ctx, client, ip, jails, BanOperationType)
}

// ProcessUnbanOperation processes unban operations across multiple jails
func ProcessUnbanOperation(client fail2ban.Client, ip string, jails []string) ([]OperationResult, error) {
	return ProcessOperation(client, ip, jails, UnbanOperationType)
}

// ProcessUnbanOperationWithContext processes unban operations across multiple jails with timeout context
func ProcessUnbanOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return ProcessOperationWithContext(ctx, client, ip, jails, UnbanOperationType)
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
	if IsEmptyString(arg) {
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

// String processing helpers

// TrimmedString safely trims whitespace and returns empty string when input is empty
func TrimmedString(s string) string {
	return strings.TrimSpace(s)
}

// IsEmptyString checks if a string is empty after trimming whitespace
func IsEmptyString(s string) bool {
	return strings.TrimSpace(s) == ""
}

// NonEmptyString checks if a string has content after trimming whitespace
func NonEmptyString(s string) bool {
	return strings.TrimSpace(s) != ""
}

// Error handling helpers

// WrapError provides consistent error wrapping with operation context
func WrapError(err error, operation string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// WrapErrorf provides formatted error wrapping with context
func WrapErrorf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	// Append ": %w" to format and add err as final argument for single formatting
	allArgs := append(args, err)
	return fmt.Errorf(format+": %w", allArgs...)
}

// Command output helpers

// TrimmedOutput safely trims whitespace from command output bytes
func TrimmedOutput(output []byte) string {
	return strings.TrimSpace(string(output))
}
