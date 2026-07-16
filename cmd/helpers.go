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

	"github.com/ivuorinen/f2b/constants"

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
	timeout := constants.DefaultCommandTimeout
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

// NewCommand creates a new cobra command with standard setup.
// SilenceErrors/SilenceUsage are set so a runtime failure (e.g. fail2ban down)
// is reported once by our own error handler instead of being reprinted by
// cobra and followed by a full usage dump as if it were a syntax error.
func NewCommand(use, short string, aliases []string, runE func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:           use,
		Short:         short,
		Aliases:       aliases,
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
}

// AddLogFlags adds common log-related flags to a command
func AddLogFlags(cmd *cobra.Command) {
	cmd.Flags().IntP(constants.FlagLimit, "n", 0, "Show only the last N log lines")
}

// Validation helpers

// ValidateIPArgumentWithContext validates that an IP address is provided in args with context support
func ValidateIPArgumentWithContext(_ context.Context, args []string) (string, error) {
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

// GetJailsFromArgsWithContext gets jail list from arguments or client with timeout context
func GetJailsFromArgsWithContext(
	ctx context.Context,
	client fail2ban.Client,
	args []string,
	startIndex int,
) ([]string, error) {
	if len(args) > startIndex {
		// fail2ban jail names are case-sensitive; pass through verbatim.
		return []string{args[startIndex]}, nil
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
		return printedError{err}
	}
	return nil
}

// errorPatternMatch defines a pattern and its associated remediation message
type errorPatternMatch struct {
	patterns    []string
	remediation string
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
	if contextErr, ok := errors.AsType[*fail2ban.ContextualError](err); ok && contextErr.GetCategory() == category {
		PrintError(err)
		return printedError{err}
	}

	// Check for pattern matches
	errMsg := strings.ToLower(err.Error())
	for _, pm := range patternMatches {
		for _, pattern := range pm.patterns {
			if strings.Contains(errMsg, pattern) {
				newErr := createError(err, pm.remediation)
				PrintError(newErr)
				return printedError{newErr}
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

// Output helpers

// OutputResults outputs results in the specified format
func OutputResults(cmd *cobra.Command, results any, config *Config) {
	if config != nil && config.Format == JSONFormat {
		PrintOutputTo(GetCmdOutput(cmd), results, JSONFormat)
	} else {
		PrintOutputTo(GetCmdOutput(cmd), results, PlainFormat)
	}
}

// InterpretBanStatus interprets ban operation status codes
func InterpretBanStatus(code int, operation string) string {
	switch operation {
	case constants.MetricsBan:
		if code == 1 {
			return "Already banned"
		}
		return "Banned"
	case constants.MetricsUnban:
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
	// MetricsType is the metrics key for this operation (e.g., constants.MetricsBan)
	MetricsType string
	// Message is the log message for this operation (e.g., constants.MsgBanResult)
	Message string
	// Operation is the function to execute without context
	Operation func(client fail2ban.Client, ip, jail string) (int, error)
	// OperationCtx is the function to execute with context
	OperationCtx func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error)
}

// BanOperationType defines the ban operation
var BanOperationType = OperationType{
	MetricsType: constants.MetricsBan,
	Message:     constants.MsgBanResult,
	Operation: func(c fail2ban.Client, ip, jail string) (int, error) {
		return c.BanIP(ip, jail)
	},
	OperationCtx: func(ctx context.Context, c fail2ban.Client, ip, jail string) (int, error) {
		return c.BanIPWithContext(ctx, ip, jail)
	},
}

// UnbanOperationType defines the unban operation
var UnbanOperationType = OperationType{
	MetricsType: constants.MetricsUnban,
	Message:     constants.MsgUnbanResult,
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
		Logger.WithFields(map[string]any{
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
		Logger.WithFields(map[string]any{
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

// IsEmptyString checks if a string is empty after trimming whitespace
func IsEmptyString(s string) bool {
	return strings.TrimSpace(s) == ""
}

// Command output helpers

// TrimmedOutput safely trims whitespace from command output bytes
func TrimmedOutput(output []byte) string {
	return strings.TrimSpace(string(output))
}
