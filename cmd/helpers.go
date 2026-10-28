// Shared helpers for CLI commands: argument validation, error handling and
// output formatting.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// createTimeoutContext derives a context with the configured command timeout
// from base, which is always cmd.Context() (cobra sets it before RunE).
func createTimeoutContext(base context.Context, config *Config) (context.Context, context.CancelFunc) {
	timeout := constants.DefaultCommandTimeout
	if config != nil && config.CommandTimeout > 0 {
		timeout = config.CommandTimeout
	}
	// #nosec G118 -- cancel is returned to callers who are responsible for calling it
	return context.WithTimeout(base, timeout)
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

// ValidateIPArgument validates that a valid IP address is the first of args.
// It took a context it never used, so the "WithContext" name promised
// cancellation that never happened.
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

// serviceActions is the single list of accepted `f2b service` actions; the
// usage text, the missing-action message and validation are all built from
// it, so they cannot drift apart.
var serviceActions = []string{"start", "stop", "restart", "status", "reload", "enable", "disable"}

// ValidateServiceAction validates that a service action is valid
func ValidateServiceAction(action string) error {
	if !slices.Contains(serviceActions, action) {
		return fmt.Errorf("invalid service action: %s. Valid actions: %s", action, strings.Join(serviceActions, ", "))
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

// InterpretBanStatus interprets ban operation status codes
func InterpretBanStatus(code int, operation string) string {
	switch operation {
	case constants.OpBan:
		if code == 1 {
			return "Already banned"
		}
		return "Banned"
	case constants.OpUnban:
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
	// Operation is the operation name used in logs and status text (e.g., constants.OpBan)
	Operation string
	// Message is the log message for this operation (e.g., constants.MsgBanResult)
	Message string
	// OperationCtx is the function to execute with context
	OperationCtx func(ctx context.Context, client fail2ban.Client, ip, jail string) (int, error)
}

// BanOperationType defines the ban operation
var BanOperationType = OperationType{
	Operation: constants.OpBan,
	Message:   constants.MsgBanResult,
	OperationCtx: func(ctx context.Context, c fail2ban.Client, ip, jail string) (int, error) {
		return c.BanIPWithContext(ctx, ip, jail)
	},
}

// UnbanOperationType defines the unban operation
var UnbanOperationType = OperationType{
	Operation: constants.OpUnban,
	Message:   constants.MsgUnbanResult,
	OperationCtx: func(ctx context.Context, c fail2ban.Client, ip, jail string) (int, error) {
		return c.UnbanIPWithContext(ctx, ip, jail)
	},
}

// ProcessOperationWithContext processes operations across jails in order with
// timeout context. On a failing jail it returns the results gathered so far
// with the error: earlier jails were already banned/unbanned, and dropping
// their results hid that firewall state had changed.
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
		jailCtx := fail2ban.WithJail(ctx, jail)

		// Time the operation
		start := time.Now()
		code, err := opType.OperationCtx(jailCtx, client, ip, jail)
		duration := time.Since(start)

		if err != nil {
			// Log the failed operation with timing
			logger.LogBanOperation(jailCtx, opType.Operation, ip, jail, false, duration)
			return results, err
		}

		status := InterpretBanStatus(code, opType.Operation)

		// Log the successful operation with timing
		logger.LogBanOperation(jailCtx, opType.Operation, ip, jail, true, duration)

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

// ProcessBanOperationWithContext processes ban operations across multiple jails with timeout context
func ProcessBanOperationWithContext(
	ctx context.Context,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	return ProcessOperationWithContext(ctx, client, ip, jails, BanOperationType)
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
