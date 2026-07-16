package fail2ban

import "fmt"

// Enhanced error messages with context and remediation hints
const (
	ErrJailNotFound      = "jail '%s' not found. Use 'f2b status' to list available jails"
	ErrInvalidIP         = "invalid IP address: %s. Expected: IPv4 (192.168.1.1) or IPv6 (2001:db8::1)"
	ErrInvalidJail       = "invalid jail name: %s. Must contain only letters, digits, dots, hyphens, underscores"
	ErrInvalidFilter     = "invalid filter name: %s. Must contain only alphanumeric, hyphens, underscores"
	ErrFilterNotFound    = "filter %s not found. Check the filter directory (filter.d) for available filters"
	ErrIPRequired        = "IP address required. Usage: f2b <command> <ip-address> [jail]"
	ErrJailRequired      = "jail name required. Use 'f2b status' to list available jails"
	ErrFilterRequired    = "filter name required. Usage: f2b test-filter <filter>"
	ErrActionRequired    = "action required. Valid actions: start, stop, restart, status, reload, enable, disable"
	ErrInvalidCommand    = "invalid command: %s. Use 'f2b --help' to see available commands"
	ErrCommandNotAllowed = "command not allowed: %s. This command contains potentially dangerous characters"
	ErrInvalidArgument   = "invalid argument: %s. Check command usage with 'f2b <command> --help'"
)

// NewJailNotFoundError creates a formatted error for jail not found scenarios.
func NewJailNotFoundError(jail string) error {
	return fmt.Errorf(ErrJailNotFound, jail)
}

// NewInvalidIPError creates a formatted error for invalid IP address scenarios.
func NewInvalidIPError(ip string) error {
	return fmt.Errorf(ErrInvalidIP, ip)
}

// NewInvalidJailError creates a formatted error for invalid jail name scenarios.
func NewInvalidJailError(jail string) error {
	return fmt.Errorf(ErrInvalidJail, jail)
}

// NewInvalidFilterError creates a formatted error for invalid filter name scenarios.
func NewInvalidFilterError(filter string) error {
	return fmt.Errorf(ErrInvalidFilter, filter)
}

// NewFilterNotFoundError creates a formatted error for filter not found scenarios.
func NewFilterNotFoundError(filter string) error {
	return fmt.Errorf(ErrFilterNotFound, filter)
}

// NewInvalidCommandError creates a formatted error for invalid command scenarios.
func NewInvalidCommandError(command string) error {
	return fmt.Errorf(ErrInvalidCommand, command)
}

// NewCommandNotAllowedError creates a formatted error for command not allowed scenarios.
func NewCommandNotAllowedError(command string) error {
	return fmt.Errorf(ErrCommandNotAllowed, command)
}

// NewInvalidArgumentError creates a formatted error for invalid argument scenarios.
func NewInvalidArgumentError(arg string) error {
	return fmt.Errorf(ErrInvalidArgument, arg)
}

// ErrorCategory represents the category of an error for better error handling
type ErrorCategory string

// Error category constants for categorizing different types of errors
const (
	ErrorCategoryValidation ErrorCategory = "validation" // Input validation errors
	ErrorCategoryNetwork    ErrorCategory = "network"    // Network-related errors
	ErrorCategoryPermission ErrorCategory = "permission" // Permission/authentication errors
	ErrorCategorySystem     ErrorCategory = "system"     // System-level errors
	ErrorCategoryConfig     ErrorCategory = "config"     // Configuration errors
)

// ContextualError provides enhanced error information with category and remediation
type ContextualError struct {
	Message     string
	Category    ErrorCategory
	Remediation string
	Cause       error
}

func (e *ContextualError) Error() string {
	return e.Message
}

func (e *ContextualError) Unwrap() error {
	return e.Cause
}

// GetRemediation returns suggested remediation for the error
func (e *ContextualError) GetRemediation() string {
	return e.Remediation
}

// GetCategory returns the error category
func (e *ContextualError) GetCategory() ErrorCategory {
	return e.Category
}

// Enhanced error constructors with remediation hints

// NewValidationError creates a validation error with remediation
func NewValidationError(message, remediation string) *ContextualError {
	return &ContextualError{
		Message:     message,
		Category:    ErrorCategoryValidation,
		Remediation: remediation,
	}
}

// NewSystemError creates a system error with remediation
func NewSystemError(message, remediation string, cause error) *ContextualError {
	return &ContextualError{
		Message:     message,
		Category:    ErrorCategorySystem,
		Remediation: remediation,
		Cause:       cause,
	}
}

// NewPermissionError creates a permission error with remediation
func NewPermissionError(message, remediation string) *ContextualError {
	return &ContextualError{
		Message:     message,
		Category:    ErrorCategoryPermission,
		Remediation: remediation,
	}
}

// Common validation errors with enhanced context
var (
	ErrIPRequiredError = NewValidationError(
		ErrIPRequired,
		"Provide a valid IPv4 or IPv6 address as the first argument",
	)
	ErrJailRequiredError = NewValidationError(
		ErrJailRequired,
		"Specify a jail name or use 'f2b status' to see available jails",
	)
	ErrFilterRequiredError = NewValidationError(
		ErrFilterRequired,
		"Specify a filter name, e.g. 'f2b test-filter sshd'; filters live in the filter directory (filter.d)",
	)
	ErrActionRequiredError = NewValidationError(
		ErrActionRequired,
		"Choose from: start, stop, restart, status, reload, enable, disable",
	)
)
