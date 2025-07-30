package fail2ban

import "fmt"

// Common error messages as constants to reduce string allocations and ensure consistency
const (
	ErrJailNotFound       = "jail '%s' not found"
	ErrInvalidIP          = "invalid IP address: %s"
	ErrInvalidJail        = "invalid jail name: %s"
	ErrInvalidFilter      = "invalid filter name: %s"
	ErrFilterNotFound     = "filter %s not found"
	ErrClientNotAvailable = "fail2ban client not available for this command"
	ErrIPRequired         = "IP address required"
	ErrJailRequired       = "jail name required"
	ErrFilterRequired     = "filter name required"
	ErrActionRequired     = "action required"
	ErrInvalidCommand     = "invalid command: %s"
	ErrCommandNotAllowed  = "command not allowed: %s"
	ErrInvalidArgument    = "invalid argument: %s"
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

// Common validation errors
var (
	ErrClientNotAvailableError = fmt.Errorf("%s", ErrClientNotAvailable)
	ErrIPRequiredError         = fmt.Errorf("%s", ErrIPRequired)
	ErrJailRequiredError       = fmt.Errorf("%s", ErrJailRequired)
	ErrFilterRequiredError     = fmt.Errorf("%s", ErrFilterRequired)
	ErrActionRequiredError     = fmt.Errorf("%s", ErrActionRequired)
)
