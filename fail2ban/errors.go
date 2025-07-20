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
)

// Error creation helpers to standardize error formatting
func NewJailNotFoundError(jail string) error {
	return fmt.Errorf(ErrJailNotFound, jail)
}

func NewInvalidIPError(ip string) error {
	return fmt.Errorf(ErrInvalidIP, ip)
}

func NewInvalidJailError(jail string) error {
	return fmt.Errorf(ErrInvalidJail, jail)
}

func NewInvalidFilterError(filter string) error {
	return fmt.Errorf(ErrInvalidFilter, filter)
}

func NewFilterNotFoundError(filter string) error {
	return fmt.Errorf(ErrFilterNotFound, filter)
}

// Common validation errors
var (
	ErrClientNotAvailableError = fmt.Errorf("%s", ErrClientNotAvailable)
	ErrIPRequiredError         = fmt.Errorf("%s", ErrIPRequired)
	ErrJailRequiredError       = fmt.Errorf("%s", ErrJailRequired)
	ErrFilterRequiredError     = fmt.Errorf("%s", ErrFilterRequired)
	ErrActionRequiredError     = fmt.Errorf("%s", ErrActionRequired)
)
