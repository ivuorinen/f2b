package fail2ban

import (
	"context"
)

// NoOpClient is a no-operation client that implements the Client interface
// but doesn't perform any actual fail2ban operations. It's used for commands
// that don't require fail2ban functionality (like version, help, completion).
type NoOpClient struct{}

// NewNoOpClient creates a new no-operation client
func NewNoOpClient() *NoOpClient {
	return &NoOpClient{}
}

// ListJails returns an empty list of jails
func (c *NoOpClient) ListJails() ([]string, error) {
	return []string{}, nil
}

// StatusAll returns an error indicating the client is not available
func (c *NoOpClient) StatusAll() (string, error) {
	return "", ErrClientNotAvailableError
}

// StatusJail returns an error indicating the client is not available
func (c *NoOpClient) StatusJail(_ string) (string, error) {
	return "", ErrClientNotAvailableError
}

// BanIP returns an error indicating the client is not available
func (c *NoOpClient) BanIP(_, _ string) (int, error) {
	return 0, ErrClientNotAvailableError
}

// UnbanIP returns an error indicating the client is not available
func (c *NoOpClient) UnbanIP(_, _ string) (int, error) {
	return 0, ErrClientNotAvailableError
}

// BannedIn returns an empty list
func (c *NoOpClient) BannedIn(_ string) ([]string, error) {
	return []string{}, nil
}

// GetBanRecords returns an empty list of ban records
func (c *NoOpClient) GetBanRecords(_ []string) ([]BanRecord, error) {
	return []BanRecord{}, nil
}

// GetLogLines returns an empty list of log lines
func (c *NoOpClient) GetLogLines(_, _ string) ([]string, error) {
	return []string{}, nil
}

// ListFilters returns an empty list of filters
func (c *NoOpClient) ListFilters() ([]string, error) {
	return []string{}, nil
}

// TestFilter returns an error indicating the client is not available
func (c *NoOpClient) TestFilter(_ string) (string, error) {
	return "", ErrClientNotAvailableError
}

// Context-aware methods for NoOpClient

// Context-aware methods using helpers to reduce boilerplate

// ListJailsWithContext returns an error indicating the client is not available.
func (c *NoOpClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(c.ListJails)(ctx)
}

// StatusAllWithContext returns an error indicating the client is not available.
func (c *NoOpClient) StatusAllWithContext(ctx context.Context) (string, error) {
	return wrapWithContext0(c.StatusAll)(ctx)
}

// StatusJailWithContext returns an error indicating the client is not available.
func (c *NoOpClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	return wrapWithContext1(c.StatusJail)(ctx, jail)
}

// BanIPWithContext returns an error indicating the client is not available.
func (c *NoOpClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return wrapWithContext2(c.BanIP)(ctx, ip, jail)
}

// UnbanIPWithContext returns an error indicating the client is not available.
func (c *NoOpClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return wrapWithContext2(c.UnbanIP)(ctx, ip, jail)
}

// BannedInWithContext returns an error indicating the client is not available.
func (c *NoOpClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	return wrapWithContext1(c.BannedIn)(ctx, ip)
}

// GetBanRecordsWithContext returns an error indicating the client is not available.
func (c *NoOpClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	return wrapWithContext1(c.GetBanRecords)(ctx, jails)
}

// GetLogLinesWithContext returns an error indicating the client is not available.
func (c *NoOpClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return wrapWithContext2(c.GetLogLines)(ctx, jail, ip)
}

// ListFiltersWithContext returns an error indicating the client is not available.
func (c *NoOpClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(c.ListFilters)(ctx)
}

// TestFilterWithContext returns an error indicating the client is not available.
func (c *NoOpClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	return wrapWithContext1(c.TestFilter)(ctx, filter)
}
