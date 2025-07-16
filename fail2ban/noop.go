package fail2ban

import (
	"context"
	"errors"
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
	return "", errors.New("fail2ban client not available for this command")
}

// StatusJail returns an error indicating the client is not available
func (c *NoOpClient) StatusJail(jail string) (string, error) {
	return "", errors.New("fail2ban client not available for this command")
}

// BanIP returns an error indicating the client is not available
func (c *NoOpClient) BanIP(ip, jail string) (int, error) {
	return 0, errors.New("fail2ban client not available for this command")
}

// UnbanIP returns an error indicating the client is not available
func (c *NoOpClient) UnbanIP(ip, jail string) (int, error) {
	return 0, errors.New("fail2ban client not available for this command")
}

// BannedIn returns an empty list
func (c *NoOpClient) BannedIn(ip string) ([]string, error) {
	return []string{}, nil
}

// GetBanRecords returns an empty list of ban records
func (c *NoOpClient) GetBanRecords(jails []string) ([]BanRecord, error) {
	return []BanRecord{}, nil
}

// GetLogLines returns an empty list of log lines
func (c *NoOpClient) GetLogLines(jail, ip string) ([]string, error) {
	return []string{}, nil
}

// ListFilters returns an empty list of filters
func (c *NoOpClient) ListFilters() ([]string, error) {
	return []string{}, nil
}

// TestFilter returns an error indicating the client is not available
func (c *NoOpClient) TestFilter(filter string) (string, error) {
	return "", errors.New("fail2ban client not available for this command")
}

// Context-aware methods for NoOpClient

// ListJailsWithContext returns an empty list of jails
func (c *NoOpClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

// StatusAllWithContext returns an error indicating the client is not available
func (c *NoOpClient) StatusAllWithContext(ctx context.Context) (string, error) {
	return "", errors.New("fail2ban client not available for this command")
}

// StatusJailWithContext returns an error indicating the client is not available
func (c *NoOpClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	return "", errors.New("fail2ban client not available for this command")
}

// BanIPWithContext returns an error indicating the client is not available
func (c *NoOpClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return 0, errors.New("fail2ban client not available for this command")
}

// UnbanIPWithContext returns an error indicating the client is not available
func (c *NoOpClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return 0, errors.New("fail2ban client not available for this command")
}

// BannedInWithContext returns an empty list
func (c *NoOpClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	return []string{}, nil
}

// GetBanRecordsWithContext returns an empty list of ban records
func (c *NoOpClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	return []BanRecord{}, nil
}

// GetLogLinesWithContext returns an empty list of log lines
func (c *NoOpClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return []string{}, nil
}

// ListFiltersWithContext returns an empty list of filters
func (c *NoOpClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

// TestFilterWithContext returns an error indicating the client is not available
func (c *NoOpClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	return "", errors.New("fail2ban client not available for this command")
}
