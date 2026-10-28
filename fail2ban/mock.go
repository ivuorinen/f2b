package fail2ban

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// setNestedMapValue sets a value in a nested map[string]map[string]T structure with mutex protection.
// It initializes the inner map if nil.
func setNestedMapValue[T any](mu *sync.Mutex, mp map[string]map[string]T, jail, ip string, value T) {
	mu.Lock()
	defer mu.Unlock()
	if mp[jail] == nil {
		mp[jail] = make(map[string]T)
	}
	mp[jail][ip] = value
}

// MockClient is a stateful, thread-safe mock implementation of the Client interface for testing.
//
// Every method checks ctx first, like the real client, so tests exercise
// cancellation instead of receiving canned data from a canceled context.
type MockClient struct {
	mu         sync.Mutex
	Jails      map[string]struct{}
	Banned     map[string]map[string]time.Time // jail -> ip -> ban time
	Logs       []string
	Filters    []string
	FilterRuns map[string]string
	// Enhanced features for advanced testing
	StatusAllData  string
	StatusJailData map[string]string
	BanRecords     []BanRecord
	BanResults     map[string]map[string]int   // jail -> ip -> result code
	BanErrors      map[string]map[string]error // jail -> ip -> error
	UnbanResults   map[string]map[string]int   // jail -> ip -> result code
	UnbanErrors    map[string]map[string]error // jail -> ip -> error
	BannedIPs      map[string][]string         // jail -> list of banned IPs
	LogLines       []string                    // configurable log lines
	FilterTests    map[string]string           // filter -> test result
	// Recorded query arguments so tests can assert that jail/ip flags actually
	// reach the client (configured LogLines/BanRecords are returned verbatim).
	LastLogQuery        [2]string // last (jail, ip) passed to a log read
	LastLogLimit        int       // last maxLines passed to a log read
	LastBanRecordsJails []string  // last jails passed to GetBanRecordsWithContext
}

// NewMockClient creates a new MockClient with default jails and filters.
func NewMockClient() *MockClient {
	return &MockClient{
		Jails:          map[string]struct{}{"sshd": {}, "apache": {}},
		Banned:         make(map[string]map[string]time.Time),
		Logs:           []string{},
		Filters:        []string{"sshd", "apache"},
		FilterRuns:     make(map[string]string),
		StatusAllData:  "Mock status for all jails",
		StatusJailData: make(map[string]string),
		BanRecords:     []BanRecord{},
		BanResults:     make(map[string]map[string]int),
		BanErrors:      make(map[string]map[string]error),
		UnbanResults:   make(map[string]map[string]int),
		UnbanErrors:    make(map[string]map[string]error),
		BannedIPs:      make(map[string][]string),
		LogLines:       []string{},
		FilterTests:    make(map[string]string),
	}
}

// ListJailsWithContext returns the sorted list of available jails.
func (m *MockClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	jails := make([]string, 0, len(m.Jails))
	for jail := range m.Jails {
		jails = append(jails, jail)
	}
	// Sort jails for consistent output
	sort.Strings(jails)
	return jails, nil
}

// StatusAllWithContext returns a mock status for all jails.
func (m *MockClient) StatusAllWithContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.StatusAllData, nil
}

// StatusJailWithContext returns a mock status for a specific jail.
func (m *MockClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Jails[jail]; !ok {
		return "", NewJailNotFoundError(jail)
	}
	if status, ok := m.StatusJailData[jail]; ok {
		return status, nil
	}
	return fmt.Sprintf("Mock status for jail %s", jail), nil
}

// BanIPWithContext bans the given IP in the specified jail. Returns 0 if banned, 1 if already banned.
func (m *MockClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for configured error
	if m.BanErrors[jail] != nil {
		if err, ok := m.BanErrors[jail][ip]; ok {
			return 0, err
		}
	}

	// Check for configured result
	if m.BanResults[jail] != nil {
		if result, ok := m.BanResults[jail][ip]; ok {
			return result, nil
		}
	}

	if _, ok := m.Jails[jail]; !ok {
		return 0, NewJailNotFoundError(jail)
	}
	if m.Banned[jail] == nil {
		m.Banned[jail] = make(map[string]time.Time)
	}
	if _, exists := m.Banned[jail][ip]; exists {
		return 1, nil // Already banned
	}
	m.Banned[jail][ip] = time.Now()
	// Real fail2ban log shape ("[jail] Ban <ip>") so the shared filter
	// semantics (bracketed jail, IP token boundary) apply to mock logs too.
	m.Logs = append(m.Logs, fmt.Sprintf("%s fail2ban.actions [mock]: NOTICE [%s] Ban %s",
		time.Now().Format(time.RFC3339), jail, ip))
	return 0, nil
}

// UnbanIPWithContext unbans the given IP in the specified jail. Returns 0 if unbanned, 1 if already unbanned.
func (m *MockClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for configured error
	if m.UnbanErrors[jail] != nil {
		if err, ok := m.UnbanErrors[jail][ip]; ok {
			return 0, err
		}
	}

	// Check for configured result
	if m.UnbanResults[jail] != nil {
		if result, ok := m.UnbanResults[jail][ip]; ok {
			return result, nil
		}
	}

	if _, ok := m.Jails[jail]; !ok {
		return 0, NewJailNotFoundError(jail)
	}
	if m.Banned[jail] == nil || m.Banned[jail][ip].IsZero() {
		return 1, nil // Already unbanned
	}
	delete(m.Banned[jail], ip)
	m.Logs = append(m.Logs, fmt.Sprintf("%s fail2ban.actions [mock]: NOTICE [%s] Unban %s",
		time.Now().Format(time.RFC3339), jail, ip))
	return 0, nil
}

// BannedInWithContext returns the sorted list of jails in which the IP is currently banned.
func (m *MockClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var jails []string
	for jail, ips := range m.Banned {
		if _, ok := ips[ip]; ok {
			jails = append(jails, jail)
		}
	}
	// Sort jails for consistent output
	sort.Strings(jails)
	return jails, nil
}

// GetBanRecordsWithContext returns ban records for the specified jails.
func (m *MockClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastBanRecordsJails = jails

	// Use configured ban records if available
	if len(m.BanRecords) > 0 {
		return m.BanRecords, nil
	}

	// Mirror the real client: an empty list or any ""/"all" element queries
	// every jail instead of returning nothing.
	if requestsAllJails(jails) {
		jails = make([]string, 0, len(m.Banned))
		for jail := range m.Banned {
			jails = append(jails, jail)
		}
		sort.Strings(jails)
	}

	var recs []BanRecord
	for _, jail := range jails {
		for ip, t := range m.Banned[jail] {
			recs = append(recs, BanRecord{
				Jail:      jail,
				IP:        ip,
				BannedAt:  t,
				Remaining: "01:00:00:00",
			})
		}
	}
	return recs, nil
}

// GetLogLinesWithContext returns the newest DefaultLogLinesLimit log lines
// filtered by jail and/or IP, like the real client.
func (m *MockClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return m.GetLogLinesWithLimitContext(ctx, jail, ip, constants.DefaultLogLinesLimit)
}

// GetLogLinesWithLimitContext returns the newest maxLines log lines filtered
// by jail and/or IP, recording the query and limit so tests can assert that
// the command forwarded them.
func (m *MockClient) GetLogLinesWithLimitContext(ctx context.Context, jail, ip string, maxLines int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastLogQuery = [2]string{jail, ip}
	m.LastLogLimit = maxLines

	// Filter with the same semantics as the real client (passesFilters +
	// canonical IP token matching) so tests can't pass against substring
	// behavior the production path doesn't have (e.g. "10.0.0.1" matching
	// inside "10.0.0.100").
	cfg := prepareLogFilters(LogReadConfig{JailFilter: jail, IPFilter: ip})
	source := m.LogLines
	if len(source) == 0 {
		source = m.Logs
	}
	lines := []string{} // never nil, like the real client
	for _, l := range source {
		if passesFilters(l, cfg) {
			lines = append(lines, l)
		}
	}
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

// ListFiltersWithContext returns the available Fail2Ban filters.
func (m *MockClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy so a caller mutating the result cannot corrupt mock state.
	filters := make([]string, len(m.Filters))
	copy(filters, m.Filters)
	return filters, nil
}

// TestFilterWithContext simulates running fail2ban-regex for the given filter.
func (m *MockClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Check configured filter tests first
	if result, ok := m.FilterTests[filter]; ok {
		return result, nil
	}
	if result, ok := m.FilterRuns[filter]; ok {
		return result, nil
	}
	return "", fmt.Errorf(ErrFilterNotFound, filter)
}

// Reset clears all bans and logs in the mock (for test isolation).
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Banned = make(map[string]map[string]time.Time)
	m.Logs = []string{}
}

// Helper methods for test configuration

// SetBanError configures an error to return for BanIPWithContext(ip, jail).
func (m *MockClient) SetBanError(jail, ip string, err error) {
	setNestedMapValue(&m.mu, m.BanErrors, jail, ip, err)
}

// SetBanResult configures a result code to return for BanIPWithContext(ip, jail).
func (m *MockClient) SetBanResult(jail, ip string, result int) {
	setNestedMapValue(&m.mu, m.BanResults, jail, ip, result)
}

// SetUnbanError configures an error to return for UnbanIPWithContext(ip, jail).
func (m *MockClient) SetUnbanError(jail, ip string, err error) {
	setNestedMapValue(&m.mu, m.UnbanErrors, jail, ip, err)
}

// SetUnbanResult configures a result code to return for UnbanIPWithContext(ip, jail).
func (m *MockClient) SetUnbanResult(jail, ip string, result int) {
	setNestedMapValue(&m.mu, m.UnbanResults, jail, ip, result)
}

// SetStatusJailData configures the status data for a specific jail.
func (m *MockClient) SetStatusJailData(jail, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StatusJailData[jail] = status
}

// SetFilterTest configures the test result for a filter.
func (m *MockClient) SetFilterTest(filter, result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FilterTests[filter] = result
}
