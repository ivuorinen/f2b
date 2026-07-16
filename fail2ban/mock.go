package fail2ban

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
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
	LastLogQuery        [2]string // last (jail, ip) passed to GetLogLines
	LastBanRecordsJails []string  // last jails passed to GetBanRecords
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

// ListJails returns the list of available jails.
func (m *MockClient) ListJails() ([]string, error) {
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

// StatusAll returns a mock status for all jails.
func (m *MockClient) StatusAll() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.StatusAllData, nil
}

// StatusJail returns a mock status for a specific jail.
func (m *MockClient) StatusJail(jail string) (string, error) {
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

// BanIP bans the given IP in the specified jail. Returns 0 if banned, 1 if already banned.
func (m *MockClient) BanIP(ip, jail string) (int, error) {
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

// UnbanIP unbans the given IP in the specified jail. Returns 0 if unbanned, 1 if already unbanned.
func (m *MockClient) UnbanIP(ip, jail string) (int, error) {
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

// BannedIn returns the list of jails in which the IP is currently banned.
func (m *MockClient) BannedIn(ip string) ([]string, error) {
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

// GetBanRecords returns ban records for the specified jails.
func (m *MockClient) GetBanRecords(jails []string) ([]BanRecord, error) {
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

// GetLogLines returns log lines filtered by jail and/or IP.
func (m *MockClient) GetLogLines(jail, ip string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastLogQuery = [2]string{jail, ip}

	// Filter with the same semantics as the real client (passesFilters +
	// canonical IP token matching) so tests can't pass against substring
	// behavior the production path doesn't have (e.g. "10.0.0.1" matching
	// inside "10.0.0.100").
	cfg := LogReadConfig{JailFilter: jail, IPFilter: canonicalizeIPFilter(ip)}
	source := m.LogLines
	if len(source) == 0 {
		source = m.Logs
	}
	var lines []string
	for _, l := range source {
		if passesFilters(l, cfg) {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// ListFilters returns the available Fail2Ban filters.
func (m *MockClient) ListFilters() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy so a caller mutating the result cannot corrupt mock state.
	filters := make([]string, len(m.Filters))
	copy(filters, m.Filters)
	return filters, nil
}

// TestFilter simulates running fail2ban-regex for the given filter.
func (m *MockClient) TestFilter(filter string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Check configured filter tests first
	if result, ok := m.FilterTests[filter]; ok {
		return result, nil
	}
	if result, ok := m.FilterRuns[filter]; ok {
		return result, nil
	}
	return "", NewFilterNotFoundError(filter)
}

// Context-aware methods for MockClient (using helpers to reduce boilerplate)

// ListJailsWithContext returns a list of jails using the provided context.
func (m *MockClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(m.ListJails)(ctx)
}

// StatusAllWithContext returns the status of all jails using the provided context.
func (m *MockClient) StatusAllWithContext(ctx context.Context) (string, error) {
	return wrapWithContext0(m.StatusAll)(ctx)
}

// StatusJailWithContext returns the status of the specified jail using the provided context.
func (m *MockClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	return wrapWithContext1(m.StatusJail)(ctx, jail)
}

// BanIPWithContext bans the specified IP in the given jail using the provided context.
func (m *MockClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return wrapWithContext2(m.BanIP)(ctx, ip, jail)
}

// UnbanIPWithContext unbans the specified IP from the given jail using the provided context.
func (m *MockClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	return wrapWithContext2(m.UnbanIP)(ctx, ip, jail)
}

// BannedInWithContext returns the jails where the IP is banned using the provided context.
func (m *MockClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	return wrapWithContext1(m.BannedIn)(ctx, ip)
}

// GetBanRecordsWithContext returns ban records for the specified jails using the provided context.
func (m *MockClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]BanRecord, error) {
	return wrapWithContext1(m.GetBanRecords)(ctx, jails)
}

// GetLogLinesWithContext returns log lines for the specified jail and IP using the provided context.
func (m *MockClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	return wrapWithContext2(m.GetLogLines)(ctx, jail, ip)
}

// ListFiltersWithContext returns a list of available filters using the provided context.
func (m *MockClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	return wrapWithContext0(m.ListFilters)(ctx)
}

// TestFilterWithContext tests the specified filter using the provided context.
func (m *MockClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	return wrapWithContext1(m.TestFilter)(ctx, filter)
}

// Reset clears all bans and logs in the mock (for test isolation).
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Banned = make(map[string]map[string]time.Time)
	m.Logs = []string{}
}

// Helper methods for test configuration

// SetBanError configures an error to return for BanIP(ip, jail).
func (m *MockClient) SetBanError(jail, ip string, err error) {
	setNestedMapValue(&m.mu, m.BanErrors, jail, ip, err)
}

// SetBanResult configures a result code to return for BanIP(ip, jail).
func (m *MockClient) SetBanResult(jail, ip string, result int) {
	setNestedMapValue(&m.mu, m.BanResults, jail, ip, result)
}

// SetUnbanError configures an error to return for UnbanIP(ip, jail).
func (m *MockClient) SetUnbanError(jail, ip string, err error) {
	setNestedMapValue(&m.mu, m.UnbanErrors, jail, ip, err)
}

// SetUnbanResult configures a result code to return for UnbanIP(ip, jail).
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
