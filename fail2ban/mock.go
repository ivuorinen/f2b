package fail2ban

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// MockClient is a stateful, thread-safe mock implementation of the Client interface for testing.
type MockClient struct {
	mu         sync.Mutex
	Jails      map[string]struct{}
	Banned     map[string]map[string]time.Time // jail -> ip -> ban time
	Logs       []string
	Filters    []string
	FilterRuns map[string]string
}

// NewMockClient creates a new MockClient with default jails and filters.
func NewMockClient() *MockClient {
	return &MockClient{
		Jails:      map[string]struct{}{"sshd": {}, "apache": {}},
		Banned:     make(map[string]map[string]time.Time),
		Logs:       []string{},
		Filters:    []string{"sshd", "apache"},
		FilterRuns: make(map[string]string),
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
	return jails, nil
}

// StatusAll returns a mock status for all jails.
func (m *MockClient) StatusAll() (string, error) {
	return "Mock status for all jails", nil
}

// StatusJail returns a mock status for a specific jail.
func (m *MockClient) StatusJail(jail string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Jails[jail]; !ok {
		return "", fmt.Errorf("jail %s not found", jail)
	}
	return fmt.Sprintf("Mock status for jail %s", jail), nil
}

// BanIP bans the given IP in the specified jail. Returns 0 if banned, 1 if already banned.
func (m *MockClient) BanIP(ip, jail string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Jails[jail]; !ok {
		return 0, fmt.Errorf("jail %s not found", jail)
	}
	if m.Banned[jail] == nil {
		m.Banned[jail] = make(map[string]time.Time)
	}
	if _, exists := m.Banned[jail][ip]; exists {
		return 1, nil // Already banned
	}
	m.Banned[jail][ip] = time.Now()
	m.Logs = append(m.Logs, fmt.Sprintf("%s [mock] Ban %s in %s", time.Now().Format(time.RFC3339), ip, jail))
	return 0, nil
}

// UnbanIP unbans the given IP in the specified jail. Returns 0 if unbanned, 1 if already unbanned.
func (m *MockClient) UnbanIP(ip, jail string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Jails[jail]; !ok {
		return 0, fmt.Errorf("jail %s not found", jail)
	}
	if m.Banned[jail] == nil || m.Banned[jail][ip].IsZero() {
		return 1, nil // Already unbanned
	}
	delete(m.Banned[jail], ip)
	m.Logs = append(m.Logs, fmt.Sprintf("%s [mock] Unban %s in %s", time.Now().Format(time.RFC3339), ip, jail))
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
	return jails, nil
}

// GetBanRecords returns ban records for the specified jails.
func (m *MockClient) GetBanRecords(jails []string) ([]BanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	var lines []string
	for _, l := range m.Logs {
		if (jail == "" || strings.Contains(l, jail)) && (ip == "" || strings.Contains(l, ip)) {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// ListFilters returns the available Fail2Ban filters.
func (m *MockClient) ListFilters() ([]string, error) {
	return m.Filters, nil
}

// TestFilter simulates running fail2ban-regex for the given filter.
func (m *MockClient) TestFilter(filter string) (string, error) {
	if result, ok := m.FilterRuns[filter]; ok {
		return result, nil
	}
	return "", fmt.Errorf("filter %s not found", filter)
}

// Reset clears all bans and logs in the mock (for test isolation).
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Banned = make(map[string]map[string]time.Time)
	m.Logs = []string{}
}
