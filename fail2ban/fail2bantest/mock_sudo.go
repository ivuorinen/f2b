package fail2bantest

// MockSudoChecker is a test double for the fail2ban.SudoChecker interface.
type MockSudoChecker struct {
	MockIsRoot            bool
	MockInSudoGroup       bool
	MockCanUseSudo        bool
	MockHasPrivileges     bool
	ExplicitPrivilegesSet bool // Track if MockHasPrivileges was explicitly set
}

// IsRoot returns the mocked root status
func (m *MockSudoChecker) IsRoot() bool {
	return m.MockIsRoot
}

// InSudoGroup returns the mocked sudo group status
func (m *MockSudoChecker) InSudoGroup() bool {
	return m.MockInSudoGroup
}

// CanUseSudo returns the mocked sudo capability status
func (m *MockSudoChecker) CanUseSudo() bool {
	return m.MockCanUseSudo
}

// HasSudoPrivileges returns the mocked sudo privileges status
func (m *MockSudoChecker) HasSudoPrivileges() bool {
	// If ExplicitPrivilegesSet is true, use MockHasPrivileges directly
	if m.ExplicitPrivilegesSet {
		return m.MockHasPrivileges
	}
	// Otherwise, compute from individual privileges
	return m.MockIsRoot || m.MockInSudoGroup || m.MockCanUseSudo
}
