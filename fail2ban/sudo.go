package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"time"
)

const (
	// DefaultSudoTimeout is the default timeout for sudo privilege checks
	DefaultSudoTimeout = 5 * time.Second
)

// SudoChecker provides methods to check sudo privileges
type SudoChecker interface {
	// IsRoot returns true if the current user is root (UID 0)
	IsRoot() bool
	// InSudoGroup returns true if the current user is in the sudo group
	InSudoGroup() bool
	// CanUseSudo returns true if the current user can use sudo
	CanUseSudo() bool
	// HasSudoPrivileges returns true if user has any form of sudo access
	HasSudoPrivileges() bool
}

// RealSudoChecker implements SudoChecker using actual system calls
type RealSudoChecker struct{}

// MockSudoChecker implements SudoChecker for testing
type MockSudoChecker struct {
	MockIsRoot            bool
	MockInSudoGroup       bool
	MockCanUseSudo        bool
	MockHasPrivileges     bool
	ExplicitPrivilegesSet bool // Track if MockHasPrivileges was explicitly set
}

var (
	sudoChecker   SudoChecker  = &RealSudoChecker{}
	sudoCheckerMu sync.RWMutex // protects sudoChecker from concurrent access
)

// SetSudoChecker allows injecting a mock sudo checker for testing
func SetSudoChecker(checker SudoChecker) {
	sudoCheckerMu.Lock()
	defer sudoCheckerMu.Unlock()
	sudoChecker = checker
}

// GetSudoChecker returns the current sudo checker
func GetSudoChecker() SudoChecker {
	sudoCheckerMu.RLock()
	defer sudoCheckerMu.RUnlock()
	return sudoChecker
}

// IsRoot returns true if the current user is root (UID 0)
func (r *RealSudoChecker) IsRoot() bool {
	return os.Geteuid() == 0
}

// InSudoGroup returns true if the current user is in the sudo group
func (r *RealSudoChecker) InSudoGroup() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	// Get user groups
	groups, err := currentUser.GroupIds()
	if err != nil {
		return false
	}

	// Check for sudo group (GID varies by system, common ones are 27 and 1001)
	// Also check by group name
	for _, gid := range groups {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}

		// Check common sudo group names (portable across systems)
		if group.Name == "sudo" || group.Name == "wheel" || group.Name == "admin" {
			return true
		}

		// Removed hard-coded GID checks for better portability
		// Group name lookup above handles all standard sudo groups
	}

	return false
}

// CanUseSudo returns true if the current user can use sudo
func (r *RealSudoChecker) CanUseSudo() bool {
	// In test environment, don't actually run sudo
	if IsTestEnvironment() {
		return false // Default to false in tests unless mocked
	}

	// Create a context with timeout to prevent hanging processes
	ctx, cancel := context.WithTimeout(context.Background(), DefaultSudoTimeout)
	defer cancel()

	// Try to run 'sudo -n true' (non-interactive) to test sudo access
	cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	err := cmd.Run()
	return err == nil
}

// HasSudoPrivileges returns true if user has any form of sudo access
func (r *RealSudoChecker) HasSudoPrivileges() bool {
	return r.IsRoot() || r.InSudoGroup() || r.CanUseSudo()
}

// Mock implementations

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

// RequiresSudo returns true if the given command typically requires sudo privileges
func RequiresSudo(command string, args ...string) bool {
	// Commands that typically require sudo for fail2ban operations
	if command == "fail2ban-client" {
		if len(args) > 0 {
			switch args[0] {
			case "set", "reload", "restart", "start", "stop":
				return true
			case "get":
				// Some get operations might require sudo depending on configuration
				if len(args) > 2 && (args[2] == "banip" || args[2] == "unbanip") {
					return true
				}
			}
		}
		return false
	}

	if command == "service" && len(args) > 0 && args[0] == "fail2ban" {
		return true
	}

	if command == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "start", "stop", "restart", "reload", "enable", "disable":
			return true
		}
	}

	return false
}

// CheckSudoRequirements checks if the current user has the necessary privileges
// for fail2ban operations and returns an error if not
func CheckSudoRequirements() error {
	checker := GetSudoChecker()

	if !checker.HasSudoPrivileges() {
		uid := os.Getuid()
		username := "unknown"
		if currentUser, err := user.Current(); err == nil {
			username = currentUser.Username
		}

		return fmt.Errorf("fail2ban operations require sudo privileges. "+
			"Current user: %s (UID: %d). "+
			"Please run with sudo or ensure user is in sudo group",
			username, uid)
	}

	return nil
}

// GetCurrentUserInfo returns information about the current user for debugging
func GetCurrentUserInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["uid"] = os.Getuid()
	info["gid"] = os.Getgid()
	info["euid"] = os.Geteuid()
	info["egid"] = os.Getegid()

	if currentUser, err := user.Current(); err == nil {
		info["username"] = currentUser.Username
		info["name"] = currentUser.Name
		info["home_dir"] = currentUser.HomeDir

		if groups, err := currentUser.GroupIds(); err == nil {
			var groupNames []string
			for _, gid := range groups {
				if group, err := user.LookupGroupId(gid); err == nil {
					groupNames = append(groupNames, group.Name)
				}
			}
			info["groups"] = groupNames
			info["group_ids"] = groups
		}
	}

	checker := GetSudoChecker()
	info["is_root"] = checker.IsRoot()
	info["in_sudo_group"] = checker.InSudoGroup()
	info["can_use_sudo"] = checker.CanUseSudo()
	info["has_sudo_privileges"] = checker.HasSudoPrivileges()

	return info
}

// NewMockSudoChecker creates a new MockSudoChecker with specified privileges
func NewMockSudoChecker(isRoot, inSudoGroup, canUseSudo bool) *MockSudoChecker {
	return &MockSudoChecker{
		MockIsRoot:            isRoot,
		MockInSudoGroup:       inSudoGroup,
		MockCanUseSudo:        canUseSudo,
		ExplicitPrivilegesSet: false, // Let HasSudoPrivileges() compute from individual flags
	}
}

// NewMockSudoCheckerWithPrivileges creates a MockSudoChecker with explicit privilege setting
func NewMockSudoCheckerWithPrivileges(hasPrivileges bool) *MockSudoChecker {
	return &MockSudoChecker{
		MockHasPrivileges:     hasPrivileges,
		ExplicitPrivilegesSet: true,
	}
}
