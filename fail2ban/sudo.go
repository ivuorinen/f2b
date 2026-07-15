package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

const (
	// DefaultSudoTimeout is the default timeout for sudo privilege checks
	DefaultSudoTimeout = 5 * time.Second
)

// RealSudoChecker implements SudoChecker using actual system calls
type RealSudoChecker struct {
	// runSudoProbe runs the non-interactive sudo probe. Tests inject a mock
	// here so the probe branch is exercisable without ever executing real
	// sudo; nil means the real `sudo -n true` probe.
	runSudoProbe func(ctx context.Context) error
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
		if group.Name == constants.SudoCommand || group.Name == "wheel" || group.Name == "admin" {
			return true
		}

		// Removed hard-coded GID checks for better portability
		// Group name lookup above handles all standard sudo groups
	}

	return false
}

// defaultSudoProbe tries to run 'sudo -n true' (non-interactive) to test sudo access.
func defaultSudoProbe(ctx context.Context) error {
	// #nosec G204 -- constants.SudoCommand is a hardcoded constant "sudo", not user input
	return exec.CommandContext(ctx, constants.SudoCommand, "-n", "true").Run()
}

// CanUseSudo returns true if the current user can use sudo
func (r *RealSudoChecker) CanUseSudo() bool {
	probe := r.runSudoProbe
	if probe == nil {
		// In test environment, never execute the real sudo binary
		if IsTestEnvironment() {
			return false // Default to false in tests unless mocked
		}
		probe = defaultSudoProbe
	}

	// Create a context with timeout to prevent hanging processes
	ctx, cancel := context.WithTimeout(context.Background(), DefaultSudoTimeout)
	defer cancel()

	return probe(ctx) == nil
}

// HasSudoPrivileges returns true if user has any form of sudo access
func (r *RealSudoChecker) HasSudoPrivileges() bool {
	return r.IsRoot() || r.InSudoGroup() || r.CanUseSudo()
}

// Mock implementations

// RequiresSudo returns true if the given command typically requires sudo privileges
func RequiresSudo(command string, args ...string) bool {
	// Every fail2ban-client subcommand talks to the server socket
	// (/var/run/fail2ban/fail2ban.sock), which is root-only, so all of them
	// need sudo for a non-root user. The sole exception is `-V`, which only
	// prints the client version and never touches the socket.
	if command == constants.Fail2BanClientCommand {
		// No subcommand (prints usage) and -V (prints version) never touch the
		// root-only server socket, so they don't need sudo. Every real
		// subcommand does.
		if len(args) == 0 || args[0] == constants.CommandArgVersion {
			return false
		}
		return true
	}

	// fail2ban-regex reads the log file named in the filter's logpath; those
	// logs (e.g. /var/log/auth.log) are typically root-only, so the probe is
	// useless without sudo. The logpath is validated against the log allowlist
	// before it reaches argv (TestFilterWithContext), so sudo cannot be turned
	// into an arbitrary read-as-root primitive.
	if command == constants.Fail2BanRegexCommand {
		return true
	}

	if command == constants.ServiceCommand && len(args) > 0 && args[0] == constants.ServiceFail2ban {
		return true
	}

	if command == "systemctl" && len(args) > 0 {
		switch args[0] {
		case constants.ActionStart, "stop", "restart", "reload", "enable", "disable":
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
