package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	// groupNames returns the current user's group names. Tests inject it so
	// the sudo/wheel/admin match is checkable without the host group
	// database; nil means currentGroupNames.
	groupNames func() ([]string, error)
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

// InSudoGroup returns true if the current user belongs to a group that
// conventionally grants sudo (sudo, wheel or admin). Group names, not GIDs,
// are matched because GIDs vary between distributions.
func (r *RealSudoChecker) InSudoGroup() bool {
	lookup := r.groupNames
	if lookup == nil {
		lookup = currentGroupNames
	}
	names, err := lookup()
	if err != nil {
		return false
	}
	for _, name := range names {
		if name == constants.SudoCommand || name == "wheel" || name == "admin" {
			return true
		}
	}
	return false
}

// currentGroupNames resolves the current user's group IDs to names, skipping
// IDs that no longer resolve to a group.
func currentGroupNames() ([]string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	gids, err := currentUser.GroupIds()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		if group, err := user.LookupGroupId(gid); err == nil {
			names = append(names, group.Name)
		}
	}
	return names, nil
}

// defaultSudoProbe runs the non-interactive sudo probes against the real sudo binary.
func defaultSudoProbe(ctx context.Context) error {
	return probeSudo(ctx, func(ctx context.Context, args ...string) error {
		// #nosec G204 -- constants.SudoCommand is a hardcoded constant "sudo"; args are fixed literals
		return exec.CommandContext(ctx, constants.SudoCommand, args...).Run()
	})
}

// probeSudo reports whether sudo works non-interactively for fail2ban: either
// for any command (`sudo -n true`) or for fail2ban-client alone (`sudo -n -l
// fail2ban-client`, which succeeds only when that command is permitted without
// a password prompt). A least-privilege sudoers grant scoped to
// fail2ban-client fails the first probe but still covers every operation f2b
// needs, so the second probe accepts it. run executes sudo with the given
// arguments.
func probeSudo(ctx context.Context, run func(ctx context.Context, args ...string) error) error {
	if err := run(ctx, "-n", "true"); err == nil {
		return nil
	}
	return run(ctx, "-n", "-l", constants.Fail2BanClientCommand)
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

// RequiresSudo returns true if the given command typically requires sudo privileges.
//
// command may be a bare name or an absolute path: production passes the
// exec.LookPath result (/usr/bin/fail2ban-client) while tests pass the bare
// name, and matching only the bare name made every non-root fail2ban-client
// call skip sudo and fail on the root-only socket. The absolute path was
// already pinned to a trusted directory by validateCommandExecution, so only
// its base name decides here.
func RequiresSudo(command string, args ...string) bool {
	command = filepath.Base(command)

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
