package fail2bantest

import (
	"os"

	"github.com/ivuorinen/f2b/fail2ban"
)

// KeepTempDirUnderDevPaths points TMPDIR at /tmp when the dev-path allowlist
// does not admit the directory os.TempDir() names. A package's TestMain calls
// it before m.Run. The path tests write their logs, filters and log files
// under t.TempDir() and set ALLOW_DEV_PATHS, which admits only /tmp and
// /var/folders, so with TMPDIR elsewhere, such as a directory in the home
// tree, they failed validation instead of testing anything. The production
// allowlist stays as it is, and the decision comes from it rather than from a
// copy of its roots.
func KeepTempDirUnderDevPaths() error {
	admitted, err := devPathsAdmit(os.TempDir())
	if err != nil || admitted {
		return err
	}
	return os.Setenv("TMPDIR", "/tmp")
}

// devPathsAdmit reports whether the log allowlist admits dir with
// ALLOW_DEV_PATHS on, as the path tests run, and restores the variable.
func devPathsAdmit(dir string) (bool, error) {
	prev, had := os.LookupEnv("ALLOW_DEV_PATHS")
	if err := os.Setenv("ALLOW_DEV_PATHS", "true"); err != nil {
		return false, err
	}
	_, validateErr := fail2ban.ValidateClientLogPath(dir)
	var err error
	if had {
		err = os.Setenv("ALLOW_DEV_PATHS", prev)
	} else {
		err = os.Unsetenv("ALLOW_DEV_PATHS")
	}
	return validateErr == nil, err
}
