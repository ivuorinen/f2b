package fail2ban

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// copyLogForRegex copies the validated log at logPath into a new private
// directory and returns the copy's path and a function that removes that
// directory. fail2ban-regex runs as root, so it must not be handed logPath: a
// user who can write a directory on it could swap the file for a symlink
// after validation. The log is opened through an os.Root anchored at the
// allowlisted base that holds it, which refuses any component leading
// outside the base at open time. Only a regular file of at most maxSize bytes
// is copied; a larger log is an error, not a truncated copy.
func copyLogForRegex(logPath string, bases []string, maxSize int64) (string, func() error, error) {
	src, err := openUnderBase(logPath, bases)
	if err != nil {
		return "", nil, err
	}
	defer safeCloseFile(src, logPath)

	info, err := src.Stat()
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("log %s is not a regular file", logPath)
	}

	dir, err := os.MkdirTemp("", "f2b-regex-") // created 0700
	if err != nil {
		return "", nil, err
	}
	remove := func() error { return os.RemoveAll(dir) }
	copyPath := filepath.Join(dir, filepath.Base(logPath))
	if err := writeCapped(copyPath, src, maxSize); err != nil {
		return "", nil, errors.Join(fmt.Errorf("log %s: %w", logPath, err), remove())
	}
	return copyPath, remove, nil
}

// openUnderBase opens path, relative to the base in bases that holds it,
// through an os.Root. O_NONBLOCK keeps a named pipe from blocking the open
// until a writer appears, so the caller's file type check can refuse it; it
// does not change how a regular file is read.
func openUnderBase(path string, bases []string) (*os.File, error) {
	for _, base := range bases {
		rel, err := filepath.Rel(base, path)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		root, err := os.OpenRoot(base)
		if err != nil {
			return nil, err
		}
		f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if closeErr := root.Close(); closeErr != nil {
			getLogger().WithError(closeErr).WithField("base", base).Warn("Failed to close log directory")
		}
		return f, err
	}
	return nil, fmt.Errorf("log %s is not under an allowed log directory", path)
}

// writeCapped writes at most maxSize bytes of src to a new file at path, and
// fails when src holds more.
func writeCapped(path string, src io.Reader, maxSize int64) error {
	// #nosec G304 -- path is inside the private directory copyLogForRegex created
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(dst, io.LimitReader(src, maxSize+1))
	closeErr := dst.Close()
	if err != nil {
		return err
	}
	if n > maxSize {
		return fmt.Errorf("larger than %d bytes", maxSize)
	}
	return closeErr
}
