package fail2ban

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ivuorinen/f2b/constants"
)

// PathSecurityConfig holds configuration for path security validation.
// Symlinks are always resolved before the base check: a path is judged by
// where it leads.
type PathSecurityConfig struct {
	AllowedBasePaths []string // List of allowed base directories
	MaxPathLength    int      // Maximum allowed path length (0 = unlimited)
	AllowSymlinks    bool     // Whether to allow symlinks
}

// GetLogAllowedPaths returns allowed paths for log directories.
//
// Only /var/log: test-filter hands the filter's logpath to sudo fail2ban-regex,
// which prints the file's lines, so every allowed tree is a tree root can be
// made to read. Whole subtrees such as /home, /opt and /usr/local exposed other
// users' keys and secrets under `sudo f2b`.
func GetLogAllowedPaths() []string {
	paths := []string{"/var/log"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// GetFilterAllowedPaths returns allowed paths for filter directories: the
// fail2ban configuration locations only, never a user-writable tree such as
// /home, because a filter file names the logpath root reads.
func GetFilterAllowedPaths() []string {
	paths := []string{"/etc/fail2ban", "/usr/local/etc/fail2ban", "/opt/fail2ban"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// appendDevPathsIfAllowed adds development paths when ALLOW_DEV_PATHS is true.
// It is parsed as a boolean because it widens what root may be made to read: a
// presence check turned ALLOW_DEV_PATHS=0 into an enable.
func appendDevPathsIfAllowed(paths []string) []string {
	if allowed, err := strconv.ParseBool(os.Getenv("ALLOW_DEV_PATHS")); err == nil && allowed {
		return append(paths, "/tmp", "/var/folders") // macOS temp dirs
	}
	return paths
}

// expandAllowedPaths adds resolved equivalents for allowed paths and removes duplicates
func expandAllowedPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths)*2)
	expanded := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; !ok {
			expanded = append(expanded, p)
			seen[p] = struct{}{}
		}
		if resolved, err := resolveAncestorSymlinks(p); err == nil && resolved != "" && resolved != p {
			if _, ok := seen[resolved]; !ok {
				expanded = append(expanded, resolved)
				seen[resolved] = struct{}{}
			}
		}
	}
	return expanded
}

// CreateLogPathConfig creates a standard PathSecurityConfig for log directories
func CreateLogPathConfig() PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: GetLogAllowedPaths(),
		MaxPathLength:    4096,
		AllowSymlinks:    true,
	}
}

// CreateFilterPathConfig creates a standard PathSecurityConfig for filter directories
func CreateFilterPathConfig() PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: GetFilterAllowedPaths(),
		MaxPathLength:    4096,
		AllowSymlinks:    true,
	}
}

// CreateSingleDirPathConfig creates a path config for a single directory (like log file validation)
func CreateSingleDirPathConfig(baseDir string) PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: expandAllowedPaths([]string{baseDir}),
		MaxPathLength:    4096,
		AllowSymlinks:    false,
	}
}

// checkPathLimits enforces the max-length and null-byte checks. phase is
// appended to error messages (e.g. " after decoding") so the same logic can run
// before and after path decoding/normalization.
func checkPathLimits(path string, maxLen int, phase string) error {
	if maxLen > 0 && len(path) > maxLen {
		return fmt.Errorf("path too long%s: %d characters (max: %d)", phase, len(path), maxLen)
	}
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null byte%s", phase)
	}
	return nil
}

// ValidatePathWithSecurity performs comprehensive path security validation.
func ValidatePathWithSecurity(path string, config PathSecurityConfig) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path not allowed")
	}

	// Length and null-byte checks, run once on the raw input...
	if err := checkPathLimits(path, config.MaxPathLength, ""); err != nil {
		return "", err
	}

	// URL-decode and unicode-normalize for DETECTION only: encoded traversal
	// (%2e%2e) and lookalike-unicode tricks must be caught, but the path that
	// is validated and returned keeps its ORIGINAL bytes — a legitimate
	// "%25"-containing filename must not be rewritten to "%" (that would make
	// subsequent opens target a different path).
	detectPath := path
	if decodedPath, err := url.PathUnescape(path); err == nil && decodedPath != path {
		getLogger().Debug("Detected URL-encoded path; using decoded version for traversal detection")
		detectPath = decodedPath
	}
	detectPath = normalizeUnicode(detectPath)

	// ...and again after decoding/normalization to prevent bypass.
	if err := checkPathLimits(detectPath, config.MaxPathLength, " after decoding"); err != nil {
		return "", err
	}

	// Basic path traversal detection (before cleaning), on both the raw and
	// the decoded/normalized representation.
	if hasPathTraversal(path) || hasPathTraversal(detectPath) {
		return "", fmt.Errorf("path contains path traversal patterns")
	}

	// Clean and resolve the path
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Additional check after cleaning (double-check for sophisticated attacks)
	if hasPathTraversal(cleanPath) {
		return "", fmt.Errorf("path contains path traversal patterns after normalization")
	}

	// Handle symlinks according to configuration
	finalPath, err := handleSymlinks(cleanPath, config)
	if err != nil {
		return "", err
	}

	// Validate against allowed base paths using Rel, not prefix
	if err := validateBasePath(finalPath, config.AllowedBasePaths); err != nil {
		return "", err
	}

	// Check if path points to a device file or other dangerous file types
	if err := validateFileType(finalPath); err != nil {
		return "", err
	}

	return finalPath, nil
}

// hasPathTraversal detects various path traversal patterns
func hasPathTraversal(path string) bool {
	// Check for various path traversal patterns
	dangerousPatterns := []string{
		"..",
		"./",
		".\\",
		"//",
		"\\\\",
		"/../",
		"\\..\\",
		"%2e%2e", // URL encoded ..
		"%2f",    // URL encoded /
		"%5c",    // URL encoded \
		"․․",     // Unicode bullet points (can look like ..)
		"．．",     // Full-width Unicode ..
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(pathLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// normalizeUnicode normalizes unicode characters to prevent bypass attempts
func normalizeUnicode(path string) string {
	// Replace various Unicode representations of dots and slashes
	replacements := map[string]string{
		"․": ".",  // Unicode bullet (one dot leader)
		"．": ".",  // Full-width dot
		"⁄": "/",  // Unicode fraction slash
		"／": "/",  // Full-width slash
		"＼": "\\", // Full-width backslash
	}

	result := path
	for unicode, ascii := range replacements {
		result = strings.ReplaceAll(result, unicode, ascii)
	}

	return result
}

// handleSymlinks returns path with every symlink resolved, so the base check
// that follows sees where the path really leads. Inspecting only the leaf let
// <base>/link/secret pass while link pointed outside the base.
func handleSymlinks(path string, config PathSecurityConfig) (string, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 && !config.AllowSymlinks {
			return "", fmt.Errorf("symlinks not allowed: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check file info: %w", err)
	}

	resolved, err := resolveAncestorSymlinks(path)
	if err != nil {
		return "", err
	}
	if !config.AllowSymlinks && resolved != path && !differsOnlyInBase(path, resolved, config.AllowedBasePaths) {
		return "", fmt.Errorf("symlinks not allowed in path: %s", path)
	}
	return resolved, nil
}

// differsOnlyInBase reports whether path and resolved name the same location
// relative to one of bases, meaning the only symlink sits at or above the base.
// A symlink there is the host's layout (/var on macOS), not an escape.
func differsOnlyInBase(path, resolved string, bases []string) bool {
	for _, base := range bases {
		rel, err := filepath.Rel(base, path)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		realBase, err := resolveAncestorSymlinks(base)
		if err == nil && filepath.Join(realBase, rel) == resolved {
			return true
		}
	}
	return false
}

// resolveAncestorSymlinks resolves every symlink in the deepest existing prefix
// of path and re-appends the components that do not exist yet, such as a log
// file about to be created.
func resolveAncestorSymlinks(path string) (string, error) {
	existing := path
	var tail []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return path, nil
		}
		tail = append([]string{filepath.Base(existing)}, tail...)
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf(constants.ErrFailedToResolveSymlink, err)
	}
	return filepath.Join(append([]string{resolved}, tail...)...), nil
}

// validateBasePath ensures the path is within allowed base directories. An
// empty list allows nothing.
func validateBasePath(path string, allowedBasePaths []string) error {
	for _, basePath := range allowedBasePaths {
		cleanBasePath, err := filepath.Abs(filepath.Clean(basePath))
		if err != nil {
			continue
		}

		rel, err := filepath.Rel(cleanBasePath, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}

	return fmt.Errorf("path outside allowed directories: %s", path)
}

// validateFileType refuses anything but regular files and directories: opening
// a device, named pipe or socket can block or have side effects.
func validateFileType(path string) error {
	// Check if file exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // File doesn't exist yet, allow it
	}
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if mode := info.Mode(); !mode.IsRegular() && !mode.IsDir() {
		return fmt.Errorf("only regular files and directories are allowed: %s", path)
	}

	return nil
}

// The validators below take no context: they do no blocking work, so a
// context parameter would promise cancellation they cannot honor.

// ValidateLogPath validates and sanitizes a log file path, confined to logDir.
func ValidateLogPath(path, logDir string) (string, error) {
	return ValidatePathWithSecurity(path, CreateSingleDirPathConfig(logDir))
}

// ValidateClientLogPath validates a log directory against the log allowlist.
func ValidateClientLogPath(logDir string) (string, error) {
	return ValidatePathWithSecurity(logDir, CreateLogPathConfig())
}

// ValidateClientFilterPath validates a filter directory against the filter allowlist.
func ValidateClientFilterPath(filterDir string) (string, error) {
	return ValidatePathWithSecurity(filterDir, CreateFilterPathConfig())
}
