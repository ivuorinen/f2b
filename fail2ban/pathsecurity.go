package fail2ban

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivuorinen/f2b/constants"
)

// PathSecurityConfig holds configuration for path security validation
type PathSecurityConfig struct {
	AllowedBasePaths []string // List of allowed base directories
	MaxPathLength    int      // Maximum allowed path length (0 = unlimited)
	AllowSymlinks    bool     // Whether to allow symlinks
	ResolveSymlinks  bool     // Whether to resolve symlinks before validation
}

// GetLogAllowedPaths returns allowed paths for log directories
func GetLogAllowedPaths() []string {
	paths := []string{"/var/log", "/opt", "/usr/local", "/home"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// GetFilterAllowedPaths returns allowed paths for filter directories
func GetFilterAllowedPaths() []string {
	paths := []string{"/etc/fail2ban", "/usr/local/etc/fail2ban", "/opt/fail2ban", "/home"}
	paths = appendDevPathsIfAllowed(paths)
	return expandAllowedPaths(paths)
}

// appendDevPathsIfAllowed adds development paths if ALLOW_DEV_PATHS is set
func appendDevPathsIfAllowed(paths []string) []string {
	if os.Getenv("ALLOW_DEV_PATHS") != "" {
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
		if resolved, err := resolveAncestorSymlinks(p, true); err == nil && resolved != "" && resolved != p {
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
		ResolveSymlinks:  true,
	}
}

// CreateFilterPathConfig creates a standard PathSecurityConfig for filter directories
func CreateFilterPathConfig() PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: GetFilterAllowedPaths(),
		MaxPathLength:    4096,
		AllowSymlinks:    true,
		ResolveSymlinks:  true,
	}
}

// CreateSingleDirPathConfig creates a path config for a single directory (like log file validation)
func CreateSingleDirPathConfig(baseDir string) PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: []string{baseDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
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
		"..",     // Unicode ..
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
		".": ".",  // Unicode dot
		"․": ".",  // Unicode bullet (one dot leader)
		"．": ".",  // Full-width dot
		"/": "/",  // Unicode slash
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

// handleSymlinks resolves or validates symlinks according to configuration
func handleSymlinks(path string, config PathSecurityConfig) (string, error) {
	// Check if the path is a symlink
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if !config.AllowSymlinks {
				return "", fmt.Errorf("symlinks not allowed: %s", path)
			}

			if config.ResolveSymlinks {
				resolved, err := filepath.EvalSymlinks(path)
				if err != nil {
					return "", fmt.Errorf(constants.ErrFailedToResolveSymlink, err)
				}
				return resolved, nil
			}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check file info: %w", err)
	}

	// If leaf doesn't exist, resolve symlinks in the deepest existing ancestor
	if config.ResolveSymlinks {
		return resolveAncestorSymlinks(path, config.AllowSymlinks)
	}
	return path, nil
}

// resolveAncestorSymlinks resolves symlinks in existing ancestor directories
func resolveAncestorSymlinks(path string, allowSymlinks bool) (string, error) {
	dir := path
	var tail []string
	for {
		d := filepath.Dir(dir)
		if d == dir {
			break
		}
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		tail = append([]string{filepath.Base(dir)}, tail...)
		dir = d
	}
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if !allowSymlinks {
			return "", fmt.Errorf("symlinks not allowed in path: %s", dir)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", fmt.Errorf(constants.ErrFailedToResolveSymlink, err)
		}
		return filepath.Join(append([]string{resolved}, tail...)...), nil
	}
	return path, nil
}

// validateBasePath ensures the path is within allowed base directories
func validateBasePath(path string, allowedBasePaths []string) error {
	if len(allowedBasePaths) == 0 {
		return nil // No restrictions if no base paths configured
	}

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

// validateFileType checks for dangerous file types (devices, named pipes, etc.)
func validateFileType(path string) error {
	// Check if file exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // File doesn't exist yet, allow it
	}
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	mode := info.Mode()

	// Block device files
	if mode&os.ModeDevice != 0 {
		return fmt.Errorf("device files not allowed: %s", path)
	}

	// Block named pipes (FIFOs)
	if mode&os.ModeNamedPipe != 0 {
		return fmt.Errorf("named pipes not allowed: %s", path)
	}

	// Block socket files
	if mode&os.ModeSocket != 0 {
		return fmt.Errorf("socket files not allowed: %s", path)
	}

	// Block irregular files (anything that's not a regular file or directory)
	if !mode.IsRegular() && !mode.IsDir() {
		return fmt.Errorf("irregular file type not allowed: %s", path)
	}

	return nil
}

// ValidateLogPath validates and sanitizes a log file path using standard log directory config
// Context parameter accepted for API consistency but not currently used
func ValidateLogPath(ctx context.Context, path string, logDir string) (string, error) {
	_ = ctx // Context not currently used by ValidatePathWithSecurity
	config := CreateSingleDirPathConfig(logDir)
	return ValidatePathWithSecurity(path, config)
}

// validateClientPath is a generic helper for client path validation.
// It reduces duplication between ValidateClientLogPath and ValidateClientFilterPath.
func validateClientPath(ctx context.Context, path string, configFn func() PathSecurityConfig) (string, error) {
	_ = ctx // Context not currently used by ValidatePathWithSecurity
	return ValidatePathWithSecurity(path, configFn())
}

// ValidateClientLogPath validates log directory path for client initialization
// Context parameter accepted for API consistency but not currently used
func ValidateClientLogPath(ctx context.Context, logDir string) (string, error) {
	return validateClientPath(ctx, logDir, CreateLogPathConfig)
}

// ValidateClientFilterPath validates filter directory path for client initialization
// Context parameter accepted for API consistency but not currently used
func ValidateClientFilterPath(ctx context.Context, filterDir string) (string, error) {
	return validateClientPath(ctx, filterDir, CreateFilterPathConfig)
}
