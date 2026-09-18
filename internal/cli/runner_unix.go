//go:build unix

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ValidateRunnerPath checks the governed runner binary before every
// launch: the path must be absolute and, after cleaning, must name a
// regular file that is not a symlink, is owned by the current user or
// root, and is not group- or world-writable. It returns the cleaned
// absolute path.
func ValidateRunnerPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("cli: runner path is required")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("cli: runner path must be absolute: %q", path)
	}
	abs := filepath.Clean(path)
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("cli: runner: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("cli: runner must not be a symlink: %q", abs)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("cli: runner is not a regular file: %q", abs)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("cli: runner must not be group- or world-writable: %q", abs)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cli: runner: cannot read ownership: %q", abs)
	}
	uid := uint32(os.Getuid())
	if st.Uid != uid && st.Uid != 0 {
		return "", fmt.Errorf("cli: runner must be owned by the current user or root: %q", abs)
	}
	return abs, nil
}
