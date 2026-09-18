//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwnedBySelf verifies path is owned by the current user or root.
func checkOwnedBySelf(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership")
	}
	uid := uint32(os.Getuid())
	if st.Uid != uid && st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, want %d or root", st.Uid, uid)
	}
	return nil
}
