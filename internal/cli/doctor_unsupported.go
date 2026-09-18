//go:build !unix

package cli

import (
	"os"
)

// checkOwnedBySelf is a no-op where ownership metadata is unavailable;
// permission bits are still enforced by the caller.
func checkOwnedBySelf(path string, fi os.FileInfo) error { return nil }
