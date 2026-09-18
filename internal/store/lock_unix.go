//go:build unix

package store

import (
	"fmt"
	"os"
	"syscall"
)

// lockExclusiveNonblock takes an exclusive advisory lock on f without
// blocking. It fails when another process holds the lock.
func lockExclusiveNonblock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("store: lock data directory: %w", err)
	}
	return nil
}
