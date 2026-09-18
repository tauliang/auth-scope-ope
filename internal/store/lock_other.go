//go:build !unix

package store

import (
	"errors"
	"os"
)

// lockExclusiveNonblock is only supported on unix: the exclusive
// data-directory lock has no portable meaning elsewhere.
func lockExclusiveNonblock(_ *os.File) error {
	return errors.New("store: exclusive data-directory lock is only supported on unix")
}
