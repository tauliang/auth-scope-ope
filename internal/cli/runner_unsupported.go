//go:build !unix

package cli

import "errors"

// ValidateRunnerPath is only supported on unix: the ownership and
// permission checks have no portable meaning elsewhere.
func ValidateRunnerPath(_ string) (string, error) {
	return "", errors.New("cli: governed runner launch is only supported on unix")
}
