//go:build !linux

package session

import (
	"errors"
)

var errHolePunchUnsupported = errors.New("hole punching unsupported on this platform")

func punchHole(fd int, off int64, len int64) error {
	return errHolePunchUnsupported
}
