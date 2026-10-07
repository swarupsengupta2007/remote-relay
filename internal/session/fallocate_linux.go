//go:build linux

package session

import (
	"golang.org/x/sys/unix"
)

func punchHole(fd int, off int64, len int64) error {
	return unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, len)
}
