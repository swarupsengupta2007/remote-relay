//go:build !windows

package tui

import (
	"os"
	"syscall"
)

// resizeSignals are delivered when the terminal is resized.
var resizeSignals = []os.Signal{syscall.SIGWINCH}
