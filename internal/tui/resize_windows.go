//go:build windows

package tui

import "os"

// resizeSignals is empty: Windows has no resize signal, so the dashboard
// picks up a new width on the next refresh tick.
var resizeSignals []os.Signal
