package relay

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// HUDConfig configures the terminal reconnection HUD and desktop notifications.
type HUDConfig struct {
	Enabled             bool
	Out                 io.Writer
	IsTerminal          *bool
	NotificationTimeout time.Duration
	WidthFn             func() int
	Clock               func() time.Time
}

// HUD provides unobtrusive single-line status updates on stderr via carriage returns (\r)
// during reconnection attempts, alongside terminal desktop notifications (OSC 9 / OSC 777)
// for prolonged disruptions.
type HUD struct {
	mu               sync.Mutex
	cfg              HUDConfig
	out              io.Writer
	isTTY            bool
	active           bool
	disruptedAt      time.Time
	notificationSent bool
	clock            func() time.Time
	noColor          bool
	// notifyTimer emits the prolonged-outage notification even while a single
	// reconnect attempt blocks; notifyGen discards a timer from an earlier outage.
	notifyTimer *time.Timer
	notifyGen   uint64
}

// NewHUD creates a new HUD instance.
func NewHUD(cfg HUDConfig) *HUD {
	out := cfg.Out
	if out == nil {
		out = os.Stderr
	}

	isTTY := false
	if cfg.IsTerminal != nil {
		isTTY = *cfg.IsTerminal
	} else if os.Getenv("TERM") != "dumb" {
		if f, ok := out.(*os.File); ok {
			isTTY = term.IsTerminal(int(f.Fd()))
		}
	}

	// Explicit environment variable override
	if os.Getenv("RELAY_HUD") == "0" {
		isTTY = false
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	timeout := cfg.NotificationTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	noColor := os.Getenv("NO_COLOR") != ""

	return &HUD{
		cfg: HUDConfig{
			Enabled:             cfg.Enabled,
			Out:                 out,
			NotificationTimeout: timeout,
			WidthFn:             cfg.WidthFn,
		},
		out:     out,
		isTTY:   isTTY,
		clock:   clock,
		noColor: noColor,
	}
}

// tag returns the formatted [remote-relay] prefix.
func (h *HUD) tag(level string) string {
	prefix := "[remote-relay] "
	if h.noColor || !h.isTTY {
		return prefix
	}
	switch level {
	case "warning":
		return "\033[33m[remote-relay]\033[0m "
	case "success":
		return "\033[32m[remote-relay]\033[0m "
	case "error":
		return "\033[31m[remote-relay]\033[0m "
	default:
		return prefix
	}
}

// OnDisrupted marks the onset of a connection disruption and prints an initial status line.
func (h *HUD) OnDisrupted(transport string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.disruptedAt = h.clock()
	h.active = true
	h.notificationSent = false
	h.armNotifyLocked()

	if !h.isTTY || !h.cfg.Enabled {
		return
	}

	proto := strings.ToUpper(transport)
	if proto == "" {
		proto = "TCP"
	}

	msg := fmt.Sprintf("%sLink disrupted. Reconnecting via %s...", h.tag("warning"), proto)
	h.renderLine(msg, false)
}

// OnAttempt updates the status line during each reconnection retry.
func (h *HUD) OnAttempt(attempt, maxAttempts int, transport string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active {
		h.disruptedAt = h.clock()
		h.active = true
		h.notificationSent = false
		h.armNotifyLocked()
	}

	elapsed := h.clock().Sub(h.disruptedAt)
	if elapsed >= h.cfg.NotificationTimeout && !h.notificationSent {
		h.emitNotification("remote-relay", "Link disrupted, attempting reconnect...")
		h.notificationSent = true
	}

	if !h.isTTY || !h.cfg.Enabled {
		return
	}

	proto := strings.ToUpper(transport)
	if proto == "" {
		proto = "TCP"
	}

	var attemptStr string
	if maxAttempts > 0 {
		attemptStr = fmt.Sprintf("attempt %d/%d, %.1fs elapsed", attempt, maxAttempts, elapsed.Seconds())
	} else {
		attemptStr = fmt.Sprintf("attempt %d, %.1fs elapsed", attempt, elapsed.Seconds())
	}

	msg := fmt.Sprintf("%sLink disrupted. Reconnecting via %s... (%s)", h.tag("warning"), proto, attemptStr)
	h.renderLine(msg, false)
}

// OnRestored notifies the user that the connection has resumed successfully.
func (h *HUD) OnRestored(transport string, bufferedBytes int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active {
		return
	}

	elapsed := h.clock().Sub(h.disruptedAt)
	if h.notificationSent {
		protoUpper := strings.ToUpper(transport)
		if protoUpper == "" {
			protoUpper = "TCP"
		}
		h.emitNotification("remote-relay", fmt.Sprintf("Link restored via %s.", protoUpper))
	}

	if !h.isTTY || !h.cfg.Enabled {
		h.stopNotifyLocked()
		return
	}

	proto := strings.ToUpper(transport)
	if proto == "" {
		proto = "TCP"
	}

	var msg string
	if bufferedBytes > 0 {
		msg = fmt.Sprintf("%sLink restored via %s in %.1fs (resumed %s buffered).",
			h.tag("success"), proto, elapsed.Seconds(), formatBytes(bufferedBytes))
	} else {
		msg = fmt.Sprintf("%sLink restored via %s in %.1fs.",
			h.tag("success"), proto, elapsed.Seconds())
	}

	h.renderLine(msg, true)
	h.stopNotifyLocked()
}

// OnFailed prints a final failure line when reconnection is permanently exhausted.
func (h *HUD) OnFailed(reason string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active {
		return
	}

	elapsed := h.clock().Sub(h.disruptedAt)
	h.emitNotification("remote-relay", fmt.Sprintf("Reconnection failed: %s", reason))

	if !h.isTTY || !h.cfg.Enabled {
		h.stopNotifyLocked()
		return
	}

	msg := fmt.Sprintf("%sReconnection failed: %s (after %.1fs).",
		h.tag("error"), reason, elapsed.Seconds())
	h.renderLine(msg, true)
	h.stopNotifyLocked()
}

// OnAborted prints a cancellation or fatal termination line.
func (h *HUD) OnAborted(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active {
		return
	}

	if !h.isTTY || !h.cfg.Enabled {
		h.stopNotifyLocked()
		return
	}

	msg := fmt.Sprintf("%sReconnection aborted: %s.", h.tag("error"), reason)
	h.renderLine(msg, true)
	h.stopNotifyLocked()
}

// Clear erases the in-progress HUD line if active, leaving the terminal clean.
func (h *HUD) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.active || !h.isTTY || !h.cfg.Enabled {
		h.stopNotifyLocked()
		return
	}

	_, _ = fmt.Fprint(h.out, "\r\033[K")
	h.stopNotifyLocked()
}

// armNotifyLocked schedules the prolonged-outage notification for the
// disruption that started at h.disruptedAt.
func (h *HUD) armNotifyLocked() {
	if h.notifyTimer != nil {
		h.notifyTimer.Stop()
		h.notifyTimer = nil
	}
	h.notifyGen++
	if !h.isTTY || !h.cfg.Enabled {
		return
	}
	gen := h.notifyGen
	h.notifyTimer = time.AfterFunc(h.cfg.NotificationTimeout, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.notifyGen != gen || !h.active || h.notificationSent {
			return
		}
		h.emitNotification("remote-relay", "Link disrupted, attempting reconnect...")
		h.notificationSent = true
	})
}

// stopNotifyLocked ends the current disruption.
func (h *HUD) stopNotifyLocked() {
	h.active = false
	h.notifyGen++
	if h.notifyTimer != nil {
		h.notifyTimer.Stop()
		h.notifyTimer = nil
	}
}

// renderLine renders a line to the output stream.
func (h *HUD) renderLine(msg string, finish bool) {
	width := h.getTerminalWidth()
	if width > 0 {
		msg = truncateToWidth(msg, width)
	}

	var line string
	if finish {
		line = fmt.Sprintf("\r\033[K%s\n", msg)
	} else {
		line = fmt.Sprintf("\r\033[K%s", msg)
	}

	_, _ = fmt.Fprint(h.out, line)
}

// emitNotification writes OSC 9 and OSC 777 desktop notification escape sequences to stderr.
func (h *HUD) emitNotification(title, msg string) {
	if !h.isTTY || !h.cfg.Enabled {
		return
	}
	// OSC 9 (iTerm2, WezTerm, ConEmu)
	_, _ = fmt.Fprintf(h.out, "\033]9;%s: %s\007", title, msg)
	// OSC 777 (Ghostty, Alacritty, rxvt-unicode)
	_, _ = fmt.Fprintf(h.out, "\033]777;notify;%s;%s\007", title, msg)
}

// getTerminalWidth queries the current width of the terminal.
func (h *HUD) getTerminalWidth() int {
	if h.cfg.WidthFn != nil {
		return h.cfg.WidthFn()
	}
	if f, ok := h.out.(*os.File); ok {
		if w, _, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return w
		}
	}
	return 0
}

// formatBytes formats a byte count into a human-readable string.
func formatBytes(b int) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	kb := float64(b) / 1024.0
	if kb < 1024.0 {
		return fmt.Sprintf("%.1f KiB", kb)
	}
	mb := kb / 1024.0
	if mb < 1024.0 {
		return fmt.Sprintf("%.1f MiB", mb)
	}
	gb := mb / 1024.0
	return fmt.Sprintf("%.1f GiB", gb)
}

// visibleLen calculates the visible rune length of a string, ignoring ANSI escape sequences.
func visibleLen(s string) int {
	inEscape := false
	count := 0
	for i := 0; i < len(s); {
		if !inEscape && s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			inEscape = true
			i += 2
			continue
		}
		if inEscape {
			// ANSI sequences end at a letter
			c := s[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == 'm' || c == 'K' {
				inEscape = false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != '\r' && r != '\n' && r != '\a' {
			count++
		}
		i += size
	}
	return count
}

// truncateToWidth truncates a string containing ANSI color escapes so that its visible
// character length does not exceed maxWidth, appending "..." before resetting colors.
func truncateToWidth(s string, maxWidth int) string {
	if maxWidth <= 0 || visibleLen(s) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}

	target := maxWidth - 3
	var b strings.Builder
	inEscape := false
	visCount := 0

	for i := 0; i < len(s); {
		if !inEscape && s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			inEscape = true
			b.WriteByte(s[i])
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if inEscape {
			c := s[i]
			b.WriteByte(c)
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == 'm' || c == 'K' {
				inEscape = false
			}
			i++
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if visCount >= target {
			break
		}
		b.WriteRune(r)
		visCount++
		i += size
	}

	b.WriteString("...\033[0m")
	return b.String()
}
