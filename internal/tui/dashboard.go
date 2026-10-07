package tui

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// ANSI color escapes
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	blue      = "\033[34m"
	magenta   = "\033[35m"
	cyan      = "\033[36m"
	white     = "\033[37m"
	bgRed     = "\033[41m"
	bgGreen   = "\033[42m"
	bgYellow  = "\033[43m"
	bgBlue    = "\033[44m"
)

// DashboardConfig configures the dashboard rendering.
type DashboardConfig struct {
	Endpoint string
	Interval time.Duration
	Color    string // "auto", "always", "never"
	Paused   bool
}

// Renderer renders terminal UI frames.
type Renderer struct {
	cfg     DashboardConfig
	noColor bool
}

// NewRenderer creates a new Renderer.
func NewRenderer(cfg DashboardConfig) *Renderer {
	noColor := false
	if cfg.Color == "never" || os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	return &Renderer{
		cfg:     cfg,
		noColor: noColor,
	}
}

func (r *Renderer) c(colorCode string, text string) string {
	if r.noColor {
		return text
	}
	return colorCode + text + reset
}

// FormatBytes formats a byte count into KiB, MiB, GiB string.
func FormatBytes(b float64) string {
	const (
		kib = 1024.0
		mib = kib * 1024.0
		gib = mib * 1024.0
	)
	if b < kib {
		return fmt.Sprintf("%.0f B", b)
	} else if b < mib {
		return fmt.Sprintf("%.1f KiB", b/kib)
	} else if b < gib {
		return fmt.Sprintf("%.2f MiB", b/mib)
	}
	return fmt.Sprintf("%.2f GiB", b/gib)
}

// FormatRate formats bytes/sec into KiB/s, MiB/s string.
func FormatRate(r float64) string {
	return FormatBytes(r) + "/s"
}

// FormatDuration formats duration in a friendly format.
func FormatDuration(sec float64) string {
	d := time.Duration(sec * float64(time.Second))
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %02ds", m, s)
	}
	return fmt.Sprintf("%.1fs", sec)
}

// RenderFrame generates a complete dashboard frame string.
func (r *Renderer) RenderFrame(snap *Snapshot, tracker *RateTracker, termWidth int, err error) string {
	if termWidth <= 0 {
		termWidth = 80
	}
	if termWidth > 120 {
		termWidth = 120
	}

	var sb strings.Builder

	// Top status header
	r.renderHeader(&sb, snap, termWidth, err)

	if err != nil {
		r.renderErrorBox(&sb, termWidth, err)
		r.renderFooter(&sb, termWidth)
		return sb.String()
	}

	// 1. Transport & Session breakdown
	r.renderTransports(&sb, snap, termWidth)

	// 2. Throughput & Sparklines
	r.renderThroughput(&sb, snap, tracker, termWidth)

	// 3. Ring Buffer & Memory Usage
	r.renderBuffers(&sb, snap, termWidth)

	// 4. Resiliency, BFD & RBAC
	r.renderResiliency(&sb, snap, termWidth)

	// Footer keybindings
	r.renderFooter(&sb, termWidth)

	return sb.String()
}

func (r *Renderer) renderHeader(sb *strings.Builder, snap *Snapshot, width int, err error) {
	status := r.c(bold+green, "CONNECTED (200 OK)")
	latencyStr := "0.0ms"
	if snap != nil {
		latencyStr = fmt.Sprintf("%.1fms", float64(snap.ScrapeDuration.Microseconds())/1000.0)
	}
	if err != nil {
		status = r.c(bold+red, "DISCONNECTED")
	}

	pausedStr := r.c(green, "[LIVE]")
	if r.cfg.Paused {
		pausedStr = r.c(yellow+bold, "[PAUSED]")
	}

	title := fmt.Sprintf(" REMOTE-RELAY TOP  %s ", pausedStr)
	sb.WriteString(r.c(bold+cyan, "┌─") + r.c(bold, title) + r.c(bold+cyan, strings.Repeat("─", max(2, width-len(title)-4))+"┐\n"))

	line1 := fmt.Sprintf("│ Target: %-32s Status: %-20s Latency: %-7s │\n", r.cfg.Endpoint, status, latencyStr)
	sb.WriteString(line1)

	uptimeStr := "n/a"
	totalSessions := 0
	heldSessions := 0
	standbyConns := 0
	if snap != nil {
		uptimeStr = FormatDuration(snap.UptimeSeconds)
		totalSessions = snap.SessionsTotal
		heldSessions = snap.SessionsHeld
		standbyConns = snap.StandbyConns
	}

	line2 := fmt.Sprintf("│ Uptime: %-12s Live Sessions: %-5d Held: %-4d Standby: %-4d Refresh: %-5s │\n",
		uptimeStr, totalSessions, heldSessions, standbyConns, r.cfg.Interval.String())
	sb.WriteString(line2)

	sb.WriteString(r.c(bold+cyan, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderErrorBox(sb *strings.Builder, width int, err error) {
	sb.WriteString(r.c(bold+red, "┌─ CONNECTION WARNING "+strings.Repeat("─", max(2, width-22))+"┐\n"))
	errMsg := err.Error()
	if len(errMsg) > width-6 {
		errMsg = errMsg[:width-6]
	}
	sb.WriteString(fmt.Sprintf("│ %s\n", r.c(red+bold, fmt.Sprintf("%-*s", width-4, "Endpoint unreachable: "+errMsg))+" │"))
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, "Retrying automatically on next tick... (press 'r' to force refresh, 'q' to quit)"))
	sb.WriteString(r.c(bold+red, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderTransports(sb *strings.Builder, snap *Snapshot, width int) {
	sb.WriteString(r.c(bold+blue, "┌─ Active Transports & Multiplexing "+strings.Repeat("─", max(2, width-36))+"┐\n"))

	total := snap.SessionsTotal
	barWidth := max(10, width-24)

	var tcpRatio, kcpRatio, quicRatio, wsRatio float64
	if total > 0 {
		tcpRatio = float64(snap.SessionsTCP) / float64(total)
		kcpRatio = float64(snap.SessionsKCP) / float64(total)
		quicRatio = float64(snap.SessionsQUIC) / float64(total)
		wsRatio = float64(snap.SessionsWS) / float64(total)
	}

	tcpLen := int(math.Round(tcpRatio * float64(barWidth)))
	kcpLen := int(math.Round(kcpRatio * float64(barWidth)))
	quicLen := int(math.Round(quicRatio * float64(barWidth)))
	wsLen := int(math.Round(wsRatio * float64(barWidth)))

	for tcpLen+kcpLen+quicLen+wsLen > barWidth {
		if tcpLen > 0 {
			tcpLen--
		} else if quicLen > 0 {
			quicLen--
		} else if kcpLen > 0 {
			kcpLen--
		} else if wsLen > 0 {
			wsLen--
		}
	}
	rem := barWidth - (tcpLen + kcpLen + quicLen + wsLen)
	if rem < 0 {
		rem = 0
	}

	visualBar := r.c(green, strings.Repeat("█", tcpLen)) +
		r.c(magenta, strings.Repeat("█", quicLen)) +
		r.c(yellow, strings.Repeat("█", kcpLen)) +
		r.c(cyan, strings.Repeat("█", wsLen)) +
		r.c(dim, strings.Repeat("░", rem))

	sb.WriteString(fmt.Sprintf("│ Sessions: [%s] %-4d total │\n", visualBar, total))

	statsLine := fmt.Sprintf("TCP: %s  QUIC: %s  KCP: %s  WS: %s | SOCKS: %d  Chain Hops: %d",
		r.c(green, fmt.Sprintf("%d", snap.SessionsTCP)),
		r.c(magenta, fmt.Sprintf("%d", snap.SessionsQUIC)),
		r.c(yellow, fmt.Sprintf("%d", snap.SessionsKCP)),
		r.c(cyan, fmt.Sprintf("%d", snap.SessionsWS)),
		snap.SocksStreams, snap.ChainHopsTotal,
	)
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, statsLine))
	sb.WriteString(r.c(bold+blue, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderThroughput(sb *strings.Builder, snap *Snapshot, tracker *RateTracker, width int) {
	sb.WriteString(r.c(bold+magenta, "┌─ Throughput & Bandwidth Rates "+strings.Repeat("─", max(2, width-32))+"┐\n"))

	sparkLen := max(10, min(30, width-50))
	var upHist, downHist []float64
	var curUp, curDown float64
	if tracker != nil {
		upHist, downHist, curUp, curDown = tracker.History()
	}

	upSpark := RenderSparkline(upHist, sparkLen)
	downSpark := RenderSparkline(downHist, sparkLen)

	upRateStr := FormatRate(curUp)
	downRateStr := FormatRate(curDown)

	upTotalStr := FormatBytes(float64(snap.BytesUpTotal))
	downTotalStr := FormatBytes(float64(snap.BytesDownTotal))

	sb.WriteString(fmt.Sprintf("│ ▲ Upload:   %-11s [%-30s] (Total: %-9s) │\n",
		r.c(cyan+bold, upRateStr), r.c(cyan, upSpark), upTotalStr))
	sb.WriteString(fmt.Sprintf("│ ▼ Download: %-11s [%-30s] (Total: %-9s) │\n",
		r.c(green+bold, downRateStr), r.c(green, downSpark), downTotalStr))

	if snap.SpliceCalls > 0 {
		spliceLine := fmt.Sprintf("Kernel splice(2): %s in / %s out (%d calls)",
			FormatBytes(float64(snap.SplicedBytesIn)),
			FormatBytes(float64(snap.SplicedBytesOut)),
			snap.SpliceCalls,
		)
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, spliceLine))
	}

	sb.WriteString(r.c(bold+magenta, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderBuffers(sb *strings.Builder, snap *Snapshot, width int) {
	sb.WriteString(r.c(bold+yellow, "┌─ Memory & Ring Buffer Utilization "+strings.Repeat("─", max(2, width-36))+"┐\n"))

	ratio := snap.BufferUtilRatio
	pct := ratio * 100.0
	barWidth := max(10, width-46)
	filled := int(math.Round(ratio * float64(barWidth)))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	empty := barWidth - filled

	color := green
	status := "NORMAL"
	if pct >= 85.0 {
		color = red
		status = r.c(red+bold, "ALERT: HIGH BACKPRESSURE")
	} else if pct >= 70.0 {
		color = yellow
		status = r.c(yellow, "ELEVATED")
	}

	bar := r.c(color, strings.Repeat("█", filled)) + r.c(dim, strings.Repeat("░", empty))

	usedStr := FormatBytes(float64(snap.BufferUsedBytes))
	totalStr := FormatBytes(float64(snap.BufferTotalBytes))

	sb.WriteString(fmt.Sprintf("│ Buffer: [%s] %-5.1f%% (%s / %s) │\n",
		bar, pct, usedStr, totalStr))
	sb.WriteString(fmt.Sprintf("│ State:  %-*s │\n", width-12, status))
	sb.WriteString(r.c(bold+yellow, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderResiliency(sb *strings.Builder, snap *Snapshot, width int) {
	sb.WriteString(r.c(bold+green, "┌─ Reliability, Resiliency & Security "+strings.Repeat("─", max(2, width-38))+"┐\n"))

	meanReconnect := "0ms"
	if snap.ReconnectCount > 0 && snap.ReconnectDurationSum > 0 {
		meanReconnect = fmt.Sprintf("%.0fms", (snap.ReconnectDurationSum/float64(snap.ReconnectCount))*1000.0)
	}

	meanHeld := "0ms"
	if snap.HeldCount > 0 && snap.HeldDurationSum > 0 {
		meanHeld = fmt.Sprintf("%.0fms", (snap.HeldDurationSum/float64(snap.HeldCount))*1000.0)
	}

	reconLine := fmt.Sprintf("Reconnections: %d ok / %s fail (mean: %s) | Held Mean: %s",
		snap.ReconnectSuccess,
		r.c(red, fmt.Sprintf("%d", snap.ReconnectFailure)),
		meanReconnect, meanHeld,
	)
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, reconLine))

	resLine := fmt.Sprintf("BFD Dead-Peers: %s  | Accepts: %d  Refused: %d",
		r.c(yellow, fmt.Sprintf("%d", snap.BFDDeadPeers)),
		snap.AcceptsTotal, snap.RefusedTotal,
	)
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, resLine))

	rbacSummary := "None"
	if snap.TotalRBACRejects > 0 {
		var parts []string
		for reason, count := range snap.RBACRejections {
			parts = append(parts, fmt.Sprintf("%s: %d", reason, count))
		}
		sort.Strings(parts)
		rbacSummary = strings.Join(parts, ", ")
	}
	rbacLine := fmt.Sprintf("RBAC Rejections: %s (%s)",
		r.c(red, fmt.Sprintf("%d", snap.TotalRBACRejects)),
		rbacSummary,
	)
	sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, rbacLine))

	if snap.KCPSegsOut > 0 || snap.KCPSegsRetrans > 0 || snap.KCPSegsLost > 0 {
		kcpLine := fmt.Sprintf("KCP SNMP: out %d, retrans %d, lost %d, snd_queue %d",
			snap.KCPSegsOut, snap.KCPSegsRetrans, snap.KCPSegsLost, snap.KCPSndQueue)
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", width-4, kcpLine))
	}

	sb.WriteString(r.c(bold+green, "└"+strings.Repeat("─", width-2)+"┘\n"))
}

func (r *Renderer) renderFooter(sb *strings.Builder, width int) {
	keys := " [q/Esc] Quit  [r] Refresh  [p] Pause  [1/2/5] Rate  [+/-] Interval "
	sb.WriteString(r.c(dim, fmt.Sprintf("%-*s\n", width, keys)))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
