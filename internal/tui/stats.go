package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatStats formats a snapshot as a clean, structured text report.
func FormatStats(snap *Snapshot, endpoint string) string {
	var sb strings.Builder

	sb.WriteString("REMOTE-RELAY METRICS SNAPSHOT\n")
	sb.WriteString(strings.Repeat("=", 32) + "\n")
	sb.WriteString(fmt.Sprintf("Target:       %s\n", endpoint))
	sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", snap.Timestamp.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Uptime:       %s\n", FormatDuration(snap.UptimeSeconds)))
	sb.WriteString("\n")

	sb.WriteString("ACTIVE SESSIONS & TRANSPORTS:\n")
	sb.WriteString(fmt.Sprintf("  Total Live:     %d\n", snap.SessionsTotal))
	sb.WriteString(fmt.Sprintf("  Breakdown:      TCP: %d, QUIC: %d, KCP: %d, WS: %d\n",
		snap.SessionsTCP, snap.SessionsQUIC, snap.SessionsKCP, snap.SessionsWS))
	sb.WriteString(fmt.Sprintf("  Held Sessions:  %d\n", snap.SessionsHeld))
	sb.WriteString(fmt.Sprintf("  Standby Conns:  %d\n", snap.StandbyConns))
	sb.WriteString(fmt.Sprintf("  SOCKS5 Streams: %d\n", snap.SocksStreams))
	sb.WriteString(fmt.Sprintf("  Chain Hops:     %d\n", snap.ChainHopsTotal))
	sb.WriteString("\n")

	sb.WriteString("MEMORY & BUFFER OCCUPANCY:\n")
	pct := snap.BufferUtilRatio * 100.0
	status := "NORMAL"
	if pct >= 85.0 {
		status = "ALERT: HIGH BACKPRESSURE"
	} else if pct >= 70.0 {
		status = "ELEVATED"
	}
	sb.WriteString(fmt.Sprintf("  Utilization:    %.1f%% (%s / %s)\n",
		pct, FormatBytes(float64(snap.BufferUsedBytes)), FormatBytes(float64(snap.BufferTotalBytes))))
	sb.WriteString(fmt.Sprintf("  Buffer State:   %s\n", status))
	sb.WriteString("\n")

	sb.WriteString("THROUGHPUT COUNTERS:\n")
	sb.WriteString(fmt.Sprintf("  Upload Total:   %s (%d bytes)\n", FormatBytes(float64(snap.BytesUpTotal)), snap.BytesUpTotal))
	sb.WriteString(fmt.Sprintf("  Download Total: %s (%d bytes)\n", FormatBytes(float64(snap.BytesDownTotal)), snap.BytesDownTotal))
	if snap.SpliceCalls > 0 {
		sb.WriteString(fmt.Sprintf("  Kernel Splice:  %s in / %s out (%d calls)\n",
			FormatBytes(float64(snap.SplicedBytesIn)),
			FormatBytes(float64(snap.SplicedBytesOut)),
			snap.SpliceCalls))
	}
	sb.WriteString("\n")

	sb.WriteString("RELIABILITY & RESILIENCY:\n")
	meanReconnect := "0ms"
	if snap.ReconnectCount > 0 && snap.ReconnectDurationSum > 0 {
		meanReconnect = fmt.Sprintf("%.0fms", (snap.ReconnectDurationSum/float64(snap.ReconnectCount))*1000.0)
	}
	sb.WriteString(fmt.Sprintf("  Accepted Conns: %d\n", snap.AcceptsTotal))
	sb.WriteString(fmt.Sprintf("  Refused Conns:  %d\n", snap.RefusedTotal))
	sb.WriteString(fmt.Sprintf("  Reconnections:  %d success / %d failure (mean: %s)\n",
		snap.ReconnectSuccess, snap.ReconnectFailure, meanReconnect))
	sb.WriteString(fmt.Sprintf("  BFD Dead Peers: %d\n", snap.BFDDeadPeers))

	rbacSummary := "none"
	if snap.TotalRBACRejects > 0 {
		var parts []string
		for reason, count := range snap.RBACRejections {
			parts = append(parts, fmt.Sprintf("%s: %d", reason, count))
		}
		sort.Strings(parts)
		rbacSummary = strings.Join(parts, ", ")
	}
	sb.WriteString(fmt.Sprintf("  RBAC Rejects:   %d (%s)\n", snap.TotalRBACRejects, rbacSummary))

	if snap.KCPSegsOut > 0 || snap.KCPSegsRetrans > 0 || snap.KCPSegsLost > 0 {
		sb.WriteString(fmt.Sprintf("  KCP SNMP:       out %d, retrans %d, lost %d, snd_queue %d\n",
			snap.KCPSegsOut, snap.KCPSegsRetrans, snap.KCPSegsLost, snap.KCPSndQueue))
	}

	return sb.String()
}
