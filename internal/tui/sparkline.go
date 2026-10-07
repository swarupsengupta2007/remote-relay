package tui

import (
	"strings"
	"sync"
	"time"
)

var sparkRunes = []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// RenderSparkline renders a slice of float64 values as an ANSI Unicode sparkline string.
func RenderSparkline(values []float64, maxLen int) string {
	if len(values) == 0 || maxLen <= 0 {
		return ""
	}

	if len(values) > maxLen {
		values = values[len(values)-maxLen:]
	}

	minVal := values[0]
	maxVal := values[0]
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	span := maxVal - minVal
	var sb strings.Builder
	sb.Grow(len(values))

	for _, v := range values {
		if span <= 0 {
			sb.WriteRune(sparkRunes[0])
			continue
		}
		normalized := (v - minVal) / span
		idx := int(normalized * float64(len(sparkRunes)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		sb.WriteRune(sparkRunes[idx])
	}

	return sb.String()
}

// RateTracker tracks moving throughput rates and sparkline history.
type RateTracker struct {
	mu           sync.Mutex
	maxSamples   int
	lastTime     time.Time
	lastUpBytes  uint64
	lastDownBytes uint64

	currentUpRate   float64
	currentDownRate float64

	upRateHistory   []float64
	downRateHistory []float64
}

// NewRateTracker creates a new RateTracker retaining up to maxSamples history.
func NewRateTracker(maxSamples int) *RateTracker {
	if maxSamples <= 0 {
		maxSamples = 30
	}
	return &RateTracker{
		maxSamples:      maxSamples,
		upRateHistory:   make([]float64, 0, maxSamples),
		downRateHistory: make([]float64, 0, maxSamples),
	}
}

// Update records new cumulative totals and computes the instant rate per second.
func (rt *RateTracker) Update(now time.Time, upBytes, downBytes uint64) (upRate, downRate float64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.lastTime.IsZero() {
		rt.lastTime = now
		rt.lastUpBytes = upBytes
		rt.lastDownBytes = downBytes
		return 0, 0
	}

	deltaSec := now.Sub(rt.lastTime).Seconds()
	if deltaSec <= 0.001 {
		return rt.currentUpRate, rt.currentDownRate
	}

	var deltaUp uint64
	if upBytes >= rt.lastUpBytes {
		deltaUp = upBytes - rt.lastUpBytes
	}
	var deltaDown uint64
	if downBytes >= rt.lastDownBytes {
		deltaDown = downBytes - rt.lastDownBytes
	}

	rt.currentUpRate = float64(deltaUp) / deltaSec
	rt.currentDownRate = float64(deltaDown) / deltaSec

	rt.upRateHistory = append(rt.upRateHistory, rt.currentUpRate)
	if len(rt.upRateHistory) > rt.maxSamples {
		rt.upRateHistory = rt.upRateHistory[1:]
	}

	rt.downRateHistory = append(rt.downRateHistory, rt.currentDownRate)
	if len(rt.downRateHistory) > rt.maxSamples {
		rt.downRateHistory = rt.downRateHistory[1:]
	}

	rt.lastTime = now
	rt.lastUpBytes = upBytes
	rt.lastDownBytes = downBytes

	return rt.currentUpRate, rt.currentDownRate
}

// History returns copies of the rate histories.
func (rt *RateTracker) History() (up, down []float64, curUp, curDown float64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	upCopy := make([]float64, len(rt.upRateHistory))
	copy(upCopy, rt.upRateHistory)
	downCopy := make([]float64, len(rt.downRateHistory))
	copy(downCopy, rt.downRateHistory)

	return upCopy, downCopy, rt.currentUpRate, rt.currentDownRate
}
