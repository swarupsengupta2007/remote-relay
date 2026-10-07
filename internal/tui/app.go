package tui

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

// AppOptions contains CLI options for relay top and relay stats.
type AppOptions struct {
	Endpoint string
	Interval time.Duration
	Color    string
	Batch    bool
}

// DefaultAppOptions returns standard options.
func DefaultAppOptions() AppOptions {
	return AppOptions{
		Endpoint: "http://127.0.0.1:9090/metrics",
		Interval: 1 * time.Second,
		Color:    "auto",
		Batch:    false,
	}
}

// NormalizeEndpoint ensures the endpoint has a scheme.
func NormalizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "http://127.0.0.1:9090/metrics"
	}
	if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
		ep = "http://" + ep
	}
	if !strings.Contains(ep[strings.Index(ep, "//")+2:], "/") {
		ep = ep + "/metrics"
	}
	return ep
}

// RunStats performs a one-shot metrics fetch and prints the formatted summary.
func RunStats(opts AppOptions, out io.Writer) error {
	opts.Endpoint = NormalizeEndpoint(opts.Endpoint)
	snap, err := ScrapeSnapshot(opts.Endpoint)
	if err != nil {
		return fmt.Errorf("scrape %s: %w", opts.Endpoint, err)
	}

	report := FormatStats(snap, opts.Endpoint)
	_, _ = fmt.Fprint(out, report)
	return nil
}

// ScrapeSnapshot fetches metrics from the endpoint and parses them.
func ScrapeSnapshot(endpoint string) (*Snapshot, error) {
	start := time.Now()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	snap, err := ParsePrometheus(data)
	if err != nil {
		return nil, err
	}
	snap.ScrapeDuration = time.Since(start)
	return snap, nil
}

// RunApp runs the interactive TUI or falls back to batch mode if non-TTY.
func RunApp(opts AppOptions) error {
	opts.Endpoint = NormalizeEndpoint(opts.Endpoint)
	if opts.Interval <= 0 {
		opts.Interval = 1 * time.Second
	}

	isTTY := term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
	if os.Getenv("TERM") == "dumb" {
		isTTY = false
	}

	if opts.Batch || !isTTY {
		return RunStats(opts, os.Stdout)
	}

	return runInteractive(opts)
}

func runInteractive(opts AppOptions) error {
	stdinFd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("terminal raw mode: %w", err)
	}

	// Alt-screen buffer and hide cursor
	os.Stdout.WriteString("\033[?1049h\033[?25l\033[2J")

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			os.Stdout.WriteString("\033[?25h\033[?1049l")
			_ = term.Restore(stdinFd, oldState)
		})
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, append([]os.Signal{syscall.SIGINT, syscall.SIGTERM}, resizeSignals...)...)
	defer signal.Stop(sigCh)

	cfg := DashboardConfig{
		Endpoint: opts.Endpoint,
		Interval: opts.Interval,
		Color:    opts.Color,
		Paused:   false,
	}
	renderer := NewRenderer(cfg)
	tracker := NewRateTracker(60)

	keyCh := make(chan rune, 16)
	go func() {
		buf := make([]byte, 16)
		for {
			n, rerr := os.Stdin.Read(buf)
			if rerr != nil || n == 0 {
				return
			}
			for i := 0; i < n; i++ {
				b := buf[i]
				keyCh <- rune(b)
			}
		}
	}()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	refreshCh := make(chan struct{}, 1)
	refreshCh <- struct{}{} // Initial scrape immediately

	var lastSnap *Snapshot
	var lastErr error

	render := func() {
		w, _, gerr := term.GetSize(int(os.Stdout.Fd()))
		if gerr != nil || w <= 0 {
			w = 80
		}
		frame := renderer.RenderFrame(lastSnap, tracker, w, lastErr)
		os.Stdout.WriteString("\033[H\033[2J" + frame)
	}

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				return nil
			default: // terminal resize
				render()
			}

		case r := <-keyCh:
			switch r {
			case 'q', 'Q', 27, 3: // 'q', 'Q', Esc, Ctrl+C
				return nil
			case 'r', 'R':
				select {
				case refreshCh <- struct{}{}:
				default:
				}
			case 'p', 'P':
				cfg.Paused = !cfg.Paused
				renderer = NewRenderer(cfg)
				render()
			case '+', '=':
				cfg.Interval += 500 * time.Millisecond
				ticker.Reset(cfg.Interval)
				renderer = NewRenderer(cfg)
				render()
			case '-', '_':
				if cfg.Interval > 500*time.Millisecond {
					cfg.Interval -= 500 * time.Millisecond
					ticker.Reset(cfg.Interval)
					renderer = NewRenderer(cfg)
					render()
				}
			case '1':
				cfg.Interval = 1 * time.Second
				ticker.Reset(cfg.Interval)
				renderer = NewRenderer(cfg)
				render()
			case '2':
				cfg.Interval = 2 * time.Second
				ticker.Reset(cfg.Interval)
				renderer = NewRenderer(cfg)
				render()
			case '5':
				cfg.Interval = 5 * time.Second
				ticker.Reset(cfg.Interval)
				renderer = NewRenderer(cfg)
				render()
			}

		case <-ticker.C:
			if !cfg.Paused {
				select {
				case refreshCh <- struct{}{}:
				default:
				}
			}

		case <-refreshCh:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			snap, serr := scrapeWithContext(ctx, cfg.Endpoint)
			cancel()

			lastErr = serr
			if serr == nil && snap != nil {
				lastSnap = snap
				tracker.Update(snap.Timestamp, snap.BytesUpTotal, snap.BytesDownTotal)
			}
			render()
		}
	}
}

func scrapeWithContext(ctx context.Context, endpoint string) (*Snapshot, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	snap, err := ParsePrometheus(data)
	if err != nil {
		return nil, err
	}
	snap.ScrapeDuration = time.Since(start)
	return snap, nil
}
