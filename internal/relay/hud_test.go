package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func truePtr() *bool {
	b := true
	return &b
}

func falsePtr() *bool {
	b := false
	return &b
}

// errorWriter simulates a broken terminal output stream (e.g. broken pipe / EPIPE).
type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("broken pipe")
}

func TestHUD_HappyPath_QuickResume(t *testing.T) {
	var buf bytes.Buffer
	currTime := time.Date(2026, 9, 25, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	hud := NewHUD(HUDConfig{
		Enabled:             true,
		Out:                 &buf,
		IsTerminal:          truePtr(),
		NotificationTimeout: 5 * time.Second,
		Clock:               clock,
	})

	hud.OnDisrupted("quic")
	out1 := buf.String()
	if !strings.Contains(out1, "Link disrupted. Reconnecting via QUIC...") {
		t.Fatalf("expected initial disruption line, got %q", out1)
	}
	if !strings.HasPrefix(out1, "\r\033[K") {
		t.Fatalf("expected carriage return and line clear prefix, got %q", out1)
	}

	// Advance time by 400ms
	currTime = currTime.Add(400 * time.Millisecond)
	hud.OnAttempt(1, 8, "quic", nil)
	out2 := buf.String()
	if !strings.Contains(out2, "(attempt 1/8, 0.4s elapsed)") {
		t.Fatalf("expected attempt line, got %q", out2)
	}

	// Resume after 800ms with 35,020 bytes buffered (34.2 KiB)
	currTime = currTime.Add(400 * time.Millisecond)
	hud.OnRestored("quic", 35020)
	out3 := buf.String()

	if !strings.Contains(out3, "Link restored via QUIC in 0.8s (resumed 34.2 KiB buffered).\n") {
		t.Fatalf("expected restored line with buffered bytes, got %q", out3)
	}
	if !strings.HasSuffix(out3, "\n") {
		t.Fatalf("expected final newline on restore, got %q", out3)
	}

	// Should NOT have sent desktop notification (elapsed < 5s)
	if strings.Contains(out3, "\033]9;") || strings.Contains(out3, "\033]777;") {
		t.Fatalf("should not emit desktop notification for short outage (<5s), got %q", out3)
	}
}

func TestHUD_HappyPath_RestoredZeroBytes(t *testing.T) {
	var buf bytes.Buffer
	currTime := time.Date(2026, 9, 25, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	hud := NewHUD(HUDConfig{
		Enabled:             true,
		Out:                 &buf,
		IsTerminal:          truePtr(),
		NotificationTimeout: 5 * time.Second,
		Clock:               clock,
	})

	hud.OnDisrupted("tcp")
	currTime = currTime.Add(1200 * time.Millisecond)
	hud.OnRestored("tcp", 0)

	out := buf.String()
	if !strings.Contains(out, "Link restored via TCP in 1.2s.\n") {
		t.Fatalf("expected clean restore without buffered bytes clause, got %q", out)
	}
	if strings.Contains(out, "buffered") {
		t.Fatalf("should not mention buffered when 0 bytes, got %q", out)
	}
}

func TestHUD_HappyPath_ProlongedOutageNotifications(t *testing.T) {
	var buf bytes.Buffer
	currTime := time.Date(2026, 9, 25, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	hud := NewHUD(HUDConfig{
		Enabled:             true,
		Out:                 &buf,
		IsTerminal:          truePtr(),
		NotificationTimeout: 5 * time.Second,
		Clock:               clock,
	})

	hud.OnDisrupted("kcp")

	// 2s elapsed - no notification yet
	currTime = currTime.Add(2 * time.Second)
	hud.OnAttempt(1, 8, "kcp", nil)
	if strings.Contains(buf.String(), "\033]9;") {
		t.Fatal("unexpected notification before 5s")
	}

	// 5.5s elapsed - notification triggers!
	currTime = currTime.Add(3500 * time.Millisecond)
	hud.OnAttempt(2, 8, "kcp", nil)
	out := buf.String()
	if !strings.Contains(out, "\033]9;remote-relay: Link disrupted, attempting reconnect...\007") {
		t.Fatalf("expected OSC 9 notification, got %q", out)
	}
	if !strings.Contains(out, "\033]777;notify;remote-relay;Link disrupted, attempting reconnect...\007") {
		t.Fatalf("expected OSC 777 notification, got %q", out)
	}

	// Next attempt at 7.0s: verify notification is NOT spammed again
	buf.Reset()
	currTime = currTime.Add(1500 * time.Millisecond)
	hud.OnAttempt(3, 8, "kcp", nil)
	if strings.Contains(buf.String(), "\033]9;") || strings.Contains(buf.String(), "\033]777;") {
		t.Fatalf("notification should be debounced and not repeated on every attempt, got %q", buf.String())
	}

	// Restored after prolonged outage: sends recovery notification
	buf.Reset()
	currTime = currTime.Add(1 * time.Second)
	hud.OnRestored("kcp", 1024)
	outRestored := buf.String()
	if !strings.Contains(outRestored, "\033]9;remote-relay: Link restored via KCP.\007") {
		t.Fatalf("expected recovery notification after prolonged outage, got %q", outRestored)
	}
	if !strings.Contains(outRestored, "Link restored via KCP in 8.0s (resumed 1.0 KiB buffered).\n") {
		t.Fatalf("expected restored line, got %q", outRestored)
	}
}

func TestHUD_SadPath_NonTTY(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: falsePtr(), // NOT a TTY
	})

	hud.OnDisrupted("quic")
	hud.OnAttempt(1, 8, "quic", nil)
	hud.OnRestored("quic", 1024)
	hud.OnFailed("budget exhausted", errors.New("timeout"))
	hud.OnAborted("user cancel")
	hud.Clear()

	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes written to non-TTY destination, got %d bytes: %q", buf.Len(), buf.String())
	}
}

func TestHUD_SadPath_DisabledConfig(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    false, // Explicitly disabled
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	hud.OnDisrupted("quic")
	hud.OnAttempt(1, 8, "quic", nil)
	hud.OnRestored("quic", 1024)

	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes when HUD is disabled, got %d bytes: %q", buf.Len(), buf.String())
	}
}

func TestHUD_SadPath_RelayHUDEnvZero(t *testing.T) {
	t.Setenv("RELAY_HUD", "0")
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	hud.OnDisrupted("quic")
	hud.OnAttempt(1, 8, "quic", nil)
	hud.OnRestored("quic", 1024)

	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes when RELAY_HUD=0, got %d bytes: %q", buf.Len(), buf.String())
	}
}

func TestHUD_SadPath_TermDumb(t *testing.T) {
	t.Setenv("TERM", "dumb")
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: nil, // Auto-detect with TERM=dumb
	})

	hud.OnDisrupted("quic")
	hud.OnAttempt(1, 8, "quic", nil)
	hud.OnRestored("quic", 1024)

	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes when TERM=dumb, got %d bytes: %q", buf.Len(), buf.String())
	}
}

func TestHUD_SadPath_BudgetExhausted(t *testing.T) {
	var buf bytes.Buffer
	currTime := time.Date(2026, 9, 25, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
		Clock:      clock,
	})

	hud.OnDisrupted("quic")
	currTime = currTime.Add(30 * time.Second)
	hud.OnFailed("budget exhausted", errors.New("timeout"))

	out := buf.String()
	if !strings.Contains(out, "Reconnection failed: budget exhausted (after 30.0s).\n") {
		t.Fatalf("expected failure line, got %q", out)
	}
	if !strings.Contains(out, "\033]9;remote-relay: Reconnection failed: budget exhausted\007") {
		t.Fatalf("expected failure notification, got %q", out)
	}
}

func TestHUD_SadPath_FatalAuthError(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	hud.OnDisrupted("tcp")
	hud.OnFailed("authentication failed (ERR_AUTH)", errors.New("ERR_AUTH"))

	out := buf.String()
	if !strings.Contains(out, "Reconnection failed: authentication failed (ERR_AUTH)") {
		t.Fatalf("expected auth failure line, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected newline termination, got %q", out)
	}
}

func TestHUD_SadPath_UserCancellation(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	hud.OnDisrupted("quic")
	hud.OnAborted("canceled by user")

	out := buf.String()
	if !strings.Contains(out, "Reconnection aborted: canceled by user.\n") {
		t.Fatalf("expected aborted line, got %q", out)
	}
}

func TestHUD_SadPath_Clear(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	// Clear on inactive HUD is a no-op
	hud.Clear()
	if buf.Len() != 0 {
		t.Fatalf("Clear() on inactive HUD should do nothing, got %q", buf.String())
	}

	// Clear on active HUD outputs line erase \r\033[K
	hud.OnDisrupted("quic")
	buf.Reset()
	hud.Clear()
	if buf.String() != "\r\033[K" {
		t.Fatalf("Clear() on active HUD should output line clear, got %q", buf.String())
	}

	// Subsequent Clear is a no-op
	buf.Reset()
	hud.Clear()
	if buf.Len() != 0 {
		t.Fatalf("subsequent Clear() should do nothing, got %q", buf.String())
	}
}

func TestHUD_SadPath_NarrowTerminalTruncation(t *testing.T) {
	var buf bytes.Buffer
	currTime := time.Date(2026, 9, 25, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return currTime }

	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
		Clock:      clock,
		WidthFn:    func() int { return 45 }, // Constrained to 45 columns
	})

	hud.OnDisrupted("quic")
	buf.Reset()
	hud.OnAttempt(3, 8, "quic", nil)

	out := buf.String()
	// Strip ANSI sequences to verify visible width <= 45
	vLen := visibleLen(out)
	if vLen > 45 {
		t.Fatalf("visible line length %d exceeded terminal width 45: %q", vLen, out)
	}
	if !strings.Contains(out, "...") {
		t.Fatalf("expected truncated string to contain ellipsis, got %q", out)
	}
}

func TestHUD_SadPath_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	hud.OnDisrupted("quic")
	hud.OnRestored("quic", 0)

	out := buf.String()
	if strings.Contains(out, "\033[33m") || strings.Contains(out, "\033[32m") || strings.Contains(out, "\033[31m") {
		t.Fatalf("expected no ANSI color sequences when NO_COLOR=1, got %q", out)
	}
	if !strings.Contains(out, "[remote-relay] Link disrupted.") {
		t.Fatalf("expected plain text [remote-relay], got %q", out)
	}
}

func TestHUD_SadPath_BrokenWriter(t *testing.T) {
	// Writer always errors out. HUD must not panic or block.
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &errorWriter{},
		IsTerminal: truePtr(),
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("HUD panicked on broken writer: %v", r)
		}
	}()

	hud.OnDisrupted("quic")
	hud.OnAttempt(1, 8, "quic", nil)
	hud.OnRestored("quic", 1024)
	hud.OnFailed("budget exhausted", errors.New("timeout"))
	hud.OnAborted("user cancel")
	hud.Clear()
}

func TestHUD_SadPath_ConcurrentAccess(t *testing.T) {
	var buf bytes.Buffer
	hud := NewHUD(HUDConfig{
		Enabled:    true,
		Out:        &buf,
		IsTerminal: truePtr(),
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hud.OnDisrupted("quic")
			hud.OnAttempt(idx%5+1, 8, "quic", nil)
			if idx%3 == 0 {
				hud.Clear()
			} else if idx%3 == 1 {
				hud.OnRestored("quic", idx*1024)
			} else {
				hud.OnFailed("timeout", errors.New("timeout"))
			}
		}(i)
	}
	wg.Wait()
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{35020, "34.2 KiB"},
		{1048576, "1.0 MiB"},
		{16777216, "16.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, tc := range cases {
		got := formatBytes(tc.in)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVisibleLenAndTruncate(t *testing.T) {
	plain := "hello world"
	if visibleLen(plain) != 11 {
		t.Fatalf("expected 11, got %d", visibleLen(plain))
	}

	colored := "\033[33mhello\033[0m world"
	if visibleLen(colored) != 11 {
		t.Fatalf("expected 11, got %d", visibleLen(colored))
	}

	trunc := truncateToWidth(colored, 8)
	if visibleLen(trunc) > 8 {
		t.Fatalf("expected visible len <= 8, got %d (%q)", visibleLen(trunc), trunc)
	}
	if !strings.HasSuffix(trunc, "...\033[0m") {
		t.Fatalf("expected ellipsis and reset suffix, got %q", trunc)
	}
}

func TestHUD_RunClientIntegration_StdoutIsolation(t *testing.T) {
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srv, srvAddr, cancelSrv := startRelay(t, destLn.Addr().String())
	defer cancelSrv()
	_ = srv

	var hudBuf bytes.Buffer
	var stdoutBuf bytes.Buffer
	var stdoutMu sync.Mutex

	safeStdout := &struct {
		io.Writer
	}{
		Writer: writerFunc(func(p []byte) (n int, err error) {
			stdoutMu.Lock()
			defer stdoutMu.Unlock()
			return stdoutBuf.Write(p)
		}),
	}

	clientInR, clientInW := io.Pipe()
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer clientCancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = srvAddr
	ccfg.Destination = destLn.Addr().String()
	ccfg.Transport = "tcp"
	ccfg.HUD = true
	ccfg.HUDWriter = &hudBuf
	ccfg.HUDIsTerminal = truePtr()

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- RunClient(clientCtx, ccfg, clientInR, safeStdout, logging.New(io.Discard, "error", "text"))
	}()

	// Send data chunk 1
	payload1 := []byte("hello world payload part 1\n")
	if _, err := clientInW.Write(payload1); err != nil {
		t.Fatal(err)
	}

	// Wait for echo of chunk 1
	waitUntil(t, 4*time.Second, func() bool {
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		return stdoutBuf.Len() >= len(payload1)
	})

	// Drop carrier transports on server to trigger client disruption & HUD reconnection
	srv.dropLiveTransports()

	// Send data chunk 2
	payload2 := []byte("hello world payload part 2 after carrier drop\n")
	if _, err := clientInW.Write(payload2); err != nil {
		t.Fatal(err)
	}

	expectedTotal := len(payload1) + len(payload2)
	waitUntil(t, 6*time.Second, func() bool {
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		return stdoutBuf.Len() >= expectedTotal
	})

	_ = clientInW.Close()
	clientCancel()

	// 1. Verify stdout is 100% clean and contains ONLY payload1 + payload2
	stdoutMu.Lock()
	gotStdout := stdoutBuf.Bytes()[:expectedTotal]
	stdoutMu.Unlock()

	expectedPayload := append(payload1, payload2...)
	if !bytes.Equal(gotStdout, expectedPayload) {
		t.Fatalf("stdout corrupted! got %q, want %q", gotStdout, expectedPayload)
	}

	// 2. Verify HUD messages were written to hudBuf, NOT stdout!
	hudOut := hudBuf.String()
	if !strings.Contains(hudOut, "Link disrupted. Reconnecting via TCP...") {
		t.Fatalf("expected HUD disruption message in hudBuf, got %q", hudOut)
	}
	if !strings.Contains(hudOut, "Link restored via TCP") {
		t.Fatalf("expected HUD restored message in hudBuf, got %q", hudOut)
	}
	if strings.Contains(string(gotStdout), "Link disrupted") || strings.Contains(string(gotStdout), "[remote-relay]") {
		t.Fatalf("stdout was contaminated with HUD output! got %q", string(gotStdout))
	}
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

