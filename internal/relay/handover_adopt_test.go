//go:build !windows

package relay

import (
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/session"
)

// TestAdoptHandoverNilDestHeldAndRealFDPumps drives the shipped adoptHandover
// path: a session with no destination FD is held and never Read, and a session
// whose destination FD was passed across the handover still moves bytes.
func TestAdoptHandoverNilDestHeldAndRealFDPumps(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	destTCP, ok := accepted.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted conn is %T", accepted)
	}
	destFile, err := destTCP.File()
	if err != nil {
		t.Fatal(err)
	}
	defer destFile.Close()
	// Drop the original accepted socket so the only descriptor the child can
	// read is the one carried in the handover.
	if err := destTCP.Close(); err != nil {
		t.Fatal(err)
	}

	nilSess, _, err := session.New()
	if err != nil {
		t.Fatal(err)
	}
	nilSess.Destination = "socks"
	fdSess, _, err := session.New()
	if err != nil {
		t.Fatal(err)
	}
	fdSess.Destination = ln.Addr().String()

	const holdMs = int64(120_000)
	state := HandoverState{
		Version:      1,
		Timestamp:    time.Now().UTC(),
		HasListenTCP: false,
		HasListenUDP: false,
		Sessions: []HandoverSession{
			{
				Session:         nilSess.Snapshot(),
				SendLogCap:      1 << 20,
				RemainingHoldMs: holdMs,
				HasDestFD:       false,
			},
			{
				Session:         fdSess.Snapshot(),
				SendLogCap:      1 << 20,
				RemainingHoldMs: holdMs,
				HasDestFD:       true,
			},
		},
	}

	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile := os.NewFile(uintptr(sp[0]), "parent-handover")
	childFile := os.NewFile(uintptr(sp[1]), "child-handover")
	defer parentFile.Close()
	defer childFile.Close()

	parentConn, err := net.FileConn(parentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer parentConn.Close()
	parentUnix := parentConn.(*net.UnixConn)

	// Dup the child end so adoptHandover's os.NewFile().Close does not close
	// the descriptor this test still owns.
	childDup, err := syscall.Dup(int(childFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_HANDOVER_FD", strconv.Itoa(childDup))

	cfg := config.DefaultServer()
	cfg.Splice = false
	cfg.NoSpill = true
	cfg.HoldTimeout = config.Duration(120 * time.Second)
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)
	defer srv.Close()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- SendHandover(parentUnix, state, []*os.File{destFile})
	}()

	adopted, err := srv.adoptHandover()
	if err != nil {
		t.Fatalf("adoptHandover: %v", err)
	}
	if !adopted {
		t.Fatal("adoptHandover returned false")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("SendHandover: %v", err)
	}

	payload := []byte("handover-dest-fd-bytes")
	if _, err := peer.Write(payload); err != nil {
		t.Fatalf("peer write: %v", err)
	}

	waitUntil(t, 3*time.Second, func() bool {
		srv.livesMu.Lock()
		live := srv.lives[fdSess.ID]
		srv.livesMu.Unlock()
		if live == nil || live.srcReads.Load() == 0 {
			return false
		}
		_, data, _ := live.sendLog.Snapshot()
		return bytes.Contains(data, payload)
	})

	srv.livesMu.Lock()
	nilLive := srv.lives[nilSess.ID]
	fdLive := srv.lives[fdSess.ID]
	srv.livesMu.Unlock()

	if nilLive == nil {
		t.Fatal("nil-dest session was not held after adoptHandover")
	}
	if nilLive.io.src != nil || nilLive.io.sink != nil {
		t.Fatalf("nil-dest session endpoints: src=%v sink=%v", nilLive.io.src, nilLive.io.sink)
	}
	if got := nilLive.srcReads.Load(); got != 0 {
		t.Fatalf("nil-dest session srcReads=%d, want 0", got)
	}
	if fdLive == nil {
		t.Fatal("dest-fd session missing after adoptHandover")
	}
	if !endpointReady(fdLive.io.src) || !endpointReady(fdLive.io.sink) {
		t.Fatal("dest-fd session did not adopt a usable endpoint")
	}
	if fdLive.srcReads.Load() == 0 {
		t.Fatal("dest-fd session never read")
	}
	_, data, _ := fdLive.sendLog.Snapshot()
	if !bytes.Contains(data, payload) {
		t.Fatalf("dest-fd send log = %q, want payload %q", data, payload)
	}
}
