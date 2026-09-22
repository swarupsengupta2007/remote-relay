//go:build !windows

package relay

import (
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func TestSystemdSocketActivationMismatchedPID(t *testing.T) {
	t.Setenv("LISTEN_PID", "99999999")
	t.Setenv("LISTEN_FDS", "1")

	ln, pc, err := systemdListeners()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ln != nil || pc != nil {
		t.Fatalf("expected nil listeners for mismatched PID, got ln=%v pc=%v", ln, pc)
	}
}

func TestSystemdSocketActivationAdoption(t *testing.T) {
	// Create a real listening TCP socket
	realLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	realAddr := realLn.Addr().String()

	tl := realLn.(*net.TCPListener)
	file, err := tl.File()
	if err != nil {
		_ = realLn.Close()
		t.Fatalf("File: %v", err)
	}
	_ = realLn.Close()

	// Save original FD 3 and dup our listening socket to FD 3
	origFD3, _ := syscall.Dup(3)
	if err := syscall.Dup2(int(file.Fd()), 3); err != nil {
		_ = file.Close()
		t.Fatalf("dup2 to 3: %v", err)
	}
	_ = file.Close()

	defer func() {
		if origFD3 >= 0 {
			_ = syscall.Dup2(origFD3, 3)
			_ = syscall.Close(origFD3)
		} else {
			_ = syscall.Close(3)
		}
	}()

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0" // Should be overridden by adopted socket
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)

	if err := srv.Listen(); err != nil {
		t.Fatalf("srv.Listen: %v", err)
	}
	defer srv.Close()

	if srv.Addr() != realAddr {
		t.Fatalf("adopted addr mismatch: got %s want %s", srv.Addr(), realAddr)
	}

	// Verify env vars were cleared
	if v := os.Getenv("LISTEN_PID"); v != "" {
		t.Fatalf("LISTEN_PID was not cleared: %q", v)
	}
	if v := os.Getenv("LISTEN_FDS"); v != "" {
		t.Fatalf("LISTEN_FDS was not cleared: %q", v)
	}

	// Verify incoming connections reach the adopted listener
	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial adopted listener: %v", err)
	}
	_ = conn.Close()
}
