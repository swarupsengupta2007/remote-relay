//go:build !windows

package relay

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
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

// TestSystemdSocketActivationAdoption re-executes the test binary with the
// listener as fd 3, as systemd does. Dup2-ing over fd 3 in-process would
// clobber whatever the Go runtime already opened there (e.g. the netpoller).
func TestSystemdSocketActivationAdoption(t *testing.T) {
	if os.Getenv("RELAY_SYSTEMD_CHILD") == "1" {
		systemdAdoptionChild(t)
		return
	}

	realLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer realLn.Close()
	file, err := realLn.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	defer file.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestSystemdSocketActivationAdoption$", "-test.v")
	cmd.Env = append(os.Environ(),
		"RELAY_SYSTEMD_CHILD=1",
		"RELAY_SYSTEMD_WANT_ADDR="+realLn.Addr().String(),
		"LISTEN_FDS=1",
	)
	cmd.ExtraFiles = []*os.File{file} // becomes fd 3 in the child
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func systemdAdoptionChild(t *testing.T) {
	// systemd sets LISTEN_PID to the activated process; only the child knows it.
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0" // Should be overridden by adopted socket
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)

	if err := srv.Listen(); err != nil {
		t.Fatalf("srv.Listen: %v", err)
	}
	defer srv.Close()

	if want := os.Getenv("RELAY_SYSTEMD_WANT_ADDR"); srv.Addr() != want {
		t.Fatalf("adopted addr mismatch: got %s want %s", srv.Addr(), want)
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
