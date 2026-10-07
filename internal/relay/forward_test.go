package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/socks5"
)

// startForwardForTest runs RunForward against serverAddr and returns the
// bound listener addresses (Locals in order, then SOCKS5 if requested).
func startForwardForTest(t *testing.T, serverAddr string, locals []config.LocalForward, socksListen string) []string {
	t.Helper()
	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = serverAddr
	ccfg.Destination = proto.DestSOCKS5
	ccfg.Transport = "tcp"
	ccfg.IdentityFiles = []string{os.Getenv("RELAY_TEST_IDENTITY")}
	ccfg.LogLevel = "error"

	boundCh := make(chan []string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunForward(ctx, ForwardConfig{
			Locals:      locals,
			SocksListen: socksListen,
			Log:         logging.New(io.Discard, "error", "text"),
			OnBound:     func(addrs []string) { boundCh <- addrs },
		}, ccfg)
	}()

	var addrs []string
	select {
	case addrs = <-boundCh:
	case err := <-errCh:
		cancel()
		t.Fatalf("RunForward failed on startup: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timeout waiting for forward listeners to bind")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("RunForward returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunForward did not return after cancel")
		}
	})
	return addrs
}

func echoRoundTrip(t *testing.T, addr string, size int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	go func() {
		_, _ = conn.Write(payload)
		_ = conn.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read via %s: %v", addr, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("via %s: got %d bytes, want %d identical bytes", addr, len(got), len(payload))
	}
}

func TestLocalForward_MultipleForwardsAndSocksShareTunnel(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, nil, false)
	h1, p1, stop1 := startEchoServer(t)
	defer stop1()
	h2, p2, stop2 := startEchoServer(t)
	defer stop2()

	addrs := startForwardForTest(t, serverAddr, []config.LocalForward{
		{Listen: "127.0.0.1:0", Dest: net.JoinHostPort(h1, strconv.Itoa(int(p1)))},
		{Listen: "127.0.0.1:0", Dest: net.JoinHostPort(h2, strconv.Itoa(int(p2)))},
	}, "127.0.0.1:0")
	if len(addrs) != 3 {
		t.Fatalf("bound %v, want 3 listeners", addrs)
	}

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			echoRoundTrip(t, addrs[i%2], 128*1024)
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	conn, rep, err := socks5DialTarget(addrs[2], socks5.CmdConnect, h1, p1)
	if err != nil {
		t.Fatalf("socks via forward client: %v rep 0x%02x", err, rep)
	}
	_ = conn.Close()
}

func TestLocalForward_ForbiddenDestinationClosesConn(t *testing.T) {
	serverAddr, _, _ := testSocksServer(t, []string{"10.0.0.0/8"}, false)
	addrs := startForwardForTest(t, serverAddr, []config.LocalForward{
		{Listen: "127.0.0.1:0", Dest: "127.0.0.1:80"},
	}, "")

	conn, err := net.DialTimeout("tcp", addrs[0], 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("read on forbidden forward = %d, %v; want closed connection", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("forbidden forward left the connection open")
	}
}

func TestLocalForward_ListenConflictFailsFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ccfg := config.DefaultClient()
	ccfg.Server = "127.0.0.1:1"
	err = RunForward(context.Background(), ForwardConfig{
		Locals: []config.LocalForward{{Listen: ln.Addr().String(), Dest: "127.0.0.1:22"}},
		Log:    logging.New(io.Discard, "error", "text"),
	}, ccfg)
	if err == nil {
		t.Fatal("RunForward bound an address already in use")
	}
}

func TestLocalForward_ResumesAcrossCarrierDrop(t *testing.T) {
	serverAddr, srv, _ := testSocksServer(t, nil, false)
	h, p, stop := startEchoServer(t)
	defer stop()
	addrs := startForwardForTest(t, serverAddr, []config.LocalForward{
		{Listen: "127.0.0.1:0", Dest: net.JoinHostPort(h, strconv.Itoa(int(p)))},
	}, "")

	conn, err := net.DialTimeout("tcp", addrs[0], 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	const total = 256 * 1024
	payload := make([]byte, total)
	_, _ = rand.Read(payload)
	go func() {
		for off := 0; off < total; off += 16384 {
			_, _ = conn.Write(payload[off : off+16384])
			time.Sleep(5 * time.Millisecond)
		}
		_ = conn.(*net.TCPConn).CloseWrite()
	}()

	received := make([]byte, 0, total)
	buf := make([]byte, 16384)
	dropped := false
	for {
		n, err := conn.Read(buf)
		received = append(received, buf[:n]...)
		if !dropped && len(received) >= 64*1024 {
			dropped = true
			srv.dropLiveTransports()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read failed mid-stream: %v", err)
			}
			break
		}
	}
	if sha256.Sum256(received) != sha256.Sum256(payload) {
		t.Fatalf("data corrupted across carrier drop (%d of %d bytes)", len(received), total)
	}
}
