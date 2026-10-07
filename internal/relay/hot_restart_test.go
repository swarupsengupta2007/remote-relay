//go:build !windows

package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func TestServerHandoverDirect(t *testing.T) {
	// 1. Start echo destination TCP server
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	destAddr := destLn.Addr().String()

	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	// 2. Start Server 1 (Parent)
	cfg1 := config.DefaultServer()
	cfg1.ListenTCP = "127.0.0.1:0"
	cfg1.DefaultDestination = destAddr
	cfg1.AllowDestinations = []string{destAddr, "*"}
	cfg1.Transports = []string{"tcp"}
	cfg1.HoldTimeout = config.Duration(30 * time.Second)
	log := logging.New(os.Stderr, "info", "text")

	srv1 := NewServer(cfg1, log)
	srv1.SetNoExitOnRestart(true)
	if err := srv1.Listen(); err != nil {
		t.Fatal(err)
	}
	relayAddr := srv1.Addr()

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() {
		_ = srv1.Serve(ctx1)
	}()

	// 3. Start client and connect to Server 1
	clientInR, clientInW := io.Pipe()
	clientOutR, clientOutW := io.Pipe()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer clientCancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = relayAddr
	ccfg.Destination = destAddr
	ccfg.Transport = "tcp"
	ccfg.LogLevel = "debug"
	clog := logging.New(os.Stderr, "debug", "text")

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- RunClient(clientCtx, ccfg, clientInR, clientOutW, clog)
	}()

	// 4. Concurrently read echoes from clientOutR
	var echoReceived bytes.Buffer
	var echoMu sync.Mutex
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := clientOutR.Read(buf)
			if n > 0 {
				echoMu.Lock()
				echoReceived.Write(buf[:n])
				echoMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Send Part 1 of data through client
	part1 := []byte("hello-before-handover-data-stream-part-1\n")
	if _, err := clientInW.Write(part1); err != nil {
		t.Fatalf("clientInW write part 1: %v", err)
	}

	waitUntil(t, 5*time.Second, func() bool {
		echoMu.Lock()
		defer echoMu.Unlock()
		return echoReceived.Len() >= len(part1)
	})

	echoMu.Lock()
	if !bytes.Equal(echoReceived.Bytes()[:len(part1)], part1) {
		t.Fatalf("echo part 1 mismatch: got %q want %q", echoReceived.Bytes()[:len(part1)], part1)
	}
	echoMu.Unlock()

	// Verify server 1 has 1 live session
	if srv1.sessionCount() != 1 {
		t.Fatalf("expected 1 session on srv1, got %d", srv1.sessionCount())
	}

	// 5. Perform Handover from Server 1 to Server 2 via UNIX socketpair
	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile := os.NewFile(uintptr(sp[0]), "parent-file")
	childFile := os.NewFile(uintptr(sp[1]), "child-file")
	defer parentFile.Close()
	defer childFile.Close()

	parentConn, err := net.FileConn(parentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer parentConn.Close()
	parentUnix := parentConn.(*net.UnixConn)

	t.Setenv("RELAY_HANDOVER_FD", strconv.Itoa(int(childFile.Fd())))

	// Start Server 2 (Child)
	cfg2 := config.DefaultServer()
	cfg2.ListenTCP = "127.0.0.1:0"
	cfg2.DefaultDestination = destAddr
	cfg2.AllowDestinations = []string{destAddr, "*"}
	cfg2.Transports = []string{"tcp"}
	cfg2.HoldTimeout = config.Duration(30 * time.Second)

	srv2 := NewServer(cfg2, log)
	srv2.SetNoExitOnRestart(true)

	// Execute handover concurrently: parent sends, child listens/adopts
	handoverErrCh := make(chan error, 1)
	go func() {
		handoverErrCh <- srv1.HandoverTo(parentUnix)
	}()

	if err := srv2.Listen(); err != nil {
		t.Fatalf("srv2.Listen: %v", err)
	}
	defer srv2.Close()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	srv2ErrCh := make(chan error, 1)
	go func() {
		srv2ErrCh <- srv2.Serve(ctx2)
	}()

	if err := <-handoverErrCh; err != nil {
		t.Fatalf("srv1.HandoverTo failed: %v", err)
	}

	// 6. Send Part 2 through client (client will automatically resume to child)
	part2 := []byte("hello-after-handover-data-stream-part-2\n")
	if _, err := clientInW.Write(part2); err != nil {
		t.Fatalf("clientInW write part 2: %v", err)
	}

	expectedTotal := len(part1) + len(part2)
	waitUntil(t, 5*time.Second, func() bool {
		select {
		case err := <-srv2ErrCh:
			t.Fatalf("srv2.Serve exited unexpectedly: %v", err)
		default:
		}
		select {
		case err := <-clientErrCh:
			t.Fatalf("client exited unexpectedly: %v", err)
		default:
		}
		echoMu.Lock()
		defer echoMu.Unlock()
		return echoReceived.Len() >= expectedTotal
	})

	echoMu.Lock()
	t.Logf("echoReceived len=%d, expectedTotal=%d, got=%q", echoReceived.Len(), expectedTotal, echoReceived.String())
	gotBytes := echoReceived.Bytes()
	if !bytes.Equal(gotBytes[:expectedTotal], append(part1, part2...)) {
		t.Fatalf("combined echo mismatch: got %q", gotBytes)
	}
	echoMu.Unlock()

	// Cancel client and verify clean termination
	clientCancel()
	select {
	case err := <-clientErrCh:
		if err != nil && err != io.EOF && !errors.Is(err, context.Canceled) {
			t.Fatalf("client finished with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not terminate cleanly after cancel")
	}
}

func TestServerZeroDowntimeHotRestartProcess(t *testing.T) {
	// Compile relay binary for real process re-exec
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "relay-test-bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/relay")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}

	// Create authorized keys and test identity using test helper
	privPath, pubLine := writeEd25519Key(t, tmpDir, "id_ed25519")
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, []byte(pubLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_TEST_IDENTITY", privPath)

	// Start echo destination TCP server
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	destAddr := destLn.Addr().String()

	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	// Write server config allowing destination
	srvToml := fmt.Sprintf(`
allow_destinations = ["%s", "*"]
default_destination = "%s"
transports = ["tcp"]
hold_timeout = "30s"
`, destAddr, destAddr)
	srvTomlPath := filepath.Join(tmpDir, "server.toml")
	if err := os.WriteFile(srvTomlPath, []byte(srvToml), 0600); err != nil {
		t.Fatal(err)
	}

	// Track child process PID so test cleanup can kill it
	childPIDFile := filepath.Join(tmpDir, "child.pid")
	t.Setenv("RELAY_CHILD_PID_FILE", childPIDFile)

	// Find an open port for the relay server
	testLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := testLn.Addr().String()
	_ = testLn.Close()

	// Launch Parent Server process
	serverCmd := exec.Command(binPath, "server",
		"--config", srvTomlPath,
		"--listen", relayAddr,
		"--authorized-keys", authKeysPath,
		"--log-level", "debug",
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	parentPID := serverCmd.Process.Pid
	t.Cleanup(func() {
		// Clean up parent/child if still alive
		_ = syscall.Kill(parentPID, syscall.SIGKILL)
		if data, err := os.ReadFile(childPIDFile); err == nil {
			if childPID, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && childPID > 0 {
				_ = syscall.Kill(childPID, syscall.SIGKILL)
			}
		}
	})

	// Wait until server is listening
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", relayAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server failed to start on %s: %v", relayAddr, err)
	}

	// Prepare data payloads for continuous transfer
	const payloadSize = 256 * 1024 // 256 KiB
	streamData := make([]byte, payloadSize)
	for i := range streamData {
		streamData[i] = byte(i % 251)
	}
	expectedHash := sha256.Sum256(streamData)

	// Start Client process/goroutine
	clientInR, clientInW := io.Pipe()
	clientOutR, clientOutW := io.Pipe()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer clientCancel()

	ccfg := config.DefaultClient()
	ccfg.StrictHostKeyChecking = "no"
	ccfg.Server = relayAddr
	ccfg.Destination = destAddr
	ccfg.Transport = "tcp"
	ccfg.LogLevel = "debug"
	ccfg.IdentityFiles = []string{privPath}
	clog := logging.New(os.Stderr, "debug", "text")

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- RunClient(clientCtx, ccfg, clientInR, clientOutW, clog)
	}()

	// Concurrently write streamData, trigger SIGUSR2 midway, and read echoed bytes
	var echoReceived bytes.Buffer
	var writeErr error
	var readErr error
	var wg sync.WaitGroup
	wg.Add(2)

	// Reader goroutine
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for echoReceived.Len() < payloadSize {
			n, rerr := clientOutR.Read(buf)
			if n > 0 {
				echoReceived.Write(buf[:n])
			}
			if rerr != nil {
				if rerr != io.EOF {
					readErr = rerr
				}
				break
			}
		}
	}()

	// Writer goroutine that triggers SIGUSR2 after writing half the payload
	go func() {
		defer wg.Done()
		half := payloadSize / 2
		if _, err := clientInW.Write(streamData[:half]); err != nil {
			writeErr = err
			return
		}

		// Wait briefly for data to be in flight
		time.Sleep(100 * time.Millisecond)

		// Send SIGUSR2 to parent process to trigger hot restart!
		t.Logf("Sending SIGUSR2 to parent process PID %d", parentPID)
		if err := syscall.Kill(parentPID, syscall.SIGUSR2); err != nil {
			writeErr = fmt.Errorf("kill SIGUSR2: %w", err)
			return
		}

		// Small delay to allow child adoption and client resume transition
		time.Sleep(200 * time.Millisecond)

		// Write remaining half
		if _, err := clientInW.Write(streamData[half:]); err != nil {
			writeErr = err
			return
		}
		_ = clientInW.Close()
	}()

	wg.Wait()

	if writeErr != nil {
		t.Fatalf("stream write error: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("stream read error: %v", readErr)
	}

	// Verify SHA-256 matches byte-exact!
	gotHash := sha256.Sum256(echoReceived.Bytes())
	if gotHash != expectedHash {
		t.Fatalf("byte fidelity failure across hot restart: got %d bytes, hash mismatch", echoReceived.Len())
	}
	t.Logf("Successfully transferred %d bytes across SIGUSR2 zero-downtime hot restart with matching SHA-256!", echoReceived.Len())

	// Wait for client to finish cleanly
	select {
	case err := <-clientErrCh:
		if err != nil && err != io.EOF {
			t.Fatalf("client error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not finish in time")
	}

	// Verify parent process exited 0 cleanly
	parentState, err := serverCmd.Process.Wait()
	if err != nil {
		t.Logf("parent Process.Wait: %v", err)
	} else if !parentState.Success() {
		t.Fatalf("parent process exited with non-zero status: %v", parentState)
	}
}

// TestHandoverPassesWSAndMetricsListeners checks that a hot restart hands the
// WebSocket and metrics listeners to the child instead of having the child
// bind addresses the parent still holds.
func TestHandoverPassesWSAndMetricsListeners(t *testing.T) {
	log := logging.New(io.Discard, "error", "text")

	// Reserve fixed ports so the child config names the same addresses.
	reserve := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		return addr
	}
	wsAddr := reserve()
	metricsAddr := reserve()

	mkCfg := func() config.Server {
		cfg := config.DefaultServer()
		cfg.ListenTCP = "127.0.0.1:0"
		cfg.ListenWS = "ws://" + wsAddr
		cfg.MetricsListen = metricsAddr
		cfg.Transports = []string{"tcp"}
		return cfg
	}

	srv1 := NewServer(mkCfg(), log)
	srv1.SetNoExitOnRestart(true)
	if err := srv1.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() { _ = srv1.Serve(ctx1) }()
	waitUntil(t, 5*time.Second, func() bool { return srv1.MetricsAddr() != "" && srv1.WSAddr() != "" })

	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile := os.NewFile(uintptr(sp[0]), "parent-file")
	childFile := os.NewFile(uintptr(sp[1]), "child-file")
	defer parentFile.Close()
	defer childFile.Close()
	parentConn, err := net.FileConn(parentFile)
	if err != nil {
		t.Fatal(err)
	}
	defer parentConn.Close()
	t.Setenv("RELAY_HANDOVER_FD", strconv.Itoa(int(childFile.Fd())))

	srv2 := NewServer(mkCfg(), log)
	srv2.SetNoExitOnRestart(true)
	handoverErrCh := make(chan error, 1)
	go func() { handoverErrCh <- srv1.HandoverTo(parentConn.(*net.UnixConn)) }()

	if err := srv2.Listen(); err != nil {
		t.Fatalf("srv2.Listen: %v", err)
	}
	defer srv2.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	srv2ErrCh := make(chan error, 1)
	go func() { srv2ErrCh <- srv2.Serve(ctx2) }()

	if err := <-handoverErrCh; err != nil {
		t.Fatalf("HandoverTo: %v", err)
	}
	// Parent still holds its copy of the metrics socket here, as it does until
	// os.Exit in a real restart; the child must not have tried to bind it.
	waitUntil(t, 5*time.Second, func() bool {
		select {
		case err := <-srv2ErrCh:
			t.Fatalf("child Serve exited: %v", err)
		default:
		}
		return srv2.MetricsAddr() == metricsAddr && srv2.WSAddr() == wsAddr
	})
	cancel1()

	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("metrics after handover: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}
	c, err := net.DialTimeout("tcp", wsAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("websocket port after handover: %v", err)
	}
	_ = c.Close()
}
