package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func startTestEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
	}
}

func setupTestServer(t *testing.T, akLines ...string) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	akPath := filepath.Join(dir, "authorized_keys")
	var akContent string
	for _, l := range akLines {
		akContent += l + "\n"
	}
	if err := os.WriteFile(akPath, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.Transports = []string{"tcp"}
	cfg.AuthorizedKeys = akPath
	cfg.LogLevel = "error"
	cfg.AgentHoldTimeout = config.Duration(5 * time.Second)

	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})

	return srv, srv.Addr(), dir
}

func TestAgentRegistrationAndReservation(t *testing.T) {
	dir := t.TempDir()
	priv1, pub1 := writeEd25519Key(t, dir, "id_agent1")
	priv2, pub2 := writeEd25519Key(t, dir, "id_agent2")

	srv, srvAddr, _ := setupTestServer(t, pub1, pub2)

	// Agent 1 registers "homelab"
	agentCfg1 := config.DefaultAgent()
	agentCfg1.Server = srvAddr
	agentCfg1.Name = "homelab"
	agentCfg1.Destination = "127.0.0.1:22"
	agentCfg1.Transport = "tcp"
	agentCfg1.IdentityFiles = []string{priv1}
	agentCfg1.StrictHostKeyChecking = "no"

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() {
		_ = RunAgent(ctx1, agentCfg1, logging.New(io.Discard, "error", "text"))
	}()

	// Wait for agent 1 to register
	deadline := time.Now().Add(3 * time.Second)
	var registered bool
	for time.Now().Before(deadline) {
		if _, ok := srv.AgentRegistry().GetTarget("homelab"); ok {
			registered = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !registered {
		t.Fatal("agent 1 failed to register target 'homelab'")
	}

	// Agent 2 attempts to register the same name "homelab" with a different key
	agentCfg2 := config.DefaultAgent()
	agentCfg2.Server = srvAddr
	agentCfg2.Name = "homelab"
	agentCfg2.Destination = "127.0.0.1:22"
	agentCfg2.Transport = "tcp"
	agentCfg2.IdentityFiles = []string{priv2}
	agentCfg2.StrictHostKeyChecking = "no"

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	err := RunAgent(ctx2, agentCfg2, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected agent 2 to fail claiming target 'homelab' already owned by agent 1")
	}
}

func TestAgentPermitListenRBAC(t *testing.T) {
	dir := t.TempDir()
	priv1, pub1 := writeEd25519Key(t, dir, "id_restricted")
	// pub1 is only permitted to listen/register "nas"
	restrictedPub := fmt.Sprintf(`permitlisten="nas" %s`, pub1)

	_, srvAddr, _ := setupTestServer(t, restrictedPub)

	// Attempt to register disallowed target "homelab"
	agentCfgBad := config.DefaultAgent()
	agentCfgBad.Server = srvAddr
	agentCfgBad.Name = "homelab"
	agentCfgBad.Destination = "127.0.0.1:22"
	agentCfgBad.Transport = "tcp"
	agentCfgBad.IdentityFiles = []string{priv1}
	agentCfgBad.StrictHostKeyChecking = "no"

	ctxBad, cancelBad := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelBad()
	err := RunAgent(ctxBad, agentCfgBad, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected error registering disallowed target 'homelab' under permitlisten='nas'")
	}

	// Attempt to register allowed target "nas"
	agentCfgGood := config.DefaultAgent()
	agentCfgGood.Server = srvAddr
	agentCfgGood.Name = "nas"
	agentCfgGood.Destination = "127.0.0.1:22"
	agentCfgGood.Transport = "tcp"
	agentCfgGood.IdentityFiles = []string{priv1}
	agentCfgGood.StrictHostKeyChecking = "no"

	ctxGood, cancelGood := context.WithCancel(context.Background())
	defer cancelGood()
	go func() {
		_ = RunAgent(ctxGood, agentCfgGood, logging.New(io.Discard, "error", "text"))
	}()

	// Wait for successful registration
	deadline := time.Now().Add(3 * time.Second)
	success := false
	for time.Now().Before(deadline) {
		a := agentAuth(agentCfgGood)
		conn, err := dialAgent(ctxGood, agentCfgGood)
		if err == nil {
			rerr := registerAgent(ctxGood, conn, agentCfgGood, a)
			_ = conn.Close()
			if rerr == nil {
				success = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !success {
		t.Fatal("expected agent with permitlisten='nas' to register target 'nas' successfully")
	}
}

func TestAgentEndToEndDataTransfer(t *testing.T) {
	echoAddr, stopEcho := startTestEchoServer(t)
	defer stopEcho()

	dir := t.TempDir()
	privAgent, pubAgent := writeEd25519Key(t, dir, "id_agent")
	privClient, pubClient := writeEd25519Key(t, dir, "id_client")

	srv, srvAddr, _ := setupTestServer(t, pubAgent, pubClient)

	// Start Agent
	agentCfg := config.DefaultAgent()
	agentCfg.Server = srvAddr
	agentCfg.Name = "echo-target"
	agentCfg.Destination = echoAddr
	agentCfg.Transport = "tcp"
	agentCfg.IdentityFiles = []string{privAgent}
	agentCfg.StrictHostKeyChecking = "no"

	ctxAgent, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()
	log := logging.New(io.Discard, "error", "text")
	go func() {
		_ = RunAgent(ctxAgent, agentCfg, log)
	}()

	// Wait for agent to register target
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := srv.AgentRegistry().GetTarget("echo-target"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Client dials target
	clientCfg := config.DefaultClient()
	clientCfg.Server = srvAddr
	clientCfg.Target = "echo-target"
	clientCfg.Transport = "tcp"
	clientCfg.IdentityFiles = []string{privClient}
	clientCfg.StrictHostKeyChecking = "no"

	msg := []byte("hello from reverse relay inverted tunnel!\n")
	stdin := bytes.NewReader(msg)
	var stdout bytes.Buffer

	ctxClient, cancelClient := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelClient()

	err := RunClient(ctxClient, clientCfg, stdin, &stdout, log)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && err != io.EOF {
		t.Logf("RunClient finished with: %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), msg) {
		t.Fatalf("expected stdout to contain %q, got %q", string(msg), stdout.String())
	}
}

func TestAgentDestinationAllowedPolicy(t *testing.T) {
	echoAddr1, stopEcho1 := startTestEchoServer(t)
	defer stopEcho1()
	echoAddr2, stopEcho2 := startTestEchoServer(t)
	defer stopEcho2()

	dir := t.TempDir()
	privAgent, pubAgent := writeEd25519Key(t, dir, "id_agent")
	privClient, pubClient := writeEd25519Key(t, dir, "id_client")

	srv, srvAddr, _ := setupTestServer(t, pubAgent, pubClient)

	// Agent only allows echoAddr1
	agentCfg := config.DefaultAgent()
	agentCfg.Server = srvAddr
	agentCfg.Name = "app"
	agentCfg.Destination = echoAddr1
	agentCfg.AllowDestinations = []string{echoAddr1}
	agentCfg.Transport = "tcp"
	agentCfg.IdentityFiles = []string{privAgent}
	agentCfg.StrictHostKeyChecking = "no"

	ctxAgent, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()
	go func() {
		_ = RunAgent(ctxAgent, agentCfg, logging.New(io.Discard, "error", "text"))
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := srv.AgentRegistry().GetTarget("app"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Client requests disallowed destination echoAddr2
	clientCfgBad := config.DefaultClient()
	clientCfgBad.Server = srvAddr
	clientCfgBad.Target = "app"
	clientCfgBad.Destination = echoAddr2
	clientCfgBad.Transport = "tcp"
	clientCfgBad.IdentityFiles = []string{privClient}
	clientCfgBad.StrictHostKeyChecking = "no"

	ctxClientBad, cancelClientBad := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelClientBad()

	var outBad bytes.Buffer
	err := RunClient(ctxClientBad, clientCfgBad, bytes.NewReader([]byte("test")), &outBad, logging.New(io.Discard, "error", "text"))
	if err == nil {
		t.Fatal("expected error when client requested disallowed destination override")
	}

	// Client requests allowed destination echoAddr1
	clientCfgGood := config.DefaultClient()
	clientCfgGood.Server = srvAddr
	clientCfgGood.Target = "app"
	clientCfgGood.Destination = echoAddr1
	clientCfgGood.Transport = "tcp"
	clientCfgGood.IdentityFiles = []string{privClient}
	clientCfgGood.StrictHostKeyChecking = "no"

	ctxClientGood, cancelClientGood := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClientGood()

	var outGood bytes.Buffer
	testMsg := []byte("ping policy test\n")
	_ = RunClient(ctxClientGood, clientCfgGood, bytes.NewReader(testMsg), &outGood, logging.New(io.Discard, "error", "text"))
	if !bytes.Contains(outGood.Bytes(), testMsg) {
		t.Fatalf("expected allowed destination to echo %q, got %q", string(testMsg), outGood.String())
	}
}

func TestAgentControlGracePeriodAndReconnect(t *testing.T) {
	dir := t.TempDir()
	privAgent, pubAgent := writeEd25519Key(t, dir, "id_agent")

	srv, srvAddr, _ := setupTestServer(t, pubAgent)

	agentCfg := config.DefaultAgent()
	agentCfg.Server = srvAddr
	agentCfg.Name = "grace-target"
	agentCfg.Destination = "127.0.0.1:22"
	agentCfg.Transport = "tcp"
	agentCfg.IdentityFiles = []string{privAgent}
	agentCfg.StrictHostKeyChecking = "no"

	a := agentAuth(agentCfg)
	conn1, err := dialAgent(context.Background(), agentCfg)
	if err != nil {
		t.Fatalf("dialAgent conn1: %v", err)
	}

	if err := registerAgent(context.Background(), conn1, agentCfg, a); err != nil {
		t.Fatalf("registerAgent conn1: %v", err)
	}

	target, ok := srv.AgentRegistry().GetTarget("grace-target")
	if !ok || target == nil {
		t.Fatal("expected grace-target to be registered")
	}

	// Drop control connection
	_ = conn1.Close()
	srv.AgentRegistry().OnControlDisconnect("grace-target", 5*time.Second, nil)

	// Target should still be reserved in registry during grace period
	targetAfterDrop, ok := srv.AgentRegistry().GetTarget("grace-target")
	if !ok || targetAfterDrop == nil {
		t.Fatal("expected target to still be held during grace period")
	}
	if targetAfterDrop.IsConnected() {
		t.Fatal("control conn should be nil after drop")
	}

	// Reconnect with same key within grace period
	conn2, err := dialAgent(context.Background(), agentCfg)
	if err != nil {
		t.Fatalf("dialAgent conn2: %v", err)
	}
	defer conn2.Close()

	if err := registerAgent(context.Background(), conn2, agentCfg, a); err != nil {
		t.Fatalf("reconnection within grace period failed: %v", err)
	}

	reconnectedTarget, ok := srv.AgentRegistry().GetTarget("grace-target")
	if !ok || reconnectedTarget == nil {
		t.Fatal("expected target to be present after reconnect")
	}
	if !reconnectedTarget.IsConnected() {
		t.Fatal("control conn should be re-established after reconnect")
	}
}
