package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func startTargetTestEcho(t *testing.T) (string, func()) {
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
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startChainedAgent(t *testing.T, srvAddr, name, dest string, allowDest []string) context.CancelFunc {
	t.Helper()
	agentCfg := config.DefaultAgent()
	agentCfg.Server = srvAddr
	agentCfg.Name = name
	agentCfg.Destination = dest
	agentCfg.AllowDestinations = allowDest
	agentCfg.Transport = "tcp"
	agentCfg.StrictHostKeyChecking = "no"
	agentCfg.LogLevel = "error"

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = RunAgent(ctx, agentCfg, logging.New(io.Discard, "error", "text"))
	}()
	t.Cleanup(cancel)
	return cancel
}

func waitForAgentTarget(t *testing.T, srv *Server, target string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := srv.agentReg.GetTarget(target); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent target %q did not register within %v", target, timeout)
}

func TestChainedJumphostTarget_SingleHop(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	// Jump server where agent registers
	cfg := chainServerCfg(echoAddr)
	cfg.AllowRelayHops = []string{"*"}
	cfg.MaxChainDepth = 2
	srv, _, _ := startRelayCfg(t, cfg)

	startChainedAgent(t, srv.Addr(), "homelab", echoAddr, nil)
	waitForAgentTarget(t, srv, "homelab", 3*time.Second)

	// Client: -J jump --target homelab (no --server)
	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = ""
	cliCfg.Target = "homelab"
	cliCfg.Jumphost = []string{srv.Addr()}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"

	payload := make([]byte, 32*1024)
	_, _ = rand.Read(payload)

	var inBuf bytes.Buffer
	inBuf.Write(payload)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil && err != context.Canceled {
		t.Fatalf("RunClient: %v", err)
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", outBuf.Len(), len(payload))
	}
}

func TestChainedJumphostTarget_MultiHop(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	// Jump2 (where agent connects)
	cfg2 := chainServerCfg(echoAddr)
	cfg2.AllowRelayHops = []string{"*"}
	cfg2.MaxChainDepth = 3
	srv2, _, _ := startRelayCfg(t, cfg2)

	// Jump1 (intermediate hop dialled by client)
	cfg1 := chainServerCfg(echoAddr)
	cfg1.AllowRelayHops = []string{srv2.Addr()}
	cfg1.MaxChainDepth = 3
	srv1, _, _ := startRelayCfg(t, cfg1)

	startChainedAgent(t, srv2.Addr(), "homelab", echoAddr, nil)
	waitForAgentTarget(t, srv2, "homelab", 3*time.Second)

	// Client: -J jump1,jump2 --target homelab
	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = ""
	cliCfg.Target = "homelab"
	cliCfg.Jumphost = []string{srv1.Addr(), srv2.Addr()}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"

	payload := make([]byte, 32*1024)
	_, _ = rand.Read(payload)

	var inBuf bytes.Buffer
	inBuf.Write(payload)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil && err != context.Canceled {
		t.Fatalf("RunClient: %v", err)
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", outBuf.Len(), len(payload))
	}
}

func TestChainedJumphostTarget_HopSyntax(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	cfg := chainServerCfg(echoAddr)
	cfg.AllowRelayHops = []string{"*"}
	cfg.MaxChainDepth = 2
	srv, _, _ := startRelayCfg(t, cfg)

	startChainedAgent(t, srv.Addr(), "homelab", echoAddr, nil)
	waitForAgentTarget(t, srv, "homelab", 3*time.Second)

	// Client uses -J jump,target:homelab syntax
	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = ""
	cliCfg.Target = ""
	cliCfg.Jumphost = []string{srv.Addr(), "target:homelab"}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"

	payload := []byte("hello from hop syntax")
	var inBuf bytes.Buffer
	inBuf.Write(payload)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil && err != context.Canceled {
		t.Fatalf("RunClient: %v", err)
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %q, want %q", outBuf.String(), string(payload))
	}
}

func TestChainedJumphostTarget_DestinationOverride(t *testing.T) {
	echo1, stop1 := startTargetTestEcho(t)
	defer stop1()
	echo2, stop2 := startTargetTestEcho(t)
	defer stop2()

	cfg := chainServerCfg(echo1)
	cfg.AllowRelayHops = []string{"*"}
	cfg.MaxChainDepth = 2
	srv, _, _ := startRelayCfg(t, cfg)

	// Agent default is echo1, but permits echo2
	startChainedAgent(t, srv.Addr(), "homelab", echo1, []string{echo1, echo2})
	waitForAgentTarget(t, srv, "homelab", 3*time.Second)

	// Client specifies --dest echo2
	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = ""
	cliCfg.Target = "homelab"
	cliCfg.Destination = echo2
	cliCfg.Jumphost = []string{srv.Addr()}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"

	payload := []byte("destination override through chain")
	var inBuf bytes.Buffer
	inBuf.Write(payload)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil && err != context.Canceled {
		t.Fatalf("RunClient: %v", err)
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %q, want %q", outBuf.String(), string(payload))
	}
}

func TestChainedJumphostTarget_Policies(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	// 1. Agent offline / not registered
	t.Run("agent offline", func(t *testing.T) {
		cfg := chainServerCfg(echoAddr)
		cfg.AllowRelayHops = []string{"*"}
		cfg.MaxChainDepth = 2
		srv, _, _ := startRelayCfg(t, cfg)

		cliCfg := config.DefaultClient()
		cliCfg.StrictHostKeyChecking = "no"
		cliCfg.Server = ""
		cliCfg.Target = "offline-target"
		cliCfg.Jumphost = []string{srv.Addr()}
		cliCfg.Transport = "tcp"
		cliCfg.LogLevel = "error"

		var inBuf, outBuf bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
		if err == nil {
			t.Fatal("expected error connecting to offline target")
		}
	})

	// 2. Server target policy forbidden
	t.Run("server target forbidden", func(t *testing.T) {
		cfg := chainServerCfg(echoAddr)
		cfg.AllowRelayHops = []string{"*"}
		cfg.MaxChainDepth = 2
		cfg.AllowTargets = []string{"allowed-only"}
		srv, _, _ := startRelayCfg(t, cfg)

		cliCfg := config.DefaultClient()
		cliCfg.StrictHostKeyChecking = "no"
		cliCfg.Server = ""
		cliCfg.Target = "disallowed-target"
		cliCfg.Jumphost = []string{srv.Addr()}
		cliCfg.Transport = "tcp"
		cliCfg.LogLevel = "error"

		var inBuf, outBuf bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
		if err == nil {
			t.Fatal("expected error on disallowed target")
		}
	})

	// 3. Agent destination policy forbidden
	t.Run("agent destination forbidden", func(t *testing.T) {
		cfg := chainServerCfg(echoAddr)
		cfg.AllowRelayHops = []string{"*"}
		cfg.MaxChainDepth = 2
		srv, _, _ := startRelayCfg(t, cfg)

		// Agent only allows 127.0.0.1:22
		startChainedAgent(t, srv.Addr(), "secure-agent", "127.0.0.1:22", []string{"127.0.0.1:22"})
		waitForAgentTarget(t, srv, "secure-agent", 3*time.Second)

		// Client requests override to echoAddr
		cliCfg := config.DefaultClient()
		cliCfg.StrictHostKeyChecking = "no"
		cliCfg.Server = ""
		cliCfg.Target = "secure-agent"
		cliCfg.Destination = echoAddr
		cliCfg.Jumphost = []string{srv.Addr()}
		cliCfg.Transport = "tcp"
		cliCfg.LogLevel = "error"

		var inBuf, outBuf bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
		if err == nil {
			t.Fatal("expected error when agent policy rejects destination override")
		}
	})
}

func TestChainedJumphostTarget_ResumeOnHopDrop(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	cfg2 := chainServerCfg(echoAddr)
	cfg2.AllowRelayHops = []string{"*"}
	cfg2.MaxChainDepth = 3
	srv2, _, _ := startRelayCfg(t, cfg2)

	cfg1 := chainServerCfg(echoAddr)
	cfg1.AllowRelayHops = []string{srv2.Addr()}
	cfg1.MaxChainDepth = 3
	srv1, _, _ := startRelayCfg(t, cfg1)

	startChainedAgent(t, srv2.Addr(), "homelab", echoAddr, nil)
	waitForAgentTarget(t, srv2, "homelab", 3*time.Second)

	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = ""
	cliCfg.Target = "homelab"
	cliCfg.Jumphost = []string{srv1.Addr(), srv2.Addr()}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"
	cliCfg.ReconnectMaxElapsed = config.Duration(10 * time.Second)
	cliCfg.ReconnectBackoff = []string{"20ms", "50ms"}

	const n = 64 * 1024
	payload := make([]byte, n)
	_, _ = rand.Read(payload)

	inR, inW := io.Pipe()
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, cliCfg, inR, &outBuf, logging.New(io.Discard, "error", "text"))
	}()

	// Write first half
	half := n / 2
	if _, err := inW.Write(payload[:half]); err != nil {
		t.Fatal(err)
	}

	// Wait until both hops have established sessions
	waitUntil(t, 5*time.Second, func() bool {
		return srv1.sessionCount() >= 1 && srv2.sessionCount() >= 1
	})

	// Drop carrier at hop 1
	srv1.dropLiveTransports()

	// Write second half
	if _, err := inW.Write(payload[half:]); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	select {
	case err := <-errc:
		if err != nil && err != context.Canceled {
			t.Fatalf("RunClient: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for RunClient")
	}

	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch after resume: got %d bytes, want %d", outBuf.Len(), len(payload))
	}
}

// TestChainedJumphostTarget_TerminalWithoutRelayHops covers
// `-J jump --server terminal --target name` where the terminal has an empty
// allow_relay_hops: the rendezvous with its own agent is not onward chaining.
func TestChainedJumphostTarget_TerminalWithoutRelayHops(t *testing.T) {
	echoAddr, stopEcho := startTargetTestEcho(t)
	defer stopEcho()

	cfg2 := chainServerCfg(echoAddr)
	cfg2.AllowRelayHops = nil
	srv2, _, _ := startRelayCfg(t, cfg2)

	cfg1 := chainServerCfg(echoAddr)
	cfg1.AllowRelayHops = []string{srv2.Addr()}
	srv1, _, _ := startRelayCfg(t, cfg1)

	startChainedAgent(t, srv2.Addr(), "homelab", echoAddr, nil)
	waitForAgentTarget(t, srv2, "homelab", 3*time.Second)

	cliCfg := config.DefaultClient()
	cliCfg.StrictHostKeyChecking = "no"
	cliCfg.Server = srv2.Addr()
	cliCfg.Target = "homelab"
	cliCfg.Jumphost = []string{srv1.Addr()}
	cliCfg.Transport = "tcp"
	cliCfg.LogLevel = "error"

	payload := make([]byte, 32*1024)
	_, _ = rand.Read(payload)
	var inBuf bytes.Buffer
	inBuf.Write(payload)
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := RunClient(ctx, cliCfg, &inBuf, &outBuf, logging.New(io.Discard, "error", "text"))
	if err != nil && err != context.Canceled {
		t.Fatalf("RunClient: %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", outBuf.Len(), len(payload))
	}
}
