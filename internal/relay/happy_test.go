package relay

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func TestRelayHappyEyeballsClientConnectAndTransfer(t *testing.T) {
	dest := echoDest(t)
	srv, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	fingerprint := srv.HostFingerprint()
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("unexpected host fingerprint: %s", fingerprint)
	}

	cliCfg := config.DefaultClient()
	cliCfg.Server = srvAddr
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.ServerFingerprint = fingerprint
	cliCfg.StrictHostKeyChecking = "yes"
	cliCfg.LogLevel = "error"
	cliCfg.HappyEyeballsDelay = config.Duration(100 * time.Millisecond)

	log := logging.New(io.Discard, "error", "text")

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, cliCfg, inR, outW, log)
	}()

	testPayload := []byte("happy-eyeballs-v2-dual-stack-relay-test-payload")
	go func() {
		_, _ = inW.Write(testPayload)
		_ = inW.Close()
	}()

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(outR, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}

	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("payload mismatch: got %q, want %q", string(buf), string(testPayload))
	}
}

func TestRelayHappyEyeballsHAStandbyCarrier(t *testing.T) {
	dest := echoDest(t)
	srv, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	fingerprint := srv.HostFingerprint()

	cliCfg := config.DefaultClient()
	cliCfg.Server = srvAddr
	cliCfg.Destination = dest
	cliCfg.Transport = "quic"
	cliCfg.AllowHA = true
	cliCfg.ServerFingerprint = fingerprint
	cliCfg.StrictHostKeyChecking = "yes"
	cliCfg.LogLevel = "error"
	cliCfg.HappyEyeballsDelay = config.Duration(100 * time.Millisecond)

	log := logging.New(io.Discard, "error", "text")

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, cliCfg, inR, outW, log)
	}()

	testPayload := []byte("happy-eyeballs-ha-standby-dual-stack-test-payload")
	go func() {
		_, _ = inW.Write(testPayload)
		_ = inW.Close()
	}()

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(outR, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}

	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("payload mismatch: got %q, want %q", string(buf), string(testPayload))
	}
}

func TestRelayInterfaceAndSourceIP_TCPAndUDP(t *testing.T) {
	dest := echoDest(t)
	srv, srvAddr, cancel := startRelay(t, dest)
	defer cancel()

	fingerprint := srv.HostFingerprint()

	cliCfg := config.DefaultClient()
	cliCfg.Server = srvAddr
	cliCfg.Destination = dest
	cliCfg.Transport = "tcp"
	cliCfg.TCPInterface = "lo"
	cliCfg.TCPSourceIP = "127.0.0.1"
	cliCfg.UDPInterface = "lo"
	cliCfg.UDPSourceIP = "127.0.0.1"
	cliCfg.ServerFingerprint = fingerprint
	cliCfg.StrictHostKeyChecking = "yes"
	cliCfg.LogLevel = "error"
	cliCfg.HappyEyeballsDelay = config.Duration(100 * time.Millisecond)

	log := logging.New(io.Discard, "error", "text")

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	errc := make(chan error, 1)
	go func() {
		errc <- RunClient(ctx, cliCfg, inR, outW, log)
	}()

	testPayload := []byte("interface-and-source-ip-split-legs-test-payload")
	go func() {
		_, _ = inW.Write(testPayload)
		_ = inW.Close()
	}()

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(outR, buf); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}

	if !bytes.Equal(buf, testPayload) {
		t.Fatalf("payload mismatch: got %q, want %q", string(buf), string(testPayload))
	}
}
