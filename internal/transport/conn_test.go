package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

func TestKindString(t *testing.T) {
	if KindTCP.String() != "tcp" {
		t.Fatalf("expected tcp, got %s", KindTCP)
	}
	if KindQUIC.String() != "quic" {
		t.Fatalf("expected quic, got %s", KindQUIC)
	}
	if KindKCP.String() != "kcp" {
		t.Fatalf("expected kcp, got %s", KindKCP)
	}
	if Kind(99).String() != "unknown" {
		t.Fatalf("expected unknown, got %s", Kind(99))
	}
}

func TestLoadOrGenerateCert(t *testing.T) {
	// Ephemeral path
	c1, err := LoadOrGenerateCert("", "")
	if err != nil {
		t.Fatalf("LoadOrGenerateCert empty: %v", err)
	}
	if len(c1.Certificate) == 0 {
		t.Fatal("expected certificate in c1")
	}

	// Test error when file does not exist
	if _, err := LoadOrGenerateCert("/nonexistent/cert", "/nonexistent/key"); err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

func TestTCPTransport(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		c, err := WrapTCP(raw)
		if err != nil {
			raw.Close()
			errCh <- err
			return
		}
		defer c.Close()

		if c.Kind() != KindTCP {
			t.Errorf("expected KindTCP, got %v", c.Kind())
		}
		if c.LocalAddr() == nil || c.RemoteAddr() == nil {
			t.Errorf("nil addr")
		}

		fr, err := c.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- c.WriteFrame(fr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialTCP(ctx, addr)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()

	if client.Kind() != KindTCP {
		t.Fatalf("expected KindTCP, got %v", client.Kind())
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	want := proto.Frame{Type: proto.TypePing, Payload: []byte("ping")}
	if err := client.WriteFrame(want); err != nil {
		t.Fatalf("client WriteFrame: %v", err)
	}
	got, err := client.ReadFrame()
	if err != nil {
		t.Fatalf("client ReadFrame: %v", err)
	}
	if got.Type != want.Type || string(got.Payload) != string(want.Payload) {
		t.Fatalf("frame mismatch: got %+v, want %+v", got, want)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server err: %v", err)
	}

	// WrapTCP on non-TCP conn
	pipeR, _ := net.Pipe()
	defer pipeR.Close()
	if _, err := WrapTCP(pipeR); err == nil {
		t.Fatal("expected error wrapping non-TCP conn")
	}
}
