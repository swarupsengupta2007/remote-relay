package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

func TestQUICTransport(t *testing.T) {
	qconf := NewQUICConfig(30*time.Second, 5*time.Second, 1024*1024)
	if qconf.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("unexpected MaxIdleTimeout %v", qconf.MaxIdleTimeout)
	}

	// Tiny window clamping check
	tinyConf := NewQUICConfig(10*time.Second, 1*time.Second, 64*1024)
	if tinyConf.InitialStreamReceiveWindow < 512*1024 {
		t.Fatalf("window should be clamped to at least 512KB")
	}

	cert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatalf("GenerateEphemeralCert: %v", err)
	}
	tlsConf := ServerTLSConfig(cert)

	srvPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer srvPacketConn.Close()

	srvAddr := srvPacketConn.LocalAddr()

	// Missing TLS config error check
	if _, err := ListenQUIC(srvPacketConn, nil, qconf); err == nil {
		t.Fatal("expected error with nil tlsConf")
	}

	ln, err := ListenQUIC(srvPacketConn, tlsConf, qconf)
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	defer ln.Close()

	if ln.Addr() == nil {
		t.Fatal("expected non-nil Addr()")
	}

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		qconn, err := ln.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}

		c, err := AcceptQUICConn(ctx, qconn)
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()

		if c.Kind() != KindQUIC {
			t.Errorf("expected KindQUIC, got %v", c.Kind())
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

	cliPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket cli: %v", err)
	}
	defer cliPacketConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialQUIC(ctx, cliPacketConn, srvAddr, qconf)
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	defer client.Close()

	if client.Kind() != KindQUIC {
		t.Fatalf("expected KindQUIC, got %v", client.Kind())
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	want := proto.Frame{Type: proto.TypePing, Payload: []byte("quic-ping")}
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
}
