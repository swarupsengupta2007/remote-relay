package transport

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

func TestKCPMuxFrameRoundTrip(t *testing.T) {
	srvMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvMux.Close()
	ln, err := ListenKCP(srvMux.KCP())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan FrameOrErr, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- FrameOrErr{err: err}
			return
		}
		defer conn.Close()
		if conn.Kind() != KindKCP {
			got <- FrameOrErr{err: errKind}
			return
		}
		f, err := conn.ReadFrame()
		got <- FrameOrErr{f: f, err: err}
		if err == nil {
			_ = conn.WriteFrame(proto.Frame{Type: proto.TypePong, Payload: f.Payload})
		}
	}()

	cliMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliMux.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := DialKCP(ctx, cliMux.KCP(), srvMux.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if cli.Kind() != KindKCP {
		t.Fatalf("kind %s", cli.Kind())
	}

	payload := bytes.Repeat([]byte("kcp-stream-"), 100)
	if err := cli.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.f.Type != proto.TypePing || !bytes.Equal(r.f.Payload, payload) {
			t.Fatalf("server got type=%s len=%d", r.f.Type, len(r.f.Payload))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for server read")
	}
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	pong, err := cli.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if pong.Type != proto.TypePong || !bytes.Equal(pong.Payload, payload) {
		t.Fatalf("pong type=%s len=%d", pong.Type, len(pong.Payload))
	}
}

type FrameOrErr struct {
	f   proto.Frame
	err error
}

var errKind = errString("unexpected kind")

type errString string

func (e errString) Error() string { return string(e) }
