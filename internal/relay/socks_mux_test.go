package relay

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/socks5"
)

func TestSocksMuxReaderNotBlockedByFullStream(t *testing.T) {
	cfg := config.DefaultServer()
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)
	defer srv.Close()

	toMuxR, toMuxW := io.Pipe()
	fromMuxR, fromMuxW := io.Pipe()
	defer toMuxW.Close()
	defer fromMuxW.Close()
	go func() { _, _ = io.Copy(io.Discard, fromMuxR) }()

	smux := newSocksServerMux(srv, "s-socks", toMuxR, toMuxW, fromMuxR, fromMuxW, false, nil)
	st1 := &serverStream{
		id:         1,
		dataCh:     make(chan []byte, 64),
		resetCh:    make(chan struct{}),
		readerDone: make(chan struct{}),
		writerDone: make(chan struct{}),
	}
	st2 := &serverStream{
		id:         2,
		dataCh:     make(chan []byte, 64),
		resetCh:    make(chan struct{}),
		readerDone: make(chan struct{}),
		writerDone: make(chan struct{}),
	}
	for i := 0; i < cap(st1.dataCh); i++ {
		st1.dataCh <- []byte("saturated")
	}
	smux.mu.Lock()
	smux.streams[1] = st1
	smux.streams[2] = st2
	smux.mu.Unlock()

	ctx := t.Context()
	go smux.Run(ctx)

	first := []byte("stream-1-first")
	second := []byte("stream-1-second")
	want := []byte("stream-2-proceeds")
	start := time.Now()
	for _, payload := range [][]byte{first, second} {
		if err := socks5.WriteMuxFrame(toMuxW, socks5.MuxFrame{
			StreamID: 1,
			Type:     socks5.TypeStreamData,
			Payload:  payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := socks5.WriteMuxFrame(toMuxW, socks5.MuxFrame{
		StreamID: 2,
		Type:     socks5.TypeStreamData,
		Payload:  want,
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-st2.dataCh:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("stream 2 waited %s behind a full stream", elapsed)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("stream 2 got %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("stream 2 did not receive data within 1s")
	}

	// The pre-filled buffer, then the two saturated-stream frames in order.
	got := make([][]byte, 0, cap(st1.dataCh)+2)
	for i := 0; i < cap(st1.dataCh)+2; i++ {
		select {
		case b := <-st1.dataCh:
			got = append(got, b)
		case <-time.After(time.Second):
			t.Fatalf("stream 1 delivered %d/%d frames", i, cap(st1.dataCh)+2)
		}
	}
	if !bytes.Equal(got[len(got)-2], first) || !bytes.Equal(got[len(got)-1], second) {
		t.Fatalf("saturated stream reordered: last two %q %q, want %q %q", got[len(got)-2], got[len(got)-1], first, second)
	}
}
