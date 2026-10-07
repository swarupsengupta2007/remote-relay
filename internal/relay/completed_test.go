package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/proto"
)

// A client that loses the link right after the server's BYE resumes into a
// session the server already finished. The server must answer with the final
// offsets, only to a holder of the resume token.
func TestResumeAfterCompletionReportsFinalOffsets(t *testing.T) {
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		c, err := destLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.ReadAll(c)
		_, _ = c.Write([]byte("pong"))
	}()
	dest := destLn.Addr().String()

	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest}
	cfg.Transports = []string{"tcp"}
	cfg.Splice = false
	srv, addr, _ := startRelayCfg(t, cfg)

	ccfg := config.DefaultClient()
	ccfg.Server = addr
	ccfg.Destination = dest
	ccfg.Transport = "tcp"
	ccfg.StrictHostKeyChecking = "no"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, hok, err := clientHello(ctx, ccfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Upstream: "ping", then close the up direction.
	writeFrame := func(typ proto.Type, payload []byte) {
		t.Helper()
		if err := conn.WriteFrame(proto.Frame{Type: typ, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	writeFrame(proto.TypeData, proto.EncodeData(0, []byte("ping")))
	cd, err := proto.MarshalFrame(proto.TypeCloseDir, proto.CloseDir{Dir: proto.DirUp, FinalOffset: 4})
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(cd.Type, cd.Payload)

	// Downstream: take "pong" and its CLOSE_DIR, acknowledge, wait for BYE.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var down []byte
	for {
		f, err := conn.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v (down=%q)", err, down)
		}
		if f.Type == proto.TypeData {
			_, data, err := proto.DecodeData(f.Payload)
			if err != nil {
				t.Fatal(err)
			}
			down = append(down, data...)
			writeFrame(proto.TypeAck, proto.EncodeAck(uint64(len(down))))
		}
		if f.Type == proto.TypeBye {
			break
		}
	}
	if string(down) != "pong" {
		t.Fatalf("downstream = %q, want pong", down)
	}
	_ = conn.Close() // as if the BYE had been lost with the link
	waitUntil(t, 5*time.Second, func() bool { return srv.sessionCount() == 0 })

	_, _, err = clientResume(ctx, ccfg, hok.SessionID, hok.ResumeToken, uint64(len(down)))
	var done *proto.CompletedError
	if !errors.As(err, &done) {
		t.Fatalf("resume after completion: got %v, want CompletedError", err)
	}
	if done.Final != (proto.Completed{UpFinal: 4, DownFinal: 4}) {
		t.Fatalf("final offsets = %+v, want up=4 down=4", done.Final)
	}
	var pe *proto.Error
	if !errors.As(err, &pe) || pe.Code != proto.CodeUnknownSession {
		t.Fatalf("code = %v, want %s for older clients", err, proto.CodeUnknownSession)
	}

	_, _, err = clientResume(ctx, ccfg, hok.SessionID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 4)
	if errors.As(err, &done) {
		t.Fatal("completed offsets disclosed without the resume token")
	}
}

func TestFinishFromCompletedRequiresExactOffsets(t *testing.T) {
	newPump := func() *pump {
		p := &pump{kick: make(chan struct{}, 1)}
		p.outEOF.Store(true)
		p.outFinal.Store(100)
		p.delivered.Store(50)
		return p
	}
	for _, tc := range []struct {
		name  string
		final proto.Completed
		setup func(*pump)
		ok    bool
	}{
		{name: "match", final: proto.Completed{UpFinal: 100, DownFinal: 50}, ok: true},
		{name: "server missed upstream bytes", final: proto.Completed{UpFinal: 90, DownFinal: 50}},
		{name: "client missed downstream bytes", final: proto.Completed{UpFinal: 100, DownFinal: 60}},
		{name: "upstream still open", final: proto.Completed{UpFinal: 100, DownFinal: 50},
			setup: func(p *pump) { p.outEOF.Store(false) }},
		{name: "close offset disagrees", final: proto.Completed{UpFinal: 100, DownFinal: 50},
			setup: func(p *pump) { p.inGotClose.Store(true); p.inFinal.Store(40) }},
	} {
		p := newPump()
		if tc.setup != nil {
			tc.setup(p)
		}
		if got := p.finishFromCompleted(tc.final); got != tc.ok {
			t.Fatalf("%s: finishFromCompleted = %v, want %v", tc.name, got, tc.ok)
		}
		if tc.ok && (!p.finished.Load() || !p.inGotClose.Load() || p.inFinal.Load() != tc.final.DownFinal) {
			t.Fatalf("%s: session not marked finished", tc.name)
		}
	}
}
