package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestMuxTagRoundTrip(t *testing.T) {
	a, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	dst := b.LocalAddr()
	payload := []byte("hello-quic")
	if _, err := a.QUIC().WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = b.QUIC().SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := b.QUIC().ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestMuxDoesNotSniff(t *testing.T) {
	a, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// 0x80 looks like a QUIC long header; without tag 0x02 it must not reach QUIC.
	raw := []byte{0x80, 0x01, 0x02, 0x03}
	if _, err := a.conn.WriteTo(raw, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = b.QUIC().SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	if _, _, err := b.QUIC().ReadFrom(buf); err == nil {
		t.Fatal("untagged QUIC-looking datagram was delivered")
	}

	kcp := []byte("kcp-payload")
	if _, err := a.KCP().WriteTo(kcp, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = b.KCP().SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := b.KCP().ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], kcp) {
		t.Fatalf("kcp got %q", buf[:n])
	}
}

func TestMuxProbeRoundTrip(t *testing.T) {
	srv, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	var want [16]byte
	want[0] = 9
	srv.SetProbeHandler(func(token [16]byte, nonce uint64, addr net.Addr) {
		if token != want {
			return
		}
		_ = srv.WriteProbeOK(addr, nonce)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Probe(ctx, cli, srv.LocalAddr(), want, 2, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestParseProbeToken(t *testing.T) {
	var tok [16]byte
	tok[15] = 0xff
	s := EncodeProbeToken(tok)
	got, ok := ParseProbeToken(s)
	if !ok || got != tok {
		t.Fatalf("round trip %v %v", ok, got)
	}
	if _, ok := ParseProbeToken("not-base64"); ok {
		t.Fatal("accepted junk")
	}
	if _, ok := ParseProbeToken(EncodeProbeToken(tok) + "aa"); ok {
		t.Fatal("accepted oversize")
	}
}
