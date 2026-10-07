//go:build linux

package relay

import (
	"net"
	"testing"

	"github.com/remote-relay/relay/internal/obs"
	"github.com/remote-relay/relay/internal/proto"
	"golang.org/x/sys/unix"
)

func TestSplicePathCountsTransferredBytes(t *testing.T) {
	payload := []byte("spliced-bytes-xyz")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	var sink [2]int
	if err := unix.Pipe2(sink[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sink[0])
	defer unix.Close(sink[1])
	mid, err := newPipePair(64 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer mid.Close()

	m := obs.NewMetrics()
	n, err := spliceSocketToSink(accepted.(*net.TCPConn), sink[1], mid, len(payload), &byteAcct{
		metrics:   m,
		dir:       proto.DirUp,
		transport: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("spliced %d, want %d", n, len(payload))
	}
	got := make([]byte, len(payload))
	if err := readFullFD(sink[0], got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("spliced payload %q", got)
	}
	if counted := m.BytesTransferred.WithLabelValues("up", "tcp").Get(); counted != float64(len(payload)) {
		t.Fatalf("relay_bytes_transferred_total=%v, want %d", counted, len(payload))
	}
}
