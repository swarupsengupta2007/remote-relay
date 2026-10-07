//go:build linux

package relay

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// forceFinalizers runs GC until a canary finalizer has executed. A single
// runtime.GC does not guarantee that os.File finalizers have run.
func forceFinalizers(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	armCanaryFinalizer(done)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		select {
		case <-done:
			// One more cycle so any os.File finalizer queued with the canary runs.
			runtime.GC()
			time.Sleep(50 * time.Millisecond)
			return
		case <-time.After(15 * time.Millisecond):
		}
	}
	t.Fatal("finalizer did not run")
}

//go:noinline
func armCanaryFinalizer(done chan struct{}) {
	obj := &[64]byte{}
	runtime.SetFinalizer(obj, func(*[64]byte) { close(done) })
	obj = nil
}

// spliceRetainOnce runs the shipped retain path and returns only the pooled
// retain pipe. Callers must not keep a temporary *os.File alive across GC.
func spliceRetainOnce(t *testing.T) (*pipePair, []byte) {
	t.Helper()
	payload := []byte("teed-retain-bytes")

	var src [2]int
	if err := unix.Pipe2(src[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(src[0])
	defer unix.Close(src[1])
	if _, err := unix.Write(src[1], payload); err != nil {
		t.Fatal(err)
	}

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
	rawTCP := accepted.(*net.TCPConn)

	mid, err := newPipePair(64 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer mid.Close()
	retain, err := newPipePair(64 * 1024)
	if err != nil {
		t.Fatal(err)
	}

	n, retained, err := spliceSrcToSocket(src[0], rawTCP, mid, retain, len(payload), nil, nil)
	if err != nil {
		retain.Close()
		t.Fatalf("spliceSrcToSocket: %v", err)
	}
	if n != int64(len(payload)) || !bytes.Equal(retained, payload) {
		retain.Close()
		t.Fatalf("retain read n=%d data=%q", n, retained)
	}
	return retain, append([]byte(nil), retained...)
}

func TestSpliceRetainFDSurvivesFinalizers(t *testing.T) {
	retain, retained := spliceRetainOnce(t)
	defer retain.Close()
	if len(retained) == 0 {
		t.Fatal("retain path returned no bytes")
	}

	rrfd := retain.R()
	forceFinalizers(t)

	more := []byte("pipe-still-open")
	if _, err := unix.Write(retain.W(), more); err != nil {
		t.Fatalf("write pooled retain fd %d after GC: %v", retain.W(), err)
	}
	buf := make([]byte, len(more))
	if err := readFullFD(rrfd, buf); err != nil {
		t.Fatalf("read pooled retain fd %d after GC: %v", rrfd, err)
	}
	if !bytes.Equal(buf, more) {
		t.Fatalf("pooled retain fd %d read %q, want %q", rrfd, buf, more)
	}
}
