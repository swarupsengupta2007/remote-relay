//go:build !windows

package relay

import (
	"bytes"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/session"
)

func TestSendReceiveHandover(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "parent")
	childFile := os.NewFile(uintptr(fds[1]), "child")
	defer parentFile.Close()
	defer childFile.Close()

	parentConn, err := net.FileConn(parentFile)
	if err != nil {
		t.Fatalf("FileConn parent: %v", err)
	}
	defer parentConn.Close()

	childConn, err := net.FileConn(childFile)
	if err != nil {
		t.Fatalf("FileConn child: %v", err)
	}
	defer childConn.Close()

	parentUnix := parentConn.(*net.UnixConn)
	childUnix := childConn.(*net.UnixConn)

	// Create dummy files to pass across socket
	pipeR1, pipeW1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeR1.Close()
	defer pipeW1.Close()

	pipeR2, pipeW2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeR2.Close()
	defer pipeW2.Close()

	sess, _, err := session.New()
	if err != nil {
		t.Fatal(err)
	}
	sess.Destination = "10.0.0.1:22"
	snapSess := sess.Snapshot()

	state := HandoverState{
		Version:      1,
		Timestamp:    time.Now().UTC().Truncate(time.Second),
		HasListenTCP: true,
		HasListenUDP: true,
		Sessions: []HandoverSession{
			{
				Session:         snapSess,
				UpAcked:         1024,
				DownNext:        2048,
				UpClosed:        false,
				DownClosed:      true,
				SendLogBase:     1024,
				SendLogData:     []byte("test-send-log-bytes-payload"),
				SendLogCap:      65536,
				RemainingHoldMs: 25000,
				ClientIP:        "192.168.1.50",
				HasDestFD:       false,
			},
		},
	}

	filesToSend := []*os.File{pipeR1, pipeR2}

	// Send in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- SendHandover(parentUnix, state, filesToSend)
	}()

	recvState, recvFiles, err := ReceiveHandover(childUnix)
	if err != nil {
		t.Fatalf("ReceiveHandover: %v", err)
	}
	defer func() {
		for _, f := range recvFiles {
			_ = f.Close()
		}
	}()

	if err := <-errCh; err != nil {
		t.Fatalf("SendHandover: %v", err)
	}

	if len(recvFiles) != 2 {
		t.Fatalf("expected 2 received files, got %d", len(recvFiles))
	}

	// Test writing to pipeW1 and reading from recvFiles[0]
	testMsg := []byte("hello passed socket!")
	if _, err := pipeW1.Write(testMsg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(recvFiles[0], buf); err != nil {
		t.Fatalf("read from received FD 0: %v", err)
	}
	if !bytes.Equal(buf, testMsg) {
		t.Fatalf("received fd content: got %q want %q", buf, testMsg)
	}

	// Verify state fields
	if recvState.Version != 1 {
		t.Fatalf("expected version 1, got %d", recvState.Version)
	}
	if !recvState.HasListenTCP || !recvState.HasListenUDP {
		t.Fatal("expected HasListenTCP and HasListenUDP to be true")
	}
	if len(recvState.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(recvState.Sessions))
	}
	s0 := recvState.Sessions[0]
	if s0.Session.ID != sess.ID {
		t.Fatalf("session ID: got %s want %s", s0.Session.ID, sess.ID)
	}
	if s0.UpAcked != 1024 || s0.DownNext != 2048 {
		t.Fatalf("stream offsets mismatch: upAcked=%d downNext=%d", s0.UpAcked, s0.DownNext)
	}
	if !bytes.Equal(s0.SendLogData, []byte("test-send-log-bytes-payload")) {
		t.Fatalf("sendLog data mismatch: %q", s0.SendLogData)
	}
	if s0.RemainingHoldMs != 25000 {
		t.Fatalf("remainingHoldMs: got %d want 25000", s0.RemainingHoldMs)
	}
}
