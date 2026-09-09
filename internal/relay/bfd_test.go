package relay

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

type mockFrameConn struct {
	in  chan proto.Frame
	out chan proto.Frame
}

func newMockFrameConn() (*mockFrameConn, *mockFrameConn) {
	c1 := make(chan proto.Frame, 64)
	c2 := make(chan proto.Frame, 64)
	return &mockFrameConn{in: c1, out: c2}, &mockFrameConn{in: c2, out: c1}
}

func (m *mockFrameConn) ReadFrame() (proto.Frame, error) {
	f, ok := <-m.in
	if !ok {
		return proto.Frame{}, io.EOF
	}
	return f, nil
}

func (m *mockFrameConn) WriteFrame(f proto.Frame) error {
	select {
	case m.out <- f:
		return nil
	default:
		return errors.New("buffer full")
	}
}

func (m *mockFrameConn) SetDeadline(t time.Time) error { return nil }
func (m *mockFrameConn) LocalAddr() net.Addr           { return mockAddr("local") }
func (m *mockFrameConn) RemoteAddr() net.Addr          { return mockAddr("remote") }
func (m *mockFrameConn) Kind() transport.Kind          { return transport.KindTCP }
func (m *mockFrameConn) Close() error {
	select {
	case <-m.in:
	default:
		close(m.in)
	}
	return nil
}
func (m *mockFrameConn) ResetReader() {}

type mockAddr string

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return string(m) }

func TestPumpBFDHeartbeatExchange(t *testing.T) {
	conn1, conn2 := newMockFrameConn()
	defer conn1.Close()
	defer conn2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	buf := session.NewRing(1024, session.NewBudget(4096))
	p := newPump(ctx, sessionIO{
		outDir: proto.DirUp,
		inDir:  proto.DirDown,
	}, pumpConfig{
		chunk:         64,
		window:        512,
		buffer:        1024,
		heartbeat:     30 * time.Millisecond,
		deadThreshold: 3,
		log:           slog.Default(),
	}, buf)

	errc := make(chan error, 1)
	go func() {
		errc <- p.serveConn(ctx, conn1, 0)
	}()

	// Peer side: read BFD ping from pump
	f1, err := conn2.ReadFrame()
	if err != nil {
		t.Fatalf("read f1 error: %v", err)
	}
	if f1.Type != proto.TypePing {
		t.Fatalf("expected TypePing, got %v", f1.Type)
	}
	pkt1, err := bfd.DecodePacket(f1.Payload)
	if err != nil {
		t.Fatalf("decode pkt1 error: %v", err)
	}
	if pkt1.State != bfd.StateDown {
		t.Fatalf("expected pump initial state Down, got %v", pkt1.State)
	}

	// Peer replies with BFD StateDown adopting pump's discriminator
	peerDisc := uint32(0xCAFE)
	peerPkt := bfd.Packet{
		State:                 bfd.StateDown,
		DetectMult:            3,
		MyDisc:                peerDisc,
		YourDisc:              pkt1.MyDisc,
		DesiredMinTxInterval:  30 * time.Millisecond,
		RequiredMinRxInterval: 30 * time.Millisecond,
	}
	if err := conn2.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: bfd.EncodePacket(peerPkt)}); err != nil {
		t.Fatalf("write peer reply error: %v", err)
	}

	// Read next ping from pump (should be StateInit or StateUp)
	f2, err := conn2.ReadFrame()
	if err != nil {
		t.Fatalf("read f2 error: %v", err)
	}
	pkt2, err := bfd.DecodePacket(f2.Payload)
	if err != nil {
		t.Fatalf("decode pkt2 error: %v", err)
	}
	if pkt2.State != bfd.StateInit && pkt2.State != bfd.StateUp {
		t.Fatalf("expected pump state Init or Up, got %v", pkt2.State)
	}

	// Send Up from peer
	peerPkt.State = bfd.StateUp
	peerPkt.YourDisc = pkt2.MyDisc
	if err := conn2.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: bfd.EncodePacket(peerPkt)}); err != nil {
		t.Fatalf("write peer Up error: %v", err)
	}

	// Read next ping from pump: must be StateUp!
	f3, err := conn2.ReadFrame()
	if err != nil {
		t.Fatalf("read f3 error: %v", err)
	}
	pkt3, err := bfd.DecodePacket(f3.Payload)
	if err != nil {
		t.Fatalf("decode pkt3 error: %v", err)
	}
	if pkt3.State != bfd.StateUp {
		t.Fatalf("expected pump state Up, got %v", pkt3.State)
	}

	cancel()
	_ = conn1.Close()
	_ = conn2.Close()
	<-errc
}

func TestPumpBFDDeadPeerTimeout(t *testing.T) {
	conn1, conn2 := newMockFrameConn()
	defer conn1.Close()
	defer conn2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	buf := session.NewRing(1024, session.NewBudget(4096))
	p := newPump(ctx, sessionIO{
		outDir: proto.DirUp,
		inDir:  proto.DirDown,
	}, pumpConfig{
		chunk:         64,
		window:        512,
		buffer:        1024,
		heartbeat:     25 * time.Millisecond,
		deadThreshold: 3, // 3 * 25ms = 75ms timeout
		log:           slog.Default(),
	}, buf)

	errc := make(chan error, 1)
	go func() {
		errc <- p.serveConn(ctx, conn1, 0)
	}()

	// Read initial ping
	f1, err := conn2.ReadFrame()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	pkt1, err := bfd.DecodePacket(f1.Payload)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Send Up to bring session Up
	peerPkt := bfd.Packet{
		State:                 bfd.StateUp,
		DetectMult:            3,
		MyDisc:                0x5678,
		YourDisc:              pkt1.MyDisc,
		DesiredMinTxInterval:  25 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
	}
	_ = conn2.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: bfd.EncodePacket(peerPkt)})

	// Peer now goes silent!
	start := time.Now()
	// Drain any outgoing frames so pump doesn't block on write
	go func() {
		for {
			if _, err := conn2.ReadFrame(); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-errc:
		elapsed := time.Since(start)
		if !errors.Is(err, ErrDeadPeer) {
			t.Fatalf("expected ErrDeadPeer, got %v", err)
		}
		// With 25ms interval and 3 mult, timeout is 75ms.
		// It should detect within ~75ms to 250ms (well under 500ms!).
		if elapsed > 500*time.Millisecond {
			t.Fatalf("dead peer detection took too long: %v (expected <500ms)", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for dead-peer detection")
	}
}

func TestServerStandbyAttachAndPromotion(t *testing.T) {
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()

	// Destination echo server
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srvCfg := config.DefaultServer()
	srvCfg.ListenTCP = "127.0.0.1:0"
	srvCfg.DefaultDestination = destLn.Addr().String()
	srvCfg.AllowDestinations = []string{destLn.Addr().String(), "*"}
	srvCfg.Transports = []string{"tcp"}
	srvCfg.HeartbeatInterval = config.Duration(30 * time.Millisecond)
	srvCfg.DeadPeerThreshold = 3

	srv := NewServer(srvCfg, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ctx) }()

	// 1. Establish active client connection over TCP
	c1, err := net.Dial("tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	tc1, err := transport.WrapTCP(c1)
	if err != nil {
		t.Fatal(err)
	}

	hFr, _ := proto.MarshalFrame(proto.TypeHello, proto.Hello{
		V:           1,
		Transport:   []string{"tcp"},
		Destination: destLn.Addr().String(),
	})
	if err := tc1.WriteFrame(hFr); err != nil {
		t.Fatal(err)
	}
	hResp, err := tc1.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	var hok proto.HelloOK
	if err := proto.UnmarshalPayload(hResp, &hok); err != nil {
		t.Fatal(err)
	}

	// 2. Establish standby connection over TCP with Role: "standby"
	c2, err := net.Dial("tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	tc2, err := transport.WrapTCP(c2)
	if err != nil {
		t.Fatal(err)
	}

	rFr, _ := proto.MarshalFrame(proto.TypeResume, proto.Resume{
		V:           1,
		SessionID:   hok.SessionID,
		ResumeToken: hok.ResumeToken,
		Transport:   []string{"tcp"},
		Role:        "standby",
	})
	if err := tc2.WriteFrame(rFr); err != nil {
		t.Fatal(err)
	}
	rResp, err := tc2.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	var rok proto.ResumeOK
	if err := proto.UnmarshalPayload(rResp, &rok); err != nil {
		t.Fatal(err)
	}
	if rok.Role != "standby" {
		t.Fatalf("expected ResumeOK with Role: standby, got %q", rok.Role)
	}

	// Standby connection runs BFD exchange
	// Read ping from server on standby
	sbPktFr, err := tc2.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if sbPktFr.Type != proto.TypePing {
		t.Fatalf("expected TypePing on standby, got %v", sbPktFr.Type)
	}
	sbPkt, err := bfd.DecodePacket(sbPktFr.Payload)
	if err != nil {
		t.Fatal(err)
	}

	// Send Up back to bring server's standbyBFD to StateUp
	replyPkt := bfd.Packet{
		State:                 bfd.StateUp,
		DetectMult:            3,
		MyDisc:                0x9999,
		YourDisc:              sbPkt.MyDisc,
		DesiredMinTxInterval:  30 * time.Millisecond,
		RequiredMinRxInterval: 30 * time.Millisecond,
	}
	if err := tc2.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: bfd.EncodePacket(replyPkt)}); err != nil {
		t.Fatal(err)
	}

	// Allow server to process standby Up
	time.Sleep(50 * time.Millisecond)

	// 3. Drop active connection c1!
	_ = tc1.Close()

	// 4. Server should promote standby tc2 to active!
	// Now tc2 should be the active carrier. Send data frame on tc2:
	testData := []byte("hello promoted standby!")
	dataFr := proto.Frame{Type: proto.TypeData, Payload: proto.EncodeData(0, testData)}
	if err := tc2.WriteFrame(dataFr); err != nil {
		t.Fatalf("write data on promoted connection: %v", err)
	}

	// Expect echo response from dest back over tc2
	respFr, err := tc2.ReadFrame()
	if err != nil {
		t.Fatalf("read response from promoted connection: %v", err)
	}
	for respFr.Type == proto.TypePing || respFr.Type == proto.TypeAck {
		respFr, err = tc2.ReadFrame()
		if err != nil {
			t.Fatalf("read after ping/ack: %v", err)
		}
	}
	if respFr.Type != proto.TypeData {
		t.Fatalf("expected TypeData echo, got %v", respFr.Type)
	}
	_, payload, err := proto.DecodeData(respFr.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(testData) {
		t.Fatalf("echo payload mismatch: got %q, want %q", string(payload), string(testData))
	}
}

func TestDualPathClientStandbyPromotion(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srvCfg := config.DefaultServer()
	srvCfg.ListenTCP = "127.0.0.1:0"
	srvCfg.UDPListen = "127.0.0.1:0"
	srvCfg.DefaultDestination = dest
	srvCfg.AllowDestinations = []string{dest, "*"}
	srvCfg.Transports = []string{"quic"}
	srvCfg.HeartbeatInterval = config.Duration(30 * time.Millisecond)
	srvCfg.DeadPeerThreshold = 3
	srvCfg.IdleTimeout = config.Duration(30 * time.Second)
	srvCfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, srvCfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.HAProbeInterval = config.Duration(50 * time.Millisecond)
	ccfg.ProbeTimeout = config.Duration(30 * time.Millisecond)
	ccfg.HeartbeatInterval = config.Duration(30 * time.Millisecond)
	ccfg.DeadPeerThreshold = 3

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, slog.Default())
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()

	// 1. Initially connects on QUIC
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream 64 KiB on active QUIC
	const chunk = 64 << 10
	offset := 0
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 1: %v", err)
	}
	offset += chunk

	// Allow client standby manager time to establish standby TCP connection and converge BFD to Up
	time.Sleep(200 * time.Millisecond)

	// 2. Drop active QUIC on server and block UDP probe
	testDropUDPProbe.Store(true)
	t.Cleanup(func() { testDropUDPProbe.Store(false) })
	srv.dropLiveKind(transport.KindQUIC)

	// Verify server and client promote to TCP
	waitKind(t, srv, transport.KindTCP, 8*time.Second)

	// Stream second chunk over promoted TCP
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 2: %v", err)
	}
	offset += chunk

	// 3. Restore UDP -> client upgrades back to QUIC
	testDropUDPProbe.Store(false)
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream final chunk on restored QUIC
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[offset:])
	}()

	gotDown := <-downCh
	gotUp := <-gotUpCh

	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}

	if got := sha256.Sum256(gotUp); got != upHash {
		t.Fatalf("upstream payload mismatch: got %x want %x", got, upHash)
	}
	if got := sha256.Sum256(gotDown); got != downHash {
		t.Fatalf("downstream payload mismatch: got %x want %x", got, downHash)
	}
}

func TestStandbyTCPDropAndAutoRecovery(t *testing.T) {
	const n = 256 << 10
	upWant := makePattern(n)
	downWant := makePattern(n)
	upHash := sha256.Sum256(upWant)
	downHash := sha256.Sum256(downWant)

	dest, gotUpCh := startBidiDest(t, n, n)
	srvCfg := config.DefaultServer()
	srvCfg.ListenTCP = "127.0.0.1:0"
	srvCfg.UDPListen = "127.0.0.1:0"
	srvCfg.DefaultDestination = dest
	srvCfg.AllowDestinations = []string{dest, "*"}
	srvCfg.Transports = []string{"quic"}
	srvCfg.HeartbeatInterval = config.Duration(30 * time.Millisecond)
	srvCfg.DeadPeerThreshold = 3
	srvCfg.IdleTimeout = config.Duration(30 * time.Second)
	srvCfg.HoldTimeout = config.Duration(30 * time.Second)
	srv, relayAddr, _ := startRelayCfg(t, srvCfg)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ccfg := defaultQUICClient(relayAddr, dest)
	ccfg.AllowHA = true
	ccfg.HAProbeInterval = config.Duration(50 * time.Millisecond)
	ccfg.ProbeTimeout = config.Duration(30 * time.Millisecond)
	ccfg.HeartbeatInterval = config.Duration(30 * time.Millisecond)
	ccfg.DeadPeerThreshold = 3

	errc := make(chan error, 1)
	go func() {
		err := RunClient(ctx, ccfg, inR, outW, slog.Default())
		_ = outW.Close()
		errc <- err
	}()

	downCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		downCh <- b
	}()

	// 1. Initially connects on QUIC
	waitKind(t, srv, transport.KindQUIC, 8*time.Second)

	// Stream 64 KiB on active QUIC
	const chunk = 64 << 10
	offset := 0
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 1: %v", err)
	}
	offset += chunk

	// Wait until standby connection is attached on server
	waitUntil(t, 2*time.Second, func() bool {
		return srv.hasStandby()
	})

	// 2. Sever standby TCP connection! Active QUIC must continue undisturbed!
	srv.dropStandbyConns()

	// Stream second chunk over active QUIC while standby is recovering
	if _, err := inW.Write(upWant[offset : offset+chunk]); err != nil {
		t.Fatalf("write chunk 2: %v", err)
	}
	offset += chunk

	// 3. Client background reconnect loop must autonomously restore standby TCP!
	waitUntil(t, 3*time.Second, func() bool {
		return srv.hasStandby()
	})

	// Stream final chunk on QUIC
	go func() {
		defer inW.Close()
		_, _ = inW.Write(upWant[offset:])
	}()

	gotDown := <-downCh
	gotUp := <-gotUpCh

	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}

	if got := sha256.Sum256(gotUp); got != upHash {
		t.Fatalf("upstream payload mismatch: got %x want %x", got, upHash)
	}
	if got := sha256.Sum256(gotDown); got != downHash {
		t.Fatalf("downstream payload mismatch: got %x want %x", got, downHash)
	}
}
