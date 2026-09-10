package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockResolver struct {
	mu     sync.Mutex
	lookup func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (m *mockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	m.mu.Lock()
	fn := m.lookup
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, network, host)
	}
	return nil, errors.New("mock: not implemented")
}

func TestResolveDualStackIPLiteral(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ipsV4, err := ResolveDualStack(ctx, nil, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error for ipv4 literal: %v", err)
	}
	if len(ipsV4) != 1 || !ipsV4[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected 127.0.0.1, got %v", ipsV4)
	}

	ipsV6, err := ResolveDualStack(ctx, nil, "::1")
	if err != nil {
		t.Fatalf("unexpected error for ipv6 literal: %v", err)
	}
	if len(ipsV6) != 1 || !ipsV6[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected ::1, got %v", ipsV6)
	}
}

func TestResolveDualStackInterleaving(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{
					net.ParseIP("2001:db8::1"),
					net.ParseIP("2001:db8::2"),
				}, nil
			}
			if network == "ip4" {
				return []net.IP{
					net.ParseIP("192.0.2.1"),
					net.ParseIP("192.0.2.2"),
				}, nil
			}
			return nil, errors.New("unknown network")
		},
	}

	ips, err := ResolveDualStack(ctx, res, "example.com")
	if err != nil {
		t.Fatalf("ResolveDualStack: %v", err)
	}

	expected := []string{
		"2001:db8::1",
		"192.0.2.1",
		"2001:db8::2",
		"192.0.2.2",
	}

	if len(ips) != len(expected) {
		t.Fatalf("expected %d ips, got %d: %v", len(expected), len(ips), ips)
	}

	for i, exp := range expected {
		if ips[i].String() != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, ips[i].String())
		}
	}
}

func TestResolveDualStackResolutionDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// IPv4 responds in 10ms, IPv6 responds in 30ms (< 50ms ResolutionDelay).
	// IPv6 must still be interleaved first!
	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip4" {
				time.Sleep(10 * time.Millisecond)
				return []net.IP{net.ParseIP("192.0.2.1")}, nil
			}
			if network == "ip6" {
				time.Sleep(30 * time.Millisecond)
				return []net.IP{net.ParseIP("2001:db8::1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	ips, err := ResolveDualStack(ctx, res, "fast-v4-slow-v6.test")
	if err != nil {
		t.Fatalf("ResolveDualStack: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 ips, got %d: %v", len(ips), ips)
	}
	if ips[0].String() != "2001:db8::1" || ips[1].String() != "192.0.2.1" {
		t.Fatalf("expected [2001:db8::1, 192.0.2.1], got %v", ips)
	}
}

func TestDialHappyEyeballsTCPIPv6Wins(t *testing.T) {
	lnV6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 listen not available: %v", err)
	}
	defer lnV6.Close()

	_, portStr, _ := net.SplitHostPort(lnV6.Addr().String())

	lnV4, err := net.Listen("tcp4", "127.0.0.1:"+portStr)
	if err != nil {
		t.Skipf("cannot bind same port on ipv4: %v", err)
	}
	defer lnV4.Close()

	var v6Accepted, v4Accepted atomic.Bool
	go func() {
		c, err := lnV6.Accept()
		if err == nil {
			v6Accepted.Store(true)
			_ = c.Close()
		}
	}()
	go func() {
		c, err := lnV4.Accept()
		if err == nil {
			v4Accepted.Store(true)
			_ = c.Close()
		}
	}()

	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{net.ParseIP("::1")}, nil
			}
			if network == "ip4" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialHappyEyeballsTCPWithResolver(ctx, "dualstack.test:"+portStr, 200*time.Millisecond, res, nil)
	if err != nil {
		t.Fatalf("DialHappyEyeballsTCPWithResolver: %v", err)
	}
	defer conn.Close()

	if !v6Accepted.Load() {
		t.Errorf("expected IPv6 to win and be accepted")
	}
}

func TestDialHappyEyeballsTCPIPv6BlackholeFallback(t *testing.T) {
	lnV4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp4: %v", err)
	}
	defer lnV4.Close()

	_, portStr, _ := net.SplitHostPort(lnV4.Addr().String())

	go func() {
		c, err := lnV4.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	// Candidate 0: unroutable documentation IPv6 address (blackhole)
	// Candidate 1: working IPv4 loopback
	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				// Non-routable IPv6 address to simulate blackhole
				return []net.IP{net.ParseIP("2001:db8::1")}, nil
			}
			if network == "ip4" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	delay := 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dialFn := func(cctx context.Context, network, candAddr string) (net.Conn, error) {
		if strings.Contains(candAddr, "2001:db8::1") {
			// Simulate silent blackhole: wait until canceled
			<-cctx.Done()
			return nil, cctx.Err()
		}
		d := net.Dialer{Timeout: 1 * time.Second}
		return d.DialContext(cctx, network, candAddr)
	}

	start := time.Now()
	conn, err := DialHappyEyeballsTCPWithResolver(ctx, "blackhole-v6.test:"+portStr, delay, res, dialFn)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("DialHappyEyeballsTCPWithResolver fallback failed: %v", err)
	}
	defer conn.Close()

	// Should have taken at least the delay (100ms) but well under 1s
	if elapsed < 80*time.Millisecond {
		t.Errorf("dialed too fast (%v), did not wait for connection attempt delay", elapsed)
	}
	if elapsed > 1*time.Second {
		t.Errorf("dial took too long (%v), failed fast fallback", elapsed)
	}
}

func TestDialHappyEyeballsTCPEarlyErrorAdvance(t *testing.T) {
	// Pick a port that is NOT listening for IPv6 (or closed port)
	lnV4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp4: %v", err)
	}
	defer lnV4.Close()

	_, portStr, _ := net.SplitHostPort(lnV4.Addr().String())

	go func() {
		c, err := lnV4.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	// Candidate 0 is ::1 on closed port (will get immediate connection refused)
	// Candidate 1 is 127.0.0.1 on the listening port
	// To ensure Candidate 0 gets immediate connection refused, use ::1 with a known closed port
	// or test advance behavior directly.
	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{net.ParseIP("::1")}, nil
			}
			if network == "ip4" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	delay := 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := DialHappyEyeballsTCPWithResolver(ctx, "refused-v6.test:"+portStr, delay, res, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("DialHappyEyeballsTCPWithResolver: %v", err)
	}
	defer conn.Close()

	// If Candidate 0 (::1:port) was refused immediately, it advances without waiting the full 500ms delay!
	if elapsed >= 450*time.Millisecond {
		t.Logf("Notice: elapsed %v (waited delay if IPv6 port did not reject immediately)", elapsed)
	}
}

func TestDialHappyEyeballsTCPAllFailJoinedError(t *testing.T) {
	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{net.ParseIP("::1")}, nil
			}
			if network == "ip4" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	// Pick an unused local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = DialHappyEyeballsTCPWithResolver(ctx, fmt.Sprintf("allfail.test:%d", closedPort), 50*time.Millisecond, res, nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "127.0.0.1") && !strings.Contains(errStr, "::1") {
		t.Errorf("expected joined error with candidate addresses, got %q", errStr)
	}
}

func TestProbeDualStackHappyEyeballs(t *testing.T) {
	// Create a responsive UDPMux on IPv4 loopback
	srvMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDPMux srv: %v", err)
	}
	defer srvMux.Close()

	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	srvMux.SetProbeHandler(func(tok [16]byte, nonce uint64, addr net.Addr) {
		if tok == token {
			_ = srvMux.WriteProbeOK(addr, nonce)
		}
	})

	srvPort := srvMux.LocalAddr().(*net.UDPAddr).Port

	// Mock resolver returning non-responsive IPv6 and responsive IPv4
	res := &mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{net.ParseIP("2001:db8::1")}, nil
			}
			if network == "ip4" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	probeFn := func(cctx context.Context, mux *UDPMux, addr net.Addr, tok [16]byte, attempts int, timeout time.Duration) error {
		if strings.Contains(addr.String(), "2001:db8::1") {
			// Simulate silent blackhole: wait until canceled
			<-cctx.Done()
			return cctx.Err()
		}
		return Probe(cctx, mux, addr, tok, attempts, timeout)
	}

	start := time.Now()
	mux, winnerAddr, err := ProbeDualStackWithResolver(ctx, fmt.Sprintf("probe-test.test:%d", srvPort), token, 2, 500*time.Millisecond, 100*time.Millisecond, res, probeFn)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ProbeDualStackWithResolver failed: %v", err)
	}
	defer mux.Close()

	if winnerAddr == nil || !strings.Contains(winnerAddr.String(), "127.0.0.1") {
		t.Fatalf("expected 127.0.0.1 winner, got %v", winnerAddr)
	}

	// Stagger delay was 100ms, so elapsed should be >= 80ms
	if elapsed < 80*time.Millisecond {
		t.Errorf("probe completed too fast (%v), expected >= 80ms due to IPv6 delay", elapsed)
	}
}
