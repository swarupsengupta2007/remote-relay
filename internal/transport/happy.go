package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	// DefaultResolutionDelay is the maximum RFC 8305 §3 duration to wait for IPv4
	// DNS responses when IPv6 responses arrive first (or vice versa).
	DefaultResolutionDelay = 50 * time.Millisecond

	// DefaultConnectionAttemptDelay is the RFC 8305 §5 stagger duration between
	// starting consecutive connection attempts to different address candidates.
	DefaultConnectionAttemptDelay = 250 * time.Millisecond
)

// IPResolver resolves IP addresses for hostnames by network family.
type IPResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// ResolveDualStack queries IPv6 (AAAA) and IPv4 (A) records concurrently,
// applies RFC 8305 §3 Resolution Delay (50ms), and returns an interleaved
// list of IP addresses with IPv6 preferred first. If host is already an IP literal,
// it returns that IP immediately without DNS queries.
func ResolveDualStack(ctx context.Context, resolver IPResolver, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	type lookupResult struct {
		ips []net.IP
		err error
	}

	chV6 := make(chan lookupResult, 1)
	chV4 := make(chan lookupResult, 1)

	go func() {
		ips, err := resolver.LookupIP(ctx, "ip6", host)
		chV6 <- lookupResult{ips: ips, err: err}
	}()

	go func() {
		ips, err := resolver.LookupIP(ctx, "ip4", host)
		chV4 <- lookupResult{ips: ips, err: err}
	}()

	var resV6, resV4 lookupResult
	var gotV6, gotV4 bool

	// Wait for the first response
	select {
	case resV6 = <-chV6:
		gotV6 = true
	case resV4 = <-chV4:
		gotV4 = true
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Handle Resolution Delay according to RFC 8305 §3
	if gotV6 {
		if resV6.err == nil && len(resV6.ips) > 0 {
			// IPv6 succeeded first: wait up to ResolutionDelay for IPv4
			timer := time.NewTimer(DefaultResolutionDelay)
			select {
			case resV4 = <-chV4:
				timer.Stop()
				gotV4 = true
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		} else {
			// IPv6 failed early: wait for IPv4 unconditionally
			select {
			case resV4 = <-chV4:
				gotV4 = true
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	} else if gotV4 {
		if resV4.err == nil && len(resV4.ips) > 0 {
			// IPv4 succeeded first: give IPv6 a chance to arrive within ResolutionDelay
			timer := time.NewTimer(DefaultResolutionDelay)
			select {
			case resV6 = <-chV6:
				timer.Stop()
				gotV6 = true
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		} else {
			// IPv4 failed early: wait for IPv6 unconditionally
			select {
			case resV6 = <-chV6:
				gotV6 = true
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	// Filter and sanitize into distinct IPv6 and IPv4 buckets
	var v6, v4 []net.IP
	if gotV6 && resV6.err == nil {
		for _, ip := range resV6.ips {
			if ip.To4() == nil {
				v6 = append(v6, ip)
			}
		}
	}
	if gotV4 && resV4.err == nil {
		for _, ip := range resV4.ips {
			if ip.To4() != nil {
				v4 = append(v4, ip)
			}
		}
	}

	// RFC 8305 §5 Address Interleaving (IPv6 first, then IPv4)
	var interleaved []net.IP
	maxLen := len(v6)
	if len(v4) > maxLen {
		maxLen = len(v4)
	}
	for i := 0; i < maxLen; i++ {
		if i < len(v6) {
			interleaved = append(interleaved, v6[i])
		}
		if i < len(v4) {
			interleaved = append(interleaved, v4[i])
		}
	}

	if len(interleaved) == 0 {
		var errs []error
		if resV6.err != nil {
			errs = append(errs, fmt.Errorf("ipv6: %w", resV6.err))
		}
		if resV4.err != nil {
			errs = append(errs, fmt.Errorf("ipv4: %w", resV4.err))
		}
		if len(errs) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		return nil, errors.Join(errs...)
	}

	return interleaved, nil
}

// TCPDialFunc is a function that dials a TCP network address with context.
type TCPDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialHappyEyeballsTCP dials a remote TCP host:port implementing RFC 8305 Happy Eyeballs v2.
func DialHappyEyeballsTCP(ctx context.Context, addr string, delay time.Duration) (Conn, error) {
	return DialHappyEyeballsTCPWithResolver(ctx, addr, delay, nil, nil)
}

// DialHappyEyeballsTCPWithResolver dials with an explicit IPResolver and optional dial function for testing.
func DialHappyEyeballsTCPWithResolver(ctx context.Context, addr string, delay time.Duration, resolver IPResolver, dialFn TCPDialFunc) (Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := ResolveDualStack(ctx, resolver, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	if delay <= 0 {
		delay = DefaultConnectionAttemptDelay
	}

	if dialFn == nil {
		dialFn = func(cctx context.Context, network, candAddr string) (net.Conn, error) {
			d := net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: tcpKeepAlive,
			}
			return d.DialContext(cctx, network, candAddr)
		}
	}

	if len(ips) == 1 {
		target := net.JoinHostPort(ips[0].String(), port)
		c, err := dialFn(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		return WrapTCP(c)
	}

	candidates := make([]string, len(ips))
	for i, ip := range ips {
		candidates[i] = net.JoinHostPort(ip.String(), port)
	}

	type dialWinner struct {
		conn net.Conn
		addr string
	}

	winnerCh := make(chan dialWinner, 1)
	errCh := make(chan error, len(candidates))
	advanceCh := make(chan struct{}, len(candidates))

	raceCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	dialOne := func(candAddr string) {
		c, err := dialFn(raceCtx, "tcp", candAddr)
		if err != nil {
			errCh <- fmt.Errorf("%s: %w", candAddr, err)
			select {
			case advanceCh <- struct{}{}:
			default:
			}
			return
		}

		select {
		case winnerCh <- dialWinner{conn: c, addr: candAddr}:
		default:
			_ = c.Close()
		}
	}

	for i := 0; i < len(candidates); i++ {
		go dialOne(candidates[i])

		if i < len(candidates)-1 {
			timer := time.NewTimer(delay)
			select {
			case win := <-winnerCh:
				timer.Stop()
				cancelAll()
				return WrapTCP(win.conn)
			case <-advanceCh:
				timer.Stop()
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}

	var errs []error
	for len(errs) < len(candidates) {
		select {
		case win := <-winnerCh:
			cancelAll()
			return WrapTCP(win.conn)
		case err := <-errCh:
			errs = append(errs, err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.Join(errs...)
}

// ProbeFunc is a function that performs a UDP probe to addr.
type ProbeFunc func(ctx context.Context, mux *UDPMux, addr net.Addr, token [16]byte, attempts int, timeout time.Duration) error

// ProbeDualStack probes candidate UDP endpoints using family-specific UDPMux sockets
// with RFC 8305 staggered connection attempt racing. The winning UDPMux and remote address
// are retained and returned; losing sockets are cleanly closed.
func ProbeDualStack(ctx context.Context, hostPort string, token [16]byte, attempts int, timeout time.Duration, delay time.Duration) (*UDPMux, net.Addr, error) {
	return ProbeDualStackWithResolver(ctx, hostPort, token, attempts, timeout, delay, nil, nil)
}

// ProbeDualStackWithResolver probes candidate UDP endpoints with an explicit IPResolver and optional ProbeFunc for testing.
func ProbeDualStackWithResolver(ctx context.Context, hostPort string, token [16]byte, attempts int, timeout time.Duration, delay time.Duration, resolver IPResolver, probeFn ProbeFunc) (*UDPMux, net.Addr, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid udp port %q: %w", portStr, err)
	}

	ips, err := ResolveDualStack(ctx, resolver, host)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	if delay <= 0 {
		delay = DefaultConnectionAttemptDelay
	}
	if attempts <= 0 {
		attempts = 2
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if probeFn == nil {
		probeFn = Probe
	}

	candAddrs := make([]*net.UDPAddr, len(ips))
	for i, ip := range ips {
		candAddrs[i] = &net.UDPAddr{IP: ip, Port: portNum}
	}

	if len(candAddrs) == 1 {
		mux, err := ListenUDPMux(UDPBindAll(candAddrs[0]))
		if err != nil {
			return nil, nil, err
		}
		if err := Probe(ctx, mux, candAddrs[0], token, attempts, timeout); err != nil {
			_ = mux.Close()
			return nil, nil, err
		}
		return mux, candAddrs[0], nil
	}

	var (
		muxV6   *UDPMux
		errV6   error
		muxV4   *UDPMux
		errV4   error
		muxLock sync.Mutex
	)

	getMuxFor := func(addr *net.UDPAddr) (*UDPMux, error) {
		muxLock.Lock()
		defer muxLock.Unlock()
		if addr.IP.To4() != nil {
			if muxV4 == nil && errV4 == nil {
				muxV4, errV4 = ListenUDPMux("0.0.0.0:0")
			}
			return muxV4, errV4
		}
		if muxV6 == nil && errV6 == nil {
			muxV6, errV6 = ListenUDPMux("[::]:0")
		}
		return muxV6, errV6
	}

	closeLoserMux := func(winnerMux *UDPMux) {
		muxLock.Lock()
		defer muxLock.Unlock()
		if winnerMux == muxV6 && muxV4 != nil {
			_ = muxV4.Close()
			muxV4 = nil
		} else if winnerMux == muxV4 && muxV6 != nil {
			_ = muxV6.Close()
			muxV6 = nil
		}
	}

	closeAllMuxes := func() {
		muxLock.Lock()
		defer muxLock.Unlock()
		if muxV6 != nil {
			_ = muxV6.Close()
			muxV6 = nil
		}
		if muxV4 != nil {
			_ = muxV4.Close()
			muxV4 = nil
		}
	}

	type probeWinner struct {
		mux  *UDPMux
		addr net.Addr
	}

	winnerCh := make(chan probeWinner, 1)
	errCh := make(chan error, len(candAddrs))
	advanceCh := make(chan struct{}, len(candAddrs))

	raceCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	probeOne := func(addr *net.UDPAddr) {
		mux, err := getMuxFor(addr)
		if err != nil {
			errCh <- fmt.Errorf("%s mux: %w", addr.String(), err)
			select {
			case advanceCh <- struct{}{}:
			default:
			}
			return
		}
		err = probeFn(raceCtx, mux, addr, token, attempts, timeout)
		if err != nil {
			errCh <- fmt.Errorf("%s probe: %w", addr.String(), err)
			select {
			case advanceCh <- struct{}{}:
			default:
			}
			return
		}

		select {
		case winnerCh <- probeWinner{mux: mux, addr: addr}:
		default:
		}
	}

	for i := 0; i < len(candAddrs); i++ {
		go probeOne(candAddrs[i])

		if i < len(candAddrs)-1 {
			timer := time.NewTimer(delay)
			select {
			case win := <-winnerCh:
				timer.Stop()
				cancelAll()
				closeLoserMux(win.mux)
				return win.mux, win.addr, nil
			case <-advanceCh:
				timer.Stop()
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				closeAllMuxes()
				return nil, nil, ctx.Err()
			}
		}
	}

	var errs []error
	for len(errs) < len(candAddrs) {
		select {
		case win := <-winnerCh:
			cancelAll()
			closeLoserMux(win.mux)
			return win.mux, win.addr, nil
		case err := <-errCh:
			errs = append(errs, err)
		case <-ctx.Done():
			closeAllMuxes()
			return nil, nil, ctx.Err()
		}
	}

	closeAllMuxes()
	return nil, nil, errors.Join(errs...)
}
