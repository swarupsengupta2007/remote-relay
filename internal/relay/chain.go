package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/session"
	"github.com/remote-relay/relay/internal/transport"
)

// errChainGone marks the onward leg of a chained session as terminally lost
// after nested hold/retry is exhausted. Case D may rebuild before this fires.
var errChainGone = errors.New("onward relay hop lost")

// handleChain serves a CHAIN frame at an intermediate relay. Every hop is a
// full, independent relay session (J-D1): this function terminates the inbound
// hop, performs the onward KEX itself, relays the attestation and the challenge
// back to the originator and the signature forward, and then bridges the two
// data planes through the sessionIO seam (plan §2.1, §2.4).
func (s *Server) handleChain(ctx context.Context, conn transport.Conn, f proto.Frame, ip string, releaseTCP func(), kexNonce string) {
	setupStart := time.Now()
	var ch proto.ChainHello
	if err := proto.UnmarshalPayload(f, &ch); err != nil {
		writeErr(conn, proto.CodeProto, "bad CHAIN")
		return
	}
	if ch.V != 1 {
		writeErr(conn, proto.CodeVersion, "unsupported version")
		return
	}

	selfAddr := conn.LocalAddr().String()
	log := s.log.With("chainId", ch.ChainID, "self", selfAddr)

	if perr := s.chainPolicy(ch, selfAddr); perr != nil {
		s.chainRefused.Add(1)
		log.Warn("chain refused", "code", perr.Code, "reason", perr.Msg, "hops", len(ch.Hops))
		writeErr(conn, perr.Code, perr.Msg)
		return
	}
	if _, _, err := net.SplitHostPort(ch.Destination); err != nil {
		writeErr(conn, proto.CodeProto, "bad destination")
		return
	}

	next := ch.Hops[0]
	tail := ch.Hops[1:]
	// Hop numbering is the originator's: hop 1 is the server it dialled, so this
	// process is len(Visited)+1 and the hop it is about to dial is +2.
	ownHopIndex := len(ch.Visited) + 1
	nextHopIndex := ownHopIndex + 1

	// Authenticate the originator for this hop before committing any onward
	// resource. The challenge binds the exact CHAIN bytes we received, so the
	// originator knows precisely what it authorised.
	id, sess, token, serverNonce, ok := s.chainAuth(conn, ch, f.Payload, ch.Destination, kexNonce, ownHopIndex)
	if !ok {
		return
	}
	sess.Destination = ch.Destination
	sess.AuthMethod = id.Method
	sess.AuthUser = id.Name
	sess.Fingerprint = id.Fingerprint
	sess.PublicKey = id.RawPubKey
	sess.PortForwardingBlocked = id.PortForwardingBlocked
	sess.PermittedDestinations = id.PermittedDestinations

	if id.PortForwardingBlocked {
		s.chainRefused.Add(1)
		s.refused.Add(1)
		writeErr(conn, proto.CodeDestForbidden, "port forwarding is disabled for this key")
		return
	}
	if len(id.PermittedDestinations) > 0 && !config.DestinationAllowed(ch.Destination, id.PermittedDestinations) {
		s.chainRefused.Add(1)
		s.refused.Add(1)
		writeErr(conn, proto.CodeDestForbidden, "destination not allowed by user policy")
		return
	}

	originIP := ch.OriginIP
	if originIP == "" {
		originIP = ip
	}
	releaseChain, err := s.reserveChain(ip, originIP)
	if err != nil {
		s.chainRefused.Add(1)
		s.refused.Add(1)
		var pe *proto.Error
		if errors.As(err, &pe) {
			writeErr(conn, pe.Code, pe.Msg)
			return
		}
		writeErr(conn, proto.CodeNoCapacity, "no capacity")
		return
	}
	chainReleased := false
	defer func() {
		if !chainReleased {
			releaseChain()
		}
	}()

	if err := s.store.Add(sess); err != nil {
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "too many sessions")
		return
	}
	if s.shutting() {
		s.store.Remove(sess.ID)
		writeErr(conn, proto.CodeShutdown, "shutting down")
		return
	}

	nested, perr := s.negotiateOnward(ctx, conn, ch, next, tail, selfAddr, originIP, nextHopIndex, log)
	if perr != nil {
		s.store.Remove(sess.ID)
		s.chainRefused.Add(1)
		log.Warn("onward hop failed", "code", perr.Code, "reason", perr.Msg, "upstream", next.Addr)
		writeErr(conn, perr.Code, perr.Msg)
		return
	}
	s.chainHops.Add(int64(len(ch.Hops)))

	// Ring and window sizing, separately for each leg: the inbound leg obeys
	// what the originator advertised, the onward leg what the next hop did.
	// Both rings are carved out of the same global Budget, so
	// total_buffer_bytes still bounds a chained session and exhaustion refuses
	// new work rather than killing existing sessions (design.md §7.3).
	inBuf := s.chainBufCap(0)
	outBuf := s.chainBufCap(nested.limits.BufferBytes)
	if inBuf <= 0 || outBuf <= 0 {
		nested.close()
		s.store.Remove(sess.ID)
		s.refused.Add(1)
		writeErr(conn, proto.CodeNoCapacity, "buffer budget exhausted")
		return
	}
	cfg := s.Config()
	inWindow := cfg.SendWindow
	if ch.Window > 0 && ch.Window < inWindow {
		inWindow = ch.Window
	}
	outWindow := cfg.SendWindow
	if nested.limits.Window > 0 && nested.limits.Window < outWindow {
		outWindow = nested.limits.Window
	}
	outChunk := clampChunk(nested.limits.DataChunkBytes)
	outSwitch := cfg.SwitchTimeout.Duration()
	if nested.limits.SwitchTimeoutMs > 0 {
		outSwitch = time.Duration(nested.limits.SwitchTimeoutMs) * time.Millisecond
	}

	sessLog := logging.WithSession(log, sess.ID)
	rawConn := unwrapConn(conn)
	nested.log = sessLog

	inRing := session.NewRing(inBuf, s.budget)
	p := newPump(ctx, sessionIO{
		conn:       rawConn,
		src:        nested.fromOnwardR,
		sink:       nested.toOnwardW,
		closeWrite: func() error { return nested.toOnwardW.Close() },
		closeSrc:   func() error { nested.close(); return nil },
		outDir:     proto.DirDown,
		inDir:      proto.DirUp,
	}, pumpConfig{
		chunk:         cfg.DataChunkBytes,
		window:        inWindow,
		buffer:        inBuf,
		keepalive:     cfg.KeepaliveInterval.Duration(),
		idle:          cfg.IdleTimeout.Duration(),
		switchTimeout: cfg.SwitchTimeout.Duration(),
		heartbeat:     cfg.HeartbeatInterval.Duration(),
		deadThreshold: cfg.DeadPeerThreshold,
		log:           sessLog,
		// J-D13: the bridge is an in-memory pipe, not a socket, so there is no
		// fd to splice from or to.
		splice: false,
	}, inRing)
	nested.onGone = func(gone error) {
		nested.close()
		if gone == nil {
			return
		}
		// Expire rather than remove so a client that races a RESUME gets
		// ERR_EXPIRED instead of attaching to a chain with no onward leg.
		s.store.Expire(sess.ID)
		s.chainGone.Add(1)
		sessLog.Warn("onward hop lost; ending chained session", "upstream", next.Addr, "err", gone)
		p.fail(errChainGone)
	}
	// The onward leg starts once the inbound pump exists: onGone reaches into
	// it, and the inbound pump reads the bridge the onward leg writes.
	nested.start(ctx, outBuf, outChunk, outWindow, outSwitch)

	l := &live{
		pump:         p,
		id:           sess.ID,
		srv:          s,
		store:        s.store,
		cfg:          cfg,
		window:       inWindow,
		holdTimeout:  cfg.HoldTimeout.Duration(),
		nested:       nested,
		releaseChain: releaseChain,
		log:          sessLog,
		clientIP:     "",
		// The TCP connection accounting is released when the carrier is first
		// served, exactly as for a direct session.
		releaseHelloTCP: releaseTCP,
		attachCh:        make(chan attachReq, 4),
		deadCh:          make(chan struct{}),
	}
	l.onPeerFrame = func() { l.store.ConfirmToken(l.id) }
	nested.inbound = l
	nested.hopIndex = nextHopIndex
	p.cfg.onAuth = func(a proto.Auth) error { return l.deliverChainAuth(a) }
	s.livesMu.Lock()
	s.lives[sess.ID] = l
	s.livesMu.Unlock()
	chainReleased = true
	defer func() {
		s.livesMu.Lock()
		delete(s.lives, sess.ID)
		s.livesMu.Unlock()
		l.cleanup(false)
	}()

	// Report the hop we just terminated, then our own HELLO_OK. Deeper CHAIN_OK
	// frames were already forwarded during negotiation, so the originator sees
	// hops in increasing order followed by the HELLO_OK of the hop it dialled.
	chainOK, err := proto.MarshalFrame(proto.TypeChainOK, proto.ChainHelloOK{
		V:         1,
		Hop:       nextHopIndex,
		Addr:      next.Addr,
		SessionID: nested.sessionID,
		Transport: nested.transport,
		Limits:    nested.limits,
		SetupMs:   time.Since(setupStart).Milliseconds(),
	})
	if err != nil {
		return
	}
	if err := writeFrameDeadline(conn, chainOK); err != nil {
		return
	}

	selected, udp := s.pickTransport(ch.Transport, sess.ID, conn.LocalAddr())
	okMsg := proto.HelloOK{
		V:           1,
		SessionID:   sess.ID,
		ResumeToken: token,
		Transport:   selected,
		UDP:         udp,
		Limits: proto.Limits{
			BufferBytes:     inBuf,
			HoldTimeoutMs:   int(cfg.HoldTimeout.Duration() / time.Millisecond),
			Window:          inWindow,
			DataChunkBytes:  cfg.DataChunkBytes,
			SwitchTimeoutMs: int(cfg.SwitchTimeout.Duration() / time.Millisecond),
		},
		ServerNonce: serverNonce,
	}
	fr, err := proto.MarshalFrame(proto.TypeHelloOK, okMsg)
	if err != nil {
		return
	}
	if err := writeFrameDeadline(conn, fr); err != nil {
		return
	}
	sessLog.Info("chained session started",
		"dest", ch.Destination, "peer", rawConn.RemoteAddr().String(),
		"upstream", next.Addr, "hop", ownHopIndex, "hops", len(ch.Hops)+1,
		"originIp", originIP, "transport", selected)
	l.run(ctx, rawConn)
}

func (l *live) ensureNestedLive(ctx context.Context, inbound transport.Conn) error {
	n := l.nested
	if n == nil {
		return nil
	}
	if n.pump != nil && n.pump.linkUp.Load() {
		return nil
	}
	wait := l.cfg.ChainAuthTimeout.Duration()
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if n.pump != nil && n.pump.linkUp.Load() {
			return nil
		}
		if n.termError() != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	if n.pump != nil && n.pump.linkUp.Load() {
		return nil
	}
	if n.termError() == nil {
		// Nested is between serveConn attempts (Case B). Rebuilding now
		// would cancel a live pump; hop-1 resume can proceed.
		return nil
	}
	return l.rebuildNested(ctx, inbound)
}

func (l *live) rebuildNested(ctx context.Context, inbound transport.Conn) error {
	n := l.nested
	if n == nil || l.srv == nil {
		return proto.ErrExpired
	}
	oldGone := n.onGone
	n.onGone = nil
	if n.cancel != nil {
		n.cancel()
	}
	n.closeConn()
	if n.runDone != nil {
		select {
		case <-n.runDone:
		case <-ctx.Done():
			n.onGone = oldGone
			return ctx.Err()
		}
	}

	ch := n.chainHello
	next := n.hop
	var tail []proto.HopSpec
	if len(ch.Hops) > 1 {
		tail = ch.Hops[1:]
	}
	nn, perr := l.srv.negotiateOnward(ctx, inbound, ch, next, tail, n.selfAddr, n.originIP, n.hopIndex, n.log)
	if perr != nil {
		n.onGone = oldGone
		if oldGone != nil {
			oldGone(perr)
		}
		return perr
	}
	conn := nn.takeConn()
	_ = nn.toOnwardR.Close()
	_ = nn.toOnwardW.Close()
	_ = nn.fromOnwardR.Close()
	_ = nn.fromOnwardW.Close()

	n.mu.Lock()
	n.termErr = nil
	n.sessionID = nn.sessionID
	n.token = nn.token
	n.limits = nn.limits
	n.transport = nn.transport
	n.udp = nn.udp
	n.holdTimeout = nn.holdTimeout
	n.resumeCfg = nn.resumeCfg
	n.conn = conn
	n.mu.Unlock()
	n.onGone = oldGone
	if n.pump == nil || n.parentCtx == nil {
		n.start(n.parentCtx, n.startBuf, n.startChunk, n.startWin, n.startSw)
		return nil
	}
	n.relaunch()
	return nil
}

func (l *live) relayChainAuth(aok proto.AuthOK) (proto.Auth, error) {
	var none proto.Auth
	if l.pump == nil {
		return none, proto.NewError(proto.CodeAuth, "no inbound pump")
	}
	if !l.pump.holdChainAuth() {
		return none, errChainAuthRetry
	}
	defer l.pump.releaseChainAuth()

	max := l.cfg.ChainAuthRelaysMax
	if max > 0 && int(l.chainAuthN.Load()) >= max {
		return none, proto.NewError(proto.CodeAuth, "too many relayed challenges")
	}
	l.chainAuthN.Add(1)
	if l.srv != nil {
		l.srv.chainAuthRelays.Add(1)
	}

	timeout := l.cfg.ChainAuthTimeout.Duration()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	replyCh := make(chan proto.Auth, 1)
	l.mu.Lock()
	l.chainAuthCh = replyCh
	l.chainAuthHop = aok.Hop
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.chainAuthCh = nil
		l.mu.Unlock()
	}()

	fr, err := proto.MarshalFrame(proto.TypeAuthOK, aok)
	if err != nil {
		return none, err
	}
	if err := l.sendCtrl(fr); err != nil {
		return none, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case a := <-replyCh:
		return a, nil
	case <-timer.C:
		return none, errChainAuthTimeout
	case <-l.sessCtx.Done():
		return none, l.sessCtx.Err()
	}
}

func (l *live) deliverChainAuth(a proto.Auth) error {
	l.mu.Lock()
	ch := l.chainAuthCh
	hop := l.chainAuthHop
	l.mu.Unlock()
	if ch == nil {
		return proto.NewError(proto.CodeProto, "unexpected AUTH")
	}
	if a.Hop != 0 && a.Hop != hop {
		return proto.NewError(proto.CodeProto, "AUTH hop does not match the outstanding challenge")
	}
	select {
	case ch <- a:
		return nil
	default:
		return proto.NewError(proto.CodeProto, "AUTH dropped")
	}
}

// chainPolicy applies every refusal that does not need a dial, in the order the
// plan specifies: default-deny allow list, then depth, then loops. Checking the
// whole remaining path rather than just the next hop (J-D9) means a chain that
// would be refused three hops in is refused before any resource is committed.
func (s *Server) chainPolicy(ch proto.ChainHello, selfAddr string) *proto.Error {
	if len(ch.Hops) == 0 {
		return proto.NewError(proto.CodeProto, "CHAIN without hops; send HELLO instead")
	}
	// J-D8: chaining is default-deny. Without this any authenticated client
	cfg := s.Config()
	if len(cfg.AllowRelayHops) == 0 {
		return proto.NewError(proto.CodeHopForbidden, "chaining is not enabled on this server")
	}
	for _, h := range ch.Hops {
		if _, _, err := net.SplitHostPort(h.Addr); err != nil {
			return proto.NewError(proto.CodeProto, "bad hop address "+h.Addr)
		}
		if !config.HopAllowed(h.Addr, cfg.AllowRelayHops) {
			return proto.NewError(proto.CodeHopForbidden, "relay hop not allowed: "+h.Addr)
		}
	}
	if len(ch.Hops)+1 > cfg.MaxChainDepth {
		return proto.NewError(proto.CodeChainTooLong,
			"chain of "+strconv.Itoa(len(ch.Hops)+1)+" exceeds max_chain_depth "+strconv.Itoa(cfg.MaxChainDepth))
	}
	// JR9: hairpin and mutual-reference loops.
	self := s.chainSelfAddrs(selfAddr)
	for _, v := range ch.Visited {
		if addrsMatch(self, v) {
			return proto.NewError(proto.CodeChainLoop, "this relay already appears in the chain")
		}
	}
	for i, h := range ch.Hops {
		if addrsMatch(self, h.Addr) {
			return proto.NewError(proto.CodeChainLoop, "chain would loop back to this relay")
		}
		for j := i + 1; j < len(ch.Hops); j++ {
			if addrEqual(h.Addr, ch.Hops[j].Addr) {
				return proto.NewError(proto.CodeChainLoop, "relay hop repeated in chain: "+h.Addr)
			}
		}
	}
	return nil
}

// chainSelfAddrs lists every address this process answers on, so a hairpin is
// caught whichever form the originator used to name it.
func (s *Server) chainSelfAddrs(selfAddr string) []string {
	out := make([]string, 0, 4)
	cfg := s.Config()
	for _, a := range []string{selfAddr, s.Addr(), cfg.ListenTCP, cfg.UDPListen, cfg.UDPAnnounce} {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func addrsMatch(self []string, addr string) bool {
	for _, a := range self {
		if addrEqual(a, addr) {
			return true
		}
	}
	return false
}

// addrEqual compares two host:port strings for loop detection. A wildcard bind
// host matches any host on the same port: a server listening on 0.0.0.0:7443 is
// reachable as every one of its local addresses.
func addrEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ah, ap, aerr := net.SplitHostPort(a)
	bh, bp, berr := net.SplitHostPort(b)
	if aerr != nil || berr != nil || ap != bp {
		return false
	}
	return isWildcardHost(ah) || isWildcardHost(bh)
}

func isWildcardHost(h string) bool {
	if h == "" {
		return true
	}
	ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
	return ip != nil && ip.IsUnspecified()
}

// chainAuth issues this hop's own challenge for a CHAIN request and verifies the
// originator's signature. The AuthOK carries Hop and the canonical CHAIN bytes
// but no attestation: the originator ran this KEX itself.
func (s *Server) chainAuth(conn transport.Conn, ch proto.ChainHello, canonical []byte, dest, kexNonce string, hop int) (auth.Identity, *session.Session, string, string, bool) {
	var offer auth.Offer
	if err := json.Unmarshal(bytesOrEmpty(ch.Auth), &offer); err != nil || offer.Method != auth.MethodPublicKey {
		s.authFail(conn, time.Time{})
		return auth.Identity{}, nil, "", "", false
	}
	sess, token, err := session.New()
	if err != nil {
		writeErr(conn, proto.CodeInternal, "session allocate")
		return auth.Identity{}, nil, "", "", false
	}
	serverNonce, err := authServerNonce(kexNonce)
	if err != nil {
		writeErr(conn, proto.CodeInternal, "nonce")
		return auth.Identity{}, nil, "", "", false
	}
	ac := auth.Challenge{
		SessionID:   sess.ID,
		Destination: dest,
		ClientNonce: ch.ClientNonce,
		ServerNonce: serverNonce,
		Canonical:   canonical,
		Offer:       ch.Auth,
	}
	id, ok := s.challengeAndVerify(conn, ac, hop, string(canonical), nil)
	if !ok {
		return auth.Identity{}, nil, "", "", false
	}
	return id, sess, token, serverNonce, true
}

// negotiateOnward dials the next hop, performs its KEX, and relays challenges,
// attestations and signatures between that hop and the originator until the
// onward session is established.
func (s *Server) negotiateOnward(
	ctx context.Context,
	inbound transport.Conn,
	ch proto.ChainHello,
	next proto.HopSpec,
	tail []proto.HopSpec,
	selfAddr, originIP string,
	nextHopIndex int,
	log *slog.Logger,
) (*nestedHop, *proto.Error) {
	cfg := s.Config()
	dialCtx, cancelDial := context.WithTimeout(ctx, cfg.DialTimeout.Duration())
	var oconn transport.Conn
	var err error
	if len(next.Transport) > 0 && (strings.EqualFold(next.Transport[0], "ws") || strings.EqualFold(next.Transport[0], "websocket")) {
		oconn, err = transport.DialWebSocket(dialCtx, next.Addr, &transport.WebSocketDialOptions{
			Timeout:   cfg.DialTimeout.Duration(),
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		})
	} else {
		oconn, err = transport.DialTCPWithDelayAndBind(dialCtx, next.Addr, transport.DefaultConnectionAttemptDelay, transport.BindConfig{})
	}
	cancelDial()
	if err != nil {
		return nil, proto.NewError(proto.CodeDestRefused, "dial onward hop failed")
	}
	fail := func(pe *proto.Error) (*nestedHop, *proto.Error) {
		_ = oconn.Close()
		return nil, pe
	}

	// Onward KEX. This process — not the originator — is the KEX party, so the
	// transcript it produces is what it must attest back (J-D3).
	kexCli, err := kex.NewClientSession()
	if err != nil {
		return fail(proto.NewError(proto.CodeInternal, "kex init failed"))
	}
	initPayload := kexCli.InitPayload()
	_ = oconn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := oconn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: initPayload}); err != nil {
		return fail(proto.NewError(proto.CodeDestRefused, "onward hop handshake failed"))
	}
	reply, err := oconn.ReadFrame()
	_ = oconn.SetDeadline(time.Time{})
	if err != nil || reply.Type != proto.TypeKexReply {
		return fail(proto.NewError(proto.CodeDestRefused, "onward hop handshake failed"))
	}
	verifyHostKey := func(pub ed25519.PublicKey) error {
		return s.verifyOnwardHostKey(next, pub, log)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, verifyHostKey)
	if err != nil {
		log.Warn("onward hop host key rejected", "upstream", next.Addr, "err", err)
		s.chainAttestFailures.Add(1)
		return fail(proto.NewError(proto.CodeDestRefused, "onward hop host key verification failed"))
	}
	cipher, err := kex.NewCipherConn(oconn, c2sKey, s2cKey)
	if err != nil {
		return fail(proto.NewError(proto.CodeInternal, "onward cipher failed"))
	}

	attest := &proto.HopAttestation{
		Addr:     next.Addr,
		KexInit:  base64.StdEncoding.EncodeToString(initPayload),
		KexReply: base64.StdEncoding.EncodeToString(reply.Payload),
	}
	if len(reply.Payload) == kex.KexReplyLen {
		if line, lerr := kex.RawEd25519ToAuthorizedKeysLine(reply.Payload[48:80]); lerr == nil {
			attest.HostKeySSH = line
		}
	}

	// Build the onward frame. An empty tail means the next hop is the terminal,
	// which receives an ordinary HELLO and needs no chaining code at all
	// (§2.3). The canonical bytes are echoed back to the originator as
	// AuthOK.helloJson so it can recompute the challenge it is signing.
	onwardNonce, err := proto.RandomNonce()
	if err != nil {
		_ = cipher.Close()
		return nil, proto.NewError(proto.CodeInternal, "nonce")
	}
	visited := make([]string, 0, len(ch.Visited)+1)
	visited = append(visited, ch.Visited...)
	visited = append(visited, selfAddr)
	pref := chainHopTransport(next, log)
	var onward proto.Frame
	if len(tail) > 0 {
		onward, err = proto.MarshalFrame(proto.TypeChain, proto.ChainHello{
			V:           1,
			ChainID:     ch.ChainID,
			Hops:        tail,
			Destination: ch.Destination,
			Visited:     visited,
			OriginIP:    originIP,
			Transport:   pref,
			ClientNonce: onwardNonce,
			Auth:        ch.Auth,
			Window:      cfg.SendWindow,
		})
	} else {
		onward, err = proto.MarshalFrame(proto.TypeHello, proto.Hello{
			V:           1,
			Transport:   pref,
			Destination: ch.Destination,
			ClientNonce: onwardNonce,
			Auth:        ch.Auth,
			Window:      cfg.SendWindow,
		})
	}
	if err != nil {
		_ = cipher.Close()
		return nil, proto.NewError(proto.CodeInternal, "encode onward hello")
	}
	canonical := onward.Payload
	_ = cipher.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := cipher.WriteFrame(onward); err != nil {
		_ = cipher.Close()
		return nil, proto.NewError(proto.CodeDestRefused, "onward hop handshake failed")
	}

	n := newNestedHop(s, log, next, ch.Destination, ch.ChainID, s.nestedClientConfig(next, ch.Destination))
	n.chainHello = ch
	n.selfAddr = selfAddr
	n.originIP = originIP
	n.hopIndex = nextHopIndex
	n.setConn(cipher.Underlying())

	relays := 0
	for {
		_ = cipher.SetDeadline(time.Now().Add(handshakeTimeout))
		fr, rerr := cipher.ReadFrame()
		_ = cipher.SetDeadline(time.Time{})
		if rerr != nil {
			_ = cipher.Close()
			return nil, proto.NewError(proto.CodeDestRefused, "onward hop handshake failed")
		}
		switch fr.Type {
		case proto.TypeAuthOK:
			var aok proto.AuthOK
			if uerr := proto.UnmarshalPayload(fr, &aok); uerr != nil {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeProto, "bad onward AUTH_OK")
			}
			if aok.Hop == 0 || aok.Hop == nextHopIndex {
				// The challenge belongs to the hop we just dialled, so we are
				// the party that can attest its host key. A terminal sends
				// hop=0; a deeper intermediate already labelled it.
				aok.Hop = nextHopIndex
				aok.Attest = attest
				aok.HelloJSON = string(canonical)
			}
			if relays >= cfg.ChainAuthRelaysMax {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeAuth, "too many relayed challenges")
			}
			relays++
			s.chainAuthRelays.Add(1)
			if werr := s.relayFrameInbound(inbound, proto.TypeAuthOK, aok); werr != nil {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeAuth, "originator went away during chain auth")
			}
			sig, aerr := s.readRelayedAuth(inbound, aok.Hop)
			if aerr != nil {
				_ = cipher.Close()
				return nil, aerr
			}
			_ = cipher.SetDeadline(time.Now().Add(handshakeTimeout))
			if werr := cipher.WriteFrame(sig); werr != nil {
				_ = cipher.SetDeadline(time.Time{})
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeDestRefused, "onward hop handshake failed")
			}
			_ = cipher.SetDeadline(time.Time{})

		case proto.TypeChainOK:
			// Already labelled by the intermediate that terminated that hop.
			var ok proto.ChainHelloOK
			if uerr := proto.UnmarshalPayload(fr, &ok); uerr != nil {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeProto, "bad onward CHAIN_OK")
			}
			s.chainHops.Add(1)
			if werr := s.relayFrameInbound(inbound, proto.TypeChainOK, ok); werr != nil {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeAuth, "originator went away during chain setup")
			}

		case proto.TypeHelloOK:
			var ok proto.HelloOK
			if uerr := proto.UnmarshalPayload(fr, &ok); uerr != nil {
				_ = cipher.Close()
				return nil, proto.NewError(proto.CodeProto, "bad onward HELLO_OK")
			}
			if ok.V != 1 {
				_ = cipher.Close()
				return nil, proto.ErrVersion
			}
			n.sessionID = ok.SessionID
			n.token = ok.ResumeToken
			n.limits = ok.Limits
			n.transport = ok.Transport
			n.udp = ok.UDP
			n.holdTimeout = time.Duration(ok.Limits.HoldTimeoutMs) * time.Millisecond
			_ = cipher.SetDeadline(time.Time{})
			log.Info("onward hop established", "upstream", next.Addr, "hop", nextHopIndex,
				"upstreamSession", ok.SessionID, "transport", ok.Transport)
			return n, nil

		case proto.TypeErr, proto.TypeResumeFail:
			var fl proto.Fail
			_ = proto.UnmarshalPayload(fr, &fl)
			if fl.Code == "" {
				fl.Code = proto.CodeInternal
			}
			_ = cipher.Close()
			return nil, proto.NewError(fl.Code, fl.Msg)

		default:
			_ = cipher.Close()
			return nil, proto.NewError(proto.CodeProto, "unexpected onward frame "+fr.Type.String())
		}
	}
}

// relayFrameInbound forwards a control frame to the originator on the inbound
// control channel, which is still in its handshake phase.
func (s *Server) relayFrameInbound(conn transport.Conn, typ proto.Type, v any) error {
	fr, err := proto.MarshalFrame(typ, v)
	if err != nil {
		return err
	}
	return writeFrameDeadline(conn, fr)
}

// readRelayedAuth waits for the originator's signature over a relayed
// challenge, bounded by chain_auth_timeout so a silent client cannot wedge an
// intermediate. The hop tag is stripped before the signature goes onward: the
// challenge binds the HELLO bytes, never the AUTH bytes.
func (s *Server) readRelayedAuth(conn transport.Conn, hop int) (proto.Frame, *proto.Error) {
	cfg := s.Config()
	timeout := cfg.ChainAuthTimeout.Duration()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var none proto.Frame
	_ = conn.SetDeadline(time.Now().Add(timeout))
	fr, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return none, proto.NewError(proto.CodeAuth, "originator did not answer relayed challenge")
	}
	if fr.Type != proto.TypeAuth {
		return none, proto.NewError(proto.CodeProto, "expected AUTH, got "+fr.Type.String())
	}
	var a proto.Auth
	if uerr := proto.UnmarshalPayload(fr, &a); uerr != nil || a.Sig == "" {
		return none, proto.NewError(proto.CodeProto, "bad AUTH")
	}
	if a.Hop != 0 && a.Hop != hop {
		return none, proto.NewError(proto.CodeProto, "AUTH hop does not match the outstanding challenge")
	}
	out, merr := proto.MarshalFrame(proto.TypeAuth, proto.Auth{Sig: a.Sig})
	if merr != nil {
		return none, proto.NewError(proto.CodeInternal, "encode AUTH")
	}
	return out, nil
}

// verifyOnwardHostKey checks the next hop's host key from this process's point
// of view. The authoritative check is the originator's: it re-verifies the
// relayed transcript against its own known_hosts or pin before it will sign
// anything (J-D3), so an intermediate that cannot verify locally is a defence
// in depth, not the last line.
func (s *Server) verifyOnwardHostKey(next proto.HopSpec, pub ed25519.PublicKey, log *slog.Logger) error {
	cfg := s.Config()
	if next.Fp == "" && strings.TrimSpace(cfg.RelayKnownHosts) == "" {
		log.Warn("onward hop host key not verified locally; relying on the originator's attestation check " +
			"(set relay_known_hosts to verify here too)")
		return nil
	}
	return kex.VerifyKnownHosts(cfg.RelayKnownHosts, next.Addr, pub, next.Fp, cfg.RelayStrictHostKeyChecking)
}

// chainHopTransport picks the onward transport preference. An empty hop
// transport omits the list so the next server picks (same as a bare HELLO).
// A single name expands through TransportPreferenceList (quic ⇒ quic,kcp).
func chainHopTransport(next proto.HopSpec, log *slog.Logger) []string {
	if len(next.Transport) == 0 {
		return nil
	}
	if len(next.Transport) == 1 {
		return config.TransportPreferenceList(next.Transport[0])
	}
	return next.Transport
}

// nestedClientConfig synthesises the client-side configuration for the onward
// leg, so the existing resume machinery (clientResume → writeResumeRole) can
// drive it. It carries no identity material: Case C relays a fresh challenge
// to the originator instead of signing here.
func (s *Server) nestedClientConfig(next proto.HopSpec, dest string) config.Client {
	c := config.DefaultClient()
	cfg := s.Config()
	c.Server = next.Addr
	c.Destination = dest
	c.Transport = "tcp"
	if len(next.Transport) > 0 {
		c.Transport = next.Transport[0]
	}
	c.AuthMethod = cfg.AuthMethod
	c.AuthUser = next.User
	c.KnownHosts = cfg.RelayKnownHosts
	c.ServerFingerprint = next.Fp
	c.StrictHostKeyChecking = cfg.RelayStrictHostKeyChecking
	// Unattended intermediates cannot TOFU. If this process has neither a pin
	// nor relay_known_hosts, skip local verification: the originator still
	// checks every relayed transcript (J-D3), including Case C resume KEX.
	if next.Fp == "" && strings.TrimSpace(cfg.RelayKnownHosts) == "" {
		c.StrictHostKeyChecking = "no"
	}
	c.HeartbeatInterval = cfg.HeartbeatInterval
	c.DeadPeerThreshold = cfg.DeadPeerThreshold
	c.KeepaliveInterval = cfg.KeepaliveInterval
	c.IdleTimeout = cfg.IdleTimeout
	c.ReconnectMaxElapsed = cfg.HoldTimeout
	c.AllowHA = next.AllowHA
	c.Splice = false
	c.AdaptiveKCP = cfg.AdaptiveKCP
	c.LogLevel = cfg.LogLevel
	c.LogFormat = cfg.LogFormat
	return c
}

// chainBufCap sizes one ring of a chained session against the shared Budget,
// mirroring the clipping handleHello applies to a direct session.
func (s *Server) chainBufCap(peerLimit int) int {
	cfg := s.Config()
	cap := cfg.BufferBytes
	if peerLimit > 0 && peerLimit < cap {
		cap = peerLimit
	}
	if rem := s.budget.Remaining(); rem > 0 && rem < int64(cap) {
		cap = int(rem)
	}
	if cap <= 0 {
		return 0
	}
	return cap
}

// reserveChain accounts a chained session against the originator rather than the
// upstream relay (J-D14), and separately bounds what one upstream relay may open
// (JR4). Without the first, every chained session arrives from the
// intermediate's single address and trips max_conns_per_ip almost immediately.
func (s *Server) reserveChain(peerIP, originIP string) (func(), error) {
	cfg := s.Config()
	if limit := cfg.ChainSessionLimit(); limit > 0 && int(s.chainActive.Load()) >= limit {
		return nil, proto.NewError(proto.CodeNoCapacity, "chain session limit reached")
	}
	acct := originIP
	if acct == "" {
		acct = peerIP
	}
	if err := s.tryReserveIPSess(acct); err != nil {
		return nil, err
	}
	s.ipMu.Lock()
	if s.chainPeers == nil {
		s.chainPeers = make(map[string]int)
	}
	if max := cfg.MaxChainConnsPerPeer; max > 0 && s.chainPeers[peerIP] >= max {
		s.ipMu.Unlock()
		s.decIPSess(acct)
		return nil, proto.NewError(proto.CodeNoCapacity, "too many chained sessions from this upstream relay")
	}
	s.chainPeers[peerIP]++
	s.ipMu.Unlock()
	s.chainActive.Add(1)

	var once sync.Once
	return func() {
		once.Do(func() {
			s.chainActive.Add(-1)
			s.decIPSess(acct)
			s.ipMu.Lock()
			if s.chainPeers != nil {
				s.chainPeers[peerIP]--
				if s.chainPeers[peerIP] <= 0 {
					delete(s.chainPeers, peerIP)
				}
			}
			s.ipMu.Unlock()
		})
	}, nil
}
