package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/crypto/kex"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

// clientChainHello is the originator handshake for -J: dial hop 1, send
// TypeChain instead of TypeHello, then verify-and-sign every hop's challenge
// (J-D2 / J-D3) until hop 1's HELLO_OK arrives.
func clientChainHello(ctx context.Context, cfg config.Client, jumphosts []proto.HopSpec) (transport.Conn, proto.HelloOK, error) {
	var none proto.HelloOK
	log := logging.NewClient(cfg.LogLevel, cfg.LogFormat)

	hops := make([]proto.HopSpec, 0, len(jumphosts)+1)
	hops = append(hops, jumphosts...)
	hops = append(hops, proto.HopSpec{
		Addr:      cfg.Server,
		Transport: cfg.TransportPreference(),
		Fp:        cfg.ServerFingerprint,
		User:      cfg.AuthUser,
	})
	first := hops[0]

	tcpBind := transport.BindConfig{
		Interface: cfg.TCPInterface,
		SourceIP:  net.ParseIP(cfg.TCPSourceIP),
	}
	var conn transport.Conn
	var err error
	if len(first.Transport) > 0 && (first.Transport[0] == "ws" || first.Transport[0] == "websocket") {
		wsOpts := &transport.WebSocketDialOptions{
			Bind:      tcpBind,
			Timeout:   handshakeTimeout,
			TLSConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecure},
		}
		conn, err = transport.DialWebSocket(ctx, first.Addr, wsOpts)
		if err != nil {
			return nil, none, fmt.Errorf("dial websocket jumphost: %w", err)
		}
	} else {
		conn, err = transport.DialTCPWithDelayAndBind(ctx, first.Addr, cfg.HappyEyeballsDelay.Duration(), tcpBind)
		if err != nil {
			return nil, none, fmt.Errorf("dial jumphost: %w", err)
		}
	}

	kexCli, err := kex.NewClientSession()
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("kex new client session: %w", err)
	}
	if err := conn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, none, err
	}
	if err := conn.WriteFrame(proto.Frame{Type: proto.TypeKexInit, Payload: kexCli.InitPayload()}); err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("send KEX_INIT: %w", err)
	}
	reply, err := conn.ReadFrame()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("read KEX_REPLY: %w", err)
	}
	if reply.Type != proto.TypeKexReply {
		_ = conn.Close()
		return nil, none, proto.NewError(proto.CodeProto, "expected KEX_REPLY, got "+reply.Type.String())
	}
	verifyHostKey := func(pub ed25519.PublicKey) error {
		return kex.VerifyKnownHosts(cfg.KnownHosts, first.Addr, pub, first.Fp, cfg.StrictHostKeyChecking)
	}
	c2sKey, s2cKey, err := kexCli.ProcessReply(reply.Payload, verifyHostKey)
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("kex verify reply: %w", err)
	}
	cipherConn, err := kex.NewCipherConn(conn, c2sKey, s2cKey)
	if err != nil {
		_ = conn.Close()
		return nil, none, fmt.Errorf("create cipher conn: %w", err)
	}

	a := clientAuth(cfg)
	if c, ok := a.(io.Closer); ok {
		defer c.Close()
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	chainID, err := proto.RandomNonce()
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	authMsg, err := a.Respond(auth.Challenge{Destination: cfg.Destination, ClientNonce: nonce})
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}

	hop1Pref := cfg.TransportPreference()
	if len(first.Transport) > 0 {
		hop1Pref = first.Transport
	}
	hello := proto.ChainHello{
		V:           1,
		ChainID:     chainID,
		Hops:        hops[1:],
		Destination: cfg.Destination,
		Transport:   hop1Pref,
		ClientNonce: nonce,
		Auth:        authMsg,
		Window:      cfg.SendWindow,
	}
	fr, err := proto.MarshalFrame(proto.TypeChain, hello)
	if err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	if err := cipherConn.SetDeadline(deadlineOr(ctx, handshakeTimeout)); err != nil {
		_ = cipherConn.Close()
		return nil, none, err
	}
	if err := cipherConn.WriteFrame(fr); err != nil {
		_ = cipherConn.Close()
		return nil, none, fmt.Errorf("send CHAIN: %w", err)
	}

	readTimeout := handshakeTimeout + config.DefaultServer().DialTimeout.Duration()
	var holdSum time.Duration
	for {
		if err := cipherConn.SetDeadline(deadlineOr(ctx, readTimeout)); err != nil {
			_ = cipherConn.Close()
			return nil, none, err
		}
		reply, err = cipherConn.ReadFrame()
		if err != nil {
			_ = cipherConn.Close()
			return nil, none, fmt.Errorf("read chain handshake: %w", err)
		}
		switch reply.Type {
		case proto.TypeAuthOK:
			if err := completeChainAuth(cipherConn, a, cfg, hops, cfg.Destination, authMsg, reply); err != nil {
				_ = cipherConn.Close()
				return nil, none, err
			}
		case proto.TypeChainOK:
			var ok proto.ChainHelloOK
			if err := proto.UnmarshalPayload(reply, &ok); err != nil {
				_ = cipherConn.Close()
				return nil, none, err
			}
			log.Info("chain hop ready", "hop", ok.Hop, "addr", ok.Addr,
				"setupMs", ok.SetupMs, "transport", ok.Transport)
			if ok.Limits.HoldTimeoutMs > 0 {
				holdSum += time.Duration(ok.Limits.HoldTimeoutMs) * time.Millisecond
			}
		case proto.TypeHelloOK:
			_ = cipherConn.SetDeadline(time.Time{})
			var ok proto.HelloOK
			if err := proto.UnmarshalPayload(reply, &ok); err != nil {
				_ = cipherConn.Close()
				return nil, none, err
			}
			if ok.V != 1 {
				_ = cipherConn.Close()
				return nil, none, proto.ErrVersion
			}
			if ok.Limits.HoldTimeoutMs > 0 {
				holdSum += time.Duration(ok.Limits.HoldTimeoutMs) * time.Millisecond
			}
			if budget := cfg.SSHDAliveBudget.Duration(); budget > 0 && holdSum > budget {
				log.Warn("summed hold_timeout across the chain exceeds sshd_alive_budget; sshd may kill a parked session before the relay gives up",
					"holdSum", holdSum.String(), "sshdAliveBudget", budget.String(), "hops", len(hops))
			}
			return cipherConn.Underlying(), ok, nil
		case proto.TypeErr:
			_ = cipherConn.Close()
			var fail proto.Fail
			_ = proto.UnmarshalPayload(reply, &fail)
			return nil, none, proto.NewError(fail.Code, fail.Msg)
		default:
			_ = cipherConn.Close()
			return nil, none, proto.NewError(proto.CodeProto, "expected AUTH_OK, CHAIN_OK or HELLO_OK, got "+reply.Type.String())
		}
	}
}

func signRelayedDataPlane(p *pump, cfg config.Client, hops []proto.HopSpec, dest string, a auth.Authenticator, aok proto.AuthOK) error {
	if aok.Hop == 0 {
		return proto.NewError(proto.CodeProto, "hop-0 AUTH_OK on data plane")
	}
	ch, err := verifyRelayedChallenge(cfg, hops, dest, nil, aok)
	if err != nil {
		return err
	}
	resp, err := a.Sign(ch)
	if err != nil {
		return err
	}
	var signed proto.Auth
	if err := json.Unmarshal(resp, &signed); err != nil {
		return err
	}
	signed.Hop = aok.Hop
	fr, err := proto.MarshalFrame(proto.TypeAuth, signed)
	if err != nil {
		return err
	}
	return p.sendCtrl(fr)
}

func completeChainAuth(conn transport.Conn, a auth.Authenticator, cfg config.Client, hops []proto.HopSpec, dest string, offer json.RawMessage, reply proto.Frame) error {
	var aok proto.AuthOK
	if err := proto.UnmarshalPayload(reply, &aok); err != nil {
		return err
	}
	ch, err := verifyRelayedChallenge(cfg, hops, dest, offer, aok)
	if err != nil {
		return err
	}
	resp, err := a.Sign(ch)
	if err != nil {
		return err
	}
	var signed proto.Auth
	if err := json.Unmarshal(resp, &signed); err != nil {
		return err
	}
	signed.Hop = aok.Hop
	fr, err := proto.MarshalFrame(proto.TypeAuth, signed)
	if err != nil {
		return err
	}
	return conn.WriteFrame(fr)
}

// verifyRelayedChallenge is the originator's per-hop check before it will
// sign: destination match, attestation (J-D3) bound to the challenge nonce
// (J-D16 / JR1), and a recomputed DeriveChallenge over the canonical HELLO
// the next hop actually received.
func verifyRelayedChallenge(cfg config.Client, hops []proto.HopSpec, dest string, offer json.RawMessage, aok proto.AuthOK) (auth.Challenge, error) {
	var none auth.Challenge
	hop := aok.Hop
	if hop < 1 || hop > len(hops) {
		return none, proto.NewError(proto.CodeAuth, "challenge hop out of range")
	}
	if dest != "" && aok.Destination != dest {
		return none, proto.NewError(proto.CodeAuth, "challenge mismatch")
	}
	if aok.HelloJSON == "" {
		return none, proto.NewError(proto.CodeAuth, "relayed challenge missing helloJson")
	}
	canonical := []byte(aok.HelloJSON)
	var parsed struct {
		ClientNonce string `json:"clientNonce"`
	}
	if err := json.Unmarshal(canonical, &parsed); err != nil || parsed.ClientNonce == "" {
		return none, proto.NewError(proto.CodeAuth, "relayed challenge helloJson is not a hello")
	}
	if aok.Attest != nil {
		init, err := base64.StdEncoding.DecodeString(aok.Attest.KexInit)
		if err != nil {
			return none, proto.NewError(proto.CodeAuth, "bad attestation")
		}
		reply, err := base64.StdEncoding.DecodeString(aok.Attest.KexReply)
		if err != nil {
			return none, proto.NewError(proto.CodeAuth, "bad attestation")
		}
		target := hops[hop-1]
		nonce, err := kex.VerifyAttestation(init, reply, cfg.KnownHosts, target.Addr, target.Fp, cfg.StrictHostKeyChecking)
		if err != nil {
			return none, err
		}
		if base64.StdEncoding.EncodeToString(nonce) != aok.ServerNonce {
			return none, proto.NewError(proto.CodeAuth, "attestation nonce does not match challenge")
		}
	} else if hop != 1 {
		return none, proto.NewError(proto.CodeAuth, "relayed challenge missing attestation")
	}
	ch := auth.Challenge{
		SessionID:   aok.SessionID,
		Destination: aok.Destination,
		ClientNonce: parsed.ClientNonce,
		ServerNonce: aok.ServerNonce,
		Canonical:   canonical,
		Offer:       offer,
	}
	digest := auth.DeriveChallenge(ch)
	want, err := base64.StdEncoding.DecodeString(aok.Challenge)
	if err != nil || len(want) != sha256.Size || !bytes.Equal(digest, want) {
		return none, proto.NewError(proto.CodeAuth, "challenge mismatch")
	}
	ch.Digest = digest
	return ch, nil
}
