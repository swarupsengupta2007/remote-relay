package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/remote-relay/relay/internal/proto"
)

// MaxChainDepthLimit bounds max_chain_depth so a malformed or hostile CHAIN
// cannot make an intermediate allocate an unbounded path.
const MaxChainDepthLimit = 16

// ParseJumphost expands -J / jumphost entries into wire hop specs. Entries may
// be repeated and comma-separated, matching OpenSSH's -J:
//
//	[user@]host:port[?transport=quic|kcp|tcp][&ha=1][#SHA256:…]
//
// The fragment is an inline host-key pin for that hop; it short-circuits
// known_hosts and removes the TOFU window (plan §2.8). Unknown query keys are
// rejected so a typo fails at startup instead of silently downgrading a hop.
func ParseJumphost(entries []string) ([]proto.HopSpec, error) {
	var out []proto.HopSpec
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			hop, err := ParseHopSpec(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, hop)
		}
	}
	return out, nil
}

// ParseHopSpec parses a single -J token.
func ParseHopSpec(tok string) (proto.HopSpec, error) {
	var hop proto.HopSpec

	trimmed := strings.TrimSpace(tok)
	if strings.HasPrefix(trimmed, "target:") {
		tName := strings.TrimPrefix(trimmed, "target:")
		if i := strings.Index(tName, "?"); i >= 0 {
			tName = tName[:i]
		}
		if i := strings.Index(tName, "#"); i >= 0 {
			tName = tName[:i]
		}
		tName = strings.TrimSpace(tName)
		if tName == "" {
			return hop, fmt.Errorf("jumphost %q: empty target name after 'target:'", tok)
		}
		hop.Target = tName
		return hop, nil
	}

	rest := tok
	if i := strings.Index(rest, "#"); i >= 0 {
		hop.Fp = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
		if hop.Fp == "" {
			return hop, fmt.Errorf("jumphost %q: empty host key pin after '#'", tok)
		}
		if !strings.HasPrefix(hop.Fp, "SHA256:") {
			hop.Fp = "SHA256:" + hop.Fp
		}
	}

	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}

	addr := rest
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		hop.User = addr[:i]
		addr = addr[i+1:]
		if hop.User == "" {
			return hop, fmt.Errorf("jumphost %q: empty user before '@'", tok)
		}
	}
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return hop, fmt.Errorf("jumphost %q: want [user@]host:port: %w", tok, err)
	}
	hop.Addr = addr

	if query != "" {
		vals, err := url.ParseQuery(query)
		if err != nil {
			return hop, fmt.Errorf("jumphost %q: bad query: %w", tok, err)
		}
		for k, vs := range vals {
			v := ""
			if len(vs) > 0 {
				v = vs[0]
			}
			switch strings.ToLower(k) {
			case "transport":
				if !validTransport(v) {
					return hop, fmt.Errorf("jumphost %q: unknown transport %q", tok, v)
				}
				hop.Transport = TransportPreferenceList(v)
			case "ha":
				switch strings.ToLower(v) {
				case "1", "true", "yes", "on":
					hop.AllowHA = true
				case "", "0", "false", "no", "off":
					hop.AllowHA = false
				default:
					return hop, fmt.Errorf("jumphost %q: bad ha=%q", tok, v)
				}
			default:
				return hop, fmt.Errorf("jumphost %q: unknown option %q (want transport or ha)", tok, k)
			}
		}
	}
	return hop, nil
}

// HopAllowed reports whether an intermediate may dial addr as an onward relay
// hop. Like allow_destinations this is a literal match or "*"; entries are
// compared exactly as the originator wrote them, so an operator must list the
// host:port form clients use.
func HopAllowed(addr string, allow []string) bool {
	for _, a := range allow {
		if a == "*" || a == addr {
			return true
		}
	}
	return false
}

// ChainSessionLimit is the number of concurrently chained sessions an
// intermediate accepts. A chained session holds four rings instead of two, so
// max_sessions overstates chained capacity by ~2x (JR5); the default keeps a
// quarter of the slot budget for chains.
func (s Server) ChainSessionLimit() int {
	if s.ChainMaxSessions > 0 {
		return s.ChainMaxSessions
	}
	if s.MaxSessions <= 0 {
		return 0
	}
	if n := s.MaxSessions / 4; n > 0 {
		return n
	}
	return 1
}

func (s Server) validateChain() error {
	if s.MaxChainDepth < 1 || s.MaxChainDepth > MaxChainDepthLimit {
		return fmt.Errorf("max_chain_depth must be between 1 and %d", MaxChainDepthLimit)
	}
	if s.MaxChainConnsPerPeer <= 0 {
		return fmt.Errorf("max_chain_conns_per_peer must be positive")
	}
	if s.ChainAuthTimeout <= 0 {
		return fmt.Errorf("chain_auth_timeout must be positive")
	}
	if s.ChainAuthRelaysMax <= 0 {
		return fmt.Errorf("chain_auth_relays_max must be positive")
	}
	if s.ChainMaxSessions < 0 || s.ChainMaxSessions > s.MaxSessions {
		return fmt.Errorf("chain_max_sessions must be between 0 and max_sessions (%d)", s.MaxSessions)
	}
	if err := validStrictHostKeyChecking(s.RelayStrictHostKeyChecking); err != nil {
		return fmt.Errorf("relay_strict_host_key_checking: %w", err)
	}
	for _, h := range s.AllowRelayHops {
		if h == "*" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err != nil {
			return fmt.Errorf("allow_relay_hops entry %q: want host:port: %w", h, err)
		}
	}
	// JR10: "*" plus any depth turns the relay into an open chaining amplifier.
	if AllowAll(s.AllowRelayHops) && s.MaxChainDepth != 1 {
		return fmt.Errorf(`allow_relay_hops = ["*"] requires max_chain_depth = 1`)
	}
	return nil
}

func (c Client) validateChain() error {
	hops, err := ParseJumphost(c.Jumphost)
	if err != nil {
		return err
	}
	targetCount := 0
	for i, h := range hops {
		if h.Target != "" {
			targetCount++
			if i != len(hops)-1 || c.Server != "" {
				return fmt.Errorf("target hop must be the terminal hop in chain")
			}
		}
	}
	if c.Target != "" && targetCount > 0 {
		return fmt.Errorf("target cannot be specified in both --target and -J")
	}
	if targetCount > 0 && len(hops) < 2 {
		return fmt.Errorf("chained target requires at least one intermediate jumphost relay")
	}
	if c.SSHDAliveBudget < 0 {
		return fmt.Errorf("sshd_alive_budget must not be negative")
	}
	return nil
}
