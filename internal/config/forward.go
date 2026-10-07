package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// LocalForward is one -L listener: connections accepted on Listen are
// relayed over the tunnel to Dest, which the server dials.
type LocalForward struct {
	Listen string // host:port on the client
	Dest   string // host:port as the server dials it
}

func (f LocalForward) String() string {
	return f.Listen + " -> " + f.Dest
}

// ParseLocalForwards parses -L entries (repeatable; each may be
// comma-separated) with ParseLocalForward.
func ParseLocalForwards(entries []string) ([]LocalForward, error) {
	var out []LocalForward
	for _, entry := range entries {
		for _, tok := range strings.Split(entry, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			fwd, err := ParseLocalForward(tok)
			if err != nil {
				return nil, err
			}
			out = append(out, fwd)
		}
	}
	return out, nil
}

// ParseLocalForward parses an ssh -L spec: [bind_address:]port:host:hostport.
// IPv6 addresses are written in brackets. An omitted bind address means
// 127.0.0.1; an empty one or "*" binds every interface.
func ParseLocalForward(spec string) (LocalForward, error) {
	fields, err := splitForwardSpec(spec)
	if err != nil {
		return LocalForward{}, fmt.Errorf("local forward %q: %w", spec, err)
	}
	bind := "127.0.0.1"
	switch len(fields) {
	case 3:
	case 4:
		bind = fields[0]
		if bind == "*" {
			bind = ""
		}
		fields = fields[1:]
	default:
		return LocalForward{}, fmt.Errorf("local forward %q: want [bind_address:]port:host:hostport", spec)
	}
	if _, err := parseForwardPort(fields[0], true); err != nil {
		return LocalForward{}, fmt.Errorf("local forward %q: listen port: %w", spec, err)
	}
	if fields[1] == "" {
		return LocalForward{}, fmt.Errorf("local forward %q: empty destination host", spec)
	}
	if _, err := parseForwardPort(fields[2], false); err != nil {
		return LocalForward{}, fmt.Errorf("local forward %q: destination port: %w", spec, err)
	}
	return LocalForward{
		Listen: net.JoinHostPort(bind, fields[0]),
		Dest:   net.JoinHostPort(fields[1], fields[2]),
	}, nil
}

// splitForwardSpec splits on ':' outside brackets and strips the brackets.
func splitForwardSpec(spec string) ([]string, error) {
	var fields []string
	var cur strings.Builder
	inBracket := false
	for _, r := range spec {
		switch {
		case r == '[' && !inBracket && cur.Len() == 0:
			inBracket = true
		case r == ']' && inBracket:
			inBracket = false
		case r == ':' && !inBracket:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if inBracket {
		return nil, fmt.Errorf("unterminated '['")
	}
	return append(fields, cur.String()), nil
}

func parseForwardPort(s string, allowZero bool) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 || (p == 0 && !allowZero) {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}
