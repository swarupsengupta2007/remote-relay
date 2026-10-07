package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
)

func TestParseJumphost(t *testing.T) {
	got, err := ParseJumphost([]string{
		"j1.example.com:7443",
		"alice@j2.example.com:8443?transport=kcp&ha=1,j3.example.com:7443?transport=tcp#SHA256:AbCd",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []proto.HopSpec{
		{Addr: "j1.example.com:7443"},
		{Addr: "j2.example.com:8443", User: "alice", Transport: []string{"kcp"}, AllowHA: true},
		{Addr: "j3.example.com:7443", Transport: []string{"tcp"}, Fp: "SHA256:AbCd"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d hops %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i].Addr != want[i].Addr || got[i].User != want[i].User ||
			got[i].Fp != want[i].Fp || got[i].AllowHA != want[i].AllowHA ||
			strings.Join(got[i].Transport, ",") != strings.Join(want[i].Transport, ",") {
			t.Fatalf("hop %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseJumphostQuicExpandsToPreferenceList(t *testing.T) {
	got, err := ParseJumphost([]string{"j1.example.com:7443?transport=quic"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || strings.Join(got[0].Transport, ",") != "quic,kcp" {
		t.Fatalf("got %+v, want [quic kcp]", got)
	}
}

func TestParseJumphostIPv6AndPinNormalisation(t *testing.T) {
	got, err := ParseJumphost([]string{"[2001:db8::1]:7443#AbCd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != "[2001:db8::1]:7443" || got[0].Fp != "SHA256:AbCd" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseJumphostRejects(t *testing.T) {
	for _, bad := range []string{
		"j1.example.com",          // no port
		"j1.example.com:7443?x=1", // unknown option
		"j1.example.com:7443?transport=sctp",
		"j1.example.com:7443?ha=maybe",
		"j1.example.com:7443#",      // empty pin
		"@j1.example.com:7443",      // empty user
		"j1.example.com:7443?t=%zz", // malformed query escape
	} {
		if _, err := ParseJumphost([]string{bad}); err == nil {
			t.Fatalf("%q: expected an error", bad)
		}
	}
	if _, err := ParseJumphost(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
}

func TestHopAllowed(t *testing.T) {
	if HopAllowed("j2:7443", nil) {
		t.Fatal("empty allow list must deny")
	}
	if !HopAllowed("j2:7443", []string{"j2:7443"}) {
		t.Fatal("exact match must allow")
	}
	if !HopAllowed("j2:7443", []string{"*"}) {
		t.Fatal("wildcard must allow")
	}
	if HopAllowed("j2:7443", []string{"J2:7443", "j2:8443"}) {
		t.Fatal("non-matching entries must deny")
	}
}

func TestChainSessionLimit(t *testing.T) {
	s := DefaultServer()
	if got := s.ChainSessionLimit(); got != 256 {
		t.Fatalf("derived limit = %d, want max_sessions/4 = 256", got)
	}
	s.ChainMaxSessions = 7
	if got := s.ChainSessionLimit(); got != 7 {
		t.Fatalf("explicit limit = %d, want 7", got)
	}
	s.MaxSessions, s.ChainMaxSessions = 2, 0
	if got := s.ChainSessionLimit(); got != 1 {
		t.Fatalf("small max_sessions limit = %d, want 1", got)
	}
}

func TestServerValidateChain(t *testing.T) {
	base := DefaultServer()
	if err := base.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if base.MaxChainDepth != 4 || base.MaxChainConnsPerPeer != 256 ||
		base.ChainAuthRelaysMax != 8 || base.ChainAuthTimeout.Duration() != 10*time.Second ||
		base.RelayStrictHostKeyChecking != "yes" {
		t.Fatalf("chain defaults: %+v", base)
	}

	cases := map[string]func(s *Server){
		"zero depth":        func(s *Server) { s.MaxChainDepth = 0 },
		"depth too large":   func(s *Server) { s.MaxChainDepth = MaxChainDepthLimit + 1 },
		"wildcard + depth":  func(s *Server) { s.AllowRelayHops = []string{"*"} },
		"zero peer cap":     func(s *Server) { s.MaxChainConnsPerPeer = 0 },
		"zero auth timeout": func(s *Server) { s.ChainAuthTimeout = 0 },
		"zero relay cap":    func(s *Server) { s.ChainAuthRelaysMax = 0 },
		"sessions above max": func(s *Server) {
			s.ChainMaxSessions = s.MaxSessions + 1
		},
		"bad strict":    func(s *Server) { s.RelayStrictHostKeyChecking = "maybe" },
		"bad hop entry": func(s *Server) { s.AllowRelayHops = []string{"not-an-address"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := DefaultServer()
			mutate(&s)
			if err := s.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %s", name)
			}
		})
	}

	t.Run("wildcard allowed at depth 1", func(t *testing.T) {
		s := DefaultServer()
		s.AllowRelayHops = []string{"*"}
		s.MaxChainDepth = 1
		if err := s.Validate(); err != nil {
			t.Fatalf("depth 1 with wildcard: %v", err)
		}
	})
}

func TestClientValidateJumphost(t *testing.T) {
	c := DefaultClient()
	if c.SSHDAliveBudget.Duration() != 2*time.Minute {
		t.Fatalf("sshd_alive_budget = %s", c.SSHDAliveBudget)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	c.Jumphost = []string{"j1.example.com:7443?transport=kcp"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid jumphost: %v", err)
	}
	c.Jumphost = []string{"j1.example.com"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a jumphost entry without a port")
	}
	c.Jumphost = nil
	c.SSHDAliveBudget = Duration(-time.Second)
	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a negative sshd_alive_budget")
	}
}

func TestLoadClientJumphostPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/client.toml"
	body := "server = \"toml.example.com:7443\"\njumphost = [\"toml-hop.example.com:7443\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	tomlOnly, err := LoadClient(ClientOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(tomlOnly.Jumphost) != 1 || tomlOnly.Jumphost[0] != "toml-hop.example.com:7443" {
		t.Fatalf("TOML jumphost = %v", tomlOnly.Jumphost)
	}

	cliWins, err := LoadClient(ClientOptions{
		ConfigPath:  path,
		Jumphost:    []string{"cli-hop.example.com:7443"},
		JumphostSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cliWins.Jumphost) != 1 || cliWins.Jumphost[0] != "cli-hop.example.com:7443" {
		t.Fatalf("CLI jumphost = %v, want the CLI value to win", cliWins.Jumphost)
	}

	cleared, err := LoadClient(ClientOptions{ConfigPath: path, Jumphost: nil, JumphostSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared.Jumphost) != 0 {
		t.Fatalf("an explicitly empty -J must clear the TOML value, got %v", cleared.Jumphost)
	}
}

func TestChainedTargetConfig(t *testing.T) {
	// 1. ParseHopSpec with target
	hop, err := ParseHopSpec("target:homelab")
	if err != nil {
		t.Fatalf("ParseHopSpec target: %v", err)
	}
	if hop.Target != "homelab" || hop.Addr != "" {
		t.Fatalf("unexpected hop: %+v", hop)
	}

	hop, err = ParseHopSpec("target:homelab?transport=ws")
	if err != nil {
		t.Fatalf("ParseHopSpec target with query: %v", err)
	}
	if hop.Target != "homelab" {
		t.Fatalf("unexpected target: %q", hop.Target)
	}

	if _, err := ParseHopSpec("target:"); err == nil {
		t.Fatal("expected error on empty target:")
	}

	// 2. Client.Validate with --target and -J without Server
	c := DefaultClient()
	c.Server = ""
	c.Target = "homelab"
	c.Jumphost = []string{"jump.example.com:7443"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Client.Validate with --target and -J without Server should pass: %v", err)
	}

	// 3. Client.Validate with target in -J without Server
	c2 := DefaultClient()
	c2.Server = ""
	c2.Target = ""
	c2.Jumphost = []string{"jump.example.com:7443,target:homelab"}
	if err := c2.Validate(); err != nil {
		t.Fatalf("Client.Validate with target in -J without Server should pass: %v", err)
	}

	// 4. Rejections
	// 4a. Target in -J without intermediate jumphost
	c3 := DefaultClient()
	c3.Server = ""
	c3.Target = ""
	c3.Jumphost = []string{"target:homelab"}
	if err := c3.Validate(); err == nil {
		t.Fatal("expected error when target in -J has no intermediate jumphosts")
	}

	// 4b. Target in -J is not terminal
	c4 := DefaultClient()
	c4.Server = ""
	c4.Target = ""
	c4.Jumphost = []string{"target:homelab,jump.example.com:7443"}
	if err := c4.Validate(); err == nil {
		t.Fatal("expected error when target in -J is not terminal")
	}

	// 4c. Duplicate target in --target and -J
	c5 := DefaultClient()
	c5.Server = ""
	c5.Target = "homelab"
	c5.Jumphost = []string{"jump.example.com:7443,target:other"}
	if err := c5.Validate(); err == nil {
		t.Fatal("expected error when target is specified in both --target and -J")
	}
}
