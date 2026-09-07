package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	s := DefaultServer()
	if s.ListenTCP != "0.0.0.0:7443" {
		t.Fatalf("listen_tcp=%q", s.ListenTCP)
	}
	if s.DefaultDestination != "127.0.0.1:22" {
		t.Fatalf("default_destination=%q", s.DefaultDestination)
	}
	if len(s.AllowDestinations) != 1 || s.AllowDestinations[0] != "127.0.0.1:22" {
		t.Fatalf("allow_destinations=%v", s.AllowDestinations)
	}
	if s.MaxSessions != 1024 || s.DataChunkBytes != 65536 || s.SendWindow != 4194304 {
		t.Fatalf("sizes %+v", s)
	}
	if s.BufferBytes != 67108864 || s.TotalBufferBytes != 536870912 {
		t.Fatalf("buffers %d %d", s.BufferBytes, s.TotalBufferBytes)
	}
	if s.HoldTimeout.Duration() != 5*time.Minute {
		t.Fatalf("hold=%s", s.HoldTimeout)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}

	c := DefaultClient()
	if c.Transport != "quic" || c.LogLevel != "warn" {
		t.Fatalf("client %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTOMLOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	body := `
listen_tcp = "127.0.0.1:9000"
log_level = "debug"
max_sessions = 4
hold_timeout = "90s"
allow_destinations = ["127.0.0.1:22", "127.0.0.1:7"]
transports = ["tcp"]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(ServerOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenTCP != "127.0.0.1:9000" {
		t.Fatalf("listen %q", cfg.ListenTCP)
	}
	if cfg.LogLevel != "debug" || cfg.MaxSessions != 4 {
		t.Fatalf("%+v", cfg)
	}
	if cfg.HoldTimeout.Duration() != 90*time.Second {
		t.Fatalf("hold %s", cfg.HoldTimeout)
	}
	if cfg.DefaultDestination != "127.0.0.1:22" {
		t.Fatal("default dest should remain")
	}
	if len(cfg.AllowDestinations) != 2 {
		t.Fatalf("allow %v", cfg.AllowDestinations)
	}
}

func TestFlagOverridesTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(path, []byte(`
listen_tcp = "127.0.0.1:9000"
log_level = "debug"
transports = ["tcp"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(ServerOptions{
		ConfigPath: path,
		Listen:     "127.0.0.1:8000",
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenTCP != "127.0.0.1:8000" {
		t.Fatalf("listen %q", cfg.ListenTCP)
	}
	if cfg.LogLevel != "error" {
		t.Fatalf("log %q", cfg.LogLevel)
	}
}

func TestClientFlagOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	if err := os.WriteFile(path, []byte(`
server = "cfg.example:1"
destination = "cfgdest:2"
transport = "quic"
log_level = "debug"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClient(ClientOptions{
		ConfigPath: path,
		Server:     "flag.example:7443",
		Dest:       "127.0.0.1:22",
		DestSet:    true,
		TCP:        true,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "flag.example:7443" || cfg.Destination != "127.0.0.1:22" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.Transport != "tcp" || cfg.LogLevel != "error" {
		t.Fatalf("%+v", cfg)
	}
}

func TestClientPositionalDest(t *testing.T) {
	cfg, err := LoadClient(ClientOptions{
		Server:  "127.0.0.1:7443",
		TCP:     true,
		PosHost: "10.0.0.1",
		PosPort: "2222",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Destination != "10.0.0.1:2222" {
		t.Fatalf("dest %q", cfg.Destination)
	}
}

func TestKCPNotImplemented(t *testing.T) {
	_, err := LoadClient(ClientOptions{KCP: true, Server: "127.0.0.1:1"})
	if err == nil || err.Error() != "kcp: not implemented yet" {
		t.Fatalf("got %v", err)
	}
}

func TestTransportPreference(t *testing.T) {
	c := DefaultClient()
	if got := c.TransportPreference(); len(got) != 2 || got[0] != "quic" || got[1] != "kcp" {
		t.Fatalf("default pref %v", got)
	}
	c.Transport = "tcp"
	if got := c.TransportPreference(); len(got) != 1 || got[0] != "tcp" {
		t.Fatalf("tcp pref %v", got)
	}
	s := DefaultServer()
	if !s.QUICEnabled() {
		t.Fatal("default server should enable quic")
	}
	s.Transports = []string{"tcp"}
	if s.QUICEnabled() {
		t.Fatal("tcp-only")
	}
}

func TestValidationErrors(t *testing.T) {
	s := DefaultServer()
	s.BufferBytes = s.TotalBufferBytes + 1
	if err := s.Validate(); err == nil {
		t.Fatal("expected buffer_bytes > total_buffer_bytes error")
	}

	s = DefaultServer()
	s.Transports = nil
	if err := s.Validate(); err == nil {
		t.Fatal("expected empty transports error")
	}
	s.Transports = []string{}
	if err := s.Validate(); err == nil {
		t.Fatal("expected empty transports error")
	}

	c := DefaultClient()
	c.Transport = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected empty transports error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte(`hold_timeout = "not-a-duration"`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadServer(ServerOptions{ConfigPath: path})
	if err == nil {
		t.Fatal("expected bad duration error")
	}
}

func TestMissingDefaultConfigOK(t *testing.T) {
	cfg, err := LoadServer(ServerOptions{ConfigPath: ""})
	if err != nil {
		// default path /etc/relay/server.toml may exist in some environments;
		// if it does not, LoadServer must still succeed with defaults.
		t.Fatal(err)
	}
	if cfg.ListenTCP != DefaultServer().ListenTCP && !fileExists(DefaultServerConfigPath) {
		t.Fatalf("unexpected listen %q", cfg.ListenTCP)
	}
}

func TestMissingExplicitConfigError(t *testing.T) {
	_, err := LoadServer(ServerOptions{ConfigPath: filepath.Join(t.TempDir(), "nope.toml")})
	if err == nil {
		t.Fatal("expected error")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestAllowAll(t *testing.T) {
	if AllowAll([]string{"127.0.0.1:22"}) {
		t.Fatal("not open")
	}
	if !AllowAll([]string{"*"}) {
		t.Fatal("open")
	}
	if DestinationAllowed("1.2.3.4:5", []string{"127.0.0.1:22"}) {
		t.Fatal("should deny")
	}
	if !DestinationAllowed("127.0.0.1:22", []string{"127.0.0.1:22"}) {
		t.Fatal("should allow")
	}
}
