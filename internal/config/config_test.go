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
	if s.MaxSessions != 1024 || s.MaxConnsPerIP != 8 || s.DataChunkBytes != 65536 || s.SendWindow != 4194304 {
		t.Fatalf("sizes %+v", s)
	}
	if s.PprofListen != "" || s.ExpvarListen != "" {
		t.Fatalf("debug listeners should default empty: %+v", s)
	}
	if s.AuthMethod != "ssh-publickey" {
		t.Fatalf("auth_method=%q", s.AuthMethod)
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
	if c.Transport != "quic" || c.LogLevel != "warn" || c.AuthMethod != "ssh-publickey" {
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
auth_method = "ssh-publickey"
authorized_keys = "/tmp/ak"
auth_fail_delay = "50ms"
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
	if cfg.AuthMethod != "ssh-publickey" || cfg.AuthorizedKeys != "/tmp/ak" {
		t.Fatalf("auth %+v", cfg)
	}
	if cfg.AuthFailDelay.Duration() != 50*time.Millisecond {
		t.Fatalf("auth_fail_delay %s", cfg.AuthFailDelay)
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

func TestKCPFlagSelectsKCP(t *testing.T) {
	cfg, err := LoadClient(ClientOptions{KCP: true, Server: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport != "kcp" {
		t.Fatalf("transport %q", cfg.Transport)
	}
	if got := cfg.TransportPreference(); len(got) != 1 || got[0] != "kcp" {
		t.Fatalf("pref %v", got)
	}
}

func TestTCPFlagOverridesKCP(t *testing.T) {
	cfg, err := LoadClient(ClientOptions{TCP: true, KCP: true, Server: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport != "tcp" {
		t.Fatalf("transport %q", cfg.Transport)
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
	c.Transport = "kcp"
	if got := c.TransportPreference(); len(got) != 1 || got[0] != "kcp" {
		t.Fatalf("kcp pref %v", got)
	}
	s := DefaultServer()
	if !s.QUICEnabled() || !s.KCPEnabled() {
		t.Fatal("default server should enable quic and kcp")
	}
	s.Transports = []string{"tcp"}
	if s.QUICEnabled() || s.KCPEnabled() {
		t.Fatal("tcp-only")
	}
	s.Transports = []string{"kcp"}
	if s.QUICEnabled() || !s.KCPEnabled() {
		t.Fatal("kcp-only")
	}
}

func TestValidationErrors(t *testing.T) {
	s := DefaultServer()
	s.BufferBytes = s.TotalBufferBytes + 1
	if err := s.Validate(); err == nil {
		t.Fatal("expected buffer_bytes > total_buffer_bytes error")
	}

	s = DefaultServer()
	s.MaxConnsPerIP = 0
	if err := s.Validate(); err == nil {
		t.Fatal("expected max_conns_per_ip error")
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

	s = DefaultServer()
	s.AuthMethod = "password"
	if err := s.Validate(); err == nil {
		t.Fatal("expected unknown auth_method error")
	}
	s.AuthMethod = "none"
	if err := s.Validate(); err == nil {
		t.Fatal("expected deprecated none auth_method error")
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

func TestSpliceConfig(t *testing.T) {
	s := DefaultServer()
	if s.Splice != defaultSplice() {
		t.Fatalf("expected s.Splice=%v, got %v", defaultSplice(), s.Splice)
	}
	c := DefaultClient()
	if c.Splice != defaultSplice() {
		t.Fatalf("expected c.Splice=%v, got %v", defaultSplice(), c.Splice)
	}

	dir := t.TempDir()
	srvToml := filepath.Join(dir, "srv.toml")
	if err := os.WriteFile(srvToml, []byte("splice = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedSrv, err := LoadServer(ServerOptions{ConfigPath: srvToml})
	if err != nil {
		t.Fatal(err)
	}
	if loadedSrv.Splice != false {
		t.Fatalf("expected loadedSrv.Splice=false, got %v", loadedSrv.Splice)
	}

	// Option override over TOML
	tr := true
	loadedSrv2, err := LoadServer(ServerOptions{ConfigPath: srvToml, Splice: &tr})
	if err != nil {
		t.Fatal(err)
	}
	if loadedSrv2.Splice != true {
		t.Fatalf("expected loadedSrv2.Splice=true, got %v", loadedSrv2.Splice)
	}

	cliToml := filepath.Join(dir, "cli.toml")
	if err := os.WriteFile(cliToml, []byte("server = \"1.2.3.4:5\"\nsplice = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedCli, err := LoadClient(ClientOptions{ConfigPath: cliToml})
	if err != nil {
		t.Fatal(err)
	}
	if loadedCli.Splice != false {
		t.Fatalf("expected loadedCli.Splice=false, got %v", loadedCli.Splice)
	}

	loadedCli2, err := LoadClient(ClientOptions{ConfigPath: cliToml, Splice: &tr})
	if err != nil {
		t.Fatal(err)
	}
	if loadedCli2.Splice != true {
		t.Fatalf("expected loadedCli2.Splice=true, got %v", loadedCli2.Splice)
	}
}

func TestAdaptiveKCPConfig(t *testing.T) {
	s := DefaultServer()
	if !s.AdaptiveKCP {
		t.Fatalf("expected default s.AdaptiveKCP=true, got %v", s.AdaptiveKCP)
	}
	c := DefaultClient()
	if !c.AdaptiveKCP {
		t.Fatalf("expected default c.AdaptiveKCP=true, got %v", c.AdaptiveKCP)
	}

	dir := t.TempDir()
	srvToml := filepath.Join(dir, "srv.toml")
	if err := os.WriteFile(srvToml, []byte("adaptive_kcp = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedSrv, err := LoadServer(ServerOptions{ConfigPath: srvToml})
	if err != nil {
		t.Fatal(err)
	}
	if loadedSrv.AdaptiveKCP != false {
		t.Fatalf("expected loadedSrv.AdaptiveKCP=false, got %v", loadedSrv.AdaptiveKCP)
	}

	// Option override over TOML
	tr := true
	loadedSrv2, err := LoadServer(ServerOptions{ConfigPath: srvToml, AdaptiveKCP: &tr})
	if err != nil {
		t.Fatal(err)
	}
	if loadedSrv2.AdaptiveKCP != true {
		t.Fatalf("expected loadedSrv2.AdaptiveKCP=true, got %v", loadedSrv2.AdaptiveKCP)
	}

	fl := false
	loadedSrv3, err := LoadServer(ServerOptions{AdaptiveKCP: &fl})
	if err != nil {
		t.Fatal(err)
	}
	if loadedSrv3.AdaptiveKCP != false {
		t.Fatalf("expected loadedSrv3.AdaptiveKCP=false, got %v", loadedSrv3.AdaptiveKCP)
	}

	cliToml := filepath.Join(dir, "cli.toml")
	if err := os.WriteFile(cliToml, []byte("server = \"1.2.3.4:5\"\nadaptive_kcp = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedCli, err := LoadClient(ClientOptions{ConfigPath: cliToml})
	if err != nil {
		t.Fatal(err)
	}
	if loadedCli.AdaptiveKCP != false {
		t.Fatalf("expected loadedCli.AdaptiveKCP=false, got %v", loadedCli.AdaptiveKCP)
	}

	loadedCli2, err := LoadClient(ClientOptions{ConfigPath: cliToml, AdaptiveKCP: &tr})
	if err != nil {
		t.Fatal(err)
	}
	if loadedCli2.AdaptiveKCP != true {
		t.Fatalf("expected loadedCli2.AdaptiveKCP=true, got %v", loadedCli2.AdaptiveKCP)
	}
}

func TestStrictHostKeyCheckingConfig(t *testing.T) {
	origIsTerminal := isTerminal
	defer func() { isTerminal = origIsTerminal }()

	// 1. Interactive TTY defaults to "ask"
	isTerminal = func(fd uintptr) bool { return true }
	if got := DefaultStrictHostKeyChecking(); got != "ask" {
		t.Fatalf("expected 'ask' for TTY, got %q", got)
	}
	cliTTY := DefaultClient()
	if cliTTY.StrictHostKeyChecking != "ask" {
		t.Fatalf("expected DefaultClient().StrictHostKeyChecking='ask' for TTY, got %q", cliTTY.StrictHostKeyChecking)
	}

	// 2. Headless script defaults to "yes"
	isTerminal = func(fd uintptr) bool { return false }
	if got := DefaultStrictHostKeyChecking(); got != "yes" {
		t.Fatalf("expected 'yes' for headless script, got %q", got)
	}
	cliHeadless := DefaultClient()
	if cliHeadless.StrictHostKeyChecking != "yes" {
		t.Fatalf("expected DefaultClient().StrictHostKeyChecking='yes' for headless, got %q", cliHeadless.StrictHostKeyChecking)
	}

	// 3. Validation
	for _, mode := range []string{"yes", "no", "ask", "accept-new", "YES", "ASK", ""} {
		c := DefaultClient()
		c.StrictHostKeyChecking = mode
		if err := c.Validate(); err != nil {
			t.Fatalf("expected valid for %q, got error: %v", mode, err)
		}
	}
	for _, invalid := range []string{"maybe", "true", "false", "accept"} {
		c := DefaultClient()
		c.StrictHostKeyChecking = invalid
		if err := c.Validate(); err == nil {
			t.Fatalf("expected validation error for invalid mode %q", invalid)
		}
	}

	// 4. Overrides via TOML and ClientOptions
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "strict.toml")
	if err := os.WriteFile(tomlPath, []byte("server = \"1.2.3.4:5\"\nstrict_host_key_checking = \"accept-new\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClient(ClientOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.StrictHostKeyChecking != "accept-new" {
		t.Fatalf("expected TOML value 'accept-new', got %q", loaded.StrictHostKeyChecking)
	}

	// CLI option overrides TOML
	loaded2, err := LoadClient(ClientOptions{
		ConfigPath:            tomlPath,
		StrictHostKeyChecking: "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	if loaded2.StrictHostKeyChecking != "no" {
		t.Fatalf("expected CLI override 'no', got %q", loaded2.StrictHostKeyChecking)
	}
}
