package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/remote-relay/relay/internal/config"
)

func captureOutput(f func()) (string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	outCh := make(chan string)
	errCh := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outCh <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errCh <- buf.String()
	}()

	f()

	_ = wOut.Close()
	_ = wErr.Close()
	stdout := <-outCh
	stderr := <-errCh
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	return stdout, stderr
}

func TestRunTopLevel(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"no args", []string{}, 2},
		{"version", []string{"version"}, 0},
		{"help flag -h", []string{"-h"}, 0},
		{"help flag --help", []string{"--help"}, 0},
		{"help command", []string{"help"}, 0},
		{"unknown command", []string{"unknown-cmd"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var code int
			_, _ = captureOutput(func() {
				code = run(tt.args)
			})
			if code != tt.wantCode {
				t.Fatalf("run(%v) = %d, want %d", tt.args, code, tt.wantCode)
			}
		})
	}
}

func TestRunServerArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		errSub   string
	}{
		{"server help", []string{"server", "-h"}, 0, ""},
		{"server bad flag", []string{"server", "--no-such-flag"}, 2, "flag provided but not defined"},
		{"server bad config path", []string{"server", "--config", "/nonexistent/path/server.toml"}, 1, "no such file or directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var code int
			_, stderr := captureOutput(func() {
				code = run(tt.args)
			})
			if code != tt.wantCode {
				t.Fatalf("run(%v) = %d, want %d", tt.args, code, tt.wantCode)
			}
			if tt.errSub != "" && !strings.Contains(stderr, tt.errSub) {
				t.Fatalf("run(%v) stderr %q does not contain %q", tt.args, stderr, tt.errSub)
			}
		})
	}
}

func TestRunClientArgs(t *testing.T) {
	dir := t.TempDir()
	emptyServerConf := filepath.Join(dir, "empty_server.toml")
	_ = os.WriteFile(emptyServerConf, []byte("server = \"\"\n"), 0o644)

	tests := []struct {
		name     string
		args     []string
		wantCode int
		errSub   string
	}{
		{"client help", []string{"client", "-h"}, 0, ""},
		{"client bad flag", []string{"client", "--no-such-flag"}, 2, "flag provided but not defined"},
		{"client bad config path", []string{"client", "--config", "/nonexistent/path/client.toml"}, 1, "no such file or directory"},
		{"client invalid single positional dest", []string{"client", "--server", "127.0.0.1:7443", "nohostport"}, 2, "invalid destination"},
		{"client too many positional args", []string{"client", "--server", "127.0.0.1:7443", "host", "22", "extra"}, 2, "extra arguments"},
		{"client missing server", []string{"client", "--config", emptyServerConf}, 1, "server is required"},
		{"client tcp and allow-ha mutual exclusion", []string{"client", "--tcp", "--allow-ha", "--server", "127.0.0.1:7443"}, 2, "--allow-ha cannot be used with --tcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var code int
			_, stderr := captureOutput(func() {
				code = run(tt.args)
			})
			if code != tt.wantCode {
				t.Fatalf("run(%v) = %d, want %d (stderr: %s)", tt.args, code, tt.wantCode, stderr)
			}
			if tt.errSub != "" && !strings.Contains(stderr, tt.errSub) {
				t.Fatalf("run(%v) stderr %q does not contain %q", tt.args, stderr, tt.errSub)
			}
		})
	}
}

func TestClientConfigOptionsAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "client.toml")
	tomlData := `
server = "toml.server:7443"
destination = "toml.dest:22"
transport = "kcp"
log_level = "info"
`
	if err := os.WriteFile(confPath, []byte(tomlData), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Config file values load properly
	cfg, err := config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Server != "toml.server:7443" || cfg.Destination != "toml.dest:22" || cfg.Transport != "kcp" || cfg.LogLevel != "info" {
		t.Fatalf("unexpected loaded config: %+v", cfg)
	}

	// 2. --tcp flag overrides config transport
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		TCP:        true,
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Transport != "tcp" {
		t.Fatalf("expected transport tcp, got %q", cfg.Transport)
	}

	// 3. --tcp overrides --kcp flag
	cfg, err = config.LoadClient(config.ClientOptions{
		TCP:    true,
		KCP:    true,
		Server: "127.0.0.1:7443",
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Transport != "tcp" {
		t.Fatalf("expected transport tcp, got %q", cfg.Transport)
	}

	// 4. Positional %h %p arguments override config destination
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		PosHost:    "remote.host",
		PosPort:    "2222",
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Destination != "remote.host:2222" {
		t.Fatalf("expected destination remote.host:2222, got %q", cfg.Destination)
	}

	// 5. IPv6 positional host gets bracketed
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		PosHost:    "2001:db8::1",
		PosPort:    "22",
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Destination != "[2001:db8::1]:22" {
		t.Fatalf("expected destination [2001:db8::1]:22, got %q", cfg.Destination)
	}

	// 6. AllowHA flag override
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		AllowHA:    true,
		AllowHASet: true,
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.AllowHA {
		t.Fatal("expected AllowHA to be true")
	}

	// 7. AllowHA with TCP fails validation
	_, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		TCP:        true,
		AllowHA:    true,
		AllowHASet: true,
	})
	if err == nil {
		t.Fatal("expected error with TCP and AllowHA both true")
	}

	// 8. Security options: KnownHosts, ServerFingerprint, StrictHostKeyChecking
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath:            confPath,
		KnownHosts:            "/tmp/custom_known_hosts",
		ServerFingerprint:     "SHA256:abc123",
		StrictHostKeyChecking: "yes",
	})
	if err != nil {
		t.Fatalf("load config security options: %v", err)
	}
	if cfg.KnownHosts != "/tmp/custom_known_hosts" || cfg.ServerFingerprint != "SHA256:abc123" || cfg.StrictHostKeyChecking != "yes" {
		t.Fatalf("unexpected security options: %+v", cfg)
	}

	// 9. Identity flag override
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath: confPath,
		Identity:   "/tmp/my_test_key",
	})
	if err != nil {
		t.Fatalf("load config with identity: %v", err)
	}
	if len(cfg.IdentityFiles) != 1 || cfg.IdentityFiles[0] != "/tmp/my_test_key" {
		t.Fatalf("expected IdentityFiles to contain /tmp/my_test_key, got %+v", cfg.IdentityFiles)
	}
}

func TestServerFailFastWithoutAuthorizedKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // Ensure default ~/.ssh/authorized_keys does not exist

	// 1. Without flag or TOML, server must fail fast (exit code 1)
	code := run([]string{"server", "--listen", "127.0.0.1:0"})
	if code != 1 {
		t.Fatalf("expected server to fail fast with code 1, got %d", code)
	}

	// 2. With --authorized-keys flag provided, server does not fail fast on missing flag
	// It accepts the flag path without complaining
	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	_ = os.WriteFile(ak, []byte("# empty\n"), 0o600)
	opts := config.ServerOptions{
		AuthorizedKeys: ak,
	}
	cfg, err := config.LoadServer(opts)
	if err != nil {
		t.Fatalf("expected LoadServer to succeed with flag, got %v", err)
	}
	if cfg.AuthorizedKeys != ak {
		t.Fatalf("expected AuthorizedKeys=%s, got %s", ak, cfg.AuthorizedKeys)
	}
}

func TestAdaptiveKCPCLIFlags(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "client.toml")
	_ = os.WriteFile(confPath, []byte("server = \"127.0.0.1:7443\"\n"), 0o600)

	tr := true
	fl := false

	// Client flag --adaptive-kcp
	cfg, err := config.LoadClient(config.ClientOptions{
		ConfigPath:  confPath,
		AdaptiveKCP: &tr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AdaptiveKCP {
		t.Fatalf("expected AdaptiveKCP=true, got %v", cfg.AdaptiveKCP)
	}

	// Client flag --no-adaptive-kcp
	cfg, err = config.LoadClient(config.ClientOptions{
		ConfigPath:  confPath,
		AdaptiveKCP: &fl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdaptiveKCP {
		t.Fatalf("expected AdaptiveKCP=false, got %v", cfg.AdaptiveKCP)
	}

	// Server options
	scfg, err := config.LoadServer(config.ServerOptions{
		AdaptiveKCP: &tr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !scfg.AdaptiveKCP {
		t.Fatalf("expected Server AdaptiveKCP=true, got %v", scfg.AdaptiveKCP)
	}

	scfg, err = config.LoadServer(config.ServerOptions{
		AdaptiveKCP: &fl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scfg.AdaptiveKCP {
		t.Fatalf("expected Server AdaptiveKCP=false, got %v", scfg.AdaptiveKCP)
	}
}

func TestInterfaceAndSourceIPCLIFlags(t *testing.T) {
	var code int

	// 1. Invalid interface fails fast with exit code 1
	_, stderr := captureOutput(func() {
		code = run([]string{"client", "--server", "127.0.0.1:7443", "--interface", "nonexistent_dev_42"})
	})
	if code != 1 {
		t.Fatalf("expected code 1, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "interface \"nonexistent_dev_42\" not found") {
		t.Fatalf("expected not found error, got %s", stderr)
	}

	// 2. Invalid source IP fails fast with exit code 1
	_, stderr = captureOutput(func() {
		code = run([]string{"client", "--server", "127.0.0.1:7443", "--source-ip", "999.999.999.999"})
	})
	if code != 1 {
		t.Fatalf("expected code 1, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "invalid source ip") {
		t.Fatalf("expected invalid source ip error, got %s", stderr)
	}

	// 3. Duplicate flag for same leg fails with exit code 1
	_, stderr = captureOutput(func() {
		code = run([]string{"client", "--server", "127.0.0.1:7443", "--interface", "lo@tcp", "--interface", "lo@tcp"})
	})
	if code != 1 {
		t.Fatalf("expected code 1, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "conflicting/duplicate interface for tcp") {
		t.Fatalf("expected duplicate interface error, got %s", stderr)
	}

	// 4. Unknown protocol suffix fails with exit code 1
	_, stderr = captureOutput(func() {
		code = run([]string{"client", "--server", "127.0.0.1:7443", "--interface", "lo@sctp"})
	})
	if code != 1 {
		t.Fatalf("expected code 1, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "unknown protocol \"sctp\"") {
		t.Fatalf("expected unknown protocol error, got %s", stderr)
	}

	// 5. Valid CLI flags parsed through LoadClient
	cfg, err := config.LoadClient(config.ClientOptions{
		Server:     "127.0.0.1:7443",
		Interfaces: []string{"lo@tcp", "lo@udp"},
		SourceIPs:  []string{"127.0.0.1@tcp", "127.0.0.2@udp"},
	})
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.TCPInterface != "lo" || cfg.UDPInterface != "lo" {
		t.Fatalf("expected lo/lo, got %s/%s", cfg.TCPInterface, cfg.UDPInterface)
	}
	if cfg.TCPSourceIP != "127.0.0.1" || cfg.UDPSourceIP != "127.0.0.2" {
		t.Fatalf("expected 127.0.0.1/127.0.0.2, got %s/%s", cfg.TCPSourceIP, cfg.UDPSourceIP)
	}
}
