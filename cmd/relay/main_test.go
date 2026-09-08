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
}
