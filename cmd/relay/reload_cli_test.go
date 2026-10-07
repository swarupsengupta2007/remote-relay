package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCLIOverridesSurviveReload(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(akPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "server.toml")
	writeTOML := func(logLevel, heartbeat, listen string) {
		t.Helper()
		body := "log_level = " + quoteTOML(logLevel) + "\n" +
			"heartbeat_interval = " + quoteTOML(heartbeat) + "\n" +
			"authorized_keys = " + quoteTOML(akPath) + "\n" +
			"listen_tcp = " + quoteTOML(listen) + "\n" +
			"default_destination = \"127.0.0.1:22\"\n" +
			"allow_destinations = [\"127.0.0.1:22\"]\n"
		if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeTOML("error", "2s", "127.0.0.1:1")

	srv, code := prepareServer([]string{
		"--config", cfgPath,
		"--log-level", "debug",
		"--heartbeat-interval", "50ms",
		"--authorized-keys", akPath,
	})
	if code != 0 || srv == nil {
		t.Fatalf("prepareServer code=%d srv=%v", code, srv)
	}
	defer srv.Close()

	if got := srv.Config().LogLevel; got != "debug" {
		t.Fatalf("startup log level %q", got)
	}
	if got := srv.Config().HeartbeatInterval.Duration(); got != 50*time.Millisecond {
		t.Fatalf("startup heartbeat %s", got)
	}

	writeTOML("warn", "3s", "127.0.0.1:9")
	if err := srv.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
	if got := srv.Config().LogLevel; got != "debug" {
		t.Fatalf("log level after reload %q, CLI override was lost", got)
	}
	if got := srv.Config().HeartbeatInterval.Duration(); got != 50*time.Millisecond {
		t.Fatalf("heartbeat after reload %s, CLI override was lost", got)
	}
}

func quoteTOML(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			out = append(out, '\\', s[i])
		default:
			out = append(out, s[i])
		}
	}
	out = append(out, '"')
	return string(out)
}
