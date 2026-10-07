package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relay-test-auth-*")
	if err != nil {
		panic(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		panic(err)
	}
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	authPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authPath, []byte(pubLine+"\n"), 0o600); err != nil {
		panic(err)
	}

	_ = os.Setenv("RELAY_TEST_IDENTITY", privPath)
	_ = os.Setenv("RELAY_TEST_AUTHORIZED_KEYS", authPath)
	_ = os.Setenv("RELAY_TEST_KNOWN_HOSTS", os.DevNull)

	code := m.Run()

	_ = os.Unsetenv("RELAY_TEST_IDENTITY")
	_ = os.Unsetenv("RELAY_TEST_AUTHORIZED_KEYS")
	_ = os.Unsetenv("RELAY_TEST_KNOWN_HOSTS")

	// Not deferred: os.Exit skips deferred calls.
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
