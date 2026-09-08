package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDeriveChallengeBindsDestination(t *testing.T) {
	base := Challenge{
		SessionID:   "s-abc",
		ClientNonce: "c",
		ServerNonce: "s",
		Destination: "127.0.0.1:22",
		Canonical:   []byte(`{"v":1}`),
	}
	a := DeriveChallenge(base)
	other := base
	other.Destination = "127.0.0.1:1"
	b := DeriveChallenge(other)
	if string(a) == string(b) {
		t.Fatal("destination must bind the challenge")
	}
	same := DeriveChallenge(base)
	if string(a) != string(same) {
		t.Fatal("challenge must be deterministic")
	}
}

func TestPublicKeySignVerifyEd25519OpenSSH(t *testing.T) {
	dir := t.TempDir()
	priv, pubLine := writeEd25519(t, dir, "id_ed25519", true)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{User: "alice", IdentityFiles: []string{priv}})
	server := NewPublicKey(Config{AuthorizedKeys: ak, FailDelay: DefaultFailDelay})
	if !server.RequiresChallenge() || server.Name() != MethodPublicKey {
		t.Fatalf("server %+v", server)
	}
	if server.FailDelay() != DefaultFailDelay {
		t.Fatalf("delay=%s", server.FailDelay())
	}

	ch := Challenge{
		SessionID:   "s-1",
		Destination: "127.0.0.1:22",
		ClientNonce: "cnonce",
		ServerNonce: "snonce",
		Canonical:   []byte(`{"v":1,"destination":"127.0.0.1:22"}`),
	}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatal(err)
	}
	id, err := server.Verify(ch, sig)
	if err != nil {
		t.Fatal(err)
	}
	if id.Method != MethodPublicKey || id.Name != "alice" || id.Fingerprint == "" {
		t.Fatalf("identity %+v", id)
	}

	ch.BoundFP = id.Fingerprint
	ch.RawPubKey = id.RawPubKey
	if _, err := server.Verify(ch, sig); err != nil {
		t.Fatalf("resume with same key: %v", err)
	}
	ch.BoundFP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := server.Verify(ch, sig); err == nil {
		t.Fatal("expected bound fingerprint mismatch")
	}
}

func TestPublicKeyPEMAndECDSA(t *testing.T) {
	dir := t.TempDir()
	priv, pubLine := writeECDSA(t, dir, "id_ecdsa")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{IdentityFiles: []string{priv}})
	server := NewPublicKey(Config{AuthorizedKeys: ak})
	ch := Challenge{SessionID: "s", Destination: "d", ClientNonce: "c", ServerNonce: "n", Canonical: []byte("hello")}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Verify(ch, sig); err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyRSA2048(t *testing.T) {
	dir := t.TempDir()
	priv, pubLine := writeRSA(t, dir, "id_rsa", 2048, false)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{IdentityFiles: []string{priv}})
	server := NewPublicKey(Config{AuthorizedKeys: ak})
	ch := Challenge{SessionID: "s", Destination: "d", ClientNonce: "c", ServerNonce: "n", Canonical: []byte("rsa")}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Verify(ch, sig); err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyRejectsSmallRSA(t *testing.T) {
	dir := t.TempDir()
	priv, pubLine := writeRSA(t, dir, "id_rsa", 1024, true)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{IdentityFiles: []string{priv}})
	if _, err := client.Respond(Challenge{}); err == nil {
		t.Fatal("1024-bit rsa should not be offered")
	}
}

func TestPublicKeyUnauthorized(t *testing.T) {
	dir := t.TempDir()
	priv, _ := writeEd25519(t, dir, "id_ed25519", true)
	_, other := writeEd25519(t, dir, "other", true)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{IdentityFiles: []string{priv}})
	server := NewPublicKey(Config{AuthorizedKeys: ak})
	ch := Challenge{SessionID: "s", Destination: "d", ClientNonce: "c", ServerNonce: "n", Canonical: []byte("x")}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Verify(ch, sig); err == nil {
		t.Fatal("expected unauthorized")
	}
}

func TestPublicKeyBadSignature(t *testing.T) {
	dir := t.TempDir()
	priv, pubLine := writeEd25519(t, dir, "id_ed25519", true)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewPublicKey(Config{IdentityFiles: []string{priv}})
	server := NewPublicKey(Config{AuthorizedKeys: ak})
	ch := Challenge{SessionID: "s", Destination: "d", ClientNonce: "c", ServerNonce: "n", Canonical: []byte("x")}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Offer = offer
	if _, err := server.Verify(ch, json.RawMessage(`{"sig":""}`)); err == nil {
		t.Fatal("expected bad sig")
	}
}

func writeEd25519(t *testing.T, dir, name string, openssh bool) (privPath, pubLine string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writePrivate(t, dir, name, priv, openssh)
}

func writeECDSA(t *testing.T, dir, name string) (privPath, pubLine string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writePrivate(t, dir, name, priv, false)
}

func writeRSA(t *testing.T, dir, name string, bits int, openssh bool) (privPath, pubLine string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return writePrivate(t, dir, name, priv, openssh)
}

func writePrivate(t *testing.T, dir, name string, priv any, openssh bool) (string, string) {
	t.Helper()
	var pemBytes []byte
	if openssh {
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatal(err)
		}
		pemBytes = pem.EncodeToMemory(block)
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := os.WriteFile(path+".pub", append([]byte(pubLine), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, pubLine
}
