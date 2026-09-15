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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

func startTestAgentSocket(t *testing.T, ag agent.Agent) (sockPath string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = agent.ServeAgent(ag, c)
			}(conn)
		}
	}()
	return sock, func() {
		_ = ln.Close()
		<-done
	}
}

func TestPublicKeyWithAgentInjected(t *testing.T) {
	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "agent-test"}); err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Client has NO identity files configured
	client := NewPublicKey(Config{User: "bob", Agent: keyring})
	defer client.Close()
	server := NewPublicKey(Config{AuthorizedKeys: ak})

	ch := Challenge{
		SessionID:   "s-agent-1",
		Destination: "127.0.0.1:22",
		ClientNonce: "cnonce",
		ServerNonce: "snonce",
		Canonical:   []byte(`{"v":1,"destination":"127.0.0.1:22"}`),
	}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatalf("Respond failed: %v", err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	id, err := server.Verify(ch, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if id.Name != "bob" || id.Method != MethodPublicKey {
		t.Fatalf("unexpected id: %+v", id)
	}
}

func TestPublicKeyWithAgentUnixSocket(t *testing.T) {
	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "unix-agent"}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := startTestAgentSocket(t, keyring)
	defer cleanup()

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Zero files on disk! Point only to AuthSock
	client := NewPublicKey(Config{User: "carol", AuthSock: sock})
	defer client.Close()
	server := NewPublicKey(Config{AuthorizedKeys: ak})

	ch := Challenge{
		SessionID:   "s-unix-1",
		Destination: "127.0.0.1:22",
		ClientNonce: "cnonce",
		ServerNonce: "snonce",
		Canonical:   []byte(`{"v":1}`),
	}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatalf("Respond failed: %v", err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	id, err := server.Verify(ch, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if id.Name != "carol" {
		t.Fatalf("expected name carol, got %q", id.Name)
	}
}

func TestPublicKeyFallbackChain(t *testing.T) {
	dir := t.TempDir()
	filePriv, filePubLine := writeEd25519(t, dir, "fallback_key", true)
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(filePubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("AgentHasKeysTakesPrecedence", func(t *testing.T) {
		agentKeyring := agent.NewKeyring()
		_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := agentKeyring.Add(agent.AddedKey{PrivateKey: agentPriv}); err != nil {
			t.Fatal(err)
		}

		client := NewPublicKey(Config{
			Agent: agentKeyring,
			// No identity files specified: agent should be tried first!
		})
		defer client.Close()

		signers, err := client.getSigners()
		if err != nil {
			t.Fatal(err)
		}
		if len(signers) == 0 {
			t.Fatal("expected at least 1 signer")
		}
		// First signer should be the agent's key
		agentSigner, _ := ssh.NewSignerFromKey(agentPriv)
		if string(signers[0].PublicKey().Marshal()) != string(agentSigner.PublicKey().Marshal()) {
			t.Fatal("expected agent key to take precedence")
		}
	})

	t.Run("EmptyAgentFallsBackToFiles", func(t *testing.T) {
		emptyAgent := agent.NewKeyring()
		client := NewPublicKey(Config{
			Agent:         emptyAgent,
			IdentityFiles: []string{filePriv},
		})
		defer client.Close()
		server := NewPublicKey(Config{AuthorizedKeys: ak})

		ch := Challenge{SessionID: "s-fb-1", Destination: "d", ClientNonce: "c", ServerNonce: "s", Canonical: []byte("fb")}
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
			t.Fatalf("expected fallback to file key to succeed: %v", err)
		}
	})

	t.Run("UnreachableAgentFallsBackToFiles", func(t *testing.T) {
		client := NewPublicKey(Config{
			AuthSock:      "/tmp/nonexistent-agent-socket-" + t.Name() + ".sock",
			IdentityFiles: []string{filePriv},
		})
		defer client.Close()
		server := NewPublicKey(Config{AuthorizedKeys: ak})

		ch := Challenge{SessionID: "s-fb-2", Destination: "d", ClientNonce: "c", ServerNonce: "s", Canonical: []byte("fb")}
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
			t.Fatalf("expected fallback on unreachable socket: %v", err)
		}
	})

	t.Run("NoSignerFoundFailsCleanly", func(t *testing.T) {
		emptyAgent := agent.NewKeyring()
		client := NewPublicKey(Config{
			Agent:         emptyAgent,
			IdentityFiles: []string{filepath.Join(dir, "nonexistent_key")},
		})
		defer client.Close()

		_, err := client.Respond(Challenge{})
		if err == nil {
			t.Fatal("expected error when no signers exist")
		}
		if !strings.Contains(err.Error(), "no usable identity") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestPublicKeyWithPassphraseProtectedKeyAndAgent(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_enc")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "verysecretpassword", "-f", privPath, "-C", "enc@test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(privPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	serverPub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, pubBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	encBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	rawPriv, err := ssh.ParseRawPrivateKeyWithPassphrase(encBytes, []byte("verysecretpassword"))
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	sock, cleanup := startTestAgentSocket(t, keyring)
	defer cleanup()

	if err := keyring.Add(agent.AddedKey{
		PrivateKey: rawPriv,
		Comment:    privPath,
	}); err != nil {
		t.Fatalf("failed to add key to keyring: %v", err)
	}

	client := NewPublicKey(Config{
		IdentityFiles: []string{privPath},
		AuthSock:      sock,
	})
	defer client.Close()
	server := NewPublicKey(Config{AuthorizedKeys: ak})

	ch := Challenge{SessionID: "s-enc-1", Destination: "d", ClientNonce: "c", ServerNonce: "s", Canonical: []byte("enc")}
	offer, err := client.Respond(ch)
	if err != nil {
		t.Fatalf("expected agent delegation for encrypted key file, got err: %v", err)
	}
	ch.Offer = offer
	sig, err := client.Sign(ch)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	id, err := server.Verify(ch, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if id.Fingerprint != ssh.FingerprintSHA256(serverPub) {
		t.Fatalf("fingerprint mismatch: got %s, want %s", id.Fingerprint, ssh.FingerprintSHA256(serverPub))
	}
}

func TestPublicKeyRSA2048FromAgent(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: rsaPriv}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := startTestAgentSocket(t, keyring)
	defer cleanup()

	signer, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewPublicKey(Config{AuthSock: sock})
	defer client.Close()
	server := NewPublicKey(Config{AuthorizedKeys: ak})

	ch := Challenge{SessionID: "s-rsa-agent", Destination: "d", ClientNonce: "c", ServerNonce: "s", Canonical: []byte("rsa")}
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
		t.Fatalf("RSA2048 via agent failed verify: %v", err)
	}
}

func TestPublicKeyAgentRejectsSmallRSA(t *testing.T) {
	t.Setenv("RELAY_TEST_IDENTITY", filepath.Join(t.TempDir(), "nonexistent"))
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: rsaPriv}); err != nil {
		t.Fatal(err)
	}
	sock, cleanup := startTestAgentSocket(t, keyring)
	defer cleanup()

	client := NewPublicKey(Config{AuthSock: sock})
	defer client.Close()

	if _, err := client.Respond(Challenge{}); err == nil {
		t.Fatal("expected 1024-bit RSA from agent to be rejected by key policy")
	}
}

type mockSKPubKey struct {
	keyType string
}

func (m *mockSKPubKey) Type() string                                 { return m.keyType }
func (m *mockSKPubKey) Marshal() []byte                              { return []byte("dummy-sk-key-blob") }
func (m *mockSKPubKey) Verify(data []byte, sig *ssh.Signature) error { return nil }

func TestPublicKeySKKeyPolicy(t *testing.T) {
	skEd := &mockSKPubKey{keyType: ssh.KeyAlgoSKED25519}
	if err := checkKeyPolicy(skEd); err != nil {
		t.Fatalf("expected sk-ssh-ed25519 to be allowed: %v", err)
	}
	if !allowedSigFormat(ssh.KeyAlgoSKED25519, skEd) {
		t.Fatal("expected allowedSigFormat to accept sk-ssh-ed25519")
	}

	skEcdsa := &mockSKPubKey{keyType: ssh.KeyAlgoSKECDSA256}
	if err := checkKeyPolicy(skEcdsa); err != nil {
		t.Fatalf("expected sk-ecdsa to be allowed: %v", err)
	}
	if !allowedSigFormat(ssh.KeyAlgoSKECDSA256, skEcdsa) {
		t.Fatal("expected allowedSigFormat to accept sk-ecdsa")
	}
}
