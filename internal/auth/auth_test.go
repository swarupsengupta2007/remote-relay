package auth

import (
	"encoding/json"
	"testing"
)

func TestNoneAcceptsEmptyAuth(t *testing.T) {
	n := None{}
	if n.Name() != "none" {
		t.Fatalf("Name()=%q", n.Name())
	}
	for _, raw := range []json.RawMessage{
		nil,
		{},
		[]byte(""),
		[]byte("null"),
		[]byte("{}"),
		[]byte(" {} "),
	} {
		id, err := n.Verify(Challenge{}, raw)
		if err != nil {
			t.Fatalf("raw=%q: %v", raw, err)
		}
		if id.Method != "none" {
			t.Fatalf("identity %+v", id)
		}
	}
	resp, err := n.Respond(Challenge{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "{}" {
		t.Fatalf("Respond=%s", resp)
	}
}

func TestNoneRejectsNonEmpty(t *testing.T) {
	_, err := None{}.Verify(Challenge{}, json.RawMessage(`{"method":"ssh-publickey"}`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNoneNoChallenge(t *testing.T) {
	n := None{}
	if n.RequiresChallenge() {
		t.Fatal("none must not require a challenge")
	}
	if n.FailDelay() != 0 {
		t.Fatalf("delay=%s", n.FailDelay())
	}
	sig, err := n.Sign(Challenge{})
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "{}" {
		t.Fatalf("Sign=%s", sig)
	}
}

func TestNewSelectsMethod(t *testing.T) {
	if New(Config{Method: "none"}).Name() != MethodNone {
		t.Fatal("none")
	}
	if New(Config{}).Name() != MethodNone {
		t.Fatal("default none")
	}
	if New(Config{Method: "ssh-publickey"}).Name() != MethodPublicKey {
		t.Fatal("ssh-publickey")
	}
}
