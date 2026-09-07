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
