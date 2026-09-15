package auth

import (
	"testing"
)

func TestNewAlwaysReturnsPublicKey(t *testing.T) {
	a := New(Config{})
	if a.Name() != MethodPublicKey {
		t.Fatalf("expected Name=%q, got %q", MethodPublicKey, a.Name())
	}
	if !a.RequiresChallenge() {
		t.Fatal("expected RequiresChallenge=true")
	}
	if a.FailDelay() != DefaultFailDelay {
		t.Fatalf("expected FailDelay=%v, got %v", DefaultFailDelay, a.FailDelay())
	}

	a2 := New(Config{Method: "ssh-publickey"})
	if a2.Name() != MethodPublicKey {
		t.Fatalf("expected Name=%q, got %q", MethodPublicKey, a2.Name())
	}
}
