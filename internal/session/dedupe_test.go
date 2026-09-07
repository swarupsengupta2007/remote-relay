package session

import (
	"errors"
	"testing"

	"github.com/remote-relay/relay/internal/proto"
)

func TestDedupe(t *testing.T) {
	cases := []struct {
		name     string
		seq      uint64
		payload  string
		expected uint64
		wantSeq  uint64
		wantOut  string
		drop     bool
		err      error
	}{
		{name: "pure duplicate", seq: 0, payload: "hello", expected: 5, drop: true},
		{name: "older duplicate", seq: 0, payload: "ab", expected: 10, drop: true},
		{name: "partial overlap", seq: 0, payload: "hello", expected: 3, wantSeq: 3, wantOut: "lo"},
		{name: "exact continuation", seq: 5, payload: "world", expected: 5, wantSeq: 5, wantOut: "world"},
		{name: "gap fatal", seq: 6, payload: "x", expected: 5, err: proto.ErrProto},
		{name: "zero-length at expected", seq: 5, payload: "", expected: 5, wantSeq: 5, drop: true},
		{name: "zero-length duplicate", seq: 0, payload: "", expected: 5, drop: true},
		{name: "zero-length gap", seq: 6, payload: "", expected: 5, err: proto.ErrProto},
		{name: "single byte overlap", seq: 4, payload: "abc", expected: 5, wantSeq: 5, wantOut: "bc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seq, out, drop, err := Dedupe(tc.seq, []byte(tc.payload), tc.expected)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err=%v want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if drop != tc.drop {
				t.Fatalf("drop=%v want %v", drop, tc.drop)
			}
			if !tc.drop {
				if seq != tc.wantSeq {
					t.Fatalf("seq=%d want %d", seq, tc.wantSeq)
				}
				if string(out) != tc.wantOut {
					t.Fatalf("out=%q want %q", out, tc.wantOut)
				}
			}
			if tc.drop && len(out) != 0 {
				t.Fatalf("dropped payload %q", out)
			}
		})
	}
}
