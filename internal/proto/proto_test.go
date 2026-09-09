package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := EncodeData(42, []byte("hello"))
	want := Frame{Type: TypeData, Payload: payload}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type {
		t.Fatalf("type: got %s want %s", got.Type, want.Type)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload mismatch")
	}
	seq, data, err := DecodeData(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 42 || string(data) != "hello" {
		t.Fatalf("seq=%d data=%q", seq, data)
	}
}

func TestEmptyPayloadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: TypeBye, Payload: nil}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeBye || len(got.Payload) != 0 {
		t.Fatalf("got type=%s n=%d", got.Type, len(got.Payload))
	}
}

func TestOversizeFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(TypeHello))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], MaxFrameLen+1)
	buf.Write(n[:])
	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrame) {
		t.Fatalf("got %v, want ErrFrame", err)
	}

	tooBig := Frame{Type: TypeData, Payload: make([]byte, MaxFrameLen+1)}
	if err := WriteFrame(ioDiscard{}, tooBig); !errors.Is(err, ErrFrame) {
		t.Fatalf("write got %v, want ErrFrame", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestUnknownFrameType(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x99)
	buf.Write([]byte{0, 0, 0, 0})
	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrProto) {
		t.Fatalf("got %v, want ErrProto", err)
	}
}

func TestUnknownTypeGap(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x0E)
	buf.Write([]byte{0, 0, 0, 0})
	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrProto) {
		t.Fatalf("got %v, want ErrProto", err)
	}
}

func TestControlRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		typ  Type
		v    any
	}{
		{
			name: "hello",
			typ:  TypeHello,
			v: Hello{
				V: 1, SessionID: "", ResumeToken: "",
				Transport: []string{"tcp"}, Destination: "127.0.0.1:22",
				ClientNonce: "AAAAAAAAAAAAAAA=", Auth: EmptyAuth(), Window: 4194304,
			},
		},
		{
			name: "hello_ok",
			typ:  TypeHelloOK,
			v: HelloOK{
				V: 1, SessionID: "s-abc", ResumeToken: "token",
				Transport: "tcp", UDP: nil,
				Limits:      Limits{BufferBytes: 64, HoldTimeoutMs: 300000, Window: 4, DataChunkBytes: 65536},
				ServerNonce: "BBBBBBBBBBBBBBBB",
			},
		},
		{
			name: "hello_ok_udp",
			typ:  TypeHelloOK,
			v: HelloOK{
				V: 1, SessionID: "s-abc", ResumeToken: "token", Transport: "quic",
				UDP:         &UdpInfo{Addr: "203.0.113.7:7443", ProbeToken: "p", ProbeTimeoutMs: 2000, ProbeAttempts: 2},
				Limits:      Limits{BufferBytes: 1, HoldTimeoutMs: 1, Window: 1, DataChunkBytes: 1},
				ServerNonce: "n",
			},
		},
		{
			name: "resume",
			typ:  TypeResume,
			v:    Resume{V: 1, SessionID: "s-1", ResumeToken: "t", Transport: []string{"quic"}, DownAcked: 184320, ClientNonce: "c"},
		},
		{
			name: "resume_ok",
			typ:  TypeResumeOK,
			v: ResumeOK{
				V: 1, SessionID: "s-1", ResumeToken: "t2", UpAcked: 90210, DownNext: 184320,
				State:     SessionState{UpClosed: true, DownClosed: false, HeldMs: 4213},
				Transport: "tcp", UDP: nil, Limits: Limits{Window: 1},
			},
		},
		{name: "fail", typ: TypeErr, v: Fail{Code: CodeProto, Msg: "nope"}},
		{name: "auth", typ: TypeAuth, v: Auth{Sig: "AAAA"}},
		{
			name: "auth_ok",
			typ:  TypeAuthOK,
			v:    AuthOK{SessionID: "s-1", ServerNonce: "n", Challenge: "c", Destination: "127.0.0.1:22"},
		},
		{name: "switch", typ: TypeSwitch, v: Switch{Dir: DirBoth, From: "tcp", Offset: SwitchOffset{Up: 1, Down: 2}}},
		{name: "bye", typ: TypeBye, v: Bye{Code: CodeShutdown, Msg: "bye"}},
		{name: "close_dir", typ: TypeCloseDir, v: CloseDir{Dir: DirUp, FinalOffset: 99}},
		{name: "limits", typ: TypeHelloOK, v: Limits{BufferBytes: 2, HoldTimeoutMs: 3, Window: 4, DataChunkBytes: 5, SwitchTimeoutMs: 6}},
		{name: "session_state", typ: TypeResumeOK, v: SessionState{UpClosed: true, DownClosed: true, HeldMs: 7}},
		{name: "udp_info", typ: TypeHelloOK, v: UdpInfo{Addr: "a:1", ProbeToken: "x", ProbeTimeoutMs: 1, ProbeAttempts: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := WriteFrame(&buf, Frame{Type: tc.typ, Payload: raw}); err != nil {
				t.Fatal(err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != tc.typ {
				t.Fatalf("type %s", got.Type)
			}
			raw2, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(t, got.Payload, raw2) {
				t.Fatalf("json mismatch\n got %s\nwant %s", got.Payload, raw2)
			}
			if err := roundTripValue(tc.v); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func roundTripValue(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ptr := cloneEmpty(v)
	if ptr == nil {
		return nil
	}
	return json.Unmarshal(b, ptr)
}

func cloneEmpty(v any) any {
	switch v.(type) {
	case Hello:
		return &Hello{}
	case HelloOK:
		return &HelloOK{}
	case Resume:
		return &Resume{}
	case ResumeOK:
		return &ResumeOK{}
	case Fail:
		return &Fail{}
	case Switch:
		return &Switch{}
	case Bye:
		return &Bye{}
	case CloseDir:
		return &CloseDir{}
	case Limits:
		return &Limits{}
	case SessionState:
		return &SessionState{}
	case UdpInfo:
		return &UdpInfo{}
	case Auth:
		return &Auth{}
	case AuthOK:
		return &AuthOK{}
	default:
		return nil
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var xa, xb any
	if err := json.Unmarshal(a, &xa); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &xb); err != nil {
		t.Fatal(err)
	}
	aa, _ := json.Marshal(xa)
	bb, _ := json.Marshal(xb)
	return bytes.Equal(aa, bb)
}

func TestAckPingProbeCodec(t *testing.T) {
	ack := EncodeAck(99)
	n, err := DecodeAck(ack)
	if err != nil || n != 99 {
		t.Fatalf("ack %d %v", n, err)
	}
	ping := EncodePing(1, 2)
	a, b, err := DecodePing(ping)
	if err != nil || a != 1 || b != 2 {
		t.Fatalf("ping %d %d %v", a, b, err)
	}
	var tok [16]byte
	tok[0] = 7
	pr := EncodeProbe(tok, 3)
	gt, gn, err := DecodeProbe(pr)
	if err != nil || gt != tok || gn != 3 {
		t.Fatalf("probe %v", err)
	}
	ok := EncodeProbeOK(8)
	pn, err := DecodeProbeOK(ok)
	if err != nil || pn != 8 {
		t.Fatalf("probeok %d %v", pn, err)
	}
}

func TestKnownTypes(t *testing.T) {
	types := []Type{
		TypeHello, TypeHelloOK, TypeResume, TypeResumeOK, TypeResumeFail,
		TypeSwitch, TypeBye, TypeErr, TypeAuth, TypeAuthOK,
		TypeKexInit, TypeKexReply, TypeEncrypted,
		TypeData, TypeAck, TypeCloseDir,
		TypeProbe, TypeProbeOK, TypePing, TypePong,
	}
	for _, typ := range types {
		if !typ.Known() {
			t.Fatalf("%s should be known", typ)
		}
		if s := typ.String(); s == "" || strings.HasPrefix(s, "Type(") {
			t.Fatalf("expected known string for %d, got %q", typ, s)
		}
	}
	unknown := Type(0xff)
	if unknown.Known() {
		t.Fatalf("0xff should not be known")
	}
	if s := unknown.String(); s != "0xff" {
		t.Fatalf("unexpected unknown type string: %q", s)
	}
}

func TestProtoErrors(t *testing.T) {
	pe := NewError(CodeAuth, "authentication rejected")
	if pe.Error() != "ERR_AUTH: authentication rejected" {
		t.Fatalf("unexpected error string: %s", pe.Error())
	}
	peNoMsg := NewError(CodeAuth, "")
	if peNoMsg.Error() != "ERR_AUTH" {
		t.Fatalf("unexpected no-msg error string: %s", peNoMsg.Error())
	}
	if !errors.Is(pe, ErrAuth) {
		t.Fatalf("expected errors.Is to match ErrAuth")
	}
	if errors.Is(pe, ErrVersion) {
		t.Fatalf("did not expect ErrVersion match")
	}
	if errors.Is(pe, errors.New("other")) {
		t.Fatalf("did not expect generic error match")
	}
}

func TestMarshalUnmarshalPayload(t *testing.T) {
	h := Hello{V: 1, Destination: "127.0.0.1:22"}
	fr, err := MarshalFrame(TypeHello, h)
	if err != nil {
		t.Fatalf("MarshalFrame: %v", err)
	}
	if fr.Type != TypeHello {
		t.Fatalf("expected TypeHello, got %s", fr.Type)
	}

	var got Hello
	if err := UnmarshalPayload(fr, &got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got.V != 1 || got.Destination != "127.0.0.1:22" {
		t.Fatalf("unmarshaled mismatch: %+v", got)
	}

	// Corrupted JSON payload
	badFr := Frame{Type: TypeHello, Payload: []byte("{invalid json")}
	if err := UnmarshalPayload(badFr, &got); err == nil {
		t.Fatalf("expected error unmarshaling bad json")
	}
}

func TestRandomNonce(t *testing.T) {
	n1, err := RandomNonce()
	if err != nil {
		t.Fatalf("RandomNonce 1: %v", err)
	}
	n2, err := RandomNonce()
	if err != nil {
		t.Fatalf("RandomNonce 2: %v", err)
	}
	if n1 == "" || n2 == "" {
		t.Fatalf("expected non-empty nonces")
	}
	if n1 == n2 {
		t.Fatalf("nonces must be random and unique: %s == %s", n1, n2)
	}
}

func TestCorruptPayloadDecoders(t *testing.T) {
	short := []byte{1, 2, 3}
	if _, _, err := DecodeData(short); err == nil {
		t.Fatalf("DecodeData should fail on short payload")
	}
	if _, err := DecodeAck(short); err == nil {
		t.Fatalf("DecodeAck should fail on short payload")
	}
	if _, _, err := DecodePing(short); err == nil {
		t.Fatalf("DecodePing should fail on short payload")
	}
	if _, _, err := DecodeProbe(short); err == nil {
		t.Fatalf("DecodeProbe should fail on short payload")
	}
	if _, err := DecodeProbeOK(short); err == nil {
		t.Fatalf("DecodeProbeOK should fail on short payload")
	}
}

func TestKexFrameTypes(t *testing.T) {
	for _, typ := range []Type{TypeKexInit, TypeKexReply, TypeEncrypted} {
		if !typ.Known() {
			t.Fatalf("expected %v to be known", typ)
		}
	}
	if got := TypeKexInit.String(); got != "KEX_INIT" {
		t.Fatalf("TypeKexInit.String() = %q, want KEX_INIT", got)
	}
	if got := TypeKexReply.String(); got != "KEX_REPLY" {
		t.Fatalf("TypeKexReply.String() = %q, want KEX_REPLY", got)
	}
	if got := TypeEncrypted.String(); got != "ENCRYPTED" {
		t.Fatalf("TypeEncrypted.String() = %q, want ENCRYPTED", got)
	}
}

func TestKexFrameRoundTrip(t *testing.T) {
	frames := []Frame{
		{Type: TypeKexInit, Payload: make([]byte, 48)},
		{Type: TypeKexReply, Payload: make([]byte, 144)},
		{Type: TypeEncrypted, Payload: []byte("encrypted-ciphertext-payload")},
	}
	for _, want := range frames {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, want); err != nil {
			t.Fatalf("WriteFrame %v: %v", want.Type, err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %v: %v", want.Type, err)
		}
		if got.Type != want.Type {
			t.Fatalf("type mismatch: got %v, want %v", got.Type, want.Type)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("payload mismatch for %v", want.Type)
		}
	}
}
