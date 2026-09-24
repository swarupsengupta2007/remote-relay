package socks5

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestSocks5_AuthHappyPath(t *testing.T) {
	// Client offers 2 methods: 0x00 (no auth) and 0x02 (user/pass)
	in := []byte{Version5, 0x02, MethodNoAuth, MethodUsernamePassword}
	methods, err := ReadAuth(bytes.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 || methods[0] != MethodNoAuth || methods[1] != MethodUsernamePassword {
		t.Fatalf("unexpected methods: %v", methods)
	}

	var out bytes.Buffer
	if err := WriteAuthReply(&out, MethodNoAuth); err != nil {
		t.Fatalf("WriteAuthReply error: %v", err)
	}
	expected := []byte{Version5, MethodNoAuth}
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatalf("expected auth reply %v, got %v", expected, out.Bytes())
	}
}

func TestSocks5_AuthSadPaths(t *testing.T) {
	// Bad version (e.g. SOCKS4)
	_, err := ReadAuth(bytes.NewReader([]byte{0x04, 0x01, 0x00}))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}

	// Zero methods offered
	_, err = ReadAuth(bytes.NewReader([]byte{Version5, 0x00}))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Fatalf("expected ErrMalformedRequest for 0 methods, got %v", err)
	}

	// Truncated header
	_, err = ReadAuth(bytes.NewReader([]byte{Version5}))
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF error, got %v", err)
	}

	// Truncated methods body
	_, err = ReadAuth(bytes.NewReader([]byte{Version5, 0x03, 0x00}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestSocks5_RequestHappyPath_IPv4(t *testing.T) {
	// CONNECT 127.0.0.1:8080 (0x1F90 = 8080)
	raw := []byte{
		Version5, CmdConnect, 0x00, AtypIPv4,
		127, 0, 0, 1,
		0x1F, 0x90,
	}
	req, err := ReadRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Command != CmdConnect {
		t.Fatalf("expected CmdConnect, got %d", req.Command)
	}
	if req.DestAddr != "127.0.0.1" {
		t.Fatalf("expected DestAddr 127.0.0.1, got %s", req.DestAddr)
	}
	if req.DestPort != 8080 {
		t.Fatalf("expected DestPort 8080, got %d", req.DestPort)
	}
	if req.Dest != "127.0.0.1:8080" {
		t.Fatalf("expected Dest 127.0.0.1:8080, got %s", req.Dest)
	}
}

func TestSocks5_RequestHappyPath_Domain(t *testing.T) {
	// CONNECT example.com:443 (len 11, port 0x01BB = 443)
	domain := "example.com"
	raw := []byte{
		Version5, CmdConnect, 0x00, AtypDomainName,
		byte(len(domain)),
	}
	raw = append(raw, []byte(domain)...)
	raw = append(raw, 0x01, 0xBB)

	req, err := ReadRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.DestAddr != "example.com" {
		t.Fatalf("expected DestAddr example.com, got %s", req.DestAddr)
	}
	if req.DestPort != 443 {
		t.Fatalf("expected DestPort 443, got %d", req.DestPort)
	}
	if req.Dest != "example.com:443" {
		t.Fatalf("expected Dest example.com:443, got %s", req.Dest)
	}
}

func TestSocks5_RequestHappyPath_IPv6(t *testing.T) {
	// CONNECT [::1]:22 (port 0x0016 = 22)
	ip6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	raw := []byte{
		Version5, CmdConnect, 0x00, AtypIPv6,
	}
	raw = append(raw, ip6...)
	raw = append(raw, 0x00, 0x16)

	req, err := ReadRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.DestAddr != "::1" {
		t.Fatalf("expected DestAddr ::1, got %s", req.DestAddr)
	}
	if req.DestPort != 22 {
		t.Fatalf("expected DestPort 22, got %d", req.DestPort)
	}
	if req.Dest != "[::1]:22" {
		t.Fatalf("expected Dest [::1]:22, got %s", req.Dest)
	}
}

func TestSocks5_RequestSadPaths(t *testing.T) {
	// Bad version
	_, err := ReadRequest(bytes.NewReader([]byte{0x04, CmdConnect, 0x00, AtypIPv4, 127, 0, 0, 1, 0x00, 0x50}))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}

	// RSV field non-zero
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x01, AtypIPv4, 127, 0, 0, 1, 0x00, 0x50}))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Fatalf("expected ErrMalformedRequest for non-zero RSV, got %v", err)
	}

	// Unsupported address type (e.g. 0x02 or 0x05)
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x00, 0x02, 127, 0, 0, 1, 0x00, 0x50}))
	if !errors.Is(err, ErrUnsupportedAddress) {
		t.Fatalf("expected ErrUnsupportedAddress, got %v", err)
	}

	// Empty domain name length 0
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x00, AtypDomainName, 0x00, 0x00, 0x50}))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Fatalf("expected ErrMalformedRequest for empty domain, got %v", err)
	}

	// Truncated IPv4
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x00, AtypIPv4, 127, 0}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}

	// Truncated domain payload
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x00, AtypDomainName, 0x05, 'a', 'b'}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}

	// Truncated port
	_, err = ReadRequest(bytes.NewReader([]byte{Version5, CmdConnect, 0x00, AtypIPv4, 127, 0, 0, 1, 0x00}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestSocks5_WriteReply(t *testing.T) {
	// Success with IPv4 bound address
	var out bytes.Buffer
	if err := WriteReply(&out, RepSucceeded, "10.0.0.1:1080"); err != nil {
		t.Fatalf("WriteReply error: %v", err)
	}
	expected := []byte{
		Version5, RepSucceeded, 0x00, AtypIPv4,
		10, 0, 0, 1,
		0x04, 0x38, // 1080
	}
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatalf("expected %v, got %v", expected, out.Bytes())
	}

	// Ruleset forbidden with empty bound addr (0.0.0.0:0)
	out.Reset()
	if err := WriteReply(&out, RepConnectionNotAllowed, ""); err != nil {
		t.Fatalf("WriteReply error: %v", err)
	}
	expected = []byte{
		Version5, RepConnectionNotAllowed, 0x00, AtypIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatalf("expected %v, got %v", expected, out.Bytes())
	}

	// Host unreachable with domain bound address
	out.Reset()
	if err := WriteReply(&out, RepHostUnreachable, "proxy.local:80"); err != nil {
		t.Fatalf("WriteReply error: %v", err)
	}
	expectedHeader := []byte{Version5, RepHostUnreachable, 0x00, AtypDomainName, 11}
	if !bytes.HasPrefix(out.Bytes(), expectedHeader) {
		t.Fatalf("expected prefix %v, got %v", expectedHeader, out.Bytes())
	}
}

func TestSocks5_MuxFrameRoundTrip(t *testing.T) {
	frames := []MuxFrame{
		{StreamID: 1, Type: TypeStreamOpen, Payload: []byte("example.com:443")},
		{StreamID: 1, Type: TypeStreamOpenOK, Payload: []byte("127.0.0.1:54321")},
		{StreamID: 2, Type: TypeStreamOpenFail, Payload: EncodeOpenFail(RepConnectionRefused, "connection refused")},
		{StreamID: 1, Type: TypeStreamData, Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{StreamID: 1, Type: TypeStreamClose, Payload: []byte{CloseHalfWrite}},
		{StreamID: 2, Type: TypeStreamReset, Payload: []byte("reset by peer")},
	}

	var buf bytes.Buffer
	for _, f := range frames {
		if err := WriteMuxFrame(&buf, f); err != nil {
			t.Fatalf("WriteMuxFrame failed: %v", err)
		}
	}

	for i, expected := range frames {
		got, err := ReadMuxFrame(&buf)
		if err != nil {
			t.Fatalf("[%d] ReadMuxFrame failed: %v", i, err)
		}
		if got.StreamID != expected.StreamID {
			t.Fatalf("[%d] StreamID: expected %d, got %d", i, expected.StreamID, got.StreamID)
		}
		if got.Type != expected.Type {
			t.Fatalf("[%d] Type: expected %d, got %d", i, expected.Type, got.Type)
		}
		if !bytes.Equal(got.Payload, expected.Payload) {
			t.Fatalf("[%d] Payload mismatch", i)
		}
	}

	// Test EncodeOpenFail / DecodeOpenFail
	failPayload := EncodeOpenFail(RepConnectionNotAllowed, "ruleset denied")
	rep, msg := DecodeOpenFail(failPayload)
	if rep != RepConnectionNotAllowed || msg != "ruleset denied" {
		t.Fatalf("DecodeOpenFail mismatch: rep=%d msg=%s", rep, msg)
	}

	rep, msg = DecodeOpenFail(nil)
	if rep != RepGeneralFailure || msg != "unknown failure" {
		t.Fatalf("DecodeOpenFail empty mismatch: rep=%d msg=%s", rep, msg)
	}
}

func TestSocks5_MuxFrameSadPaths(t *testing.T) {
	// Truncated header
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 1, TypeStreamData}) // only 5 bytes, need 9
	_, err := ReadMuxFrame(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}

	// Truncated payload
	buf.Reset()
	f := MuxFrame{StreamID: 42, Type: TypeStreamData, Payload: []byte("hello world")}
	var fullBuf bytes.Buffer
	_ = WriteMuxFrame(&fullBuf, f)
	buf.Write(fullBuf.Bytes()[:len(fullBuf.Bytes())-3]) // cut 3 bytes off payload
	_, err = ReadMuxFrame(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}

	// Payload exceeding MaxMuxPayloadLen
	hugeFrame := MuxFrame{StreamID: 1, Type: TypeStreamData, Payload: make([]byte, MaxMuxPayloadLen+1)}
	err = WriteMuxFrame(&buf, hugeFrame)
	if err == nil {
		t.Fatalf("expected error for oversized payload, got nil")
	}
}
