package proto

import (
	"encoding/binary"
	"io"
)

func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxFrameLen {
		return ErrFrame
	}
	var hdr [5]byte
	hdr[0] = byte(f.Type)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) == 0 {
		return nil
	}
	_, err := w.Write(f.Payload)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrameLen {
		return Frame{}, ErrFrame
	}
	typ := Type(hdr[0])
	if !typ.Known() {
		return Frame{}, ErrProto
	}
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: typ, Payload: payload}, nil
}

func EncodeData(seq uint64, p []byte) []byte {
	out := make([]byte, 8+len(p))
	binary.BigEndian.PutUint64(out, seq)
	copy(out[8:], p)
	return out
}

func DecodeData(payload []byte) (seq uint64, data []byte, err error) {
	if len(payload) < 8 {
		return 0, nil, ErrProto
	}
	seq = binary.BigEndian.Uint64(payload[:8])
	return seq, payload[8:], nil
}

func EncodeAck(ackedThrough uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ackedThrough)
	return b[:]
}

func DecodeAck(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, ErrProto
	}
	return binary.BigEndian.Uint64(payload), nil
}

func EncodePing(nonce, sentUnixMillis uint64) []byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], nonce)
	binary.BigEndian.PutUint64(b[8:16], sentUnixMillis)
	return b[:]
}

func DecodePing(payload []byte) (nonce, sentUnixMillis uint64, err error) {
	if len(payload) != 16 {
		return 0, 0, ErrProto
	}
	return binary.BigEndian.Uint64(payload[0:8]), binary.BigEndian.Uint64(payload[8:16]), nil
}

func EncodeProbe(token [16]byte, nonce uint64) []byte {
	var b [24]byte
	copy(b[:16], token[:])
	binary.BigEndian.PutUint64(b[16:], nonce)
	return b[:]
}

func DecodeProbe(payload []byte) (token [16]byte, nonce uint64, err error) {
	if len(payload) != 24 {
		return token, 0, ErrProto
	}
	copy(token[:], payload[:16])
	return token, binary.BigEndian.Uint64(payload[16:]), nil
}

func EncodeProbeOK(nonce uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], nonce)
	return b[:]
}

func DecodeProbeOK(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, ErrProto
	}
	return binary.BigEndian.Uint64(payload), nil
}
