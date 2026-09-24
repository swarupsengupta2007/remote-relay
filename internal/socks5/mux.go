package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	TypeStreamOpen     uint8 = 0x01
	TypeStreamOpenOK   uint8 = 0x02
	TypeStreamOpenFail uint8 = 0x03
	TypeStreamData     uint8 = 0x04
	TypeStreamClose    uint8 = 0x05
	TypeStreamReset    uint8 = 0x06

	MaxMuxPayloadLen = 1 << 20 // 1 MiB max
	MuxHeaderLen     = 9       // 4 bytes streamID + 1 byte type + 4 bytes length

	CloseHalfWrite byte = 0x01
	CloseBoth      byte = 0x02
)

// MuxFrame represents a multiplexed stream frame passed across the remote-relay session.
type MuxFrame struct {
	StreamID uint32
	Type     uint8
	Payload  []byte
}

// WriteMuxFrame serializes a MuxFrame to w.
func WriteMuxFrame(w io.Writer, f MuxFrame) error {
	payloadLen := len(f.Payload)
	if payloadLen > MaxMuxPayloadLen {
		return fmt.Errorf("mux frame payload %d exceeds max %d", payloadLen, MaxMuxPayloadLen)
	}
	buf := make([]byte, MuxHeaderLen+payloadLen)
	binary.BigEndian.PutUint32(buf[0:4], f.StreamID)
	buf[4] = f.Type
	binary.BigEndian.PutUint32(buf[5:9], uint32(payloadLen))
	copy(buf[9:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadMuxFrame deserializes a MuxFrame from r.
func ReadMuxFrame(r io.Reader) (MuxFrame, error) {
	var hdr [MuxHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return MuxFrame{}, err
	}
	streamID := binary.BigEndian.Uint32(hdr[0:4])
	frameType := hdr[4]
	payloadLen := binary.BigEndian.Uint32(hdr[5:9])
	if payloadLen > MaxMuxPayloadLen {
		return MuxFrame{}, fmt.Errorf("mux frame payload %d exceeds max %d", payloadLen, MaxMuxPayloadLen)
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return MuxFrame{}, err
		}
	}
	return MuxFrame{
		StreamID: streamID,
		Type:     frameType,
		Payload:  payload,
	}, nil
}

// EncodeOpenFail encodes a failure reply code and error message.
func EncodeOpenFail(rep byte, msg string) []byte {
	b := make([]byte, 1+len(msg))
	b[0] = rep
	copy(b[1:], msg)
	return b
}

// DecodeOpenFail decodes a failure reply code and message.
func DecodeOpenFail(payload []byte) (byte, string) {
	if len(payload) == 0 {
		return RepGeneralFailure, "unknown failure"
	}
	return payload[0], string(payload[1:])
}
