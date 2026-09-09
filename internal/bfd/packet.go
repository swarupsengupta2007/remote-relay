package bfd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// PacketLen is the fixed 20-byte payload length of a BFD control frame in remote-relay.
const PacketLen = 20

// State represents the BFD session state (RFC 5880 §4.1).
// AdminDown is eliminated as agreed in FEAT-ROB-01.
type State uint8

const (
	StateDown State = 0x01
	StateInit State = 0x02
	StateUp   State = 0x03
)

func (s State) String() string {
	switch s {
	case StateDown:
		return "DOWN"
	case StateInit:
		return "INIT"
	case StateUp:
		return "UP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

func (s State) Valid() bool {
	return s == StateDown || s == StateInit || s == StateUp
}

var (
	ErrPacketTooShort = errors.New("bfd: packet payload too short")
	ErrInvalidState   = errors.New("bfd: invalid state")
	ErrZeroMyDisc     = errors.New("bfd: my discriminator cannot be zero")
)

// Packet represents a BFD control frame payload.
type Packet struct {
	State                 State
	DetectMult            uint8
	Flags                 uint16
	MyDisc                uint32
	YourDisc              uint32
	DesiredMinTxInterval  time.Duration
	RequiredMinRxInterval time.Duration
}

// EncodePacket serializes a Packet into a fixed 20-byte binary slice.
func EncodePacket(p Packet) []byte {
	buf := make([]byte, PacketLen)
	buf[0] = byte(p.State)
	buf[1] = p.DetectMult
	binary.BigEndian.PutUint16(buf[2:4], p.Flags)
	binary.BigEndian.PutUint32(buf[4:8], p.MyDisc)
	binary.BigEndian.PutUint32(buf[8:12], p.YourDisc)

	txMs := uint32(p.DesiredMinTxInterval.Milliseconds())
	rxMs := uint32(p.RequiredMinRxInterval.Milliseconds())
	binary.BigEndian.PutUint32(buf[12:16], txMs)
	binary.BigEndian.PutUint32(buf[16:20], rxMs)
	return buf
}

// DecodePacket deserializes a 20-byte slice into a Packet.
func DecodePacket(b []byte) (Packet, error) {
	if len(b) < PacketLen {
		return Packet{}, ErrPacketTooShort
	}
	st := State(b[0])
	if !st.Valid() {
		return Packet{}, ErrInvalidState
	}
	myDisc := binary.BigEndian.Uint32(b[4:8])
	if myDisc == 0 {
		return Packet{}, ErrZeroMyDisc
	}
	yourDisc := binary.BigEndian.Uint32(b[8:12])
	txMs := binary.BigEndian.Uint32(b[12:16])
	rxMs := binary.BigEndian.Uint32(b[16:20])

	return Packet{
		State:                 st,
		DetectMult:            b[1],
		Flags:                 binary.BigEndian.Uint16(b[2:4]),
		MyDisc:                myDisc,
		YourDisc:              yourDisc,
		DesiredMinTxInterval:  time.Duration(txMs) * time.Millisecond,
		RequiredMinRxInterval: time.Duration(rxMs) * time.Millisecond,
	}, nil
}
