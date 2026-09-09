package bfd

import (
	"testing"
	"time"
)

func TestPacketEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		pkt  Packet
	}{
		{
			name: "down-packet",
			pkt: Packet{
				State:                 StateDown,
				DetectMult:            3,
				Flags:                 0,
				MyDisc:                0x12345678,
				YourDisc:              0,
				DesiredMinTxInterval:  750 * time.Millisecond,
				RequiredMinRxInterval: 750 * time.Millisecond,
			},
		},
		{
			name: "init-packet",
			pkt: Packet{
				State:                 StateInit,
				DetectMult:            3,
				Flags:                 1,
				MyDisc:                0xABCD1234,
				YourDisc:              0x12345678,
				DesiredMinTxInterval:  500 * time.Millisecond,
				RequiredMinRxInterval: 250 * time.Millisecond,
			},
		},
		{
			name: "up-packet",
			pkt: Packet{
				State:                 StateUp,
				DetectMult:            5,
				Flags:                 0,
				MyDisc:                0x99998888,
				YourDisc:              0x77776666,
				DesiredMinTxInterval:  1000 * time.Millisecond,
				RequiredMinRxInterval: 1200 * time.Millisecond,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := EncodePacket(tc.pkt)
			if len(raw) != PacketLen {
				t.Fatalf("expected length %d, got %d", PacketLen, len(raw))
			}
			dec, err := DecodePacket(raw)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if dec.State != tc.pkt.State {
				t.Errorf("state: want %v, got %v", tc.pkt.State, dec.State)
			}
			if dec.DetectMult != tc.pkt.DetectMult {
				t.Errorf("detectMult: want %d, got %d", tc.pkt.DetectMult, dec.DetectMult)
			}
			if dec.Flags != tc.pkt.Flags {
				t.Errorf("flags: want %d, got %d", tc.pkt.Flags, dec.Flags)
			}
			if dec.MyDisc != tc.pkt.MyDisc {
				t.Errorf("myDisc: want 0x%X, got 0x%X", tc.pkt.MyDisc, dec.MyDisc)
			}
			if dec.YourDisc != tc.pkt.YourDisc {
				t.Errorf("yourDisc: want 0x%X, got 0x%X", tc.pkt.YourDisc, dec.YourDisc)
			}
			if dec.DesiredMinTxInterval != tc.pkt.DesiredMinTxInterval {
				t.Errorf("desiredTx: want %v, got %v", tc.pkt.DesiredMinTxInterval, dec.DesiredMinTxInterval)
			}
			if dec.RequiredMinRxInterval != tc.pkt.RequiredMinRxInterval {
				t.Errorf("requiredRx: want %v, got %v", tc.pkt.RequiredMinRxInterval, dec.RequiredMinRxInterval)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	// Truncated packet
	if _, err := DecodePacket([]byte{1, 2, 3}); err != ErrPacketTooShort {
		t.Errorf("expected ErrPacketTooShort, got %v", err)
	}

	// Invalid state
	raw := EncodePacket(Packet{State: StateDown, MyDisc: 1})
	raw[0] = 0x99
	if _, err := DecodePacket(raw); err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}

	// Zero MyDisc
	raw = EncodePacket(Packet{State: StateDown, MyDisc: 1})
	raw[4] = 0
	raw[5] = 0
	raw[6] = 0
	raw[7] = 0
	if _, err := DecodePacket(raw); err != ErrZeroMyDisc {
		t.Errorf("expected ErrZeroMyDisc, got %v", err)
	}
}

func TestSessionConvergence(t *testing.T) {
	cfgA := Config{DesiredMinTxInterval: 50 * time.Millisecond, RequiredMinRxInterval: 50 * time.Millisecond, DetectMultiplier: 3}
	cfgB := Config{DesiredMinTxInterval: 50 * time.Millisecond, RequiredMinRxInterval: 50 * time.Millisecond, DetectMultiplier: 3}

	sessA := NewSessionWithDisc(cfgA, 0xAAAA)
	sessB := NewSessionWithDisc(cfgB, 0xBBBB)

	if sessA.State() != StateDown || sessB.State() != StateDown {
		t.Fatalf("expected both sessions to start in StateDown")
	}

	// Step 1: A sends to B
	pktA1 := sessA.FormatTxPacket()
	chB1, err := sessB.Receive(pktA1)
	if err != nil {
		t.Fatalf("B receive failed: %v", err)
	}
	if !chB1 || sessB.State() != StateInit {
		t.Fatalf("expected B to transition to StateInit, got %v", sessB.State())
	}
	if sessB.YourDisc() != 0xAAAA {
		t.Fatalf("expected B YourDisc to be 0xAAAA, got 0x%X", sessB.YourDisc())
	}

	// Step 2: B sends to A
	pktB1 := sessB.FormatTxPacket()
	chA1, err := sessA.Receive(pktB1)
	if err != nil {
		t.Fatalf("A receive failed: %v", err)
	}
	if !chA1 || sessA.State() != StateUp {
		t.Fatalf("expected A to transition to StateUp, got %v", sessA.State())
	}
	if sessA.YourDisc() != 0xBBBB {
		t.Fatalf("expected A YourDisc to be 0xBBBB, got 0x%X", sessA.YourDisc())
	}

	// Step 3: A sends to B
	pktA2 := sessA.FormatTxPacket()
	chB2, err := sessB.Receive(pktA2)
	if err != nil {
		t.Fatalf("B receive failed: %v", err)
	}
	if !chB2 || sessB.State() != StateUp {
		t.Fatalf("expected B to transition to StateUp, got %v", sessB.State())
	}

	if !sessA.IsUp() || !sessB.IsUp() {
		t.Fatalf("expected both sessions to be Up")
	}
}

func TestDiscriminatorMismatch(t *testing.T) {
	cfg := Config{DesiredMinTxInterval: 50 * time.Millisecond, RequiredMinRxInterval: 50 * time.Millisecond, DetectMultiplier: 3}
	sess := NewSessionWithDisc(cfg, 0x1234)

	// Valid initial packet with YourDisc = 0
	pkt1 := Packet{State: StateDown, DetectMult: 3, MyDisc: 0x9999, YourDisc: 0}
	_, err := sess.Receive(pkt1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Packet with wrong YourDisc (not matching local 0x1234)
	pktWrong := Packet{State: StateInit, DetectMult: 3, MyDisc: 0x9999, YourDisc: 0x5678}
	_, err = sess.Receive(pktWrong)
	if err != ErrDiscMismatch {
		t.Fatalf("expected ErrDiscMismatch, got %v", err)
	}
}

func TestTimeoutDetection(t *testing.T) {
	cfg := Config{DesiredMinTxInterval: 100 * time.Millisecond, RequiredMinRxInterval: 100 * time.Millisecond, DetectMultiplier: 3}
	sess := NewSessionWithDisc(cfg, 0x5555)

	// Transition to StateUp
	_, _ = sess.Receive(Packet{State: StateDown, DetectMult: 3, MyDisc: 0x6666, YourDisc: 0})
	_, _ = sess.Receive(Packet{State: StateInit, DetectMult: 3, MyDisc: 0x6666, YourDisc: 0x5555})
	if !sess.IsUp() {
		t.Fatalf("session should be Up")
	}

	// Check timeout at t + 100ms (timeout is 3 * 100ms = 300ms)
	now := sess.lastRx.Add(100 * time.Millisecond)
	if timedOut := sess.CheckTimeout(now); timedOut {
		t.Fatalf("expected no timeout at 100ms")
	}
	if !sess.IsUp() {
		t.Fatalf("session should still be Up")
	}

	// Check timeout at t + 350ms (> 300ms)
	now = sess.lastRx.Add(350 * time.Millisecond)
	if timedOut := sess.CheckTimeout(now); !timedOut {
		t.Fatalf("expected timeout at 350ms")
	}
	if sess.State() != StateDown {
		t.Fatalf("expected state to transition to StateDown, got %v", sess.State())
	}
	if sess.YourDisc() != 0 {
		t.Fatalf("expected yourDisc to be reset to 0 upon timeout")
	}
}
