package relay

import (
	"bytes"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/bfd"
	"github.com/remote-relay/relay/internal/proto"
)

func TestClientStandbyKeepsNonPingAndPromotes(t *testing.T) {
	sess := bfd.NewSessionWithDisc(bfd.Config{
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
		DetectMultiplier:      3,
	}, 0x11111111)
	if _, err := sess.Receive(bfd.Packet{
		State:                 bfd.StateUp,
		DetectMult:            3,
		MyDisc:                0x22222222,
		YourDisc:              0,
		DesiredMinTxInterval:  30 * time.Second,
		RequiredMinRxInterval: 30 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if !sess.IsUp() {
		t.Fatal("bfd session did not reach Up")
	}
	deadAfter := sess.DetectionTimeout()
	if deadAfter < time.Second {
		t.Fatalf("detection timeout %s is too short to prove immediate promotion", deadAfter)
	}

	in := make(chan proto.Frame, 4)
	out := make(chan proto.Frame, 4)
	conn := &mockFrameConn{in: in, out: out}

	gotData := make(chan struct{})
	cs := startClientStandby(t.Context(), conn, sess, nil, func() {
		close(gotData)
	})

	payload := []byte("standby-data-kept")
	start := time.Now()
	in <- proto.Frame{Type: proto.TypeData, Payload: payload}

	select {
	case <-gotData:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("non-ping frame was not promoted within 500ms (detection timeout %s)", deadAfter)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("promotion took %s, detection timeout is %s", elapsed, deadAfter)
	}

	promoted, promotedSess, frames, ok := cs.promote()
	if !ok {
		t.Fatal("promote returned false")
	}
	if promoted != conn {
		t.Fatal("promote did not return the standby conn")
	}
	if promotedSess != sess || !promotedSess.IsUp() {
		t.Fatal("promoted session is not the live BFD session")
	}
	if len(frames) != 1 || frames[0].Type != proto.TypeData || !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("promoted frames = %+v, want data %q", frames, payload)
	}
}
