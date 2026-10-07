package relay

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/obs"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

func TestTryUpgradeRecordsUpgradeSpan(t *testing.T) {
	tr := obs.NewTracer("test", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p := newPump(ctx, sessionIO{}, pumpConfig{
		log: logging.New(io.Discard, "error", "text"),
	}, nil)
	p.tracer = tr

	conn, peer := newMockFrameConn()
	defer conn.Close()
	defer peer.Close()

	var token [16]byte
	token[0] = 7
	udp := &proto.UdpInfo{
		Addr:           "127.0.0.1:1",
		ProbeToken:     transport.EncodeProbeToken(token),
		ProbeTimeoutMs: 50,
		ProbeAttempts:  1,
	}
	cfg := config.DefaultClient()
	cfg.AllowHA = false
	cfg.ProbeTimeout = config.Duration(50 * time.Millisecond)

	res := tryUpgrade(ctx, p, cfg, conn, "s-up", "token", "quic", udp, nil)
	if res.err == nil {
		t.Fatal("expected upgrade to fail closed when the UDP probe misses")
	}
	for _, span := range tr.RecentSpans() {
		if span.Name == "Upgrade" {
			return
		}
	}
	t.Fatal("upgrade sequence did not record a span named Upgrade")
}
