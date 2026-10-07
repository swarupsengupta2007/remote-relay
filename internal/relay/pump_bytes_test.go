package relay

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/obs"
	"github.com/remote-relay/relay/internal/proto"
)

func TestUserspacePumpCountsTransferredBytes(t *testing.T) {
	m := obs.NewMetrics()
	if m.BytesTransferred.Name() != "relay_bytes_transferred_total" {
		t.Fatalf("counter name %q", m.BytesTransferred.Name())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srcR, srcW := io.Pipe()
	sinkR, sinkW := io.Pipe()
	defer srcW.Close()
	defer sinkW.Close()
	go func() { _, _ = io.Copy(io.Discard, sinkR) }()

	p := newPump(ctx, sessionIO{
		src:    srcR,
		sink:   sinkW,
		outDir: proto.DirDown,
		inDir:  proto.DirUp,
	}, pumpConfig{
		chunk:   32,
		metrics: m,
		log:     logging.New(io.Discard, "error", "text"),
	}, nil)
	p.startIO()

	down := []byte("down-bytes-0123456789")
	if _, err := srcW.Write(down); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 2*time.Second, func() bool {
		return m.BytesTransferred.WithLabelValues("down", "tcp").Get() == float64(len(down))
	})

	up := []byte("up-bytes-abcdef")
	p.sinkQ <- dataFrag{data: append([]byte(nil), up...)}
	waitUntil(t, 2*time.Second, func() bool {
		return m.BytesTransferred.WithLabelValues("up", "tcp").Get() == float64(len(up))
	})

	if got := m.BytesTransferred.WithLabelValues("down", "tcp").Get(); got != float64(len(down)) {
		t.Fatalf("down bytes %v, want %d", got, len(down))
	}
	if got := m.BytesTransferred.WithLabelValues("up", "tcp").Get(); got != float64(len(up)) {
		t.Fatalf("up bytes %v, want %d", got, len(up))
	}
}
