package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
)

func TestPprofAndExpvarListen(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.PprofListen = "127.0.0.1:0"
	cfg.ExpvarListen = "127.0.0.1:0"
	log := logging.New(io.Discard, "error", "text")
	srv := NewServer(cfg, log)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})

	waitUntil(t, 2*time.Second, func() bool {
		return srv.PprofAddr() != "" && srv.ExpvarAddr() != ""
	})

	resp, err := http.Get("http://" + srv.PprofAddr() + "/debug/pprof/goroutine?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("pprof status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("goroutine")) {
		n := len(body)
		if n > 200 {
			n = 200
		}
		t.Fatalf("pprof body: %s", body[:n])
	}

	resp, err = http.Get("http://" + srv.ExpvarAddr() + "/debug/vars")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expvar status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"sessions", "held", "buffer_used", "accepts"} {
		if !bytes.Contains(raw, []byte(`"`+key+`"`)) {
			n := len(raw)
			if n > 400 {
				n = 400
			}
			t.Fatalf("expvar missing %s: %s", key, raw[:n])
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("expvar json: %v", err)
	}
}

func TestDebugDisabledWhenEmpty(t *testing.T) {
	dest := startHoldDest(t)
	cfg := config.DefaultServer()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.DefaultDestination = dest
	cfg.AllowDestinations = []string{dest, "*"}
	cfg.Transports = []string{"tcp"}
	cfg.PprofListen = ""
	cfg.ExpvarListen = ""
	srv, _, _ := startRelayCfg(t, cfg)
	if srv.PprofAddr() != "" || srv.ExpvarAddr() != "" {
		t.Fatalf("debug addrs %q %q", srv.PprofAddr(), srv.ExpvarAddr())
	}
}
