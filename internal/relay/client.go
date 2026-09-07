package relay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

const handshakeTimeout = 10 * time.Second

func RunClient(ctx context.Context, cfg config.Client, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	if log == nil {
		log = logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	}
	if cfg.Transport != "tcp" {
		log.Warn("UDP upgrade is not built yet; staying on TCP", "requested", cfg.Transport)
	}

	conn, err := transport.DialTCP(ctx, cfg.Server)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.Close()

	authMsg, err := auth.None{}.Respond(auth.Challenge{Destination: cfg.Destination})
	if err != nil {
		return err
	}
	nonce, err := proto.RandomNonce()
	if err != nil {
		return err
	}
	hello := proto.Hello{
		V:           1,
		SessionID:   "",
		ResumeToken: "",
		Transport:   []string{"tcp"},
		Destination: cfg.Destination,
		ClientNonce: nonce,
		Auth:        authMsg,
		Window:      cfg.SendWindow,
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" {
		hello.Transport = []string{cfg.Transport, "tcp"}
	}
	fr, err := proto.MarshalFrame(proto.TypeHello, hello)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.WriteFrame(fr); err != nil {
		return fmt.Errorf("send HELLO: %w", err)
	}
	reply, err := conn.ReadFrame()
	if err != nil {
		return fmt.Errorf("read HELLO_OK: %w", err)
	}
	if reply.Type == proto.TypeErr {
		var fail proto.Fail
		_ = proto.UnmarshalPayload(reply, &fail)
		return proto.NewError(fail.Code, fail.Msg)
	}
	if reply.Type != proto.TypeHelloOK {
		return proto.NewError(proto.CodeProto, "expected HELLO_OK, got "+reply.Type.String())
	}
	var ok proto.HelloOK
	if err := proto.UnmarshalPayload(reply, &ok); err != nil {
		return err
	}
	if ok.V != 1 {
		return proto.ErrVersion
	}
	_ = conn.SetDeadline(time.Time{})

	log = logging.WithSession(log, ok.SessionID)
	log.Info("session established", "transport", "tcp")

	chunk := ok.Limits.DataChunkBytes
	if chunk <= 0 {
		chunk = 65536
	}
	window := cfg.SendWindow
	if ok.Limits.Window > 0 && (window <= 0 || ok.Limits.Window < window) {
		window = ok.Limits.Window
	}

	bw := bufio.NewWriterSize(stdout, 128*1024)
	err = runPump(ctx, sessionIO{
		conn:      conn,
		src:       stdin,
		sink:      bw,
		flushSink: bw.Flush,
		outDir:    proto.DirUp,
		inDir:     proto.DirDown,
	}, pumpConfig{
		chunk:     chunk,
		window:    window,
		keepalive: 5 * time.Second,
		idle:      30 * time.Second,
		log:       log,
	})
	_ = bw.Flush()
	return err
}
