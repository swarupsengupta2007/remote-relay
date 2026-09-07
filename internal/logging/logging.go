package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New builds a slog logger that writes only to w. A nil w defaults to stderr
// so a ProxyCommand client's stdout stays a pure byte pipe.
func New(w io.Writer, level, format string) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

func NewClient(level, format string) *slog.Logger {
	return New(os.Stderr, level, format)
}

func WithSession(log *slog.Logger, sessionID string) *slog.Logger {
	if log == nil {
		log = New(os.Stderr, "info", "text")
	}
	return log.With("sessionId", sessionID)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
