package logging

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestLogsGoToConfiguredWriterNotStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = saved
	}()

	var buf bytes.Buffer
	log := New(&buf, "debug", "text")
	log.Info("secret-diagnostic")
	log.Debug("debug-diagnostic")
	log.Warn("warn-diagnostic")
	log.Error("error-diagnostic")

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = saved
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("diagnostic")) {
		t.Fatalf("log leaked to stdout: %q", out)
	}
	for _, s := range []string{"secret-diagnostic", "debug-diagnostic", "warn-diagnostic", "error-diagnostic"} {
		if !bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Fatalf("log %q not in configured writer: %s", s, buf.Bytes())
		}
	}
}

func TestNilWriterDefaultsToStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()

	log := New(nil, "info", "text")
	log.Info("stderr-check-marker")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = saved
	b, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("stderr-check-marker")) {
		t.Fatalf("expected log on stderr, got %q", b)
	}
}

func TestNewClientUsesStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout = w
	// client logger must not use stdout even if we also capture stderr separately
	er, ew, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = ew
	defer func() {
		os.Stdout = savedOut
		os.Stderr = savedErr
	}()

	log := NewClient("info", "text")
	log.Info("client-log-marker")

	_ = w.Close()
	_ = ew.Close()
	os.Stdout = savedOut
	os.Stderr = savedErr

	out, _ := io.ReadAll(r)
	_ = r.Close()
	errb, _ := io.ReadAll(er)
	_ = er.Close()
	if bytes.Contains(out, []byte("client-log-marker")) {
		t.Fatalf("client log on stdout: %q", out)
	}
	if !bytes.Contains(errb, []byte("client-log-marker")) {
		t.Fatalf("client log missing on stderr: %q", errb)
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "info", "json")
	WithSession(log, "s-1").Info("hi")
	if !bytes.Contains(buf.Bytes(), []byte(`"sessionId":"s-1"`)) && !bytes.Contains(buf.Bytes(), []byte(`"sessionId": "s-1"`)) {
		t.Fatalf("missing sessionId: %s", buf.Bytes())
	}
}
