package transport

import (
	"crypto/tls"
	"testing"
)

func TestGenerateEphemeralCert(t *testing.T) {
	cert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
	cfg := ServerTLSConfig(cert)
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		t.Fatalf("alpn %v", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min version %d", cfg.MinVersion)
	}
	cli := ClientTLSConfig()
	if !cli.InsecureSkipVerify || cli.NextProtos[0] != ALPN {
		t.Fatalf("client tls %+v", cli)
	}
}
