package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveClientBindings_Valid(t *testing.T) {
	// 1. Qualified tcp and udp
	tcpIface, udpIface, tcpIP, udpIP, err := ResolveClientBindings(
		[]string{"lo@tcp", "lo@udp"},
		[]string{"127.0.0.1@tcp", "127.0.0.2@udp"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tcpIface != "lo" || udpIface != "lo" {
		t.Fatalf("expected ifaces lo/lo, got %q/%q", tcpIface, udpIface)
	}
	if tcpIP != "127.0.0.1" || udpIP != "127.0.0.2" {
		t.Fatalf("expected ips 127.0.0.1/127.0.0.2, got %q/%q", tcpIP, udpIP)
	}

	// 2. Unqualified applies to both
	tcpIface, udpIface, tcpIP, udpIP, err = ResolveClientBindings(
		[]string{"lo"},
		[]string{"127.0.0.3"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tcpIface != "lo" || udpIface != "lo" {
		t.Fatalf("expected ifaces lo/lo, got %q/%q", tcpIface, udpIface)
	}
	if tcpIP != "127.0.0.3" || udpIP != "127.0.0.3" {
		t.Fatalf("expected ips 127.0.0.3/127.0.0.3, got %q/%q", tcpIP, udpIP)
	}

	// 3. Comma-separated and case-insensitive
	tcpIface, udpIface, tcpIP, udpIP, err = ResolveClientBindings(
		[]string{"lo@TCP, lo@UdP"},
		[]string{"127.0.0.1@tCp, 127.0.0.2@UDP"},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tcpIface != "lo" || udpIface != "lo" {
		t.Fatalf("expected ifaces lo/lo, got %q/%q", tcpIface, udpIface)
	}
	if tcpIP != "127.0.0.1" || udpIP != "127.0.0.2" {
		t.Fatalf("expected ips 127.0.0.1/127.0.0.2, got %q/%q", tcpIP, udpIP)
	}
}

func TestResolveClientBindings_CLIOverrides(t *testing.T) {
	// Mock InterfaceByName to allow testing arbitrary names
	oldIfaceByName := InterfaceByName
	defer func() { InterfaceByName = oldIfaceByName }()
	InterfaceByName = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name}, nil
	}

	// 1. CLI overrides only TCP leg; UDP leg kept from TOML
	tcpIface, udpIface, tcpIP, udpIP, err := ResolveClientBindings(
		[]string{"eth0"},                         // TOML: unqualified eth0 (both tcp and udp)
		[]string{"10.0.0.1@tcp", "10.0.0.2@udp"}, // TOML: per-leg source IPs
		[]string{"eth1@tcp"},                     // CLI: override TCP iface only
		[]string{"192.168.1.1@tcp"},              // CLI: override TCP IP only
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tcpIface != "eth1" {
		t.Fatalf("expected tcpIface eth1 from CLI, got %q", tcpIface)
	}
	if udpIface != "eth0" {
		t.Fatalf("expected udpIface eth0 from TOML, got %q", udpIface)
	}
	if tcpIP != "192.168.1.1" {
		t.Fatalf("expected tcpIP 192.168.1.1 from CLI, got %q", tcpIP)
	}
	if udpIP != "10.0.0.2" {
		t.Fatalf("expected udpIP 10.0.0.2 from TOML, got %q", udpIP)
	}

	// 2. Unqualified CLI override overrides both legs
	tcpIface, udpIface, tcpIP, udpIP, err = ResolveClientBindings(
		[]string{"eth0@tcp", "eth1@udp"},
		[]string{"10.0.0.1@tcp", "10.0.0.2@udp"},
		[]string{"eth2"},
		[]string{"172.16.0.1"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tcpIface != "eth2" || udpIface != "eth2" {
		t.Fatalf("expected eth2 for both, got %q/%q", tcpIface, udpIface)
	}
	if tcpIP != "172.16.0.1" || udpIP != "172.16.0.1" {
		t.Fatalf("expected 172.16.0.1 for both, got %q/%q", tcpIP, udpIP)
	}
}

type interfaceDummy = struct{}

func TestResolveClientBindings_ConflictsAndDuplicates(t *testing.T) {
	// 1. Duplicate TCP in same scope
	_, _, _, _, err := ResolveClientBindings([]string{"lo@tcp", "lo@tcp"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting/duplicate") {
		t.Fatalf("expected conflicting/duplicate error, got %v", err)
	}

	// 2. Duplicate UDP in CLI scope
	_, _, _, _, err = ResolveClientBindings(nil, nil, []string{"lo@udp", "lo@udp"}, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting/duplicate") {
		t.Fatalf("expected conflicting/duplicate error, got %v", err)
	}

	// 3. Unqualified conflicts with already specified leg
	_, _, _, _, err = ResolveClientBindings([]string{"lo@tcp", "lo"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting/duplicate") {
		t.Fatalf("expected conflicting/duplicate error, got %v", err)
	}

	// 4. Leg conflicts with already specified unqualified
	_, _, _, _, err = ResolveClientBindings([]string{"lo", "lo@udp"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting/duplicate") {
		t.Fatalf("expected conflicting/duplicate error, got %v", err)
	}

	// 5. Source IP conflict
	_, _, _, _, err = ResolveClientBindings(nil, []string{"127.0.0.1@tcp", "127.0.0.2@tcp"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "conflicting/duplicate") {
		t.Fatalf("expected conflicting/duplicate error, got %v", err)
	}
}

func TestResolveClientBindings_SyntaxErrors(t *testing.T) {
	tests := []struct {
		entry  string
		errSub string
	}{
		{"lo@sctp", "unknown protocol \"sctp\""},
		{"@tcp", "missing value before '@'"},
		{"lo@", "missing protocol after '@'"},
		{"lo@tcp@udp", "multiple '@' separators"},
	}

	for _, tt := range tests {
		_, _, _, _, err := ResolveClientBindings([]string{tt.entry}, nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), tt.errSub) {
			t.Fatalf("entry %q: expected error containing %q, got %v", tt.entry, tt.errSub, err)
		}
	}
}

func TestResolveClientBindings_ValidationErrors(t *testing.T) {
	// Non-existent interface
	_, _, _, _, err := ResolveClientBindings([]string{"nonexistent_dummy_device_42"}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error for interface, got %v", err)
	}

	// Invalid IP
	_, _, _, _, err = ResolveClientBindings(nil, []string{"999.999.999.999"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid source ip") {
		t.Fatalf("expected invalid source ip error, got %v", err)
	}
}

func TestLoadClient_BindingsFromTOML(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "client.toml")
	tomlData := `
server = "127.0.0.1:7443"
interfaces = ["lo@tcp", "lo@udp"]
source_ips = ["127.0.0.1@tcp", "127.0.0.2@udp"]
`
	if err := os.WriteFile(confPath, []byte(tomlData), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(ClientOptions{ConfigPath: confPath})
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.TCPInterface != "lo" || cfg.UDPInterface != "lo" {
		t.Fatalf("unexpected interfaces: %q, %q", cfg.TCPInterface, cfg.UDPInterface)
	}
	if cfg.TCPSourceIP != "127.0.0.1" || cfg.UDPSourceIP != "127.0.0.2" {
		t.Fatalf("unexpected source IPs: %q, %q", cfg.TCPSourceIP, cfg.UDPSourceIP)
	}
}
