package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/remote-relay/relay/internal/proto"
)

const (
	DefaultServerConfigPath = "/etc/relay/server.toml"
)

func DefaultClientConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "relay", "client.toml")
}

type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalTOML(v any) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("bad duration: expected string, got %T", v)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bad duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("bad duration %q: %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

type Server struct {
	ListenTCP          string   `toml:"listen_tcp"`
	UDPListen          string   `toml:"udp_listen"`
	UDPAnnounce        string   `toml:"udp_announce"`
	Transports         []string `toml:"transports"`
	DefaultDestination string   `toml:"default_destination"`
	AllowDestinations  []string `toml:"allow_destinations"`
	HoldTimeout        Duration `toml:"hold_timeout"`
	BufferBytes        int      `toml:"buffer_bytes"`
	TotalBufferBytes   int      `toml:"total_buffer_bytes"`
	SendWindow         int      `toml:"send_window"`
	DataChunkBytes     int      `toml:"data_chunk_bytes"`
	MaxSessions        int      `toml:"max_sessions"`
	MaxConnsPerIP      int      `toml:"max_conns_per_ip"`
	ProbeTimeout       Duration `toml:"probe_timeout"`
	ProbeAttempts      int      `toml:"probe_attempts"`
	KeepaliveInterval  Duration `toml:"keepalive_interval"`
	IdleTimeout        Duration `toml:"idle_timeout"`
	SwitchTimeout      Duration `toml:"switch_timeout"`
	DialTimeout        Duration `toml:"dial_timeout"`
	QUICCert           string   `toml:"quic_cert"`
	QUICKey            string   `toml:"quic_key"`
	LogLevel           string   `toml:"log_level"`
	LogFormat          string   `toml:"log_format"`
	PprofListen        string   `toml:"pprof_listen"`
	ExpvarListen       string   `toml:"expvar_listen"`
	AuthMethod         string   `toml:"auth_method"`
	AuthorizedKeys     string   `toml:"authorized_keys"`
	AuthFailDelay      Duration `toml:"auth_fail_delay"`
}

type Client struct {
	Server              string   `toml:"server"`
	Destination         string   `toml:"destination"`
	Transport           string   `toml:"transport"`
	BufferBytes         int      `toml:"buffer_bytes"`
	SendWindow          int      `toml:"send_window"`
	ProbeTimeout        Duration `toml:"probe_timeout"`
	KeepaliveInterval   Duration `toml:"keepalive_interval"`
	IdleTimeout         Duration `toml:"idle_timeout"`
	ReconnectBackoff    []string `toml:"reconnect_backoff"`
	ReconnectMaxElapsed Duration `toml:"reconnect_max_elapsed"`
	LogLevel            string   `toml:"log_level"`
	LogFormat           string   `toml:"log_format"`
	AuthMethod          string   `toml:"auth_method"`
	AuthUser            string   `toml:"auth_user"`
	IdentityFiles       []string `toml:"identity_files"`
	AllowHA             bool     `toml:"allow_ha"`
	HAProbeInterval     Duration `toml:"ha_probe_interval"`
}

func DefaultServer() Server {
	return Server{
		ListenTCP:          "0.0.0.0:7443",
		UDPListen:          "0.0.0.0:7443",
		UDPAnnounce:        "",
		Transports:         []string{"quic", "kcp"},
		DefaultDestination: "127.0.0.1:22",
		AllowDestinations:  []string{"127.0.0.1:22"},
		HoldTimeout:        Duration(5 * time.Minute),
		BufferBytes:        67108864,
		TotalBufferBytes:   536870912,
		SendWindow:         4194304,
		DataChunkBytes:     65536,
		MaxSessions:        1024,
		MaxConnsPerIP:      8,
		ProbeTimeout:       Duration(2 * time.Second),
		ProbeAttempts:      2,
		KeepaliveInterval:  Duration(5 * time.Second),
		IdleTimeout:        Duration(30 * time.Second),
		SwitchTimeout:      Duration(5 * time.Second),
		DialTimeout:        Duration(10 * time.Second),
		LogLevel:           "info",
		LogFormat:          "text",
		AuthMethod:         "none",
		AuthFailDelay:      Duration(200 * time.Millisecond),
	}
}

func DefaultClient() Client {
	return Client{
		Server:              "relay.example.com:7443",
		Destination:         "",
		Transport:           "quic",
		BufferBytes:         67108864,
		SendWindow:          4194304,
		ProbeTimeout:        Duration(2 * time.Second),
		KeepaliveInterval:   Duration(5 * time.Second),
		IdleTimeout:         Duration(30 * time.Second),
		ReconnectBackoff:    []string{"100ms", "250ms", "500ms", "1s", "2s", "5s", "10s"},
		ReconnectMaxElapsed: Duration(5 * time.Minute),
		LogLevel:            "warn",
		LogFormat:           "text",
		AuthMethod:          "none",
		AllowHA:             false,
		HAProbeInterval:     Duration(10 * time.Second),
	}
}

type ServerOptions struct {
	ConfigPath string
	Listen     string
	LogLevel   string
}

type ClientOptions struct {
	ConfigPath string
	Server     string
	Dest       string
	DestSet    bool
	TCP        bool
	KCP        bool
	AllowHA    bool
	AllowHASet bool
	LogLevel   string
	PosHost    string
	PosPort    string
}

func LoadServer(opts ServerOptions) (Server, error) {
	cfg := DefaultServer()
	path, required := opts.ConfigPath, opts.ConfigPath != ""
	if !required {
		path = DefaultServerConfigPath
	}
	if err := mergeTOML(path, required, &cfg); err != nil {
		return Server{}, err
	}
	if opts.Listen != "" {
		cfg.ListenTCP = opts.Listen
	}
	if opts.LogLevel != "" {
		cfg.LogLevel = opts.LogLevel
	}
	if err := cfg.Validate(); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

func LoadClient(opts ClientOptions) (Client, error) {
	cfg := DefaultClient()
	path, required := opts.ConfigPath, opts.ConfigPath != ""
	if !required {
		path = DefaultClientConfigPath()
	}
	if path != "" {
		if err := mergeTOML(path, required, &cfg); err != nil {
			return Client{}, err
		}
	}
	if opts.Server != "" {
		cfg.Server = opts.Server
	}
	if opts.DestSet {
		cfg.Destination = opts.Dest
	} else if opts.PosHost != "" {
		if opts.PosPort != "" {
			cfg.Destination = netJoin(opts.PosHost, opts.PosPort)
		} else {
			cfg.Destination = opts.PosHost
		}
	}
	// §8.5: --tcp > --kcp > config transport > default quic
	if opts.TCP {
		cfg.Transport = "tcp"
	} else if opts.KCP {
		cfg.Transport = "kcp"
	}
	if opts.AllowHASet {
		cfg.AllowHA = opts.AllowHA
	}
	if cfg.HAProbeInterval <= 0 {
		cfg.HAProbeInterval = Duration(10 * time.Second)
	}
	if opts.LogLevel != "" {
		cfg.LogLevel = opts.LogLevel
	}
	if err := cfg.Validate(); err != nil {
		return Client{}, err
	}
	return cfg, nil
}

func netJoin(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func mergeTOML(path string, required bool, v any) error {
	if path == "" {
		if required {
			return fmt.Errorf("config path is required")
		}
		return nil
	}
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil
		}
		return err
	}
	_, err = toml.DecodeFile(path, v)
	return err
}

func (s Server) Validate() error {
	if strings.TrimSpace(s.ListenTCP) == "" {
		return fmt.Errorf("listen_tcp is required")
	}
	if len(s.Transports) == 0 {
		return fmt.Errorf("empty transports")
	}
	for _, t := range s.Transports {
		if !validTransport(t) {
			return fmt.Errorf("unknown transport %q", t)
		}
	}
	if s.BufferBytes > s.TotalBufferBytes {
		return fmt.Errorf("buffer_bytes (%d) > total_buffer_bytes (%d)", s.BufferBytes, s.TotalBufferBytes)
	}
	if s.BufferBytes <= 0 || s.TotalBufferBytes <= 0 {
		return fmt.Errorf("buffer_bytes and total_buffer_bytes must be positive")
	}
	if s.SendWindow <= 0 {
		return fmt.Errorf("send_window must be positive")
	}
	if s.DataChunkBytes <= 0 || s.DataChunkBytes > proto.MaxFrameLen-8 {
		return fmt.Errorf("data_chunk_bytes out of range")
	}
	if s.MaxSessions <= 0 {
		return fmt.Errorf("max_sessions must be positive")
	}
	if s.MaxConnsPerIP <= 0 {
		return fmt.Errorf("max_conns_per_ip must be positive")
	}
	if len(s.AllowDestinations) == 0 {
		return fmt.Errorf("allow_destinations must not be empty")
	}
	if s.DefaultDestination == "" {
		return fmt.Errorf("default_destination is required")
	}
	if err := validAuthMethod(s.AuthMethod); err != nil {
		return err
	}
	return nil
}

func (c Client) Validate() error {
	if strings.TrimSpace(c.Transport) == "" {
		return fmt.Errorf("empty transports")
	}
	if !validTransport(c.Transport) {
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	if c.SendWindow <= 0 {
		return fmt.Errorf("send_window must be positive")
	}
	if c.BufferBytes <= 0 {
		return fmt.Errorf("buffer_bytes must be positive")
	}
	for _, s := range c.ReconnectBackoff {
		if _, err := time.ParseDuration(s); err != nil {
			return fmt.Errorf("bad duration %q: %w", s, err)
		}
	}
	if strings.TrimSpace(c.Server) == "" {
		return fmt.Errorf("server is required")
	}
	if err := validAuthMethod(c.AuthMethod); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(c.Transport)) == "tcp" && c.AllowHA {
		return fmt.Errorf("--allow-ha cannot be used with tcp transport")
	}
	return nil
}

func validAuthMethod(m string) error {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", "none", "ssh-publickey":
		return nil
	default:
		return fmt.Errorf("unknown auth_method %q", m)
	}
}

func validTransport(t string) bool {
	switch strings.ToLower(t) {
	case "tcp", "quic", "kcp":
		return true
	default:
		return false
	}
}

// TransportPreference is the HELLO/RESUME preference list (§8.5).
func (c Client) TransportPreference() []string {
	switch strings.ToLower(strings.TrimSpace(c.Transport)) {
	case "tcp":
		return []string{"tcp"}
	case "kcp":
		return []string{"kcp"}
	default:
		return []string{"quic", "kcp"}
	}
}

func (c Client) IsTCP() bool {
	return strings.EqualFold(strings.TrimSpace(c.Transport), "tcp")
}

func (s Server) QUICEnabled() bool {
	for _, t := range s.Transports {
		if strings.EqualFold(t, "quic") {
			return true
		}
	}
	return false
}

func (s Server) KCPEnabled() bool {
	for _, t := range s.Transports {
		if strings.EqualFold(t, "kcp") {
			return true
		}
	}
	return false
}

func AllowAll(allow []string) bool {
	for _, a := range allow {
		if a == "*" {
			return true
		}
	}
	return false
}

func DestinationAllowed(dest string, allow []string) bool {
	for _, a := range allow {
		if a == "*" || a == dest {
			return true
		}
	}
	return false
}
