package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/remote-relay/relay/internal/proto"
	"golang.org/x/crypto/ssh/terminal"
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
	ConfigPath         string   `toml:"config_path,omitempty"`
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
	HeartbeatInterval  Duration `toml:"heartbeat_interval"`
	DeadPeerThreshold  int      `toml:"dead_peer_threshold"`
	HostKey            string   `toml:"host_key"`
	Splice             bool     `toml:"splice"`
	AdaptiveKCP        bool     `toml:"adaptive_kcp"`

	// FEAT-UTL-05 jumphost chaining. Chaining is default-deny: an empty
	// AllowRelayHops refuses every CHAIN with ERR_HOP_FORBIDDEN (J-D8).
	AllowRelayHops             []string `toml:"allow_relay_hops"`
	MaxChainDepth              int      `toml:"max_chain_depth"`
	MaxChainConnsPerPeer       int      `toml:"max_chain_conns_per_peer"`
	ChainAuthTimeout           Duration `toml:"chain_auth_timeout"`
	ChainAuthRelaysMax         int      `toml:"chain_auth_relays_max"`
	ChainMaxSessions           int      `toml:"chain_max_sessions"`
	RelayKnownHosts            string   `toml:"relay_known_hosts"`
	RelayStrictHostKeyChecking string   `toml:"relay_strict_host_key_checking"`

	// FEAT-UTL-03 SOCKS5 dynamic proxy mode.
	DisableSOCKS    bool `toml:"disable_socks"`
	MaxSocksStreams int  `toml:"max_socks_streams"`

	// FEAT-SEC-02 WebSocket & HTTPS Port 443 transport.
	ListenWS       string   `toml:"listen_ws"`
	WebSocketPath  string   `toml:"websocket_path"`
	WSCert         string   `toml:"ws_cert"`
	WSKey          string   `toml:"ws_key"`
	TrustedProxies []string `toml:"trusted_proxies"`

	// FEAT-OBS-01 Prometheus metrics & OpenTelemetry tracing.
	MetricsListen string `toml:"metrics_listen"`
	OTELEndpoint  string `toml:"otel_endpoint"`

	// FEAT-UTL-04 Reverse Relay & NAT Gateway mode
	AllowTargets     []string `toml:"allow_targets"`
	AgentHoldTimeout Duration `toml:"agent_hold_timeout"`

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string `toml:"spill_dir"`
	SpillL1Bytes int    `toml:"spill_l1_bytes"`
	NoSpill      bool   `toml:"no_spill"`
}

type Client struct {
	Server                string   `toml:"server"`
	Destination           string   `toml:"destination"`
	Target                string   `toml:"target"`
	Transport             string   `toml:"transport"`
	BufferBytes           int      `toml:"buffer_bytes"`
	SendWindow            int      `toml:"send_window"`
	ProbeTimeout          Duration `toml:"probe_timeout"`
	KeepaliveInterval     Duration `toml:"keepalive_interval"`
	IdleTimeout           Duration `toml:"idle_timeout"`
	ReconnectBackoff      []string `toml:"reconnect_backoff"`
	ReconnectMaxElapsed   Duration `toml:"reconnect_max_elapsed"`
	LogLevel              string   `toml:"log_level"`
	LogFormat             string   `toml:"log_format"`
	AuthMethod            string   `toml:"auth_method"`
	AuthUser              string   `toml:"auth_user"`
	AuthSock              string   `toml:"auth_sock"`
	IdentityFiles         []string `toml:"identity_files"`
	AllowHA               bool     `toml:"allow_ha"`
	HAProbeInterval       Duration `toml:"ha_probe_interval"`
	HeartbeatInterval     Duration `toml:"heartbeat_interval"`
	DeadPeerThreshold     int      `toml:"dead_peer_threshold"`
	KnownHosts            string   `toml:"known_hosts"`
	ServerFingerprint     string   `toml:"server_fingerprint"`
	StrictHostKeyChecking string   `toml:"strict_host_key_checking"`
	HappyEyeballsDelay    Duration `toml:"happy_eyeballs_delay"`
	Splice                bool     `toml:"splice"`
	AdaptiveKCP           bool     `toml:"adaptive_kcp"`
	Interfaces            []string `toml:"interfaces"`
	SourceIPs             []string `toml:"source_ips"`

	// FEAT-UTL-05 jumphost chaining. Jumphost holds the raw -J entries; parse
	// them with ParseJumphost. SSHDAliveBudget bounds the summed worst-case
	// hold across all hops (§2.7): exceeding it means sshd's own
	// ClientAliveInterval×ClientAliveCountMax will kill a parked session first.
	Jumphost        []string `toml:"jumphost"`
	SSHDAliveBudget Duration `toml:"sshd_alive_budget"`

	// FEAT-UTL-02 terminal reconnection HUD and desktop notifications.
	HUD                 bool     `toml:"hud"`
	NoHUD               bool     `toml:"no_hud"`
	NotificationTimeout Duration `toml:"notification_timeout"`

	HUDWriter     io.Writer `toml:"-"`
	HUDIsTerminal *bool     `toml:"-"`

	// FEAT-UTL-03 SOCKS5 dynamic proxy mode.
	SocksListen     string `toml:"socks_listen"`
	MaxSocksStreams int    `toml:"max_socks_streams"`

	// FEAT-SEC-02 WebSocket transport.
	WS            bool   `toml:"ws"`
	WebSocketPath string `toml:"websocket_path"`
	TLSInsecure   bool   `toml:"tls_insecure"`

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string `toml:"spill_dir"`
	SpillL1Bytes int    `toml:"spill_l1_bytes"`
	NoSpill      bool   `toml:"no_spill"`

	TCPInterface string `toml:"-"`
	UDPInterface string `toml:"-"`
	TCPSourceIP  string `toml:"-"`
	UDPSourceIP  string `toml:"-"`
}

type Agent struct {
	ConfigPath            string   `toml:"config_path,omitempty"`
	Server                string   `toml:"server"`
	Name                  string   `toml:"name"`
	Destination           string   `toml:"destination"`
	AllowDestinations     []string `toml:"allow_destinations"`
	Transport             string   `toml:"transport"`
	BufferBytes           int      `toml:"buffer_bytes"`
	SendWindow            int      `toml:"send_window"`
	KeepaliveInterval     Duration `toml:"keepalive_interval"`
	IdleTimeout           Duration `toml:"idle_timeout"`
	HeartbeatInterval     Duration `toml:"heartbeat_interval"`
	DeadPeerThreshold     int      `toml:"dead_peer_threshold"`
	HoldTimeout           Duration `toml:"hold_timeout"`
	ReconnectBackoff      []string `toml:"reconnect_backoff"`
	ReconnectMaxElapsed   Duration `toml:"reconnect_max_elapsed"`
	LogLevel              string   `toml:"log_level"`
	LogFormat             string   `toml:"log_format"`
	AuthMethod            string   `toml:"auth_method"`
	AuthUser              string   `toml:"auth_user"`
	AuthSock              string   `toml:"auth_sock"`
	IdentityFiles         []string `toml:"identity_files"`
	KnownHosts            string   `toml:"known_hosts"`
	ServerFingerprint     string   `toml:"server_fingerprint"`
	StrictHostKeyChecking string   `toml:"strict_host_key_checking"`
	WS                    bool     `toml:"ws"`
	WebSocketPath         string   `toml:"websocket_path"`
	TLSInsecure           bool     `toml:"tls_insecure"`
	Splice                bool     `toml:"splice"`
	AdaptiveKCP           bool     `toml:"adaptive_kcp"`

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string `toml:"spill_dir"`
	SpillL1Bytes int    `toml:"spill_l1_bytes"`
	NoSpill      bool   `toml:"no_spill"`
}

func defaultSplice() bool {
	return runtime.GOOS == "linux"
}

var isTerminal = func(fd uintptr) bool {
	return terminal.IsTerminal(int(fd))
}

func isTTY() bool {
	return isTerminal(os.Stdin.Fd()) && isTerminal(os.Stderr.Fd())
}

// DefaultStrictHostKeyChecking returns "ask" for interactive TTY, "yes" for headless scripts.
func DefaultStrictHostKeyChecking() string {
	if isTTY() {
		return "ask"
	}
	return "yes"
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
		AuthMethod:         "ssh-publickey",
		AuthFailDelay:      Duration(200 * time.Millisecond),
		HeartbeatInterval:  Duration(750 * time.Millisecond),
		DeadPeerThreshold:  3,
		HostKey:            "/etc/relay/ssh_host_ed25519_key",
		Splice:             defaultSplice(),
		AdaptiveKCP:        true,

		MaxChainDepth:              4,
		MaxChainConnsPerPeer:       256,
		ChainAuthTimeout:           Duration(10 * time.Second),
		ChainAuthRelaysMax:         8,
		RelayStrictHostKeyChecking: "yes",
		MaxSocksStreams:            512,
		WebSocketPath:              "/relay-stream",
		AgentHoldTimeout:           Duration(15 * time.Second),
		SpillDir:                   "",
		SpillL1Bytes:               8388608,
		NoSpill:                    false,
	}
}

func DefaultAgent() Agent {
	return Agent{
		Server:                "relay.example.com:7443",
		Name:                  "",
		Destination:           "127.0.0.1:22",
		Transport:             "quic",
		WebSocketPath:         "/relay-stream",
		BufferBytes:           67108864,
		SendWindow:            4194304,
		KeepaliveInterval:     Duration(5 * time.Second),
		IdleTimeout:           Duration(30 * time.Second),
		HeartbeatInterval:     Duration(750 * time.Millisecond),
		DeadPeerThreshold:     3,
		HoldTimeout:           Duration(5 * time.Minute),
		ReconnectBackoff:      []string{"100ms", "250ms", "500ms", "1s", "2s", "5s", "10s"},
		ReconnectMaxElapsed:   Duration(5 * time.Minute),
		LogLevel:              "info",
		LogFormat:             "text",
		AuthMethod:            "ssh-publickey",
		StrictHostKeyChecking: DefaultStrictHostKeyChecking(),
		Splice:                defaultSplice(),
		AdaptiveKCP:           true,
		SpillDir:              "",
		SpillL1Bytes:          8388608,
		NoSpill:               false,
	}
}

func DefaultClient() Client {
	return Client{
		Server:                "relay.example.com:7443",
		Destination:           "",
		Transport:             "quic",
		WebSocketPath:         "/relay-stream",
		BufferBytes:           67108864,
		SendWindow:            4194304,
		ProbeTimeout:          Duration(2 * time.Second),
		KeepaliveInterval:     Duration(5 * time.Second),
		IdleTimeout:           Duration(30 * time.Second),
		ReconnectBackoff:      []string{"100ms", "250ms", "500ms", "1s", "2s", "5s", "10s"},
		ReconnectMaxElapsed:   Duration(5 * time.Minute),
		LogLevel:              "warn",
		LogFormat:             "text",
		AuthMethod:            "ssh-publickey",
		AuthSock:              "",
		AllowHA:               false,
		HAProbeInterval:       Duration(10 * time.Second),
		HeartbeatInterval:     Duration(750 * time.Millisecond),
		DeadPeerThreshold:     3,
		KnownHosts:            "",
		ServerFingerprint:     "",
		StrictHostKeyChecking: DefaultStrictHostKeyChecking(),
		HappyEyeballsDelay:    Duration(250 * time.Millisecond),
		Splice:                defaultSplice(),
		AdaptiveKCP:           true,
		SSHDAliveBudget:       Duration(2 * time.Minute),
		HUD:                   true,
		NoHUD:                 false,
		NotificationTimeout:   Duration(5 * time.Second),
		SocksListen:           "127.0.0.1:1080",
		MaxSocksStreams:       512,
		SpillDir:              "",
		SpillL1Bytes:          8388608,
		NoSpill:               false,
	}
}

type ServerOptions struct {
	ConfigPath        string
	Listen            string
	LogLevel          string
	HeartbeatInterval time.Duration
	DeadPeerThreshold int
	HostKey           string
	AuthorizedKeys    string
	Splice            *bool
	AdaptiveKCP       *bool
	DisableSOCKS      *bool
	MaxSocksStreams   int
	ListenWS          string
	WebSocketPath     string
	MetricsListen     string
	OTELEndpoint      string
	AllowTargets      []string
	AgentHoldTimeout  time.Duration

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string
	SpillL1Bytes int
	NoSpill      *bool
}

type ClientOptions struct {
	ConfigPath            string
	Server                string
	Dest                  string
	DestSet               bool
	Target                string
	TCP                   bool
	KCP                   bool
	WS                    bool
	AllowHA               bool
	AllowHASet            bool
	LogLevel              string
	PosHost               string
	PosPort               string
	HeartbeatInterval     time.Duration
	DeadPeerThreshold     int
	KnownHosts            string
	ServerFingerprint     string
	StrictHostKeyChecking string
	HappyEyeballsDelay    time.Duration
	Identity              string
	AuthSock              string
	Splice                *bool
	AdaptiveKCP           *bool
	Interfaces            []string
	SourceIPs             []string
	Jumphost              []string
	JumphostSet           bool
	HUD                   *bool
	NotificationTimeout   time.Duration
	HUDWriter             io.Writer
	HUDIsTerminal         *bool
	SocksListen           string
	MaxSocksStreams       int
	TLSInsecure           bool

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string
	SpillL1Bytes int
	NoSpill      *bool
}

type AgentOptions struct {
	ConfigPath            string
	Server                string
	Name                  string
	Dest                  string
	AllowDest             []string
	TCP                   bool
	KCP                   bool
	WS                    bool
	LogLevel              string
	HeartbeatInterval     time.Duration
	DeadPeerThreshold     int
	KnownHosts            string
	ServerFingerprint     string
	StrictHostKeyChecking string
	Identity              string
	AuthSock              string
	Splice                *bool
	AdaptiveKCP           *bool
	TLSInsecure           bool

	// FEAT-ROB-04 Tiered Disk-Spill Storage
	SpillDir     string
	SpillL1Bytes int
	NoSpill      *bool
}

func LoadServer(opts ServerOptions) (Server, error) {
	cfg := DefaultServer()
	cfg.ConfigPath = opts.ConfigPath
	path, required := opts.ConfigPath, opts.ConfigPath != ""
	if !required {
		path = DefaultServerConfigPath
	}
	if err := mergeTOML(path, required, &cfg); err != nil {
		return Server{}, err
	}
	if cfg.ConfigPath == "" {
		if _, err := os.Stat(path); err == nil {
			cfg.ConfigPath = path
		}
	}
	if opts.Listen != "" {
		cfg.ListenTCP = opts.Listen
	}
	if opts.LogLevel != "" {
		cfg.LogLevel = opts.LogLevel
	}
	if opts.HeartbeatInterval > 0 {
		cfg.HeartbeatInterval = Duration(opts.HeartbeatInterval)
	}
	if opts.DeadPeerThreshold > 0 {
		cfg.DeadPeerThreshold = opts.DeadPeerThreshold
	}
	if opts.HostKey != "" {
		cfg.HostKey = opts.HostKey
	}
	if opts.AuthorizedKeys != "" {
		cfg.AuthorizedKeys = opts.AuthorizedKeys
	}
	if opts.Splice != nil {
		cfg.Splice = *opts.Splice
	}
	if opts.AdaptiveKCP != nil {
		cfg.AdaptiveKCP = *opts.AdaptiveKCP
	}
	if opts.DisableSOCKS != nil {
		cfg.DisableSOCKS = *opts.DisableSOCKS
	}
	if opts.MaxSocksStreams > 0 {
		cfg.MaxSocksStreams = opts.MaxSocksStreams
	}
	if opts.ListenWS != "" {
		cfg.ListenWS = opts.ListenWS
	}
	if opts.WebSocketPath != "" {
		cfg.WebSocketPath = opts.WebSocketPath
	}
	if opts.MetricsListen != "" {
		cfg.MetricsListen = opts.MetricsListen
	}
	if opts.OTELEndpoint != "" {
		cfg.OTELEndpoint = opts.OTELEndpoint
	}
	if len(opts.AllowTargets) > 0 {
		cfg.AllowTargets = opts.AllowTargets
	}
	if opts.AgentHoldTimeout > 0 {
		cfg.AgentHoldTimeout = Duration(opts.AgentHoldTimeout)
	}
	if opts.SpillDir != "" {
		cfg.SpillDir = opts.SpillDir
	}
	if opts.SpillL1Bytes > 0 {
		cfg.SpillL1Bytes = opts.SpillL1Bytes
	}
	if opts.NoSpill != nil {
		cfg.NoSpill = *opts.NoSpill
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
	// §8.5: --ws > --tcp > --kcp > config transport > default quic
	if opts.WS {
		cfg.Transport = "ws"
	} else if opts.TCP {
		cfg.Transport = "tcp"
	} else if opts.KCP {
		cfg.Transport = "kcp"
	}
	if opts.TLSInsecure {
		cfg.TLSInsecure = true
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
	if opts.HeartbeatInterval > 0 {
		cfg.HeartbeatInterval = Duration(opts.HeartbeatInterval)
	}
	if opts.DeadPeerThreshold > 0 {
		cfg.DeadPeerThreshold = opts.DeadPeerThreshold
	}
	if opts.KnownHosts != "" {
		cfg.KnownHosts = opts.KnownHosts
	}
	if opts.ServerFingerprint != "" {
		cfg.ServerFingerprint = opts.ServerFingerprint
	}
	if opts.StrictHostKeyChecking != "" {
		cfg.StrictHostKeyChecking = opts.StrictHostKeyChecking
	}
	if cfg.StrictHostKeyChecking == "" {
		cfg.StrictHostKeyChecking = DefaultStrictHostKeyChecking()
	}
	if opts.HappyEyeballsDelay > 0 {
		cfg.HappyEyeballsDelay = Duration(opts.HappyEyeballsDelay)
	}
	if opts.Identity != "" {
		cfg.IdentityFiles = []string{opts.Identity}
	}
	if opts.AuthSock != "" {
		cfg.AuthSock = opts.AuthSock
	}
	if opts.Splice != nil {
		cfg.Splice = *opts.Splice
	}
	if opts.AdaptiveKCP != nil {
		cfg.AdaptiveKCP = *opts.AdaptiveKCP
	}
	if opts.JumphostSet {
		cfg.Jumphost = opts.Jumphost
	}
	tcpIface, udpIface, tcpIP, udpIP, err := ResolveClientBindings(cfg.Interfaces, cfg.SourceIPs, opts.Interfaces, opts.SourceIPs)
	if err != nil {
		return Client{}, err
	}
	cfg.TCPInterface = tcpIface
	cfg.UDPInterface = udpIface
	cfg.TCPSourceIP = tcpIP
	cfg.UDPSourceIP = udpIP
	if len(opts.Interfaces) > 0 {
		cfg.Interfaces = opts.Interfaces
	}
	if len(opts.SourceIPs) > 0 {
		cfg.SourceIPs = opts.SourceIPs
	}
	if opts.HUD != nil {
		cfg.HUD = *opts.HUD
	}
	if cfg.NoHUD {
		cfg.HUD = false
	}
	if opts.NotificationTimeout > 0 {
		cfg.NotificationTimeout = Duration(opts.NotificationTimeout)
	}
	if opts.HUDWriter != nil {
		cfg.HUDWriter = opts.HUDWriter
	}
	if opts.HUDIsTerminal != nil {
		cfg.HUDIsTerminal = opts.HUDIsTerminal
	}
	if opts.SocksListen != "" {
		cfg.SocksListen = opts.SocksListen
	}
	if opts.MaxSocksStreams > 0 {
		cfg.MaxSocksStreams = opts.MaxSocksStreams
	}
	if opts.Target != "" {
		cfg.Target = opts.Target
	}
	if opts.SpillDir != "" {
		cfg.SpillDir = opts.SpillDir
	}
	if opts.SpillL1Bytes > 0 {
		cfg.SpillL1Bytes = opts.SpillL1Bytes
	}
	if opts.NoSpill != nil {
		cfg.NoSpill = *opts.NoSpill
	}
	if err := cfg.Validate(); err != nil {
		return Client{}, err
	}
	return cfg, nil
}

func LoadAgent(opts AgentOptions) (Agent, error) {
	cfg := DefaultAgent()
	if opts.ConfigPath != "" {
		if err := mergeTOML(opts.ConfigPath, true, &cfg); err != nil {
			return Agent{}, err
		}
	}
	if opts.Server != "" {
		cfg.Server = opts.Server
	}
	if opts.Name != "" {
		cfg.Name = opts.Name
	}
	if opts.Dest != "" {
		cfg.Destination = opts.Dest
	}
	if len(opts.AllowDest) > 0 {
		cfg.AllowDestinations = opts.AllowDest
	}
	if opts.WS {
		cfg.Transport = "ws"
	} else if opts.TCP {
		cfg.Transport = "tcp"
	} else if opts.KCP {
		cfg.Transport = "kcp"
	}
	if opts.TLSInsecure {
		cfg.TLSInsecure = true
	}
	if opts.LogLevel != "" {
		cfg.LogLevel = opts.LogLevel
	}
	if opts.HeartbeatInterval > 0 {
		cfg.HeartbeatInterval = Duration(opts.HeartbeatInterval)
	}
	if opts.DeadPeerThreshold > 0 {
		cfg.DeadPeerThreshold = opts.DeadPeerThreshold
	}
	if opts.KnownHosts != "" {
		cfg.KnownHosts = opts.KnownHosts
	}
	if opts.ServerFingerprint != "" {
		cfg.ServerFingerprint = opts.ServerFingerprint
	}
	if opts.StrictHostKeyChecking != "" {
		cfg.StrictHostKeyChecking = opts.StrictHostKeyChecking
	}
	if cfg.StrictHostKeyChecking == "" {
		cfg.StrictHostKeyChecking = DefaultStrictHostKeyChecking()
	}
	if opts.Identity != "" {
		cfg.IdentityFiles = []string{opts.Identity}
	}
	if opts.AuthSock != "" {
		cfg.AuthSock = opts.AuthSock
	}
	if opts.Splice != nil {
		cfg.Splice = *opts.Splice
	}
	if opts.AdaptiveKCP != nil {
		cfg.AdaptiveKCP = *opts.AdaptiveKCP
	}
	if opts.SpillDir != "" {
		cfg.SpillDir = opts.SpillDir
	}
	if opts.SpillL1Bytes > 0 {
		cfg.SpillL1Bytes = opts.SpillL1Bytes
	}
	if opts.NoSpill != nil {
		cfg.NoSpill = *opts.NoSpill
	}
	if err := cfg.Validate(); err != nil {
		return Agent{}, err
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
	if s.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat_interval must be positive")
	}
	if s.DeadPeerThreshold <= 0 {
		return fmt.Errorf("dead_peer_threshold must be positive")
	}
	if s.MaxSocksStreams < 0 {
		return fmt.Errorf("max_socks_streams must not be negative")
	}
	if s.SpillL1Bytes < 0 {
		return fmt.Errorf("spill_l1_bytes must not be negative")
	}
	return s.validateChain()
}

func (c Client) Validate() error {
	if c.MaxSocksStreams < 0 {
		return fmt.Errorf("max_socks_streams must not be negative")
	}
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
		if !c.hasTargetChain() {
			return fmt.Errorf("server is required")
		}
	}
	if err := validAuthMethod(c.AuthMethod); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(c.Transport)) == "tcp" && c.AllowHA {
		return fmt.Errorf("--allow-ha cannot be used with tcp transport")
	}
	if c.IsWS() && c.AllowHA {
		return fmt.Errorf("--allow-ha cannot be used with websocket transport")
	}
	if c.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat_interval must be positive")
	}
	if c.DeadPeerThreshold <= 0 {
		return fmt.Errorf("dead_peer_threshold must be positive")
	}
	if c.HappyEyeballsDelay <= 0 {
		return fmt.Errorf("happy_eyeballs_delay must be positive")
	}
	if err := validStrictHostKeyChecking(c.StrictHostKeyChecking); err != nil {
		return err
	}
	if c.TCPInterface == "" && c.UDPInterface == "" && c.TCPSourceIP == "" && c.UDPSourceIP == "" && (len(c.Interfaces) > 0 || len(c.SourceIPs) > 0) {
		_, _, _, _, err := ResolveClientBindings(c.Interfaces, c.SourceIPs, nil, nil)
		if err != nil {
			return err
		}
	} else {
		if c.TCPInterface != "" {
			if _, err := InterfaceByName(c.TCPInterface); err != nil {
				return fmt.Errorf("interface %q not found: %w", c.TCPInterface, err)
			}
		}
		if c.UDPInterface != "" {
			if _, err := InterfaceByName(c.UDPInterface); err != nil {
				return fmt.Errorf("interface %q not found: %w", c.UDPInterface, err)
			}
		}
		if c.TCPSourceIP != "" {
			if ip := net.ParseIP(c.TCPSourceIP); ip == nil {
				return fmt.Errorf("invalid source ip %q", c.TCPSourceIP)
			}
		}
		if c.UDPSourceIP != "" {
			if ip := net.ParseIP(c.UDPSourceIP); ip == nil {
				return fmt.Errorf("invalid source ip %q", c.UDPSourceIP)
			}
		}
	}
	if c.SpillL1Bytes < 0 {
		return fmt.Errorf("spill_l1_bytes must not be negative")
	}
	return c.validateChain()
}

func (c Client) hasTargetChain() bool {
	if len(c.Jumphost) == 0 {
		return false
	}
	if c.Target != "" {
		return true
	}
	hops, err := ParseJumphost(c.Jumphost)
	if err != nil {
		return false
	}
	for _, h := range hops {
		if h.Target != "" {
			return true
		}
	}
	return false
}

func validStrictHostKeyChecking(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "ask", "yes", "no", "accept-new":
		return nil
	default:
		return fmt.Errorf("unknown strict_host_key_checking %q (valid: yes, no, ask, accept-new)", s)
	}
}

func validAuthMethod(m string) error {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", "ssh-publickey":
		return nil
	case "none":
		return fmt.Errorf("auth_method 'none' is completely deprecated and removed; only 'ssh-publickey' is supported")
	default:
		return fmt.Errorf("unknown auth_method %q (only 'ssh-publickey' is supported)", m)
	}
}

func validTransport(t string) bool {
	switch strings.ToLower(t) {
	case "tcp", "quic", "kcp", "ws", "websocket":
		return true
	default:
		return false
	}
}

// TransportPreference is the HELLO/RESUME preference list (§8.5).
func (c Client) TransportPreference() []string {
	return TransportPreferenceList(c.Transport)
}

// TransportPreferenceList maps a single transport name to its HELLO/RESUME
// preference list (§8.5). It is shared with the per-hop -J query suffix (J-D4).
func TransportPreferenceList(t string) []string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "tcp":
		return []string{"tcp"}
	case "kcp":
		return []string{"kcp"}
	case "ws", "websocket":
		return []string{"ws"}
	default:
		return []string{"quic", "kcp"}
	}
}

func (c Client) IsTCP() bool {
	return strings.EqualFold(strings.TrimSpace(c.Transport), "tcp")
}

func (c Client) IsWS() bool {
	t := strings.ToLower(strings.TrimSpace(c.Transport))
	if t == "ws" || t == "websocket" {
		return true
	}
	srv := strings.ToLower(strings.TrimSpace(c.Server))
	return strings.HasPrefix(srv, "ws://") || strings.HasPrefix(srv, "wss://") || strings.HasPrefix(srv, "http://") || strings.HasPrefix(srv, "https://")
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

func (s Server) WSEnabled() bool {
	if s.ListenWS != "" {
		return true
	}
	for _, t := range s.Transports {
		if strings.EqualFold(t, "ws") || strings.EqualFold(t, "websocket") {
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
	destHost, destPort, destErr := net.SplitHostPort(dest)
	destIP := net.ParseIP(destHost)

	for _, a := range allow {
		if a == "*" || a == dest {
			return true
		}
		// Check CIDR rule without port (e.g. "10.0.0.0/8")
		if _, ipNet, err := net.ParseCIDR(a); err == nil {
			if destIP != nil && ipNet.Contains(destIP) {
				return true
			}
			continue
		}
		// Check rule with host:port
		ruleHost, rulePort, rerr := net.SplitHostPort(a)
		if rerr != nil {
			continue
		}
		if rulePort != "*" && (destErr != nil || rulePort != destPort) {
			continue
		}
		if ruleHost == "*" || strings.EqualFold(ruleHost, destHost) {
			return true
		}
		if matched, err := filepath.Match(ruleHost, destHost); err == nil && matched {
			return true
		}
		if _, ipNet, err := net.ParseCIDR(ruleHost); err == nil {
			if destIP != nil && ipNet.Contains(destIP) {
				return true
			}
		}
	}
	return false
}

func (a Agent) Validate() error {
	if strings.TrimSpace(a.Server) == "" {
		return fmt.Errorf("server is required")
	}
	if strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(a.Destination) == "" {
		return fmt.Errorf("destination is required")
	}
	if strings.TrimSpace(a.Transport) == "" {
		return fmt.Errorf("empty transports")
	}
	if !validTransport(a.Transport) {
		return fmt.Errorf("unknown transport %q", a.Transport)
	}
	if a.SendWindow <= 0 {
		return fmt.Errorf("send_window must be positive")
	}
	if a.BufferBytes <= 0 {
		return fmt.Errorf("buffer_bytes must be positive")
	}
	for _, s := range a.ReconnectBackoff {
		if _, err := time.ParseDuration(s); err != nil {
			return fmt.Errorf("bad duration %q: %w", s, err)
		}
	}
	if a.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat_interval must be positive")
	}
	if a.DeadPeerThreshold <= 0 {
		return fmt.Errorf("dead_peer_threshold must be positive")
	}
	if err := validAuthMethod(a.AuthMethod); err != nil {
		return err
	}
	if err := validStrictHostKeyChecking(a.StrictHostKeyChecking); err != nil {
		return err
	}
	if a.SpillL1Bytes < 0 {
		return fmt.Errorf("spill_l1_bytes must not be negative")
	}
	return nil
}

func (a Agent) TransportPreference() []string {
	return TransportPreferenceList(a.Transport)
}

func (a Agent) IsWS() bool {
	if a.WS {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(a.Transport))
	if t == "ws" || t == "websocket" {
		return true
	}
	srv := strings.ToLower(strings.TrimSpace(a.Server))
	return strings.HasPrefix(srv, "ws://") || strings.HasPrefix(srv, "wss://") || strings.HasPrefix(srv, "http://") || strings.HasPrefix(srv, "https://")
}

func (a Agent) DestinationAllowed(dest string) bool {
	if dest == "" || dest == a.Destination {
		return true
	}
	if len(a.AllowDestinations) == 0 {
		return false
	}
	return DestinationAllowed(dest, a.AllowDestinations)
}

func (s Server) TargetAllowed(target string) bool {
	if len(s.AllowTargets) == 0 {
		return true
	}
	for _, allowed := range s.AllowTargets {
		if allowed == "*" || allowed == target {
			return true
		}
	}
	return false
}
