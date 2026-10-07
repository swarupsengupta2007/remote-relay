package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/relay"
	"github.com/remote-relay/relay/internal/tui"
	"github.com/remote-relay/relay/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "server":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:])
	case "agent":
		return runAgent(args[1:])
	case "socks":
		return runSocks(args[1:])
	case "forward":
		return runForward(args[1:])
	case "top":
		return runTop(args[1:])
	case "stats":
		return runStatsCmd(args[1:])
	case "version":
		fmt.Printf("relay %s\n", version.Version)
		return 0
	case "-h", "-help", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: relay <server|client|agent|forward|socks|top|stats|version> [flags]

  relay server [--config PATH] [--listen HOST:PORT] [--metrics-listen HOST:PORT] [--otel-endpoint URL] [--listen-ws HOST:PORT] [--websocket-path PATH] [--host-key PATH] [--splice|--no-splice] [--adaptive-kcp|--no-adaptive-kcp] [--spill-dir DIR] [--spill-l1-bytes BYTES] [--no-spill] [--log-level LVL]
  relay client [--server HOST:PORT] [--target NAME] [-J|--jumphost|--chain HOST:PORT] [--dest HOST:PORT] [--tcp|--kcp|--ws] [--insecure] [--allow-ha] [--splice|--no-splice] [--adaptive-kcp|--no-adaptive-kcp] [--spill-dir DIR] [--spill-l1-bytes BYTES] [--no-spill] [--hud|--no-hud] [--interface NAME[@proto]] [--source-ip IP[@proto]] [--auth-sock PATH] [--server-fingerprint FP] [--known-hosts PATH] [--config PATH] [--log-level LVL] [%%h %%p]
  relay agent --server HOST:PORT --name NAME [--dest HOST:PORT] [--allow-dest DEST,...] [--tcp|--kcp|--ws] [--insecure] [--identity PATH|-i PATH|--key PATH] [--auth-sock PATH] [--server-fingerprint FP] [--known-hosts PATH] [--spill-dir DIR] [--spill-l1-bytes BYTES] [--no-spill] [--config PATH] [--log-level LVL]
  relay forward -L [BIND:]PORT:HOST:HOSTPORT [-L ...] [-D [BIND:]PORT] --server HOST:PORT [-J|--jumphost|--chain HOST:PORT] [--tcp|--kcp|--ws] [--insecure] [--allow-ha] [--max-streams N] [--interface NAME[@proto]] [--source-ip IP[@proto]] [--auth-sock PATH] [--server-fingerprint FP] [--known-hosts PATH] [--config PATH] [--log-level LVL]
  relay socks [--listen HOST:PORT] --server HOST:PORT [-J|--jumphost|--chain HOST:PORT] [--tcp|--kcp|--ws] [--insecure] [--allow-ha] [--spill-dir DIR] [--spill-l1-bytes BYTES] [--no-spill] [--hud|--no-hud] [--interface NAME[@proto]] [--source-ip IP[@proto]] [--auth-sock PATH] [--server-fingerprint FP] [--known-hosts PATH] [--config PATH] [--log-level LVL]
  relay top [--endpoint URL] [--interval DURATION] [--color=auto|always|never] [--batch]
  relay stats [--endpoint URL] [--color=auto|always|never]
  relay version
`)
}

func runServer(args []string) int {
	srv, code := prepareServer(args)
	if srv == nil {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "relay server: %v\n", err)
		return 1
	}
	return 0
}

// prepareServer parses server flags the way the relay CLI does, loads config,
// and stores those flag overrides so a later ReloadConfig keeps them.
func prepareServer(args []string) (*relay.Server, int) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to server TOML config")
	listen := fs.String("listen", "", "TCP listen address (overrides config)")
	listenWS := fs.String("listen-ws", "", "WebSocket HTTP/HTTPS listen address (e.g. 0.0.0.0:8080 or 0.0.0.0:443)")
	websocketPath := fs.String("websocket-path", "", "WebSocket HTTP path (default: /relay-stream)")
	metricsListen := fs.String("metrics-listen", "", "Prometheus metrics HTTP listen address (e.g. 127.0.0.1:9090)")
	otelEndpoint := fs.String("otel-endpoint", "", "OpenTelemetry collector HTTP endpoint (e.g. http://127.0.0.1:4318/v1/traces)")
	logLevel := fs.String("log-level", "", "log level")
	heartbeat := fs.Duration("heartbeat-interval", 0, "BFD heartbeat interval (default: 750ms)")
	deadThreshold := fs.Int("dead-peer-threshold", 0, "BFD dead peer missed heartbeat threshold (default: 3)")
	hostKey := fs.String("host-key", "", "path to server Ed25519 host key")
	authorizedKeys := fs.String("authorized-keys", "", "path to authorized_keys file")
	splice := fs.Bool("splice", false, "enable Linux kernel zero-copy stream splicing (splice(2))")
	noSplice := fs.Bool("no-splice", false, "disable Linux kernel zero-copy stream splicing")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
	spillDir := fs.String("spill-dir", "", "directory for disk spill files (default: system temp dir)")
	spillL1Bytes := fs.Int("spill-l1-bytes", 0, "per-session L1 RAM limit in bytes before spilling to disk (default: 8MiB)")
	noSpill := fs.Bool("no-spill", false, "disable tiered disk spilling")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil, 0
		}
		return nil, 2
	}
	var spliceOpt *bool
	if *noSplice {
		f := false
		spliceOpt = &f
	} else if *splice {
		t := true
		spliceOpt = &t
	}
	var adaptiveKCPOpt *bool
	if *noAdaptiveKCP {
		f := false
		adaptiveKCPOpt = &f
	} else if *adaptiveKCP {
		t := true
		adaptiveKCPOpt = &t
	}
	var noSpillOpt *bool
	if *noSpill {
		t := true
		noSpillOpt = &t
	}
	opts := config.ServerOptions{
		ConfigPath:        *configPath,
		Listen:            *listen,
		ListenWS:          *listenWS,
		WebSocketPath:     *websocketPath,
		MetricsListen:     *metricsListen,
		OTELEndpoint:      *otelEndpoint,
		LogLevel:          *logLevel,
		HeartbeatInterval: *heartbeat,
		DeadPeerThreshold: *deadThreshold,
		HostKey:           *hostKey,
		AuthorizedKeys:    *authorizedKeys,
		Splice:            spliceOpt,
		AdaptiveKCP:       adaptiveKCPOpt,
		SpillDir:          *spillDir,
		SpillL1Bytes:      *spillL1Bytes,
		NoSpill:           noSpillOpt,
	}
	cfg, err := config.LoadServer(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay server: %v\n", err)
		return nil, 1
	}
	// Fail fast if flag and TOML config are absent and default ~/.ssh/authorized_keys is missing/invalid
	if *authorizedKeys == "" && cfg.AuthorizedKeys == "" {
		defAK := auth.DefaultAuthorizedKeys()
		if !auth.HasValidAuthorizedKeys(defAK) {
			fmt.Fprintf(os.Stderr, "relay server: no authorized_keys specified via --authorized-keys or TOML, and default %q is missing or has no valid keys; failing fast\n", defAK)
			return nil, 1
		}
		cfg.AuthorizedKeys = defAK
		opts.AuthorizedKeys = defAK
	}
	log := logging.New(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	srv := relay.NewServer(cfg, log)
	// NewServer keeps only the config path. Put the startup flag overrides
	// back so ReloadConfig re-applies them over the reloaded TOML.
	srv.SetOptions(opts)
	return srv, 0
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func runClient(args []string) int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to client TOML config")
	server := fs.String("server", "", "relay server host:port")
	dest := fs.String("dest", "", "destination host:port")
	target := fs.String("target", "", "target agent name for reverse relay (e.g. homelab)")
	tcp := fs.Bool("tcp", false, "use TCP data plane")
	kcp := fs.Bool("kcp", false, "use KCP data plane")
	ws := fs.Bool("ws", false, "use WebSocket & HTTPS fallback transport")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification for WebSocket transport")
	fs.BoolVar(insecure, "tls-insecure", false, "alias of --insecure")
	allowHA := fs.Bool("allow-ha", false, "allow HA dual-path failover (UDP > TCP)")
	logLevel := fs.String("log-level", "", "log level")
	heartbeat := fs.Duration("heartbeat-interval", 0, "BFD heartbeat interval (default: 750ms)")
	deadThreshold := fs.Int("dead-peer-threshold", 0, "BFD dead peer missed heartbeat threshold (default: 3)")
	knownHosts := fs.String("known-hosts", "", "path to client known_hosts file")
	fingerprint := fs.String("server-fingerprint", "", "pinned SHA256 server host key fingerprint (SHA256:...)")
	strictChecking := fs.String("strict-host-key-checking", "", "strict host key checking: yes|no|ask|accept-new")
	happyDelay := fs.Duration("happy-eyeballs-delay", 0, "RFC 8305 connection attempt delay across dual-stack addresses (default: 250ms)")
	identity := fs.String("identity", "", "path to client private key identity file")
	fs.StringVar(identity, "i", "", "path to client private key identity file (shorthand)")
	authSock := fs.String("auth-sock", "", "path to ssh-agent Unix socket (overrides $SSH_AUTH_SOCK)")
	var interfaces stringSliceFlag
	var sourceIPs stringSliceFlag
	var jumphost stringSliceFlag
	fs.Var(&interfaces, "interface", "bind to network interface [NAME[@tcp|@udp]] (repeatable or comma-separated)")
	fs.Var(&sourceIPs, "source-ip", "bind to source IP address [IP[@tcp|@udp]] (repeatable or comma-separated)")
	fs.Var(&jumphost, "J", "jumphost chain [user@]host:port[?transport=tcp|kcp|quic][&ha=1][#SHA256:…] (repeatable or comma-separated); --server is the terminal")
	fs.Var(&jumphost, "jumphost", "alias of -J")
	fs.Var(&jumphost, "chain", "alias of -J")
	splice := fs.Bool("splice", false, "enable Linux kernel zero-copy stream splicing (splice(2))")
	noSplice := fs.Bool("no-splice", false, "disable Linux kernel zero-copy stream splicing")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
	hud := fs.Bool("hud", false, "enable terminal reconnection HUD on interactive stderr")
	noHUD := fs.Bool("no-hud", false, "disable terminal reconnection HUD")
	spillDir := fs.String("spill-dir", "", "directory for disk spill files (default: system temp dir)")
	spillL1Bytes := fs.Int("spill-l1-bytes", 0, "per-session L1 RAM limit in bytes before spilling to disk (default: 8MiB)")
	noSpill := fs.Bool("no-spill", false, "disable tiered disk spilling")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	var spliceOpt *bool
	if *noSplice {
		f := false
		spliceOpt = &f
	} else if *splice {
		t := true
		spliceOpt = &t
	}

	var adaptiveKCPOpt *bool
	if *noAdaptiveKCP {
		f := false
		adaptiveKCPOpt = &f
	} else if *adaptiveKCP {
		t := true
		adaptiveKCPOpt = &t
	}

	var hudOpt *bool
	if *noHUD {
		f := false
		hudOpt = &f
	} else if *hud {
		t := true
		hudOpt = &t
	}

	var noSpillOpt *bool
	if *noSpill {
		t := true
		noSpillOpt = &t
	}

	destSet := false
	allowHASet := false
	jumphostSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dest" {
			destSet = true
		}
		if f.Name == "allow-ha" {
			allowHASet = true
		}
		if f.Name == "J" || f.Name == "jumphost" || f.Name == "chain" {
			jumphostSet = true
		}
	})

	if *tcp && *allowHA {
		fmt.Fprintf(os.Stderr, "relay client: --allow-ha cannot be used with --tcp\n")
		return 2
	}
	if *ws && *allowHA {
		fmt.Fprintf(os.Stderr, "relay client: --allow-ha cannot be used with --ws\n")
		return 2
	}

	var posHost, posPort string
	rest := fs.Args()
	switch len(rest) {
	case 0:
	case 1:
		h, p, err := net.SplitHostPort(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay client: invalid destination %q\n", rest[0])
			return 2
		}
		posHost, posPort = h, p
	case 2:
		posHost, posPort = rest[0], rest[1]
	default:
		fmt.Fprintf(os.Stderr, "relay client: extra arguments %v\n", rest)
		return 2
	}

	cfg, err := config.LoadClient(config.ClientOptions{
		ConfigPath:            *configPath,
		Server:                *server,
		Dest:                  *dest,
		DestSet:               destSet,
		Target:                *target,
		TCP:                   *tcp,
		KCP:                   *kcp,
		WS:                    *ws,
		TLSInsecure:           *insecure,
		AllowHA:               *allowHA,
		AllowHASet:            allowHASet,
		LogLevel:              *logLevel,
		PosHost:               posHost,
		PosPort:               posPort,
		HeartbeatInterval:     *heartbeat,
		DeadPeerThreshold:     *deadThreshold,
		KnownHosts:            *knownHosts,
		ServerFingerprint:     *fingerprint,
		StrictHostKeyChecking: *strictChecking,
		HappyEyeballsDelay:    *happyDelay,
		Identity:              *identity,
		AuthSock:              *authSock,
		Splice:                spliceOpt,
		AdaptiveKCP:           adaptiveKCPOpt,
		Interfaces:            interfaces,
		SourceIPs:             sourceIPs,
		Jumphost:              jumphost,
		JumphostSet:           jumphostSet,
		HUD:                   hudOpt,
		SpillDir:              *spillDir,
		SpillL1Bytes:          *spillL1Bytes,
		NoSpill:               noSpillOpt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay client: %v\n", err)
		return 1
	}
	log := logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := relay.RunClient(ctx, cfg, os.Stdin, os.Stdout, log); err != nil {
		fmt.Fprintf(os.Stderr, "relay client: %v\n", err)
		return 1
	}
	return 0
}

func runAgent(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to agent TOML config")
	server := fs.String("server", "", "relay server host:port")
	name := fs.String("name", "", "target name to register with relay server (e.g. homelab)")
	dest := fs.String("dest", "", "local destination host:port to proxy (default: 127.0.0.1:22)")
	var allowDest stringSliceFlag
	fs.Var(&allowDest, "allow-dest", "comma-separated or repeatable allowed destination host:ports")
	tcp := fs.Bool("tcp", false, "use TCP data plane")
	kcp := fs.Bool("kcp", false, "use KCP data plane")
	ws := fs.Bool("ws", false, "use WebSocket transport")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification for WebSocket transport")
	fs.BoolVar(insecure, "tls-insecure", false, "alias of --insecure")
	logLevel := fs.String("log-level", "", "log level")
	heartbeat := fs.Duration("heartbeat-interval", 0, "heartbeat interval (default: 750ms)")
	deadThreshold := fs.Int("dead-peer-threshold", 0, "dead peer missed heartbeat threshold (default: 3)")
	knownHosts := fs.String("known-hosts", "", "path to known_hosts file")
	fingerprint := fs.String("server-fingerprint", "", "pinned SHA256 server host key fingerprint (SHA256:...)")
	strictChecking := fs.String("strict-host-key-checking", "", "strict host key checking: yes|no|ask|accept-new")
	identity := fs.String("identity", "", "path to private key identity file")
	fs.StringVar(identity, "i", "", "path to private key identity file (shorthand)")
	fs.StringVar(identity, "key", "", "alias of --identity")
	authSock := fs.String("auth-sock", "", "path to ssh-agent Unix socket (overrides $SSH_AUTH_SOCK)")
	splice := fs.Bool("splice", false, "enable Linux kernel zero-copy stream splicing (splice(2))")
	noSplice := fs.Bool("no-splice", false, "disable Linux kernel zero-copy stream splicing")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
	spillDir := fs.String("spill-dir", "", "directory for disk spill files (default: system temp dir)")
	spillL1Bytes := fs.Int("spill-l1-bytes", 0, "per-session L1 RAM limit in bytes before spilling to disk (default: 8MiB)")
	noSpill := fs.Bool("no-spill", false, "disable tiered disk spilling")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	var spliceOpt *bool
	if *noSplice {
		f := false
		spliceOpt = &f
	} else if *splice {
		t := true
		spliceOpt = &t
	}

	var adaptiveKCPOpt *bool
	if *noAdaptiveKCP {
		f := false
		adaptiveKCPOpt = &f
	} else if *adaptiveKCP {
		t := true
		adaptiveKCPOpt = &t
	}

	var noSpillOpt *bool
	if *noSpill {
		t := true
		noSpillOpt = &t
	}

	cfg, err := config.LoadAgent(config.AgentOptions{
		ConfigPath:            *configPath,
		Server:                *server,
		Name:                  *name,
		Dest:                  *dest,
		AllowDest:             allowDest,
		TCP:                   *tcp,
		KCP:                   *kcp,
		WS:                    *ws,
		TLSInsecure:           *insecure,
		LogLevel:              *logLevel,
		HeartbeatInterval:     *heartbeat,
		DeadPeerThreshold:     *deadThreshold,
		KnownHosts:            *knownHosts,
		ServerFingerprint:     *fingerprint,
		StrictHostKeyChecking: *strictChecking,
		Identity:              *identity,
		AuthSock:              *authSock,
		Splice:                spliceOpt,
		AdaptiveKCP:           adaptiveKCPOpt,
		SpillDir:              *spillDir,
		SpillL1Bytes:          *spillL1Bytes,
		NoSpill:               noSpillOpt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay agent: %v\n", err)
		return 2
	}

	log := logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := relay.RunAgent(ctx, cfg, log); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "relay agent: %v\n", err)
		return 1
	}
	return 0
}

func runSocks(args []string) int {
	return runMuxClient("socks", args)
}

func runForward(args []string) int {
	return runMuxClient("forward", args)
}

// runMuxClient runs `relay socks` or `relay forward`. Both multiplex local
// connections over one resumable tunnel: socks has a single SOCKS5 listener,
// forward has ssh -L style fixed forwards (-L) plus an optional SOCKS5
// listener (-D).
func runMuxClient(cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to client TOML config")
	listen := new(string)
	var localForwards stringSliceFlag
	if cmd == "socks" {
		fs.StringVar(listen, "listen", "127.0.0.1:1080", "local SOCKS5 listen address")
		fs.StringVar(listen, "l", "127.0.0.1:1080", "local SOCKS5 listen address (shorthand)")
	} else {
		fs.Var(&localForwards, "L", "local forward [bind_address:]port:host:hostport (repeatable or comma-separated)")
		fs.Var(&localForwards, "local-forward", "alias of -L")
		fs.StringVar(listen, "D", "", "also run a SOCKS5 dynamic proxy on [bind_address:]port")
		fs.StringVar(listen, "dynamic", "", "alias of -D")
	}
	server := fs.String("server", "", "relay server host:port")
	tcp := fs.Bool("tcp", false, "use TCP data plane")
	kcp := fs.Bool("kcp", false, "use KCP data plane")
	ws := fs.Bool("ws", false, "use WebSocket & HTTPS fallback transport")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification for WebSocket transport")
	fs.BoolVar(insecure, "tls-insecure", false, "alias of --insecure")
	allowHA := fs.Bool("allow-ha", false, "allow HA dual-path failover (UDP > TCP)")
	logLevel := fs.String("log-level", "", "log level")
	heartbeat := fs.Duration("heartbeat-interval", 0, "BFD heartbeat interval (default: 750ms)")
	deadThreshold := fs.Int("dead-peer-threshold", 0, "BFD dead peer missed heartbeat threshold (default: 3)")
	knownHosts := fs.String("known-hosts", "", "path to client known_hosts file")
	fingerprint := fs.String("server-fingerprint", "", "pinned SHA256 server host key fingerprint (SHA256:...)")
	strictChecking := fs.String("strict-host-key-checking", "", "strict host key checking: yes|no|ask|accept-new")
	happyDelay := fs.Duration("happy-eyeballs-delay", 0, "RFC 8305 connection attempt delay across dual-stack addresses (default: 250ms)")
	identity := fs.String("identity", "", "path to client private key identity file")
	fs.StringVar(identity, "i", "", "path to client private key identity file (shorthand)")
	authSock := fs.String("auth-sock", "", "path to ssh-agent Unix socket (overrides $SSH_AUTH_SOCK)")
	maxStreams := fs.Int("max-streams", 512, "maximum active forwarded streams")
	var interfaces stringSliceFlag
	var sourceIPs stringSliceFlag
	var jumphost stringSliceFlag
	fs.Var(&interfaces, "interface", "bind to network interface [NAME[@tcp|@udp]] (repeatable or comma-separated)")
	fs.Var(&sourceIPs, "source-ip", "bind to source IP address [IP[@tcp|@udp]] (repeatable or comma-separated)")
	fs.Var(&jumphost, "J", "jumphost chain [user@]host:port[?transport=tcp|kcp|quic][&ha=1][#SHA256:…] (repeatable or comma-separated); --server is the terminal")
	fs.Var(&jumphost, "jumphost", "alias of -J")
	fs.Var(&jumphost, "chain", "alias of -J")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
	hud := fs.Bool("hud", false, "enable terminal reconnection HUD on interactive stderr")
	noHUD := fs.Bool("no-hud", false, "disable terminal reconnection HUD")
	spillDir := fs.String("spill-dir", "", "directory for disk spill files (default: system temp dir)")
	spillL1Bytes := fs.Int("spill-l1-bytes", 0, "per-session L1 RAM limit in bytes before spilling to disk (default: 8MiB)")
	noSpill := fs.Bool("no-spill", false, "disable tiered disk spilling")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	var adaptiveKCPOpt *bool
	if *noAdaptiveKCP {
		f := false
		adaptiveKCPOpt = &f
	} else if *adaptiveKCP {
		t := true
		adaptiveKCPOpt = &t
	}

	var hudOpt *bool
	if *noHUD {
		f := false
		hudOpt = &f
	} else if *hud {
		t := true
		hudOpt = &t
	}

	var noSpillOpt *bool
	if *noSpill {
		t := true
		noSpillOpt = &t
	}

	allowHASet := false
	jumphostSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "allow-ha" {
			allowHASet = true
		}
		if f.Name == "J" || f.Name == "jumphost" || f.Name == "chain" {
			jumphostSet = true
		}
	})

	if *tcp && *allowHA {
		fmt.Fprintf(os.Stderr, "relay %s: --allow-ha cannot be used with --tcp\n", cmd)
		return 2
	}
	if *ws && *allowHA {
		fmt.Fprintf(os.Stderr, "relay %s: --allow-ha cannot be used with --ws\n", cmd)
		return 2
	}

	noSplice := false
	spliceOpt := &noSplice // In-memory pipes for SOCKS mux don't splice

	cfg, err := config.LoadClient(config.ClientOptions{
		ConfigPath:            *configPath,
		Server:                *server,
		Dest:                  proto.DestSOCKS5,
		DestSet:               true,
		TCP:                   *tcp,
		KCP:                   *kcp,
		WS:                    *ws,
		TLSInsecure:           *insecure,
		AllowHA:               *allowHA,
		AllowHASet:            allowHASet,
		LogLevel:              *logLevel,
		HeartbeatInterval:     *heartbeat,
		DeadPeerThreshold:     *deadThreshold,
		KnownHosts:            *knownHosts,
		ServerFingerprint:     *fingerprint,
		StrictHostKeyChecking: *strictChecking,
		HappyEyeballsDelay:    *happyDelay,
		Identity:              *identity,
		AuthSock:              *authSock,
		Splice:                spliceOpt,
		AdaptiveKCP:           adaptiveKCPOpt,
		Interfaces:            interfaces,
		SourceIPs:             sourceIPs,
		Jumphost:              jumphost,
		JumphostSet:           jumphostSet,
		HUD:                   hudOpt,
		SocksListen:           *listen,
		MaxSocksStreams:       *maxStreams,
		LocalForwards:         localForwards,
		SpillDir:              *spillDir,
		SpillL1Bytes:          *spillL1Bytes,
		NoSpill:               noSpillOpt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay %s: %v\n", cmd, err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log := logging.NewClient(cfg.LogLevel, cfg.LogFormat)
	if cmd == "socks" {
		err = relay.RunSocks(ctx, relay.SocksConfig{
			Listen:     *listen,
			MaxStreams: *maxStreams,
			Log:        log,
		}, cfg)
	} else {
		var locals []config.LocalForward
		locals, err = config.ParseLocalForwards(cfg.LocalForwards)
		if *listen != "" && !strings.Contains(*listen, ":") {
			*listen = "127.0.0.1:" + *listen // ssh -D PORT binds loopback
		}
		if err == nil && len(locals) == 0 && *listen == "" {
			fmt.Fprintf(os.Stderr, "relay forward: need at least one -L (or local_forwards in config) or -D\n")
			return 2
		}
		if err == nil {
			err = relay.RunForward(ctx, relay.ForwardConfig{
				Locals:      locals,
				SocksListen: *listen,
				MaxStreams:  *maxStreams,
				Log:         log,
			}, cfg)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "relay %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func runTop(args []string) int {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	endpoint := fs.String("endpoint", "http://127.0.0.1:9090/metrics", "metrics endpoint URL")
	interval := fs.Duration("interval", 1*time.Second, "refresh interval (default 1s)")
	color := fs.String("color", "auto", "color output: auto, always, never")
	batch := fs.Bool("batch", false, "run in non-interactive batch mode and exit")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	opts := tui.AppOptions{
		Endpoint: *endpoint,
		Interval: *interval,
		Color:    *color,
		Batch:    *batch,
	}
	if err := tui.RunApp(opts); err != nil {
		fmt.Fprintf(os.Stderr, "relay top: %v\n", err)
		return 1
	}
	return 0
}

func runStatsCmd(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	endpoint := fs.String("endpoint", "http://127.0.0.1:9090/metrics", "metrics endpoint URL")
	color := fs.String("color", "auto", "color output: auto, always, never")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	opts := tui.AppOptions{
		Endpoint: *endpoint,
		Color:    *color,
	}
	if err := tui.RunStats(opts, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "relay stats: %v\n", err)
		return 1
	}
	return 0
}
