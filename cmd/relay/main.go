package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/remote-relay/relay/internal/auth"
	"github.com/remote-relay/relay/internal/config"
	"github.com/remote-relay/relay/internal/logging"
	"github.com/remote-relay/relay/internal/relay"
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
	fmt.Fprintf(os.Stderr, `usage: relay <server|client|version> [flags]

  relay server [--config PATH] [--listen HOST:PORT] [--host-key PATH] [--splice|--no-splice] [--adaptive-kcp|--no-adaptive-kcp] [--log-level LVL]
  relay client --server HOST:PORT [--dest HOST:PORT] [--tcp|--kcp] [--allow-ha] [--splice|--no-splice] [--adaptive-kcp|--no-adaptive-kcp] [--interface NAME[@proto]] [--source-ip IP[@proto]] [--auth-sock PATH] [--server-fingerprint FP] [--known-hosts PATH] [--config PATH] [--log-level LVL] [%%h %%p]
  relay version
`)
}

func runServer(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to server TOML config")
	listen := fs.String("listen", "", "TCP listen address (overrides config)")
	logLevel := fs.String("log-level", "", "log level")
	heartbeat := fs.Duration("heartbeat-interval", 0, "BFD heartbeat interval (default: 750ms)")
	deadThreshold := fs.Int("dead-peer-threshold", 0, "BFD dead peer missed heartbeat threshold (default: 3)")
	hostKey := fs.String("host-key", "", "path to server Ed25519 host key")
	authorizedKeys := fs.String("authorized-keys", "", "path to authorized_keys file")
	splice := fs.Bool("splice", false, "enable Linux kernel zero-copy stream splicing (splice(2))")
	noSplice := fs.Bool("no-splice", false, "disable Linux kernel zero-copy stream splicing")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
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
	cfg, err := config.LoadServer(config.ServerOptions{
		ConfigPath:        *configPath,
		Listen:            *listen,
		LogLevel:          *logLevel,
		HeartbeatInterval: *heartbeat,
		DeadPeerThreshold: *deadThreshold,
		HostKey:           *hostKey,
		AuthorizedKeys:    *authorizedKeys,
		Splice:            spliceOpt,
		AdaptiveKCP:       adaptiveKCPOpt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay server: %v\n", err)
		return 1
	}
	// Fail fast if flag and TOML config are absent and default ~/.ssh/authorized_keys is missing/invalid
	if *authorizedKeys == "" && cfg.AuthorizedKeys == "" {
		defAK := auth.DefaultAuthorizedKeys()
		if !auth.HasValidAuthorizedKeys(defAK) {
			fmt.Fprintf(os.Stderr, "relay server: no authorized_keys specified via --authorized-keys or TOML, and default %q is missing or has no valid keys; failing fast\n", defAK)
			return 1
		}
		cfg.AuthorizedKeys = defAK
	}
	log := logging.New(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := relay.NewServer(cfg, log)
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "relay server: %v\n", err)
		return 1
	}
	return 0
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
	tcp := fs.Bool("tcp", false, "use TCP data plane")
	kcp := fs.Bool("kcp", false, "use KCP data plane")
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
	fs.Var(&interfaces, "interface", "bind to network interface [NAME[@tcp|@udp]] (repeatable or comma-separated)")
	fs.Var(&sourceIPs, "source-ip", "bind to source IP address [IP[@tcp|@udp]] (repeatable or comma-separated)")
	splice := fs.Bool("splice", false, "enable Linux kernel zero-copy stream splicing (splice(2))")
	noSplice := fs.Bool("no-splice", false, "disable Linux kernel zero-copy stream splicing")
	adaptiveKCP := fs.Bool("adaptive-kcp", false, "enable dynamic adaptive ARQ and congestion tuning for KCP")
	noAdaptiveKCP := fs.Bool("no-adaptive-kcp", false, "disable dynamic adaptive ARQ and congestion tuning for KCP")
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

	destSet := false
	allowHASet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dest" {
			destSet = true
		}
		if f.Name == "allow-ha" {
			allowHASet = true
		}
	})

	if *tcp && *allowHA {
		fmt.Fprintf(os.Stderr, "relay client: --allow-ha cannot be used with --tcp\n")
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
		TCP:                   *tcp,
		KCP:                   *kcp,
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
