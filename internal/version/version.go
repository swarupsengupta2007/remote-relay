package version

import "runtime/debug"

// Version is set at release build time:
//
//	go build -ldflags "-X github.com/remote-relay/relay/internal/version.Version=v0.1.0"
//
// Without it, Version falls back to the module version recorded by
// `go install module@version`, then to "dev".
var Version = ""

func init() {
	if Version != "" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		Version = bi.Main.Version
		return
	}
	Version = "dev"
}
