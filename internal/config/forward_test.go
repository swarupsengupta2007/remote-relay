package config

import "testing"

func TestParseLocalForward(t *testing.T) {
	cases := []struct {
		spec, listen, dest string
	}{
		{"8080:intranet:80", "127.0.0.1:8080", "intranet:80"},
		{"0.0.0.0:8080:10.0.0.5:5432", "0.0.0.0:8080", "10.0.0.5:5432"},
		{"*:8080:db:5432", ":8080", "db:5432"},
		{":8080:db:5432", ":8080", "db:5432"},
		{"localhost:2222:127.0.0.1:22", "localhost:2222", "127.0.0.1:22"},
		{"[::1]:8080:[fd00::5]:443", "[::1]:8080", "[fd00::5]:443"},
		{"8443:[2001:db8::1]:443", "127.0.0.1:8443", "[2001:db8::1]:443"},
		{"0:echo:7", "127.0.0.1:0", "echo:7"},
	}
	for _, tc := range cases {
		got, err := ParseLocalForward(tc.spec)
		if err != nil {
			t.Errorf("%q: %v", tc.spec, err)
			continue
		}
		if got.Listen != tc.listen || got.Dest != tc.dest {
			t.Errorf("%q: got %s, want %s -> %s", tc.spec, got, tc.listen, tc.dest)
		}
	}
}

func TestParseLocalForwardRejects(t *testing.T) {
	for _, spec := range []string{
		"",
		"8080",
		"8080:host",
		"a:b:c:d:e",
		"x:host:80",
		"8080:host:0",
		"8080:host:65536",
		"70000:host:80",
		"8080::80",
		"[::1:8080:host:80",
	} {
		if fwd, err := ParseLocalForward(spec); err == nil {
			t.Errorf("%q: accepted as %s", spec, fwd)
		}
	}
}

func TestParseLocalForwardsCommaSeparated(t *testing.T) {
	got, err := ParseLocalForwards([]string{"8080:a:80, 8443:b:443", "9000:c:9000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].Dest != "b:443" || got[2].Listen != "127.0.0.1:9000" {
		t.Fatalf("got %v", got)
	}
}

func TestClientValidateLocalForwards(t *testing.T) {
	c := DefaultClient()
	c.LocalForwards = []string{"8080:host"}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid local_forwards accepted")
	}
}
