package commands

import (
	"slices"
	"testing"
)

// flagValue returns the value after flag in args and whether the flag
// appears, and fails when it appears more than once.
func flagValue(t *testing.T, args []string, flag string) (string, bool) {
	t.Helper()
	value, found := "", false
	for i, arg := range args {
		if arg != flag {
			continue
		}
		if found {
			t.Errorf("%s appears twice in %v", flag, args)
		}
		found = true
		if i+1 < len(args) {
			value = args[i+1]
		}
	}
	return value, found
}

// TestProtocolArgs_ClientCredentials pins Codex P1-1: the server refuses
// anonymous callers, so every remote transport carries the runner's client
// certificate, key and token, and embedded (no server) carries none.
func TestProtocolArgs_ClientCredentials(t *testing.T) {
	remote := []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP}
	creds := map[string]string{
		"--tls-cert": "/certs/client.crt",
		"--tls-key":  "/certs/client.key",
		"--token":    "it-token",
	}

	r := &TestRunner{
		RESTBaseURL: "https://localhost:8443",
		TLSCACert:   "/certs/ca.crt",
		ClientCert:  creds["--tls-cert"],
		ClientKey:   creds["--tls-key"],
		Token:       creds["--token"],
	}
	for _, p := range remote {
		args := r.protocolArgs(p, []string{"key", "list"})
		for flag, want := range creds {
			got, ok := flagValue(t, args, flag)
			if !ok || got != want {
				t.Errorf("%s: %s = %q (present %v), want %q; args %v", p, flag, got, ok, want, args)
			}
		}
		// A caller that already passes a credential keeps its own value.
		own := r.protocolArgs(p, []string{"--token", "own", "key", "list"})
		if got, _ := flagValue(t, own, "--token"); got != "own" {
			t.Errorf("%s: explicit --token replaced by %q; args %v", p, got, own)
		}
	}
	embedded := r.protocolArgs(ProtocolEmbedded, []string{"key", "list"})
	for flag := range creds {
		if slices.Contains(embedded, flag) {
			t.Errorf("embedded carries %s: %v", flag, embedded)
		}
	}

	empty := &TestRunner{RESTBaseURL: "https://localhost:8443", TLSCACert: "/certs/ca.crt"}
	for _, p := range append(remote, ProtocolEmbedded) {
		args := empty.protocolArgs(p, []string{"key", "list"})
		for flag := range creds {
			if slices.Contains(args, flag) {
				t.Errorf("%s with no credentials carries %s: %v", p, flag, args)
			}
		}
	}
}
