package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
)

// TestAccountAddCmd_HTTPSDirectoryWithTrustedRoots pins that account add can
// register against an HTTPS directory: the client trusts no system roots, so
// without --trusted-roots registration fails, and with the server's CA
// certificate it succeeds and the root is kept with the account.
func TestAccountAddCmd_HTTPSDirectoryWithTrustedRoots(t *testing.T) {
	var newAccounts atomic.Int32
	srv := fakeACMETLSServer(t, &newAccounts)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "acme-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "trusted-acme.yaml")
	if err := os.WriteFile(cfgPath, []byte("storage:\n  backend: memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(viper.Reset)

	run := func(name string, flags map[string]string) (string, error) {
		t.Helper()
		loadTestConfig(t, cfgPath)
		resetAccountAddFlags(t)
		add := accountAddCmd
		add.SetContext(context.Background())
		out := &bytes.Buffer{}
		add.SetOut(out)
		add.SetErr(out)
		for flag, val := range flags {
			if err := add.Flags().Set(flag, val); err != nil {
				t.Fatalf("set --%s: %v", flag, err)
			}
		}
		err := add.RunE(add, []string{name})
		return out.String(), err
	}
	base := map[string]string{"directory": srv.URL + "/directory", "email": "admin@example.com"}

	if _, err := run("untrusted", base); err == nil {
		t.Fatal("account add against an HTTPS directory with no trusted roots succeeded, want a TLS error")
	}

	withRoots := map[string]string{"trusted-roots": caPath}
	for k, v := range base {
		withRoots[k] = v
	}
	if out, err := run("board", withRoots); err != nil {
		t.Fatalf("account add --trusted-roots %s: %v (output %q)", caPath, err, out)
	}
	if got := newAccounts.Load(); got != 1 {
		t.Fatalf("server saw %d new-account requests, want 1", got)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), srv.URL+"/account/42") {
		t.Errorf("saved config lacks the account URL:\n%s", raw)
	}
	loadTestConfig(t, cfgPath)
	acct := buildServiceConfig().Accounts["board"]
	if acct == nil || len(acct.TrustedRoots) != 1 || strings.TrimSpace(acct.TrustedRoots[0]) != strings.TrimSpace(string(caPEM)) {
		t.Errorf("saved account trusted_roots = %+v, want the CA certificate PEM", acct)
	}
}
