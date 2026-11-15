package cmd

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestACMERenewRequiresChallengeAndCSR covers Codex finding 2 on PR #2126:
// a renew with only --cert and --domain is a request the acme client's
// CertificateRequest.Validate rejects, so the command must refuse it as an
// input error before it loads the certificate or builds a client.
func TestACMERenewRequiresChallengeAndCSR(t *testing.T) {
	missingCert := filepath.Join(t.TempDir(), "absent.pem")
	cases := []struct {
		name    string
		args    []string
		want    []string
		notWant []string
	}{
		{
			name: "neither",
			args: []string{"--cert", missingCert, "--domain", "example.com"},
			want: []string{"--challenge", "--csr"},
		},
		{
			name:    "no csr",
			args:    []string{"--cert", missingCert, "--domain", "example.com", "--challenge", "http-01"},
			want:    []string{"--csr"},
			notWant: []string{"--challenge"},
		},
		{
			name:    "no challenge",
			args:    []string{"--cert", missingCert, "--domain", "example.com", "--csr", filepath.Join(t.TempDir(), "r.csr")},
			want:    []string{"--challenge"},
			notWant: []string{"--csr"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newACMERenewCmd(&acmeFlags{})
			c.SetArgs(tc.args)
			c.SilenceUsage = true
			c.SilenceErrors = true
			err := c.Execute()
			if err == nil {
				t.Fatal("renew without challenge or CSR succeeded")
			}
			msg := err.Error()
			if !strings.Contains(msg, "renew needs") {
				t.Fatalf("error %q is not an input error", msg)
			}
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not name %s", msg, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("error %q names %s, which was given", msg, w)
				}
			}
		})
	}
}

// writeACMETestCSR writes a PEM CSR file the renew tests can pass; the fake
// client only checks that a CSR arrives, as the real client's Validate does.
func writeACMETestCSR(t *testing.T) (string, []byte) {
	t.Helper()
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	path := filepath.Join(t.TempDir(), "renew.csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, der
}
