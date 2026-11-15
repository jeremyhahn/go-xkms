package services

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestACMEService_RenewCertificate_NeedsChallengeAndCSR covers Codex finding
// 2 on PR #2126: a renew with only a certificate and a domain is a request
// the acme client's CertificateRequest.Validate rejects, so the service must
// refuse it as an input error before it loads the certificate or builds a
// client.
func TestACMEService_RenewCertificate_NeedsChallengeAndCSR(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "absent.pem")
	cases := []struct {
		name    string
		req     ACMERenewRequest
		want    []string
		notWant []string
	}{
		{
			name: "neither",
			req:  ACMERenewRequest{CertPath: cert, Domain: "example.com"},
			want: []string{"challenge type", "CSR"},
		},
		{
			name:    "no csr",
			req:     ACMERenewRequest{CertPath: cert, Domain: "example.com", Challenge: "http-01"},
			want:    []string{"CSR"},
			notWant: []string{"challenge type"},
		},
		{
			name:    "no challenge",
			req:     ACMERenewRequest{CertPath: cert, Domain: "example.com", CSRPath: filepath.Join(dir, "r.csr")},
			want:    []string{"challenge type"},
			notWant: []string{"CSR"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ACMEService{}
			_, err := s.RenewCertificate(ACMEConnection{}, tc.req)
			if err == nil {
				t.Fatal("renew without challenge or CSR succeeded")
			}
			msg := err.Error()
			if !strings.Contains(msg, "renew needs") {
				t.Fatalf("error %q is not an input error", msg)
			}
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not name the %s", msg, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("error %q names the %s, which was given", msg, w)
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
