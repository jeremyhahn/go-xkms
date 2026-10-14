// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// cert_issue_paths_test.go covers the CA key encodings cert issue accepts,
// the CA material it refuses, and the SAN and file variants of its output.
package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueAs runs cert issue against the CA files with the given format and
// extra flags.
func issueAs(t *testing.T, format, caCert, caKey string, extra ...verbFlag) (string, int, string) {
	t.Helper()
	cfg := NewConfig()
	cfg.OutputFormat = format
	flags := append([]verbFlag{{"ca-cert", caCert}, {"ca-key", caKey}, {"cn", "server.example.com"}}, extra...)
	return runVerb(t, cfg, certIssueCmd, nil, flags...)
}

// writePEMFile writes one PEM block of the given type to a temp file.
func writePEMFile(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "block.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
	return path
}

func TestCertIssueCmd_AcceptsSEC1ECKey(t *testing.T) {
	certPath, _, _, key := writeCAFiles(t)
	der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	require.NoError(t, err)

	out, code, stderr := issueAs(t, "text", certPath, writePEMFile(t, "EC PRIVATE KEY", der))
	assert.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "Issuer: CN=Issuer Test CA")
}

func TestCertIssueCmd_AcceptsPKCS1RSAKey(t *testing.T) {
	caCert, caKey, err := generateCA("RSA Issuer CA", "", "", "", "", "", 30, "rsa", 2048)
	require.NoError(t, err)
	certPath := writePEMFile(t, "CERTIFICATE", caCert.Raw)
	keyPath := writePEMFile(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey.(*rsa.PrivateKey)))

	out, code, stderr := issueAs(t, "text", certPath, keyPath)
	assert.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "Issuer: CN=RSA Issuer CA")
}

func TestCertIssueCmd_RefusesBadCAMaterial(t *testing.T) {
	certPath, keyPath, _, _ := writeCAFiles(t)
	notPEM := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notPEM, []byte("not pem"), 0600))
	garbage := writePEMFile(t, "CERTIFICATE", []byte("garbage"))

	cases := []struct {
		name          string
		caCert, caKey string
		extra         []verbFlag
		sentinel      error
	}{
		{"CA certificate not PEM", notPEM, keyPath, nil, ErrDecodeCACertificatePEMFailed},
		{"CA certificate not DER", garbage, keyPath, nil, ErrParseCACertificateFailed},
		{"CA key not PEM", certPath, notPEM, nil, ErrDecodeCAPrivateKeyPEMFailed},
		{"CA key in no known encoding", certPath, garbage, nil, ErrParseCAPrivateKeyFailed},
		{"oversized RSA key", certPath, keyPath, []verbFlag{{"key-algorithm", "rsa"}, {"key-size", "8192"}}, ErrRSAKeySizeTooLarge},
		{"unwritable key output", certPath, keyPath, []verbFlag{{"key-output", filepath.Join(notPEM, "leaf.key")}}, ErrWritePrivateKeyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := issueAs(t, "text", tc.caCert, tc.caKey, tc.extra...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out, "PRIVATE KEY", "a refused issue prints no key")
		})
	}
}

func TestCertIssueCmd_JSONWithSANsInline(t *testing.T) {
	certPath, keyPath, _, _ := writeCAFiles(t)

	out, code, stderr := issueAs(t, "json", certPath, keyPath,
		verbFlag{"type", "client"}, verbFlag{"ip", "192.0.2.10, 2001:db8::1"}, verbFlag{"email", "ops@example.com"})
	require.Equal(t, -1, code, stderr)
	got := lastJSONObject(t, out)
	assert.Equal(t, []any{"192.0.2.10", "2001:db8::1"}, got["ip_addresses"])
	assert.Equal(t, []any{"ops@example.com"}, got["email_addresses"])
	assert.Contains(t, got["certificate"], "BEGIN CERTIFICATE")
	assert.Contains(t, got["private_key"], "BEGIN PRIVATE KEY")
	assert.NotContains(t, got, "cert_file")
}

// lastJSONObject decodes the last of the JSON objects in out; the printer
// writes the success notice as its own object first.
func lastJSONObject(t *testing.T, out string) map[string]any {
	t.Helper()
	var got map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	for dec.More() {
		got = nil
		require.NoError(t, dec.Decode(&got), out)
	}
	return got
}

func TestCertIssueCmd_TextWithSANsToFiles(t *testing.T) {
	certPath, keyPath, _, _ := writeCAFiles(t)
	dir := t.TempDir()
	leafCert, leafKey := filepath.Join(dir, "leaf.crt"), filepath.Join(dir, "leaf.key")

	out, code, stderr := issueAs(t, "text", certPath, keyPath,
		verbFlag{"dns", "a.example.com,b.example.com"}, verbFlag{"ip", "192.0.2.10"},
		verbFlag{"type", "client"}, verbFlag{"email", "ops@example.com"},
		verbFlag{"output", leafCert}, verbFlag{"key-output", leafKey})
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "  DNS Names: [a.example.com b.example.com]")
	assert.Contains(t, out, "  IP Addresses: [192.0.2.10]")
	assert.Contains(t, out, "  Email Addresses: [ops@example.com]")
	assert.Contains(t, out, "  Certificate: "+leafCert)
	assert.Contains(t, out, "  Private Key: "+leafKey)
	assert.NotContains(t, out, "BEGIN PRIVATE KEY", "a key written to a file is not echoed")

	info, err := os.Stat(leafKey)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// generateCAAs runs cert generate-ca for "Paths Root CA" with the given
// format and extra flags.
func generateCAAs(t *testing.T, format string, extra ...verbFlag) (string, int, string) {
	t.Helper()
	cfg := NewConfig()
	cfg.OutputFormat = format
	return runVerb(t, cfg, certGenerateCACmd, nil, append([]verbFlag{{"cn", "Paths Root CA"}}, extra...)...)
}

func TestCertGenerateCACmd_JSONInline(t *testing.T) {
	out, code, stderr := generateCAAs(t, "json")
	require.Equal(t, -1, code, stderr)
	got := lastJSONObject(t, out)
	assert.Contains(t, got["certificate"], "BEGIN CERTIFICATE")
	assert.Contains(t, got["private_key"], "BEGIN PRIVATE KEY")
	assert.NotContains(t, got, "key_file")
}

func TestCertGenerateCACmd_TextToFiles(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")

	out, code, stderr := generateCAAs(t, "text", verbFlag{"output", caCert}, verbFlag{"key-output", caKey})
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "  Is CA: true")
	assert.Contains(t, out, "  Certificate: "+caCert)
	assert.Contains(t, out, "  Private Key: "+caKey)
	assert.NotContains(t, out, "BEGIN", "material written to files is not echoed")

	info, err := os.Stat(caKey)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestCertGenerateCACmd_Refusals(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))

	cases := []struct {
		name     string
		extra    []verbFlag
		sentinel error
	}{
		{"oversized RSA key", []verbFlag{{"key-algorithm", "rsa"}, {"key-size", "8192"}}, ErrGenerateCAFailed},
		{"unwritable key output", []verbFlag{{"key-output", filepath.Join(notDir, "ca.key")}}, ErrWritePrivateKeyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := generateCAAs(t, "text", tc.extra...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out, "PRIVATE KEY")
		})
	}
}
