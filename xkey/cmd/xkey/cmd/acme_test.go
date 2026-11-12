// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// fakeACMEClient records the calls the acme commands make.
type fakeACMEClient struct {
	registered    bool
	updated       []string
	deactivated   bool
	revokedCert   *x509.Certificate
	revokedReason acme.CRLReasonCode
	closed        bool
	err           error
}

func (f *fakeACMEClient) RegisterAccount() (*acme.Account, error) {
	f.registered = true
	if f.err != nil {
		return nil, f.err
	}
	return &acme.Account{URI: "https://ca.test/acme/account/7", Status: acme.StatusValid}, nil
}

func (f *fakeACMEClient) UpdateAccount(_ context.Context, contacts []string) (*acme.Account, error) {
	f.updated = contacts
	if f.err != nil {
		return nil, f.err
	}
	return &acme.Account{URI: "https://ca.test/acme/account/7", Status: acme.StatusValid, Contact: contacts}, nil
}

func (f *fakeACMEClient) DeactivateAccount(_ context.Context) error {
	f.deactivated = true
	return f.err
}

func (f *fakeACMEClient) RevokeCertificate(_ context.Context, cert *x509.Certificate, reason acme.CRLReasonCode) error {
	f.revokedCert = cert
	f.revokedReason = reason
	return f.err
}

func (f *fakeACMEClient) Close() error {
	f.closed = true
	return nil
}

type acmeTestEnv struct {
	fake    *fakeACMEClient
	opts    acmeClientOptions
	keyFile string
	keyPEM  []byte
}

// newACMETestEnv swaps the client constructor for a fake and writes an
// account key the commands load.
func newACMETestEnv(t *testing.T) *acmeTestEnv {
	t.Helper()
	env := &acmeTestEnv{fake: &fakeACMEClient{}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	env.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	env.keyFile = filepath.Join(t.TempDir(), "account.pem")
	if err := os.WriteFile(env.keyFile, env.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := newACMEClientFunc
	newACMEClientFunc = func(opts acmeClientOptions) (acmeClient, error) {
		if opts.Signer == nil {
			return nil, errors.New("nil signer")
		}
		env.opts = opts
		return env.fake, nil
	}
	t.Cleanup(func() { newACMEClientFunc = prev })
	return env
}

func (env *acmeTestEnv) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := newACMECmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	err := c.ExecuteContext(context.Background())
	return out.String(), err
}

func (env *acmeTestEnv) common() []string {
	return []string{"--directory", "https://ca.test/acme/directory", "--account-key", env.keyFile}
}

// assertNoKeyMaterial fails when the output carries the account key.
func (env *acmeTestEnv) assertNoKeyMaterial(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("output carries a PEM private key header: %q", out)
	}
	block, _ := pem.Decode(env.keyPEM)
	b64 := base64.StdEncoding.EncodeToString(block.Bytes)
	if strings.Contains(out, b64[:24]) {
		t.Fatalf("output carries account key bytes: %q", out)
	}
}

func writeTestCert(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "device.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), crypto.Signer(key))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cert
}

func TestACMEAccountRegisterPassesContact(t *testing.T) {
	env := newACMETestEnv(t)
	args := append([]string{"account", "register", "--contact", "mailto:x@example.com"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("register: %v (%s)", err, out)
	}
	if !env.fake.registered {
		t.Fatal("RegisterAccount not called")
	}
	if env.opts.Contact != "x@example.com" {
		t.Fatalf("contact = %q, want x@example.com", env.opts.Contact)
	}
	if env.opts.DirectoryURL != "https://ca.test/acme/directory" {
		t.Fatalf("directory = %q", env.opts.DirectoryURL)
	}
	if !env.fake.closed {
		t.Fatal("client not closed")
	}
	if !strings.Contains(out, "https://ca.test/acme/account/7") {
		t.Fatalf("output lacks account URL: %q", out)
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMEAccountUpdateCallsUpdate(t *testing.T) {
	env := newACMETestEnv(t)
	args := append([]string{"account", "update", "--contact", "a@example.com", "--contact", "mailto:b@example.com"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("update: %v (%s)", err, out)
	}
	want := []string{"a@example.com", "mailto:b@example.com"}
	if len(env.fake.updated) != 2 || env.fake.updated[0] != want[0] || env.fake.updated[1] != want[1] {
		t.Fatalf("UpdateAccount contacts = %v, want %v", env.fake.updated, want)
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMEAccountUpdateNeedsContact(t *testing.T) {
	env := newACMETestEnv(t)
	_, err := env.run(t, append([]string{"account", "update"}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "--contact") {
		t.Fatalf("err = %v, want a --contact error", err)
	}
	if env.fake.updated != nil {
		t.Fatal("UpdateAccount called without contacts")
	}
}

func TestACMEAccountDeactivate(t *testing.T) {
	env := newACMETestEnv(t)
	_, err := env.run(t, append([]string{"account", "deactivate"}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("err = %v, want a --yes error", err)
	}
	if env.fake.deactivated {
		t.Fatal("DeactivateAccount called without --yes")
	}
	out, err := env.run(t, append([]string{"account", "deactivate", "--yes"}, env.common()...)...)
	if err != nil {
		t.Fatalf("deactivate: %v (%s)", err, out)
	}
	if !env.fake.deactivated {
		t.Fatal("DeactivateAccount not called")
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMERevokeParsesCertAndReason(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, cert := writeTestCert(t)
	args := append([]string{"revoke", "--cert", certFile, "--reason", "keyCompromise"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("revoke: %v (%s)", err, out)
	}
	if env.fake.revokedCert == nil || !env.fake.revokedCert.Equal(cert) {
		t.Fatal("RevokeCertificate not called with the parsed certificate")
	}
	if env.fake.revokedReason != acme.CRLReasonKeyCompromise {
		t.Fatalf("reason = %d, want %d", env.fake.revokedReason, acme.CRLReasonKeyCompromise)
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMERevokeReasonByNumberAndDefault(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	if _, err := env.run(t, append([]string{"revoke", "--cert", certFile, "--reason", "4"}, env.common()...)...); err != nil {
		t.Fatal(err)
	}
	if env.fake.revokedReason != acme.CRLReasonSuperseded {
		t.Fatalf("reason = %d, want superseded", env.fake.revokedReason)
	}
	if _, err := env.run(t, append([]string{"revoke", "--cert", certFile}, env.common()...)...); err != nil {
		t.Fatal(err)
	}
	if env.fake.revokedReason != acme.CRLReasonUnspecified {
		t.Fatalf("reason = %d, want unspecified", env.fake.revokedReason)
	}
}

func TestACMERevokeErrors(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	notCert := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.pem")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing cert flag", []string{"revoke"}, "--cert"},
		{"missing cert file", []string{"revoke", "--cert", missing}, missing},
		{"not a certificate", []string{"revoke", "--cert", notCert}, "certificate"},
		{"bad reason", []string{"revoke", "--cert", certFile, "--reason", "bogus"}, "bogus"},
		{"reserved reason 7", []string{"revoke", "--cert", certFile, "--reason", "7"}, "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env.fake.revokedCert = nil
			_, err := env.run(t, append(tc.args, env.common()...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if env.fake.revokedCert != nil {
				t.Fatal("RevokeCertificate called on a failed parse")
			}
		})
	}
}

func TestACMECommonFlagErrors(t *testing.T) {
	env := newACMETestEnv(t)
	junkKey := filepath.Join(t.TempDir(), "junk.key")
	if err := os.WriteFile(junkKey, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no directory", []string{"account", "register", "--account-key", env.keyFile}, "--directory"},
		{"no account key", []string{"account", "register", "--directory", "https://ca.test/d"}, "--account-key"},
		{"missing key file", []string{"account", "register", "--directory", "https://ca.test/d", "--account-key", "/nonexistent/k.pem"}, "/nonexistent/k.pem"},
		{"bad key file", []string{"account", "register", "--directory", "https://ca.test/d", "--account-key", junkKey}, "account key"},
		{"unknown flag", append([]string{"account", "register", "--bogus"}, env.common()...), "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env.fake.registered = false
			out, err := env.run(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if env.fake.registered {
				t.Fatal("RegisterAccount called on a flag error")
			}
			env.assertNoKeyMaterial(t, out)
			env.assertNoKeyMaterial(t, err.Error())
		})
	}
}

func TestACMEClientErrorPropagates(t *testing.T) {
	env := newACMETestEnv(t)
	env.fake.err = errors.New("server said no")
	_, err := env.run(t, append([]string{"account", "register"}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "server said no") {
		t.Fatalf("err = %v, want the client error", err)
	}
	if !env.fake.closed {
		t.Fatal("client not closed after an error")
	}
}

func TestACMETrustedRootsLoaded(t *testing.T) {
	env := newACMETestEnv(t)
	rootFile, _ := writeTestCert(t)
	args := append([]string{"account", "register", "--trusted-root", rootFile, "--system-roots"}, env.common()...)
	if _, err := env.run(t, args...); err != nil {
		t.Fatal(err)
	}
	if len(env.opts.TrustedRoots) != 1 || !strings.Contains(env.opts.TrustedRoots[0], "BEGIN CERTIFICATE") {
		t.Fatalf("trusted roots = %v", env.opts.TrustedRoots)
	}
	if !env.opts.SystemRoots {
		t.Fatal("--system-roots not passed")
	}
	_, err := env.run(t, append([]string{"account", "register", "--trusted-root", "/nonexistent/root.pem"}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/root.pem") {
		t.Fatalf("err = %v, want the root path", err)
	}
}
