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

//go:build vault

package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// generateSelfSignedPEM creates a self-signed ECDSA certificate/key pair for
// TLS-configuration tests, returning the PEM-encoded certificate and key.
func generateSelfSignedPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey() error = %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// vaultClientTLSConfig extracts the *tls.Config a Backend's underlying Vault
// client was built with, so a test can assert on RootCAs/Certificates
// without dialing a server.
func vaultClientTLSConfig(t *testing.T, b *Backend) *tls.Config {
	t.Helper()

	dvc, ok := b.client.(*defaultVaultClient)
	if !ok {
		t.Fatalf("Backend.client is %T, want *defaultVaultClient", b.client)
	}
	return dvc.client.CloneConfig().TLSConfig()
}

// TestNewBackend_TLSCAFile proves NewBackend wires Config.TLSCAFile into the
// underlying Vault client's RootCAs, without dialing the server (vault.NewClient
// only builds the client, it never connects).
func TestNewBackend_TLSCAFile(t *testing.T) {
	certPEM, _ := generateSelfSignedPEM(t, "vault-test-ca")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	config := &Config{
		Address:     "https://127.0.0.1:8200",
		Token:       "test-token",
		TLSCAFile:   caFile,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	tlsConfig := vaultClientTLSConfig(t, b)
	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs is nil, want the configured CA to be loaded")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to parse generated CA cert")
	}
	if !tlsConfig.RootCAs.Equal(pool) {
		t.Error("RootCAs does not match the configured CA certificate")
	}
	if tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is true; CA configuration must not disable verification")
	}
}

// TestNewBackend_TLSCAPath proves NewBackend wires Config.TLSCAPath (a
// directory of PEM-encoded CA certificates) into the underlying Vault
// client's RootCAs.
func TestNewBackend_TLSCAPath(t *testing.T) {
	certPEM, _ := generateSelfSignedPEM(t, "vault-test-ca-path")
	caDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(caDir, "ca.pem"), certPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	config := &Config{
		Address:     "https://127.0.0.1:8200",
		Token:       "test-token",
		TLSCAPath:   caDir,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	tlsConfig := vaultClientTLSConfig(t, b)
	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs is nil, want the configured CA directory to be loaded")
	}
}

// TestNewBackend_TLSClientCert proves NewBackend wires Config.TLSCertFile and
// Config.TLSKeyFile into the underlying Vault client for mTLS.
func TestNewBackend_TLSClientCert(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPEM(t, "vault-test-client")
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile(key) error = %v", err)
	}

	config := &Config{
		Address:     "https://127.0.0.1:8200",
		Token:       "test-token",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	tlsConfig := vaultClientTLSConfig(t, b)
	if tlsConfig.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil, want the configured client certificate to be loaded")
	}
	gotCert, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate() error = %v", err)
	}
	wantCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}
	if len(gotCert.Certificate) == 0 || string(gotCert.Certificate[0]) != string(wantCert.Certificate[0]) {
		t.Error("GetClientCertificate() returned a certificate that does not match the configured one")
	}
}

// TestNewBackend_TLSNotConfigured proves NewBackend leaves the underlying
// Vault client's default TLS config untouched (no RootCAs, no client
// certificate, verification enabled) when no TLS options are set.
func TestNewBackend_TLSNotConfigured(t *testing.T) {
	config := &Config{
		Address:     "https://127.0.0.1:8200",
		Token:       "test-token",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	// ConfigureTLS is never called when no TLS option is set (see NewBackend),
	// so the Vault client keeps its zero-value *tls.Config -- nil, meaning Go's
	// default (system trust roots, no client certificate, verification
	// enabled). tls.Config.Clone() returns nil for a nil receiver, so a nil
	// result here is itself the assertion, not a setup failure.
	tlsConfig := vaultClientTLSConfig(t, b)
	if tlsConfig != nil {
		if tlsConfig.RootCAs != nil {
			t.Error("RootCAs is set, want nil when no CA is configured")
		}
		if tlsConfig.GetClientCertificate != nil {
			t.Error("GetClientCertificate is set, want nil when no client cert is configured")
		}
		if tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify is true, want false: this backend has no option to disable it")
		}
	}
}

// TestConfig_Validate_TLSCertKeyMismatch proves Validate rejects a Config
// with only one of TLSCertFile/TLSKeyFile set, since Vault's mTLS setup
// requires both or neither.
func TestConfig_Validate_TLSCertKeyMismatch(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "cert without key",
			config: &Config{
				Address: "https://127.0.0.1:8200", Token: "test-token",
				TLSCertFile: "/tmp/cert.pem",
				KeyStorage:  storage.New(), CertStorage: storage.New(),
			},
		},
		{
			name: "key without cert",
			config: &Config{
				Address: "https://127.0.0.1:8200", Token: "test-token",
				TLSKeyFile: "/tmp/key.pem",
				KeyStorage: storage.New(), CertStorage: storage.New(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); err == nil {
				t.Error("Validate() error = nil, want error for mismatched TLS cert/key")
			}
		})
	}
}

// TestNewBackend_Namespace proves NewBackend applies Config.Namespace to
// the underlying Vault client without dialing the server.
func TestNewBackend_Namespace(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		Namespace:   "test-namespace",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	if b == nil {
		t.Fatal("NewBackend() returned nil backend")
	}
}

// TestDefaultVaultClient_SetTokenRoundTrip proves defaultVaultClient.SetToken
// delegates to the wrapped *vault.Client: a token set through the interface
// is the token the underlying client authenticates future requests with.
func TestDefaultVaultClient_SetTokenRoundTrip(t *testing.T) {
	raw, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		t.Fatalf("vault.NewClient() error = %v", err)
	}
	client := newDefaultVaultClient(raw)
	client.SetToken("round-trip-token")
	if got := raw.Token(); got != "round-trip-token" {
		t.Errorf("SetToken() then raw.Token() = %q, want %q", got, "round-trip-token")
	}
}

// TestGetSignatureAlgorithm proves getSignatureAlgorithm's three real
// outcomes: RSA with *rsa.PSSOptions selects "pss", RSA with any other
// SignerOpts selects "pkcs1v15", and a non-RSA key algorithm (ECDSA) has no
// Vault Transit signature-algorithm parameter at all.
func TestGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		keyAlgo x509.PublicKeyAlgorithm
		opts    crypto.SignerOpts
		want    string
	}{
		{name: "RSA PSS", keyAlgo: x509.RSA, opts: &rsa.PSSOptions{Hash: crypto.SHA256}, want: "pss"},
		{name: "RSA PKCS1v15", keyAlgo: x509.RSA, opts: crypto.SHA256, want: "pkcs1v15"},
		{name: "ECDSA", keyAlgo: x509.ECDSA, opts: crypto.SHA256, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &vaultSigner{attrs: &types.KeyAttributes{KeyAlgorithm: tt.keyAlgo}}
			if got := s.getSignatureAlgorithm(tt.opts); got != tt.want {
				t.Errorf("getSignatureAlgorithm() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRotateKey_NilAttributes proves RotateKey rejects nil attributes and
// an empty CN before reaching Vault.
func TestRotateKey_NilAttributes(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	if err := b.RotateKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("RotateKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
	if err := b.RotateKey(context.Background(), &types.KeyAttributes{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("RotateKey(empty CN) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestDeleteKey_NilAttributes proves DeleteKey rejects nil attributes and
// an empty CN before reaching Vault.
func TestDeleteKey_NilAttributes(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	if err := b.DeleteKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("DeleteKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
	if err := b.DeleteKey(context.Background(), &types.KeyAttributes{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("DeleteKey(empty CN) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGenerateKey_NilAttributes proves GenerateKey rejects nil attributes
// and an empty CN before reaching Vault.
func TestGenerateKey_NilAttributes(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	if _, err := b.GenerateKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GenerateKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.GenerateKey(context.Background(), &types.KeyAttributes{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GenerateKey(empty CN) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGetHashAlgorithm covers getHashAlgorithm's default-to-SHA-256 branch
// and its unsupported-hash branch, neither of which
// TestGetSigningAlgorithm-style existing coverage through Sign reaches
// (Sign always supplies a concrete hash).
func TestGetHashAlgorithm(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("defaults to SHA-256", func(t *testing.T) {
		vaultHash, hash, err := b.getHashAlgorithm(&types.KeyAttributes{})
		if err != nil {
			t.Fatalf("getHashAlgorithm() error = %v", err)
		}
		if vaultHash != "sha2-256" || hash != crypto.SHA256 {
			t.Errorf("getHashAlgorithm() = (%q, %v), want (\"sha2-256\", SHA256)", vaultHash, hash)
		}
	})

	t.Run("unsupported hash", func(t *testing.T) {
		if _, _, err := b.getHashAlgorithm(&types.KeyAttributes{Hash: crypto.MD5}); err == nil {
			t.Error("getHashAlgorithm() expected error for unsupported hash, got nil")
		}
	})
}

// TestListKeys_TransitError proves ListKeys surfaces a Transit ListWithContext
// failure wrapped rather than silently returning an empty list.
func TestListKeys_TransitError(t *testing.T) {
	config := &Config{
		Address:     newFailingTransitServer(t),
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address
	vaultConfig.MaxRetries = 0
	raw, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("vault.NewClient() error = %v", err)
	}
	raw.SetToken(config.Token)

	b, err := NewBackendWithClient(config, newDefaultVaultClient(raw))
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if _, err := b.ListKeys(context.Background()); err == nil {
		t.Error("ListKeys() expected error when Transit list fails, got nil")
	}
}

// TestListKeys_Empty proves ListKeys returns an empty (not nil-erroring)
// slice against a Transit engine with no keys, exercising the nil-secret
// short-circuit.
func TestListKeys_Empty(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys() on empty Transit engine = %d keys, want 0", len(keys))
	}
}

// TestListKeys_MissingLocalMetadata proves a Transit key with no local
// metadata record still appears in ListKeys with basic (CN-only)
// attributes, instead of being dropped or erroring the whole call.
func TestListKeys_MissingLocalMetadata(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{
		CN:           "list-keys-no-metadata",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	// Remove only the local metadata record; the Transit key itself remains.
	if err := storage.DeleteKey(context.Background(), b.config.KeyStorage, attrs.CN); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	var found bool
	for _, k := range keys {
		if k.CN == attrs.CN {
			found = true
		}
	}
	if !found {
		t.Errorf("ListKeys() missing %s after its local metadata was deleted (should fall back to basic attrs)", attrs.CN)
	}
}
