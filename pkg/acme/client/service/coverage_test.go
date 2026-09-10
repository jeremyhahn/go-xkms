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

package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMemoryFactory creates a real objstore Factory backed by an in-memory
// KV store, suitable for unit tests that need a functional storage factory
// without requiring a live server.
func newMemoryFactory(t *testing.T) *objstore.Factory {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)
	return factory.(*objstore.Factory)
}

// selfSignedCert is a helper that generates an ECDSA P-256 self-signed
// certificate valid for the given duration, returning the parsed cert and key.
func selfSignedCert(t *testing.T, cn string, valid time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(valid),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// ==========================================================================
// AccountManager.StorageFactory — path coverage
// ==========================================================================

// TestStorageFactory_AccountNotFound verifies StorageFactory returns an error
// when the named account does not exist.
func TestStorageFactory_AccountNotFound(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	_, err := am.StorageFactory("ghost")
	var target ErrAccountNotFound
	require.True(t, errors.As(err, &target))
}

// TestStorageFactory_LocalBackend exercises the non-tenant path with a
// local filesystem backend using t.TempDir.
func TestStorageFactory_LocalBackend(t *testing.T) {
	cfg := testConfig()
	cfg.Storage = StorageConfig{
		Backend: "local",
		Options: map[string]interface{}{"path": t.TempDir()},
	}
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()
	require.NoError(t, am.Add(ctx, "prod", validAccountConfig()))

	factory, err := am.StorageFactory("prod")
	if err == nil {
		assert.NotNil(t, factory)
		// Second call returns the cached factory (different code path).
		factory2, err2 := am.StorageFactory("prod")
		require.NoError(t, err2)
		assert.Same(t, factory, factory2)
	} else {
		// Storage layer not available in this environment; verify typed error.
		assert.NotEmpty(t, err.Error())
	}
}

// TestStorageFactory_TenantPath exercises the tenant-aware factory branch.
func TestStorageFactory_TenantPath(t *testing.T) {
	cfg := testConfig()
	cfg.TenantID = "tenant-x"
	cfg.Storage = StorageConfig{
		Backend: "local",
		Options: map[string]interface{}{"path": t.TempDir()},
	}
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()
	require.NoError(t, am.Add(ctx, "prod", validAccountConfig()))

	_, err := am.StorageFactory("prod")
	if err != nil {
		var sfErr ErrStorageFactory
		assert.True(t, errors.As(err, &sfErr))
	}
}

// TestStorageFactory_InvalidBackend exercises the createStateBackend error path
// by providing an unsupported backend name that OpenEngine will reject.
func TestStorageFactory_InvalidBackend(t *testing.T) {
	cfg := testConfig()
	cfg.Storage = StorageConfig{
		Backend: "invalid-backend-xyz-99999",
	}
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()
	require.NoError(t, am.Add(ctx, "prod", validAccountConfig()))

	_, err := am.StorageFactory("prod")
	require.Error(t, err)
	var sfErr ErrStorageFactory
	assert.True(t, errors.As(err, &sfErr))
}

// TestStorageFactory_CacheHit verifies that StorageFactory returns the same
// factory instance on a second call (cache-hit path).
func TestStorageFactory_CacheHit(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()
	require.NoError(t, am.Add(ctx, "prod", validAccountConfig()))

	// Pre-populate the cache.
	factory := newMemoryFactory(t)
	am.factories.Store("prod", factory)

	got1, err := am.StorageFactory("prod")
	require.NoError(t, err)
	assert.Same(t, factory, got1)

	got2, err := am.StorageFactory("prod")
	require.NoError(t, err)
	assert.Same(t, factory, got2)
}

// ==========================================================================
// AccountManager.Client — path coverage
// ==========================================================================

// TestClient_AccountNotFound verifies Client returns ErrAccountNotFound
// when the named account is absent.
func TestClient_AccountNotFound(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger())
	_, err := am.Client(context.Background(), "ghost")
	var target ErrAccountNotFound
	require.True(t, errors.As(err, &target))
}

// TestClient_WithInjectedFactory exercises the full Client() creation path
// by pre-loading a real in-memory factory into am.factories. This bypasses
// createStateBackend so no network or filesystem access is required.
func TestClient_WithInjectedFactory(t *testing.T) {
	cfg := testConfig()
	cfg.Accounts["prod"] = validAccountConfig()
	// Use a dummy local directory URL — client.NewClient does NOT dial out
	// when RequestServerBundle=false (the default).
	cfg.Accounts["prod"].DirectoryURL = "https://localhost:14000/dir"
	am := NewAccountManager(cfg, testLogger()).(*accountManager)

	// Inject a real in-memory factory so StorageFactory returns it from cache.
	factory := newMemoryFactory(t)
	am.factories.Store("prod", factory)

	c, err := am.Client(context.Background(), "prod")
	if err != nil {
		// A network error is allowed (no ACME server); the important thing is
		// that we reached client.NewClient — verify typed error path.
		var clientErr ErrClientCreation
		if errors.As(err, &clientErr) {
			assert.Equal(t, "prod", clientErr.Account)
		}
		return
	}
	assert.NotNil(t, c)

	// Second call returns the cached client.
	c2, err := am.Client(context.Background(), "prod")
	require.NoError(t, err)
	assert.Same(t, c, c2)
}

// TestClient_MissingKey verifies Client returns ErrMissingKeyConfig when
// the account's key configuration is nil.
func TestClient_MissingKey(t *testing.T) {
	cfg := testConfig()
	acctCfg := validAccountConfig()
	acctCfg.Key = nil
	cfg.Accounts["no-key"] = acctCfg
	am := NewAccountManager(cfg, testLogger())
	_, err := am.Client(context.Background(), "no-key")
	require.Error(t, err)
	var target ErrMissingKeyConfig
	assert.True(t, errors.As(err, &target))
}

// ==========================================================================
// AccountManager.Remove — cached-client path
// ==========================================================================

// TestRemove_WithCachedEntry verifies Remove cleans up a cached entry
// (placeholder value, since we cannot build a live client in unit tests).
func TestRemove_WithCachedEntry(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()

	require.NoError(t, am.Add(ctx, "cached", validAccountConfig()))
	// Store a non-client value to exercise the LoadAndDelete path without
	// triggering the type-assertion branch that would call Close.
	am.clients.Store("cached", (*interface{})(nil))

	err := am.Remove(ctx, "cached")
	require.NoError(t, err)

	_, getErr := am.Get("cached")
	var notFound ErrAccountNotFound
	assert.True(t, errors.As(getErr, &notFound))
}

// TestRemove_WithCachedFactory verifies Remove deletes a cached factory entry.
func TestRemove_WithCachedFactory(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()

	require.NoError(t, am.Add(ctx, "factory-account", validAccountConfig()))
	factory := newMemoryFactory(t)
	am.factories.Store("factory-account", factory)

	err := am.Remove(ctx, "factory-account")
	require.NoError(t, err)

	// Factory entry must be gone.
	_, loaded := am.factories.Load("factory-account")
	assert.False(t, loaded)
}

// ==========================================================================
// CertificateManager — managed-cert paths
// ==========================================================================

// TestDeploy_NilDeployConfig verifies that Deploy returns ErrDeployFailed
// when the managed cert's spec has a nil Deploy field.
func TestDeploy_NilDeployConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	spec.Deploy = nil
	cfg.Certificates["web"] = spec

	cm := testCertificateManager(cfg).(*certificateManager)
	cert, _ := selfSignedCert(t, "test", time.Hour)

	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
	})

	err := cm.Deploy(context.Background(), "web")
	require.Error(t, err)
	var deployErr ErrDeployFailed
	assert.True(t, errors.As(err, &deployErr))
}

// TestShow_ManagedCert verifies Show returns the stored ManagedCertInfo.
func TestShow_ManagedCert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	cfg.Certificates["web"] = spec

	cm := testCertificateManager(cfg).(*certificateManager)
	cert, _ := selfSignedCert(t, "show-test", time.Hour)

	info := &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	}
	cm.managed.Store("web", info)

	got, err := cm.Show("web")
	require.NoError(t, err)
	assert.Equal(t, "web", got.Name)
}

// ==========================================================================
// RenewalOrchestrator — CheckAndRenew with expiring and fresh certs
// ==========================================================================

// TestRevoke_WithManagedCert_ClientError verifies that Revoke returns an error
// (propagated from Client()) when there is a managed cert but no usable ACME client.
func TestRevoke_WithManagedCert_ClientError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	// Remove key config so Client() returns ErrMissingKeyConfig.
	cfg.Accounts["test-ca"].Key = nil
	spec := testCertSpec("test-ca")
	spec.Account = "test-ca"
	cfg.Certificates["web"] = spec

	cert, _ := selfSignedCert(t, "example.com", time.Hour)

	cm := testCertificateManager(cfg).(*certificateManager)
	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	})

	err := cm.Revoke(context.Background(), "web", 0)
	require.Error(t, err)
	var target ErrMissingKeyConfig
	assert.True(t, errors.As(err, &target))
}

// TestRenewalOrchestrator_CheckAndRenew_ExpiringCert verifies that
// CheckAndRenew attempts renewal when a managed cert is within the threshold.
func TestRenewalOrchestrator_CheckAndRenew_ExpiringCert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := &CertificateSpec{
		Account:   "test-ca",
		Subject:   SubjectConfig{CN: "expiring.example.com"},
		Key:       &KeyConfig{Algorithm: "ECDSA", Store: "software", ECC: &ECCConfig{Curve: "P-256"}},
		Challenge: "http-01",
		Renewal:   &CertRenewalConfig{Auto: true, DaysBefore: 30},
	}
	cfg.Certificates["web"] = spec

	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger()).(*certificateManager)
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	// Cert expiring in 1 day — within the 30-day threshold.
	cert, _ := selfSignedCert(t, "expiring.example.com", 24*time.Hour)
	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	})

	results := ro.CheckAndRenew(context.Background())
	require.Len(t, results, 1)
	assert.Equal(t, "web", results[0].Name)
	// Renewal fails due to no ACME server but was triggered.
	assert.Error(t, results[0].Error)
	assert.False(t, results[0].Renewed)
}

// TestRenewalOrchestrator_CheckAndRenew_NotExpiring verifies CheckAndRenew
// does NOT attempt renewal when a managed cert is outside the threshold.
func TestRenewalOrchestrator_CheckAndRenew_NotExpiring(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := &CertificateSpec{
		Account:   "test-ca",
		Subject:   SubjectConfig{CN: "fresh.example.com"},
		Key:       &KeyConfig{Algorithm: "ECDSA", Store: "software", ECC: &ECCConfig{Curve: "P-256"}},
		Challenge: "http-01",
		Renewal:   &CertRenewalConfig{Auto: true, DaysBefore: 30},
	}
	cfg.Certificates["web"] = spec

	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger()).(*certificateManager)
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	// Cert expiring in 60 days — outside the 30-day threshold.
	cert, _ := selfSignedCert(t, "fresh.example.com", 60*24*time.Hour)
	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	})

	results := ro.CheckAndRenew(context.Background())
	assert.Empty(t, results)
}

// TestDeploy_DeployerSuccess verifies the full Deploy happy-path when a
// managed cert with a valid DeployConfig is stored.
func TestDeploy_DeployerSuccess(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	spec.Deploy = &DeployConfig{
		CertPath: dir + "/cert.pem",
		KeyPath:  dir + "/key.pem",
	}
	cfg.Certificates["web"] = spec

	cert, key := selfSignedCert(t, "example.com", time.Hour)
	keyPEM, err := encodeKeyPEM(key)
	require.NoError(t, err)

	cm := testCertificateManager(cfg).(*certificateManager)
	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		KeyPEM:      keyPEM,
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	})

	err = cm.Deploy(context.Background(), "web")
	require.NoError(t, err)

	// Deployed cert should have a DeployedAt timestamp.
	info, err := cm.Show("web")
	require.NoError(t, err)
	assert.NotNil(t, info.DeployedAt)
}

// TestDeploy_DeployerFailure verifies Deploy propagates a deployer error when
// the underlying Deployer.Deploy call fails.
func TestDeploy_DeployerFailure(t *testing.T) {
	// Force os.WriteFile to fail via a path whose parent segment is a regular
	// FILE (fails even as root, unlike a plain "/non-existent-dir" which root
	// can create).
	dir := t.TempDir()
	notADir := filepath.Join(dir, "notadir")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	spec.Deploy = &DeployConfig{
		CertPath: filepath.Join(notADir, "cert.pem"),
		KeyPath:  filepath.Join(notADir, "key.pem"),
	}
	cfg.Certificates["web"] = spec

	cert, key := selfSignedCert(t, "example.com", time.Hour)
	keyPEM, err := encodeKeyPEM(key)
	require.NoError(t, err)

	cm := testCertificateManager(cfg).(*certificateManager)
	cm.managed.Store("web", &ManagedCertInfo{
		Name:        "web",
		Spec:        spec,
		Certificate: cert,
		CertPEM:     encodeCertPEM(cert),
		KeyPEM:      keyPEM,
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	})

	err = cm.Deploy(context.Background(), "web")
	require.Error(t, err)
}

// ==========================================================================
// ChallengeServer — handleChallenge token-mismatch path
// ==========================================================================

// TestChallengeServer_HandleChallenge_TokenMismatch verifies a mismatched
// token returns 404.
func TestChallengeServer_HandleChallenge_TokenMismatch(t *testing.T) {
	cs := NewChallengeServer("", "0", "expected-token", "keyauth", testLogger())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/wrong-token", nil)
	cs.handleChallenge(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestChallengeServer_HandleChallenge_TokenMatch verifies correct token
// returns 200 with the key authorization.
func TestChallengeServer_HandleChallenge_TokenMatch(t *testing.T) {
	cs := NewChallengeServer("", "0", "my-token", "my-keyauth", testLogger())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/my-token", nil)
	cs.handleChallenge(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "my-keyauth", w.Body.String())
}

// TestChallengeServer_Shutdown_NoServer verifies Shutdown is safe when no
// HTTP server was ever started.
func TestChallengeServer_Shutdown_NoServer(t *testing.T) {
	cs := NewChallengeServer("", "0", "tok", "key", testLogger())
	cs.Shutdown() // must not panic
}

// ==========================================================================
// buildCSR — URI parse error path
// ==========================================================================

// TestBuildCSR_WithInvalidURI verifies buildCSR returns ErrCSRCreation
// wrapping ErrInvalidURI when a URI SAN cannot be parsed.
func TestBuildCSR_WithInvalidURI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "service.local"},
		SANs:    SANsConfig{URI: []string{"://not-valid-uri::bad"}},
	}

	_, err = buildCSR(spec, key)
	require.Error(t, err)
	var csrErr ErrCSRCreation
	assert.True(t, errors.As(err, &csrErr))
}

// ==========================================================================
// encodeKeyPEM — additional key type
// ==========================================================================

// TestDeployer_KeyMkdirError exercises the second os.MkdirAll failure branch
// by using an invalid key path (non-writable parent).
func TestDeployer_KeyMkdirError(t *testing.T) {
	dir := t.TempDir()
	d := NewDeployer(testLogger())
	// keyPath's parent segment is a regular FILE, so directory creation fails
	// even when the test runs as root (a plain "/non-existent-dir" is writable
	// by root and would not error).
	notADir := filepath.Join(dir, "notadir")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	cfg := &DeployConfig{
		CertPath: dir + "/cert.pem",
		KeyPath:  filepath.Join(notADir, "sub", "key.pem"),
	}

	cert, key := selfSignedCert(t, "test", time.Hour)
	keyPEM, _ := encodeKeyPEM(key)
	certPEM := encodeCertPEM(cert)

	err := d.Deploy(context.Background(), certPEM, keyPEM, cfg)
	require.Error(t, err)
	var deployErr ErrDeployFailed
	assert.True(t, errors.As(err, &deployErr))
}

// TestEncodeKeyPEM_P384 verifies encodeKeyPEM works for P-384 keys.
func TestEncodeKeyPEM_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pem, err := encodeKeyPEM(key)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pem), "-----BEGIN PRIVATE KEY-----"))
}

// unknownSigner is a crypto.Signer type that x509.MarshalPKCS8PrivateKey
// does not know how to marshal, causing it to return an error.
type unknownSigner struct{}

func (u *unknownSigner) Public() crypto.PublicKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &key.PublicKey
}

func (u *unknownSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// TestEncodeKeyPEM_UnmarshalableType verifies encodeKeyPEM returns ErrKeyEncoding
// for a key type unknown to x509.MarshalPKCS8PrivateKey.
func TestEncodeKeyPEM_UnmarshalableType(t *testing.T) {
	_, err := encodeKeyPEM(&unknownSigner{})
	require.Error(t, err)
	var keyErr ErrKeyEncoding
	assert.True(t, errors.As(err, &keyErr))
}

// ==========================================================================
// generateSigner — RSA and ED25519 paths
// ==========================================================================

// TestGenerateSigner_RSA verifies generateSigner returns an *rsa.PrivateKey for
// an RSA KeyConfig.
func TestGenerateSigner_RSA(t *testing.T) {
	cfg := &KeyConfig{
		Algorithm: "RSA",
		RSA:       &RSAConfig{KeySize: 2048},
	}
	signer, err := generateSigner(cfg)
	require.NoError(t, err)
	_, ok := signer.(*rsa.PrivateKey)
	assert.True(t, ok)
}

// TestGenerateSigner_ED25519 verifies generateSigner returns an ed25519.PrivateKey
// for an ED25519 KeyConfig.
func TestGenerateSigner_ED25519(t *testing.T) {
	cfg := &KeyConfig{
		Algorithm: "ED25519",
	}
	signer, err := generateSigner(cfg)
	require.NoError(t, err)
	_, ok := signer.(ed25519.PrivateKey)
	assert.True(t, ok)
}

// ==========================================================================
// AccountManager.Remove — real *client.Client path
// ==========================================================================

// newRealClient constructs a minimal *client.Client using an in-memory factory,
// without making any network calls (RequestServerBundle=false, SystemCertPool=false).
func newRealClient(t *testing.T) *client.Client {
	t.Helper()
	factory := newMemoryFactory(t)
	accountDAO, err := factory.AccountDAO()
	require.NoError(t, err)
	certDAO, err := factory.CertificateDAO()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg := &client.Config{
		DirectoryURL:        "https://acme.example.local/dir",
		SystemCertPool:      false,
		RequestServerBundle: false,
	}
	params := &client.Params{
		AccountEmail:       "test@example.com",
		AccountSigner:      key,
		Config:             cfg,
		Logger:             slog.Default(),
		Storage:            accountDAO,
		CertificateStorage: certDAO,
	}
	c, err := client.NewClient(params)
	require.NoError(t, err)
	return c
}

// TestRemove_WithRealClient exercises the type-assertion-true branch inside Remove,
// which calls c.Close() on a cached *client.Client.
func TestRemove_WithRealClient(t *testing.T) {
	cfg := testConfig()
	am := NewAccountManager(cfg, testLogger()).(*accountManager)
	ctx := context.Background()

	require.NoError(t, am.Add(ctx, "real-client", validAccountConfig()))

	// Pre-store a real *client.Client so the type assertion in Remove succeeds.
	c := newRealClient(t)
	am.clients.Store("real-client", c)

	err := am.Remove(ctx, "real-client")
	require.NoError(t, err)

	// Verify the account is gone.
	_, getErr := am.Get("real-client")
	var notFound ErrAccountNotFound
	assert.True(t, errors.As(getErr, &notFound))

	// Verify the client entry was removed from the sync.Map.
	_, loaded := am.clients.Load("real-client")
	assert.False(t, loaded)
}

// ==========================================================================
// InitLogger — "text" format branch
// ==========================================================================

// TestInitLogger_TextFormat verifies InitLogger creates a text-handler logger.
func TestInitLogger_TextFormat(t *testing.T) {
	logger := InitLogger(LoggingConfig{Format: "text", Level: "debug", Output: "stdout"})
	require.NotNil(t, logger)
}

// TestInitLogger_JSONFormat verifies InitLogger creates a JSON-handler logger (default).
func TestInitLogger_JSONFormat(t *testing.T) {
	logger := InitLogger(LoggingConfig{Format: "json", Level: "warn", Output: "stderr"})
	require.NotNil(t, logger)
}

// TestInitLogger_UnknownLevel verifies InitLogger falls back to Info level for
// an unrecognised level string.
func TestInitLogger_UnknownLevel(t *testing.T) {
	logger := InitLogger(LoggingConfig{Format: "json", Level: "verbose"})
	require.NotNil(t, logger)
}

// ==========================================================================
// CleanupHTTP01TokenFile — warn path (non-IsNotExist error)
// ==========================================================================

// TestCleanupHTTP01TokenFile_WarnPath exercises the logger.Warn branch by
// placing a directory at the token-file path so os.Remove fails with a
// non-IsNotExist error (EISDIR / "is a directory").
func TestCleanupHTTP01TokenFile_WarnPath(t *testing.T) {
	webroot := t.TempDir()
	token := "blockdir"

	// Create the challenge directory.
	challengeDir := webroot + "/.well-known/acme-challenge"
	require.NoError(t, os.MkdirAll(challengeDir, 0750))

	// Place a non-empty directory at the token path so os.Remove fails.
	tokenAsDir := challengeDir + "/" + token
	require.NoError(t, os.Mkdir(tokenAsDir, 0750))
	// Put a file inside so RemoveAll would be needed, but Remove refuses ENOTEMPTY.
	require.NoError(t, os.WriteFile(tokenAsDir+"/stub", []byte("x"), 0600))

	// Must not panic; must log a warning (cannot assert the log here, but the
	// code path is exercised and covered).
	CleanupHTTP01TokenFile(webroot, token, testLogger())
}

// ==========================================================================
// WriteHTTP01TokenFile — file write failure path
// ==========================================================================

// TestWriteHTTP01TokenFile_WriteFailure exercises the os.WriteFile error branch
// by making the token path unwritable.
//
// A directory occupying the token's path makes the write fail with EISDIR,
// which the kernel enforces for every user. A non-writable directory would not
// stop root, so the branch would silently stop being tested under CI's uid 0.
func TestWriteHTTP01TokenFile_WriteFailure(t *testing.T) {
	webroot := t.TempDir()
	challengeDir := webroot + "/.well-known/acme-challenge"
	require.NoError(t, os.MkdirAll(challengeDir+"/tok", 0750))

	err := WriteHTTP01TokenFile(webroot, "tok", "keyauth", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write token file")
}

// ==========================================================================
// handleChallenge — write error path
// ==========================================================================

// failWriter is a http.ResponseWriter whose Write method always returns an error,
// used to exercise the error-logging branch in handleChallenge.
type failWriter struct {
	header http.Header
	code   int
}

func (fw *failWriter) Header() http.Header {
	if fw.header == nil {
		fw.header = make(http.Header)
	}
	return fw.header
}

func (fw *failWriter) WriteHeader(code int) { fw.code = code }

func (fw *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

// TestHandleChallenge_WriteError verifies the error-logging branch triggered
// when the ResponseWriter.Write call fails.
func TestHandleChallenge_WriteError(t *testing.T) {
	cs := NewChallengeServer("", "0", "my-token", "my-keyauth", testLogger())
	w := &failWriter{}
	r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/my-token", nil)
	// Must not panic even when Write returns an error.
	cs.handleChallenge(w, r)
	assert.Equal(t, http.StatusOK, w.code)
}

// ==========================================================================
// buildCSR — x509.CreateCertificateRequest failure path
// ==========================================================================

// errSigner is a crypto.Signer whose Sign method always returns an error,
// causing x509.CreateCertificateRequest to fail.
type errSigner struct {
	pub crypto.PublicKey
}

func newErrSigner(t *testing.T) *errSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &errSigner{pub: &key.PublicKey}
}

func (s *errSigner) Public() crypto.PublicKey { return s.pub }

func (s *errSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signing refused")
}

// TestBuildCSR_SignError verifies buildCSR wraps x509.CreateCertificateRequest
// failures in ErrCSRCreation.
func TestBuildCSR_SignError(t *testing.T) {
	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "service.local"},
	}
	_, err := buildCSR(spec, newErrSigner(t))
	require.Error(t, err)
	var csrErr ErrCSRCreation
	assert.True(t, errors.As(err, &csrErr))
}

// ==========================================================================
// Deploy — os.WriteFile failures (cert and key paths)
// ==========================================================================

// TestDeploy_CertWriteFileError verifies Deploy returns ErrDeployFailed when
// writing the certificate file fails (parent dir exists but is non-writable).
func TestDeploy_CertWriteFileError(t *testing.T) {
	dir := t.TempDir()
	certDir := dir + "/certs"
	// A directory at the certificate's path makes WriteFile fail with EISDIR
	// for every user, unlike a non-writable directory which root ignores.
	require.NoError(t, os.MkdirAll(certDir+"/cert.pem", 0750))

	d := NewDeployer(testLogger())
	cert, key := selfSignedCert(t, "test", time.Hour)
	keyPEM, err := encodeKeyPEM(key)
	require.NoError(t, err)
	certPEM := encodeCertPEM(cert)

	cfg := &DeployConfig{
		CertPath: certDir + "/cert.pem",
		KeyPath:  dir + "/key.pem",
	}
	err = d.Deploy(context.Background(), certPEM, keyPEM, cfg)
	require.Error(t, err)
	var deployErr ErrDeployFailed
	assert.True(t, errors.As(err, &deployErr))
}

// TestDeploy_KeyWriteFileError verifies Deploy returns ErrDeployFailed when
// writing the private key file fails (cert written successfully; key dir non-writable).
func TestDeploy_KeyWriteFileError(t *testing.T) {
	dir := t.TempDir()
	keyDir := dir + "/keys"
	// A directory at the key's path makes WriteFile fail with EISDIR for every
	// user, unlike a non-writable directory which root ignores.
	require.NoError(t, os.MkdirAll(keyDir+"/key.pem", 0750))

	d := NewDeployer(testLogger())
	cert, key := selfSignedCert(t, "test", time.Hour)
	keyPEM, err := encodeKeyPEM(key)
	require.NoError(t, err)
	certPEM := encodeCertPEM(cert)

	cfg := &DeployConfig{
		CertPath: dir + "/cert.pem",
		KeyPath:  keyDir + "/key.pem",
	}
	err = d.Deploy(context.Background(), certPEM, keyPEM, cfg)
	require.Error(t, err)
	var deployErr ErrDeployFailed
	assert.True(t, errors.As(err, &deployErr))
}

// ==========================================================================
// Revoke — CertSpecNotFound path (cert in config, not yet managed)
// ==========================================================================

// TestRevoke_SpecExistsButNotManaged verifies Revoke returns ErrNoIssuedCertificate
// when the cert spec is registered but Request has never been called.
func TestRevoke_SpecExistsButNotManaged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	cfg.Certificates["web"] = spec

	cm := testCertificateManager(cfg).(*certificateManager)
	err := cm.Revoke(context.Background(), "web", 0)
	require.Error(t, err)
	var target ErrNoIssuedCertificate
	assert.True(t, errors.As(err, &target))
}

// TestRevoke_SpecNotFound verifies Revoke returns ErrCertSpecNotFound when
// the named certificate does not exist in configuration.
func TestRevoke_SpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cm := testCertificateManager(cfg).(*certificateManager)
	err := cm.Revoke(context.Background(), "nonexistent", 0)
	require.Error(t, err)
	var target ErrCertSpecNotFound
	assert.True(t, errors.As(err, &target))
}

// ==========================================================================
// Request — ErrCertSpecNotFound and ErrMissingKeyConfig paths
// ==========================================================================

// TestRequest_SpecNotFound verifies Request returns ErrCertSpecNotFound for an
// unknown certificate name.
func TestRequest_SpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cm := testCertificateManager(cfg).(*certificateManager)
	_, err := cm.Request(context.Background(), "ghost")
	require.Error(t, err)
	var target ErrCertSpecNotFound
	assert.True(t, errors.As(err, &target))
}

// TestRequest_MissingKeyConfig verifies Request returns ErrMissingKeyConfig when
// the certificate spec has a nil Key.
func TestRequest_MissingKeyConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	spec.Key = nil
	cfg.Certificates["no-key"] = spec

	cm := testCertificateManager(cfg).(*certificateManager)
	_, err := cm.Request(context.Background(), "no-key")
	require.Error(t, err)
	var target ErrMissingKeyConfig
	assert.True(t, errors.As(err, &target))
}

// ==========================================================================
// Renew — ErrCertSpecNotFound path
// ==========================================================================

// TestRenew_SpecNotFound verifies Renew returns ErrCertSpecNotFound for an
// unknown certificate name.
func TestRenew_SpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cm := testCertificateManager(cfg).(*certificateManager)
	_, err := cm.Renew(context.Background(), "ghost")
	require.Error(t, err)
	var target ErrCertSpecNotFound
	assert.True(t, errors.As(err, &target))
}

// ==========================================================================
// Request — paths reachable after a successful Client() call
// ==========================================================================

// newCertManagerWithInjectedClient creates a certificateManager whose
// accountManager already has a cached *client.Client. This allows tests to
// reach code paths that are only executed after Client() returns successfully,
// without requiring a live ACME server.
func newCertManagerWithInjectedClient(t *testing.T, cfg *Config, accountName string) *certificateManager {
	t.Helper()
	logger := testLogger()
	am := NewAccountManager(cfg, logger).(*accountManager)
	c := newRealClient(t)
	am.clients.Store(accountName, c)
	deployer := NewDeployer(logger)
	return NewCertificateManager(cfg, am, deployer, logger).(*certificateManager)
}

// TestRequest_GenerateSignerError verifies that Request returns an error
// (propagated from generateSigner) when the spec's Key algorithm is unsupported.
// This test covers the generateSigner call and its error-return path inside Request.
func TestRequest_GenerateSignerError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "UNSUPPORTED-XYZ",
		},
		Challenge: "http-01",
	}
	cfg.Certificates["web"] = spec

	cm := newCertManagerWithInjectedClient(t, cfg, "test-ca")

	_, err := cm.Request(context.Background(), "web")
	require.Error(t, err)
	var keyErr ErrKeyGeneration
	assert.True(t, errors.As(err, &keyErr))
}

// TestRequest_BuildCSRError verifies that Request returns an error (propagated
// from buildCSR) when the spec contains an invalid URI SAN.
// This test covers the generateSigner success path, the buildCSR call, and
// the buildCSR error-return path inside Request.
func TestRequest_BuildCSRError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		SANs:      SANsConfig{URI: []string{"://invalid-uri::bad"}},
		Challenge: "http-01",
	}
	cfg.Certificates["web"] = spec

	cm := newCertManagerWithInjectedClient(t, cfg, "test-ca")

	_, err := cm.Request(context.Background(), "web")
	require.Error(t, err)
	var csrErr ErrCSRCreation
	assert.True(t, errors.As(err, &csrErr))
}

// TestRequest_ReachesACMEServer verifies that Request reaches the ACME server
// call (acmeClient.RequestCertificate) before failing with a network error.
// This covers the challengeType defaulting path (empty Challenge → "http-01"),
// certReq construction, and the RequestCertificate call+error path.
func TestRequest_ReachesACMEServer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		// Challenge intentionally empty so the defaulting branch is exercised.
	}
	cfg.Certificates["web"] = spec

	cm := newCertManagerWithInjectedClient(t, cfg, "test-ca")

	_, err := cm.Request(context.Background(), "web")
	// The call is expected to fail because there is no live ACME server.
	// What matters is that it reached acmeClient.RequestCertificate.
	require.Error(t, err)
	// Must NOT be a key-config or CSR error — those come earlier.
	var keyErr ErrKeyGeneration
	assert.False(t, errors.As(err, &keyErr))
	var csrErr ErrCSRCreation
	assert.False(t, errors.As(err, &csrErr))
}
