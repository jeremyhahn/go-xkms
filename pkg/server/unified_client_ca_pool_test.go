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

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// go-xkms#794: upgradeUnifiedTLSCert used to replace the unified provider's
// client-CA pool outright with the CA bundle once the CA composed, silently
// dropping the operator's configured tls.ca_file / tls.client_cas roots.
// These tests exercise unifiedClientCAPool (the fix's union helper) and its
// caller, upgradeUnifiedTLSCert, directly.

// generateCAKeyAndCert generates a self-signed CA keypair for testing and
// returns the private key (needed to sign a leaf certificate under it), the
// parsed certificate, and its PEM encoding.
func generateCAKeyAndCert(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, cert, pemBytes
}

// issueLeafCertSignedBy issues a leaf certificate signed by caKey/caCert, so
// a test can prove a pool built by unifiedClientCAPool verifies a
// certificate the configured client CA actually issued.
func issueLeafCertSignedBy(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

// fakeBundleSource is a minimal caBundleSource test double, standing in for
// the CA's CABundle() method without needing a fully composed CA.
type fakeBundleSource struct {
	pem []byte
	err error
}

func (f fakeBundleSource) CABundle() ([]byte, error) { return f.pem, f.err }

// ============================================================================
// Tests — unifiedClientCAPool
// ============================================================================

// TestUnifiedClientCAPool_UnionIncludesConfiguredAndBundleRoots proves the
// pool unifiedClientCAPool builds contains both the operator-configured
// client CA root (and still verifies a client certificate that root issued)
// and the CA-bundle root -- the union go-xkms#794 requires instead of the
// bundle silently replacing the configured CAs.
func TestUnifiedClientCAPool_UnionIncludesConfiguredAndBundleRoots(t *testing.T) {
	dir := t.TempDir()
	configuredKey, configuredCert, configuredPEM := generateCAKeyAndCert(t, "configured-client-ca")
	configuredPath := filepath.Join(dir, "client-ca.pem")
	require.NoError(t, os.WriteFile(configuredPath, configuredPEM, 0o600))
	leaf := issueLeafCertSignedBy(t, configuredCert, configuredKey, "admin-client")

	_, bundleCert, bundlePEM := generateCAKeyAndCert(t, "bundle-root-ca")

	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{ClientCAs: []string{configuredPath}},
	})

	pool, err := s.unifiedClientCAPool(fakeBundleSource{pem: bundlePEM})
	require.NoError(t, err)
	require.NotNil(t, pool)

	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "configured client CA root must verify a client certificate it issued")

	_, err = bundleCert.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "CA-bundle root must be present in the union")
}

// TestUnifiedClientCAPool_NoConfiguredClientCAs_ExactlyBundle proves that
// with no tls.ca_file / tls.client_cas configured, the pool is exactly the
// CA bundle: the bundle root verifies, and an unrelated root does not.
func TestUnifiedClientCAPool_NoConfiguredClientCAs_ExactlyBundle(t *testing.T) {
	_, bundleCert, bundlePEM := generateCAKeyAndCert(t, "bundle-only-ca")
	_, otherCert, _ := generateCAKeyAndCert(t, "not-in-pool-ca")

	s := newTLSTestServer(t, &config.Config{})

	pool, err := s.unifiedClientCAPool(fakeBundleSource{pem: bundlePEM})
	require.NoError(t, err)
	require.NotNil(t, pool)

	_, err = bundleCert.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "the bundle root must verify")

	_, err = otherCert.Verify(x509.VerifyOptions{Roots: pool})
	assert.Error(t, err, "a root outside the bundle must not verify")
}

// TestUnifiedClientCAPool_MalformedClientCAsFile_TypedError proves a
// malformed tls.client_cas file surfaces the same typed *ErrCertParse
// loadClientCAsUnion produces at startup, rather than the file being
// silently dropped from the rebuilt pool.
func TestUnifiedClientCAPool_MalformedClientCAsFile_TypedError(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad-client-ca.pem")
	require.NoError(t, os.WriteFile(badPath, []byte("not a pem"), 0o600))

	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{ClientCAs: []string{badPath}},
	})

	pool, err := s.unifiedClientCAPool(fakeBundleSource{})
	require.Error(t, err)
	assert.Nil(t, pool)

	var parseErr *ErrCertParse
	require.True(t, errors.As(err, &parseErr), "expected *ErrCertParse, got %T (%v)", err, err)
}

// TestUnifiedClientCAPool_BundleError_TypedError proves a CABundle()
// failure surfaces as a typed *ErrTLSCertOp rather than an inline error or
// a silently empty pool.
func TestUnifiedClientCAPool_BundleError_TypedError(t *testing.T) {
	s := newTLSTestServer(t, &config.Config{})

	pool, err := s.unifiedClientCAPool(fakeBundleSource{err: errBundleUnavailable})
	require.Error(t, err)
	assert.Nil(t, pool)

	var opErr *ErrTLSCertOp
	require.True(t, errors.As(err, &opErr), "expected *ErrTLSCertOp, got %T (%v)", err, err)
	assert.ErrorIs(t, err, errBundleUnavailable)
}

// errBundleUnavailable is a sentinel used only to prove
// TestUnifiedClientCAPool_BundleError_TypedError's returned error wraps the
// original CABundle() failure.
var errBundleUnavailable = errors.New("test: CA bundle unavailable")

// ============================================================================
// Tests — upgradeUnifiedTLSCert client-CA pool union (go-xkms#794)
// ============================================================================

// TestUpgradeUnifiedTLSCert_PreservesConfiguredClientCAAfterCAComposes is
// the regression test for go-xkms#794: after the upgrade, the
// operator-configured client CA root is still in the advertised pool and
// still verifies a client certificate it issued, and the CA-bundle root is
// also present.
func TestUpgradeUnifiedTLSCert_PreservesConfiguredClientCAAfterCAComposes(t *testing.T) {
	dir := t.TempDir()
	configuredKey, configuredCert, configuredPEM := generateCAKeyAndCert(t, "configured-admin-ca")
	configuredPath := filepath.Join(dir, "client-ca.pem")
	require.NoError(t, os.WriteFile(configuredPath, configuredPEM, 0o600))
	leaf := issueLeafCertSignedBy(t, configuredCert, configuredKey, "admin-client")

	_, bundleCert, bundlePEM := generateCAKeyAndCert(t, "bundle-ca")

	tlsCert, _ := generateSelfSignedCert(t)
	cfg := buildRESTConfigTLSTestCfg()
	cfg.Datastore.Path = t.TempDir()
	cfg.TLS.ClientCAs = []string{configuredPath}
	cfg.TLS.ClientAuth = "require_and_verify"

	s := newMinimalServer(t, cfg)
	_, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)

	mock := &mockTrustedCA{initialized: true, tlsCert: tlsCert, caBundlePEM: bundlePEM}
	s.ca = mock

	require.NoError(t, s.upgradeUnifiedTLSCert(mock))

	pool := s.unifiedTLS.clientCAs.Load()
	require.NotNil(t, pool)

	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "the configured client CA root must still verify a client certificate it issued")

	_, err = bundleCert.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "the CA-bundle root must be present after the upgrade")
}

// TestUpgradeUnifiedTLSCert_MalformedClientCAsFile_ReturnsTypedErrorAndKeepsBootstrapMaterial
// proves that when tls.client_cas turns malformed between the initial bind
// and the CA composing, upgradeUnifiedTLSCert surfaces the same typed
// *ErrCertParse loadClientCAsUnion produces -- not dropped silently -- and
// both the previously installed client-CA pool and the still-serving
// bootstrap certificate are left untouched rather than partially replaced.
func TestUpgradeUnifiedTLSCert_MalformedClientCAsFile_ReturnsTypedErrorAndKeepsBootstrapMaterial(t *testing.T) {
	dir := t.TempDir()
	_, goodCert, goodPEM := generateCAKeyAndCert(t, "good-client-ca")
	goodPath := filepath.Join(dir, "good-client-ca.pem")
	require.NoError(t, os.WriteFile(goodPath, goodPEM, 0o600))

	cfg := buildRESTConfigTLSTestCfg()
	cfg.Datastore.Path = t.TempDir()
	cfg.TLS.ClientCAs = []string{goodPath}

	s := newMinimalServer(t, cfg)
	_, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)

	bootstrapCert := s.unifiedTLS.cert.Load()
	require.NotNil(t, bootstrapCert)
	originalPool := s.unifiedTLS.clientCAs.Load()
	require.NotNil(t, originalPool)
	_, err = goodCert.Verify(x509.VerifyOptions{Roots: originalPool})
	require.NoError(t, err)

	badPath := filepath.Join(dir, "bad-client-ca.pem")
	require.NoError(t, os.WriteFile(badPath, []byte("not a pem"), 0o600))
	s.config.TLS.ClientCAs = []string{badPath}

	tlsCert, _ := generateSelfSignedCert(t)
	mock := &mockTrustedCA{initialized: true, tlsCert: tlsCert}
	s.ca = mock

	err = s.upgradeUnifiedTLSCert(mock)
	require.Error(t, err, "a malformed client_cas file must surface an error, not be dropped silently")

	var parseErr *ErrCertParse
	require.True(t, errors.As(err, &parseErr), "expected *ErrCertParse, got %T (%v)", err, err)

	assert.Same(t, bootstrapCert, s.unifiedTLS.cert.Load(),
		"the bootstrap certificate must keep serving when the upgrade fails outright")
	assert.Same(t, originalPool, s.unifiedTLS.clientCAs.Load(),
		"the previously installed client-CA pool must survive a failed upgrade")
}

// TestUpgradeUnifiedTLSCert_BundleUnavailable_LogsAndStillUpgradesCertificate
// proves the softer failure mode: a CA-bundle fetch failure (the CA composed
// but its bundle is momentarily unavailable) degrades only the client-CA
// pool -- logged via unifiedClientCAPool's typed *ErrTLSCertOp, not dropped
// silently -- while the CA-issued server certificate still installs, per the
// documented "reported to the caller for logging" contract.
func TestUpgradeUnifiedTLSCert_BundleUnavailable_LogsAndStillUpgradesCertificate(t *testing.T) {
	cfg := buildRESTConfigTLSTestCfg()
	cfg.Datastore.Path = t.TempDir()

	s := newMinimalServer(t, cfg)
	_, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)

	var logBuf bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logBuf, nil))

	tlsCert, _ := generateSelfSignedCert(t)
	mock := &mockTrustedCA{initialized: true, tlsCert: tlsCert, caBundleErr: errBundleUnavailable}
	s.ca = mock

	require.NoError(t, s.upgradeUnifiedTLSCert(mock),
		"a CA-bundle fetch failure must degrade only the client-CA pool, not the certificate upgrade")

	installed := s.unifiedTLS.cert.Load()
	require.NotNil(t, installed)
	assert.Equal(t, tlsCert.Certificate[0], installed.Certificate[0],
		"the CA-issued certificate must still install despite the bundle failure")

	logged := logBuf.String()
	assert.Contains(t, logged, "client-CA pool not upgraded",
		"the bundle failure must be logged, not silently dropped")
}
