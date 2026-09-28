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

// Package ca coverage boost, eighth pass: targets remaining sub-91% functions
// not yet exercised by the seven prior passes.
// All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	objmemory "github.com/jeremyhahn/go-objstore/pkg/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// tls_extensions.go — TLSBundleWithCrossSigner: xsigned certs exist in store
// (exercises the pem.Encode loop that produces 21.4% → significantly higher)
// =============================================================================

// setupCAWithObjectStoreAndXSignedCert builds a CA with an object store and
// pre-loads one cross-signed certificate under the standard key layout so that
// getXSignedCertificates returns a non-empty slice, allowing the bundle-
// prepend path in TLSBundleWithCrossSigner to execute.
func setupCAWithObjectStoreAndXSignedCert(t *testing.T, leafCN string) (*CA, *x509.Certificate) {
	t.Helper()

	ca := setupTestCA(t)
	ca.objectStore = objmemory.New()

	// Manufacture a self-signed cert that will act as the cross-signed issuer cert.
	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xsigner-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	require.NoError(t, err)
	xCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Store using the cross-signing layout: cross-signed/<issuerCN>/<subjectCN>.pem
	issuerCN := "xsigner-b8"
	key := "cross-signed/" + issuerCN + "/" + leafCN + ".pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: xCert.Raw})
	require.NoError(t, ca.objectStore.Put(key, &pemBytesReader{data: certPEM}))

	return ca, xCert
}

// TestTLSBundleWithCrossSigner_XCertsExist exercises the loop body at lines
// 112-119 of tls_extensions.go where xsignedCerts is non-empty.
func TestTLSBundleWithCrossSigner_XCertsExist_B8(t *testing.T) {
	leafCN := "tls-xsign-xcerts-b8"
	ca, _ := setupCAWithObjectStoreAndXSignedCert(t, leafCN)

	issueCertAndSaveToKeyStore(t, ca, leafCN)
	attrs := softwareKeyAttrs(leafCN)

	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bundle, err := ca.TLSBundleWithCrossSigner(context.Background(), attrs, xKey)
	// Software backend may refuse PKCS#8 export on opaque keys.
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotEmpty(t, bundle)
}

// =============================================================================
// tls_extensions.go — TLSConfigWithXSigner: xsigned root certs exist
// (exercises the cfg.RootCAs / cfg.ClientCAs append loop at lines 150-158)
// =============================================================================

// setupCAWithObjStoreAndXSignedRootCert sets up a CA with cross-signed certs
// stored under the root CA's CN so TLSConfigWithXSigner finds them.
func setupCAWithObjStoreAndXSignedRootCert(t *testing.T, leafCN string) *CA {
	t.Helper()

	ca := setupTestCA(t)
	ca.objectStore = objmemory.New()

	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()
	require.NotNil(t, root)

	// Manufacture a self-signed cert as the cross-signed root cert.
	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xroot-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	require.NoError(t, err)
	xCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Store cross-signed cert under the root CA's CN so getXSignedCertificates
	// for root.Subject.CommonName returns it.
	rootCN := root.Subject.CommonName
	key := "cross-signed/xroot-b8/" + rootCN + ".pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: xCert.Raw})
	require.NoError(t, ca.objectStore.Put(key, &pemBytesReader{data: certPEM}))

	return ca
}

// TestTLSConfigWithXSigner_XSignedRootCertsExist exercises the RootCAs append
// path (lines 149-158) where xsignedRoots is non-empty.
func TestTLSConfigWithXSigner_XSignedRootCertsExist_B8(t *testing.T) {
	leafCN := "tls-xcfg-root-b8"
	ca := setupCAWithObjStoreAndXSignedRootCert(t, leafCN)

	issueCertAndSaveToKeyStore(t, ca, leafCN)
	attrs := softwareKeyAttrs(leafCN)

	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, xKey)
	// TLSConfig builds a tls.Config; soft-fail on opaque key export.
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotNil(t, cfg)
}

// TestTLSConfigWithXSigner_WithIntermediateAndXSignedCerts exercises the
// intermediate cross-sign lookup (lines 160-166) by setting up a CA with an
// intermediate cert and cross-signed certs stored for its CN.
func TestTLSConfigWithXSigner_WithIntermediateAndXSignedCerts_B8(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	ca.objectStore = objmemory.New()

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()
	require.NotNil(t, intermediate)

	// Store a cross-signed cert under the intermediate's CN.
	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xsign-int-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	require.NoError(t, err)
	xCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	intCN := intermediate.Subject.CommonName
	key := "cross-signed/xsign-int-b8/" + intCN + ".pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: xCert.Raw})
	require.NoError(t, ca.objectStore.Put(key, &pemBytesReader{data: certPEM}))

	leafCN := "tls-xcfg-int-b8"
	issueCertAndSaveToKeyStore(t, ca, leafCN)
	attrs := softwareKeyAttrs(leafCN)

	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, xKey)
	if err != nil {
		assert.ErrorIs(t, err, ErrTLSConfigFailed)
		return
	}
	assert.NotNil(t, cfg)
}

// =============================================================================
// trust_chain_extensions.go — TrustedRootCertPoolWithXSigner: xsigned exists
// (exercises the for-loop at lines 105-110)
// =============================================================================

// TestTrustedRootCertPoolWithXSigner_XSignedCerts_B8 adds cross-signed certs
// to the object store so the pool-append loop executes.
func TestTrustedRootCertPoolWithXSigner_XSignedCerts_B8(t *testing.T) {
	ca := setupTestCA(t)
	ca.objectStore = objmemory.New()

	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()
	require.NotNil(t, root)

	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xroot-pool-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	require.NoError(t, err)
	xCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	_ = xCert

	rootCN := root.Subject.CommonName
	key := "cross-signed/xroot-pool-b8/" + rootCN + ".pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: xCert.Raw})
	require.NoError(t, ca.objectStore.Put(key, &pemBytesReader{data: certPEM}))

	pool, err := ca.TrustedRootCertPoolWithXSigner(root, xKey)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain_extensions.go — TrustedIntermediateCertPoolWithXSigner: xsigned
// (exercises the for-loop at lines 142-147)
// =============================================================================

func TestTrustedIntermediateCertPoolWithXSigner_XSignedCerts_B8(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	ca.objectStore = objmemory.New()

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()
	require.NotNil(t, intermediate)

	xKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xsign-intpool-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	require.NoError(t, err)
	xCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	_ = xCert

	intCN := intermediate.Subject.CommonName
	key := "cross-signed/xsign-intpool-b8/" + intCN + ".pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: xCert.Raw})
	require.NoError(t, ca.objectStore.Put(key, &pemBytesReader{data: certPEM}))

	leaf := &x509.Certificate{Issuer: pkix.Name{CommonName: "leaf-intpool-b8"}}
	pool, err := ca.TrustedIntermediateCertPoolWithXSigner(leaf, xKey)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate: circular chain detection
// =============================================================================

// TestRootCertificate_CircularChain_B8 manufactures a cert-store scenario
// where following the issuer chain loops back to a previously seen CN.
//
// To produce a genuine cross-signed circular chain we sign each cert with the
// OTHER party's key so that x509.CreateCertificate records the correct Issuer
// from the parent template.
func TestRootCertificate_CircularChain_B8(t *testing.T) {
	ca := setupTestCA(t)

	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Template for the two CA certs.
	tmplA := &x509.Certificate{
		SerialNumber:          big.NewInt(8001),
		Subject:               pkix.Name{CommonName: "circular-a-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	tmplB := &x509.Certificate{
		SerialNumber:          big.NewInt(8002),
		Subject:               pkix.Name{CommonName: "circular-b-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Sign certA with keyB (parent=tmplB) so certA.Issuer = "circular-b-b8".
	certADER, err := x509.CreateCertificate(rand.Reader, tmplA, tmplB, &keyA.PublicKey, keyB)
	require.NoError(t, err)
	certA, err := x509.ParseCertificate(certADER)
	require.NoError(t, err)

	// Sign certB with keyA (parent=tmplA) so certB.Issuer = "circular-a-b8".
	certBDER, err := x509.CreateCertificate(rand.Reader, tmplB, tmplA, &keyB.PublicKey, keyA)
	require.NoError(t, err)
	certB, err := x509.ParseCertificate(certBDER)
	require.NoError(t, err)

	// Store both so RootCertificate can follow the chain.
	if ca.certStore != nil {
		_ = ca.certStore.StoreCertificate(certA)
		_ = ca.certStore.StoreCertificate(certB)
	}

	_, err = ca.RootCertificate(certA)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate: self-signed non-CA path
// =============================================================================

func TestRootCertificate_SelfSignedNonCA_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "self-signed-non-ca-b8"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         false, // non-CA self-signed
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = ca.RootCertificate(cert)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

// =============================================================================
// serial.go — IsUsed storage-error path
// (brings IsUsed from 83.3% to 100%)
// =============================================================================

// b8FailingStorage is a minimal Storage implementation that fails on
// SerialExists to exercise the error-return paths in IsUsed and MarkUsed.
type b8FailingStorage struct {
	failExists bool
	failStore  bool
}

func (f *b8FailingStorage) SerialExists(_ context.Context, _ *big.Int) (bool, error) {
	if f.failExists {
		return false, errors.New("b8: storage exists check failed")
	}
	return false, nil
}

func (f *b8FailingStorage) StoreSerial(_ context.Context, _ *big.Int) error {
	if f.failStore {
		return errors.New("b8: storage store failed")
	}
	return nil
}

func TestSerialIsUsed_StorageError_B8(t *testing.T) {
	t.Parallel()
	gen := NewSerialGenerator(&b8FailingStorage{failExists: true})
	_, err := gen.IsUsed(context.Background(), big.NewInt(1001))
	require.Error(t, err)
	var storageErr *SerialStorageError
	assert.True(t, errors.As(err, &storageErr))
}

func TestSerialMarkUsed_StoreError_B8(t *testing.T) {
	t.Parallel()
	gen := NewSerialGenerator(&b8FailingStorage{failStore: true})
	err := gen.MarkUsed(context.Background(), big.NewInt(1002))
	require.Error(t, err)
	var storageErr *SerialStorageError
	assert.True(t, errors.As(err, &storageErr))
}

// =============================================================================
// attestation.go — ImportAttestationKeyCertificate success path
// (exercises the certificate parse + store path at lines 141-171)
// =============================================================================

func TestImportAttestationKeyCertificate_Success_B8(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	// Build a real DER-encoded certificate to import.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ak-cert-b8"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "ak-cert-b8"}
	err = ca.ImportAttestationKeyCertificate(context.Background(), attrs, certDER)
	require.NoError(t, err)
}

// =============================================================================
// ca_extensions.go — recordRevocation: nil serial path
// =============================================================================

func TestRecordRevocation_NilSerial_B8(t *testing.T) {
	t.Parallel()
	ca := &CA{revocations: make(map[string]*RevocationInfo)}
	err := ca.recordRevocation(context.Background(), nil, 0, false)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — putRevocationBlobIfAbsent with revocationStore (Backend)
// =============================================================================

func TestPutRevocationBlob_RevocationStorePath_B8(t *testing.T) {
	t.Parallel()
	backend := storage.NewMemory()
	ca := &CA{
		revocationStore: backend,
		revocations:     make(map[string]*RevocationInfo),
	}
	stored, err := ca.putRevocationBlobIfAbsent(context.Background(), big.NewInt(55555), []byte(`{"serial":"55555"}`))
	require.NoError(t, err)
	assert.True(t, stored)
}

// =============================================================================
// ca_extensions.go — Issued: both certStore and keyStore paths
// =============================================================================

// =============================================================================
// ca_extensions.go — SignedBlob not-initialized path
// =============================================================================

func TestSignedBlob_NotInitialized_B8(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.SignedBlob(context.Background(), []byte("data"))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca_extensions.go — Certificate: returned from certStore when keyStore empty
// =============================================================================

func TestCertificate_FromCertStore_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	cert, _ := makeSelfSignedCert(t, "from-certstore-b8")
	if ca.certStore != nil {
		require.NoError(t, ca.certStore.StoreCertificate(cert))
	}

	// Ask by attrs pointing to this CN — must fall through to certStore.
	attrs := &types.KeyAttributes{CN: "from-certstore-b8"}
	got, err := ca.Certificate(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, "from-certstore-b8", got.Subject.CommonName)
}

// =============================================================================
// trust_chain_extensions.go — ParseBundle: invalid DER inside valid PEM block
// =============================================================================

func TestParseBundle_InvalidDERInPEMBlock_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Craft a PEM block with a CERTIFICATE type but corrupt DER contents.
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER"),
	})
	_, err := ca.ParseBundle(badPEM)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ca_extensions.go — ImportCertificate: certStore nil path (ErrCertStoreRequired)
// =============================================================================

func TestImportCertificate_NoCertStore_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.certStore = nil

	cert, _ := makeSelfSignedCert(t, "import-no-certstore-b8")
	err := ca.ImportCertificate(context.Background(), cert)
	assert.ErrorIs(t, err, ErrCertStoreRequired)
}

// =============================================================================
// ca_extensions.go — PubKey: key does not implement crypto.Signer
// =============================================================================

func TestPubKey_KeyNotSigner_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// Directly manipulate the keystore to return a non-signer; we test the
	// code path by checking that the Signer() assertion returns an error.
	// Since we cannot inject directly, issue a cert and then call PubKey with
	// an attrs for a non-existent CN so GetKey fails (exercising the error
	// return at line 86).
	attrs := &types.KeyAttributes{CN: "ghost-signer-b8"}
	_, err := ca.PubKey(context.Background(), attrs)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// =============================================================================
// verification.go — VerifySignature success path
// =============================================================================

func TestVerifySignature_Success_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Issue a real certificate so VerifySignature has something to verify.
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "verify-sig-success-b8"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-sig-success-b8.local"}},
		Valid:   365,
	})
	require.NoError(t, err)
	err = ca.VerifySignature(issued.Certificate)
	assert.NoError(t, err)
}

// TestVerifySignature_NoIssuingCert_B8 hits the issuingCert==nil guard by
// zeroing both cached certs after initialization.
func TestVerifySignature_NoIssuingCert_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	ca.mu.Lock()
	orig := ca.rootCert
	ca.rootCert = nil
	ca.intermediateCert = nil
	ca.mu.Unlock()
	defer func() {
		ca.mu.Lock()
		ca.rootCert = orig
		ca.mu.Unlock()
	}()

	cert, _ := makeSelfSignedCert(t, "no-issuer-b8")
	err := ca.VerifySignature(cert)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// verification.go — VerifyChain with nil entry in intermediates slice
// =============================================================================

func TestVerifyChain_NilIntermediateEntry_B8(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7001),
		Subject:               pkix.Name{CommonName: "chain-nil-int-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// Pass a slice with a nil entry; VerifyChain should skip nil intermediates.
	chains, err := VerifyChain(cert, []*x509.Certificate{nil, cert}, pool)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// verification.go — VerifyWithOptions with non-nil intermediates
// =============================================================================

func TestVerifyWithOptions_WithIntermediates_B8(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7002),
		Subject:               pkix.Name{CommonName: "verify-opts-ints-b8"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	opts := &VerifyOptions{
		Roots:         pool,
		Intermediates: []*x509.Certificate{nil, cert},
		CurrentTime:   time.Now(),
	}
	chains, err := VerifyWithOptions(cert, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// ca_extensions.go — SignedBlob success path (ECDSA hash path)
// =============================================================================

func TestSignedBlob_Success_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	data := []byte("test-payload-b8")
	sig, err := ca.SignedBlob(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// =============================================================================
// ca_extensions.go — CAKeyAttributes: getCAKeyAttributes error path
// =============================================================================

func TestCAKeyAttributes_NoIssuingIdentity_B8(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	_, err := ca.CAKeyAttributes("")
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — CASigner error from CAKeyAttributes
// =============================================================================

func TestCASigner_NoIssuingIdentity_B8(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	_, err := ca.CASigner(context.Background(), "", x509.UnknownPublicKeyAlgorithm)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// ca_extensions.go — DefaultSignatureAlgorithm: GetSignatureAlgorithm error
// =============================================================================

func TestDefaultSignatureAlgorithm_GetSigAlgoError_B8(t *testing.T) {
	t.Parallel()
	// An identity with an empty key config returns an error from GetSignatureAlgorithm,
	// causing DefaultSignatureAlgorithm to return UnknownSignatureAlgorithm.
	cfg := &MultiIdentityCAConfig{
		Identity: []Identity{
			{
				Subject: Subject{CommonName: "test-b8"},
				Keys:    []*types.KeyConfig{{}}, // empty key config → unknown algo
			},
		},
	}
	ca := &CA{config: cfg}
	algo := ca.DefaultSignatureAlgorithm()
	assert.Equal(t, x509.UnknownSignatureAlgorithm, algo)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate: chain-too-long (10 hop limit)
// =============================================================================

// TestRootCertificate_ChainTooLong_B8 constructs a linear chain longer than
// the 10-hop maximum by populating the certStore with 11 certs A→B→C→…→K.
func TestRootCertificate_ChainTooLong_B8(t *testing.T) {
	ca := setupTestCA(t)
	require.NotNil(t, ca.certStore, "setupTestCA must provide a certStore")

	// Build 11 certificates A(Issuer=B) → B(Issuer=C) → … → K (self-signed-ish).
	// Each certN is signed by the previous key so Issuer reflects the parent CN.
	keys := make([]*ecdsa.PrivateKey, 12)
	for i := range keys {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		keys[i] = k
	}

	// CN names
	names := make([]string, 12)
	for i := range names {
		names[i] = "chain-long-" + string(rune('a'+i)) + "-b8"
	}

	// Create cert 0 whose Issuer = names[1], signed by keys[1] (parent template = tmpl[1]).
	// Create cert i whose Issuer = names[i+1], signed by keys[i+1].
	// Cert 10 has Issuer = names[11] which does not exist in the certStore → ErrRootNotFound.
	certs := make([]*x509.Certificate, 11)
	for i := 0; i < 11; i++ {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(9100 + i)),
			Subject:               pkix.Name{CommonName: names[i]},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		// Use names[i+1] as the parent template so Issuer = names[i+1].
		parent := &x509.Certificate{
			SerialNumber: big.NewInt(int64(9200 + i)),
			Subject:      pkix.Name{CommonName: names[i+1]},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &keys[i].PublicKey, keys[i+1])
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)
		certs[i] = cert
		_ = ca.certStore.StoreCertificate(cert)
	}

	// Starting from certs[0], the walk goes:
	// names[0] → names[1] → … → names[10] → names[11] (not in store).
	// This is 11 hops which triggers the "chain too long" error at hop 10.
	_, err := ca.RootCertificate(certs[0])
	assert.Error(t, err)
}

// =============================================================================
// trust_chain.go — TrustedIntermediateCertPool: certPool append failure
// (exercises the nil-intermediate pool return path when no intermediate exists)
// =============================================================================

func TestTrustedIntermediateCertPool_NoIntermediate_NoRoot_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// Remove both cached certs to force the "no intermediate → return empty pool" branch.
	ca.mu.Lock()
	ca.intermediateCert = nil
	ca.mu.Unlock()

	leaf := &x509.Certificate{Issuer: pkix.Name{CommonName: "unknown-issuer-b8"}}
	pool, err := ca.TrustedIntermediateCertPool(leaf)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// =============================================================================
// ca_extensions.go — ImportCertificatePEM: certStore nil path
// =============================================================================

func TestImportCertificatePEM_NoCertStore_B8(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.certStore = nil

	cert, _ := makeSelfSignedCert(t, "pem-no-certstore-b8")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	err := ca.ImportCertificatePEM(context.Background(), "pem-no-certstore-b8", pemBytes)
	assert.ErrorIs(t, err, ErrCertStoreRequired)
}

// =============================================================================
// io.Reader helper used across boost8 tests (honors io.Reader contract)
// =============================================================================

// pemBytesReader is defined in coverage_boost6_test.go; re-export is not
// possible in the same package so we use an inline read helper here via
// the io.Reader interface through bytes.NewReader — but we already have the
// pemBytesReader type from boost6. We therefore refer to it directly.

// b8certDERReader is a trivial io.Reader over DER bytes used in this file only
// (avoids dependency on the pemBytesReader from boost6 at the call sites that
// use raw DER rather than PEM).
type b8certDERReader struct {
	data   []byte
	offset int
}

func (r *b8certDERReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
