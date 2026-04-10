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

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// --- Mock trust store ---

// mockTrustStore implements truststore.TrustStore for testing purposes.
type mockTrustStore struct {
	certs    map[truststore.CertPurpose][]*x509.Certificate
	allCerts []*x509.Certificate
	err      error
	closed   bool
}

func newMockTrustStore() *mockTrustStore {
	return &mockTrustStore{
		certs: make(map[truststore.CertPurpose][]*x509.Certificate),
	}
}

func (m *mockTrustStore) addCertForPurpose(cert *x509.Certificate, purpose truststore.CertPurpose) {
	m.certs[purpose] = append(m.certs[purpose], cert)
	m.allCerts = append(m.allCerts, cert)
}

func (m *mockTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }

func (m *mockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return nil
}

func (m *mockTrustStore) AddPEM(_ []byte) (int, error) { return 0, nil }

func (m *mockTrustStore) RemoveCertificate(_ string) error { return nil }

func (m *mockTrustStore) Certificates() ([]*x509.Certificate, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make([]*x509.Certificate, len(m.allCerts))
	copy(result, m.allCerts)
	return result, nil
}

func (m *mockTrustStore) CertificatesByPurpose(purpose truststore.CertPurpose) ([]*x509.Certificate, error) {
	if m.err != nil {
		return nil, m.err
	}
	certs := m.certs[purpose]
	result := make([]*x509.Certificate, len(certs))
	copy(result, certs)
	return result, nil
}

func (m *mockTrustStore) CertPool() (*x509.CertPool, error) {
	if m.err != nil {
		return nil, m.err
	}
	pool := x509.NewCertPool()
	for _, cert := range m.allCerts {
		pool.AddCert(cert)
	}
	return pool, nil
}

func (m *mockTrustStore) Contains(_ string) (bool, error) { return false, nil }

func (m *mockTrustStore) Count() (int, error) { return len(m.allCerts), nil }

func (m *mockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) {
	return nil, nil
}

func (m *mockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }

func (m *mockTrustStore) SetSource(_ string, _ string) error { return nil }

func (m *mockTrustStore) SetSystemInstalled(_ string, _ bool) error { return nil }

func (m *mockTrustStore) SetTags(_ string, _ []string) error { return nil }

func (m *mockTrustStore) Close() error { return nil }

// --- Test certificate helpers ---

// testCA holds a CA certificate and its signing key for generating leaf certs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// generateTestCA creates a self-signed CA certificate.
func generateTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// generateIntermediateCA creates an intermediate CA signed by the parent CA.
func generateIntermediateCA(t *testing.T, parent *testCA, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("failed to create intermediate CA: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate CA: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// generateLeafCert creates a leaf (end-entity) certificate signed by a CA.
func generateLeafCert(t *testing.T, signer *testCA, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return cert
}

// --- NewVerifier tests ---

func TestNewVerifier_Success(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("NewVerifier() returned nil verifier")
	}
}

func TestNewVerifier_NilStore(t *testing.T) {
	v, err := NewVerifier(nil, nil)
	if !errors.Is(err, ErrNilTrustStore) {
		t.Errorf("NewVerifier(nil) error = %v, want %v", err, ErrNilTrustStore)
	}
	if v != nil {
		t.Error("NewVerifier(nil) returned non-nil verifier")
	}
}

// --- VerifyTPMAttestation tests ---

func TestVerifyTPMAttestation_Success(t *testing.T) {
	rootCA := generateTestCA(t, "TPM Manufacturer Root CA")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeTPMManufacturer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ekCert := generateLeafCert(t, rootCA, "TPM EK Certificate")

	result, err := v.VerifyTPMAttestation(ekCert)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("VerifyTPMAttestation() Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelHardware {
		t.Errorf("VerifyTPMAttestation() TrustLevel = %q, want %q", result.TrustLevel, TrustLevelHardware)
	}
	if result.ChainLength < 1 {
		t.Errorf("VerifyTPMAttestation() ChainLength = %d, want >= 1", result.ChainLength)
	}
}

func TestVerifyTPMAttestation_WithEmbeddedRoots(t *testing.T) {
	rootCA := generateTestCA(t, "Embedded TPM Root CA")

	// Store is empty; embedded loader provides the root.
	store := newMockTrustStore()
	loader := func(purpose truststore.CertPurpose) []*x509.Certificate {
		if purpose == truststore.PurposeTPMManufacturer {
			return []*x509.Certificate{rootCA.cert}
		}
		return nil
	}

	v, err := NewVerifier(store, loader)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ekCert := generateLeafCert(t, rootCA, "TPM EK via Embedded")

	result, err := v.VerifyTPMAttestation(ekCert)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("VerifyTPMAttestation() Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelHardware {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelHardware)
	}
}

func TestVerifyTPMAttestation_NilCert(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = v.VerifyTPMAttestation(nil)
	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("VerifyTPMAttestation(nil) error = %v, want %v", err, ErrNilCertificate)
	}
}

func TestVerifyTPMAttestation_NoAnchors(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	unrelatedCA := generateTestCA(t, "Unrelated CA")
	ekCert := generateLeafCert(t, unrelatedCA, "Orphan EK")

	_, err = v.VerifyTPMAttestation(ekCert)
	if !errors.Is(err, ErrNoTrustAnchors) {
		t.Errorf("VerifyTPMAttestation() error = %v, want %v", err, ErrNoTrustAnchors)
	}
}

func TestVerifyTPMAttestation_InvalidChain(t *testing.T) {
	trustedCA := generateTestCA(t, "Trusted TPM CA")
	untrustedCA := generateTestCA(t, "Untrusted CA")

	store := newMockTrustStore()
	store.addCertForPurpose(trustedCA.cert, truststore.PurposeTPMManufacturer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	// Leaf signed by untrusted CA, not by the one in the store.
	ekCert := generateLeafCert(t, untrustedCA, "Wrong Issuer EK")

	result, err := v.VerifyTPMAttestation(ekCert)
	if !errors.Is(err, ErrChainVerification) {
		t.Errorf("VerifyTPMAttestation() error = %v, want %v", err, ErrChainVerification)
	}
	if result == nil {
		t.Fatal("VerifyTPMAttestation() returned nil result on failure")
	}
	if result.Verified {
		t.Error("VerifyTPMAttestation() Verified = true, want false")
	}
}

func TestVerifyTPMAttestation_StoreError(t *testing.T) {
	storeErr := errors.New("store is broken")
	store := newMockTrustStore()
	store.err = storeErr

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ca := generateTestCA(t, "Some CA")
	ekCert := generateLeafCert(t, ca, "EK")

	_, err = v.VerifyTPMAttestation(ekCert)
	if !errors.Is(err, ErrTrustStoreQuery) {
		t.Errorf("VerifyTPMAttestation() error = %v, want %v", err, ErrTrustStoreQuery)
	}
}

// --- VerifyAndroidAttestation tests ---

func TestVerifyAndroidAttestation_Success(t *testing.T) {
	rootCA := generateTestCA(t, "Google Hardware Attestation Root")
	intermediateCA := generateIntermediateCA(t, rootCA, "Google Attestation Intermediate")
	leaf := generateLeafCert(t, intermediateCA, "Android Key")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, intermediateCA.cert, rootCA.cert}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelHardware {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelHardware)
	}
}

func TestVerifyAndroidAttestation_TwoCertChain(t *testing.T) {
	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateLeafCert(t, rootCA, "Android Leaf")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, rootCA.cert}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
}

func TestVerifyAndroidAttestation_EmptyChain(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = v.VerifyAndroidAttestation(nil, nil)
	if !errors.Is(err, ErrEmptyCertChain) {
		t.Errorf("VerifyAndroidAttestation(nil) error = %v, want %v", err, ErrEmptyCertChain)
	}

	_, err = v.VerifyAndroidAttestation([]*x509.Certificate{}, nil)
	if !errors.Is(err, ErrEmptyCertChain) {
		t.Errorf("VerifyAndroidAttestation([]) error = %v, want %v", err, ErrEmptyCertChain)
	}
}

func TestVerifyAndroidAttestation_SingleCert(t *testing.T) {
	// Single self-signed cert in a chain. The root is also the leaf.
	rootCA := generateTestCA(t, "Self-Signed Android Root")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{rootCA.cert}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
}

func TestVerifyAndroidAttestation_InvalidChain(t *testing.T) {
	trustedCA := generateTestCA(t, "Trusted Android CA")
	untrustedCA := generateTestCA(t, "Untrusted CA")

	store := newMockTrustStore()
	store.addCertForPurpose(trustedCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	leaf := generateLeafCert(t, untrustedCA, "Wrong Android Leaf")
	chain := []*x509.Certificate{leaf}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if !errors.Is(err, ErrChainVerification) {
		t.Errorf("error = %v, want %v", err, ErrChainVerification)
	}
	if result == nil {
		t.Fatal("returned nil result on failure")
	}
	if result.Verified {
		t.Error("Verified = true, want false")
	}
}

func TestVerifyAndroidAttestation_WithNonce(t *testing.T) {
	// Nonce is accepted but not yet verified (TODO for Android extension parsing).
	rootCA := generateTestCA(t, "Android Root CA")
	leaf := generateLeafCert(t, rootCA, "Android Leaf")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, rootCA.cert}
	nonce := []byte("test-nonce-value")

	result, err := v.VerifyAndroidAttestation(chain, nonce)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
}

// --- VerifyIDevID tests ---

func TestVerifyIDevID_Success(t *testing.T) {
	rootCA := generateTestCA(t, "IDevID Issuer Root CA")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeIDevIDIssuer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	idevidCert := generateLeafCert(t, rootCA, "Device IDevID")

	result, err := v.VerifyIDevID(idevidCert)
	if err != nil {
		t.Fatalf("VerifyIDevID() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelHardware {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelHardware)
	}
}

func TestVerifyIDevID_NilCert(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = v.VerifyIDevID(nil)
	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("VerifyIDevID(nil) error = %v, want %v", err, ErrNilCertificate)
	}
}

func TestVerifyIDevID_InvalidChain(t *testing.T) {
	trustedCA := generateTestCA(t, "Trusted IDevID Issuer")
	untrustedCA := generateTestCA(t, "Untrusted CA")

	store := newMockTrustStore()
	store.addCertForPurpose(trustedCA.cert, truststore.PurposeIDevIDIssuer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	cert := generateLeafCert(t, untrustedCA, "Wrong IDevID")

	result, err := v.VerifyIDevID(cert)
	if !errors.Is(err, ErrChainVerification) {
		t.Errorf("error = %v, want %v", err, ErrChainVerification)
	}
	if result == nil {
		t.Fatal("returned nil result on failure")
	}
	if result.Verified {
		t.Error("Verified = true, want false")
	}
}

func TestVerifyIDevID_NoAnchors(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ca := generateTestCA(t, "Some CA")
	cert := generateLeafCert(t, ca, "Orphan IDevID")

	_, err = v.VerifyIDevID(cert)
	if !errors.Is(err, ErrNoTrustAnchors) {
		t.Errorf("error = %v, want %v", err, ErrNoTrustAnchors)
	}
}

// --- VerifyChain tests ---

func TestVerifyChain_Success(t *testing.T) {
	rootCA := generateTestCA(t, "User CA Root")
	intermediateCA := generateIntermediateCA(t, rootCA, "User CA Intermediate")
	leaf := generateLeafCert(t, intermediateCA, "User Leaf")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeUserCA)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, intermediateCA.cert}

	result, err := v.VerifyChain(chain, truststore.PurposeUserCA)
	if err != nil {
		t.Fatalf("VerifyChain() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelExternalCA {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelExternalCA)
	}
}

func TestVerifyChain_EmptyChain(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = v.VerifyChain(nil, truststore.PurposeGeneral)
	if !errors.Is(err, ErrEmptyCertChain) {
		t.Errorf("VerifyChain(nil) error = %v, want %v", err, ErrEmptyCertChain)
	}

	_, err = v.VerifyChain([]*x509.Certificate{}, truststore.PurposeGeneral)
	if !errors.Is(err, ErrEmptyCertChain) {
		t.Errorf("VerifyChain([]) error = %v, want %v", err, ErrEmptyCertChain)
	}
}

func TestVerifyChain_UnsupportedPurpose(t *testing.T) {
	store := newMockTrustStore()
	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ca := generateTestCA(t, "CA")
	leaf := generateLeafCert(t, ca, "Leaf")

	_, err = v.VerifyChain([]*x509.Certificate{leaf}, truststore.CertPurpose("invalid-purpose"))
	if !errors.Is(err, ErrUnsupportedPurpose) {
		t.Errorf("VerifyChain() error = %v, want %v", err, ErrUnsupportedPurpose)
	}
}

func TestVerifyChain_SingleLeafInStore(t *testing.T) {
	rootCA := generateTestCA(t, "Bootstrap CA Root")
	leaf := generateLeafCert(t, rootCA, "Bootstrap Leaf")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeBootstrapCA)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf}

	result, err := v.VerifyChain(chain, truststore.PurposeBootstrapCA)
	if err != nil {
		t.Fatalf("VerifyChain() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.TrustLevel != TrustLevelExternalCA {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelExternalCA)
	}
}

func TestVerifyChain_InvalidChain(t *testing.T) {
	trustedCA := generateTestCA(t, "Trusted CA")
	untrustedCA := generateTestCA(t, "Untrusted CA")

	store := newMockTrustStore()
	store.addCertForPurpose(trustedCA.cert, truststore.PurposeGeneral)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	leaf := generateLeafCert(t, untrustedCA, "Wrong Leaf")
	chain := []*x509.Certificate{leaf}

	result, err := v.VerifyChain(chain, truststore.PurposeGeneral)
	if !errors.Is(err, ErrChainVerification) {
		t.Errorf("error = %v, want %v", err, ErrChainVerification)
	}
	if result == nil {
		t.Fatal("returned nil result on failure")
	}
	if result.Verified {
		t.Error("Verified = true, want false")
	}
}

// --- buildTrustPool tests ---

func TestBuildTrustPool_MergesStoreAndEmbedded(t *testing.T) {
	storeCA := generateTestCA(t, "Store Root CA")
	embeddedCA := generateTestCA(t, "Embedded Root CA")

	store := newMockTrustStore()
	store.addCertForPurpose(storeCA.cert, truststore.PurposeTPMManufacturer)

	loader := func(purpose truststore.CertPurpose) []*x509.Certificate {
		if purpose == truststore.PurposeTPMManufacturer {
			return []*x509.Certificate{embeddedCA.cert}
		}
		return nil
	}

	v, err := NewVerifier(store, loader)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	// Verify a cert signed by the store CA.
	storeLeaf := generateLeafCert(t, storeCA, "Store Leaf")
	result, err := v.VerifyTPMAttestation(storeLeaf)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation(storeLeaf) error: %v", err)
	}
	if !result.Verified {
		t.Error("store-signed leaf: Verified = false, want true")
	}

	// Verify a cert signed by the embedded CA.
	embeddedLeaf := generateLeafCert(t, embeddedCA, "Embedded Leaf")
	result, err = v.VerifyTPMAttestation(embeddedLeaf)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation(embeddedLeaf) error: %v", err)
	}
	if !result.Verified {
		t.Error("embedded-signed leaf: Verified = false, want true")
	}
}

func TestBuildTrustPool_EmptyStoreWithLoader(t *testing.T) {
	embeddedCA := generateTestCA(t, "Embedded Only Root")

	store := newMockTrustStore()

	loader := func(purpose truststore.CertPurpose) []*x509.Certificate {
		if purpose == truststore.PurposeAndroidHardware {
			return []*x509.Certificate{embeddedCA.cert}
		}
		return nil
	}

	v, err := NewVerifier(store, loader)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	leaf := generateLeafCert(t, embeddedCA, "Embedded-Only Leaf")
	chain := []*x509.Certificate{leaf}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
}

func TestBuildTrustPool_NoAnchors(t *testing.T) {
	store := newMockTrustStore()

	// Loader returns nothing for the requested purpose.
	loader := func(_ truststore.CertPurpose) []*x509.Certificate {
		return nil
	}

	v, err := NewVerifier(store, loader)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ca := generateTestCA(t, "Orphan CA")
	cert := generateLeafCert(t, ca, "Orphan Leaf")

	_, err = v.VerifyTPMAttestation(cert)
	if !errors.Is(err, ErrNoTrustAnchors) {
		t.Errorf("error = %v, want %v", err, ErrNoTrustAnchors)
	}
}

func TestBuildTrustPool_StoreError(t *testing.T) {
	storeErr := errors.New("database connection lost")
	store := newMockTrustStore()
	store.err = storeErr

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ca := generateTestCA(t, "Some CA")
	cert := generateLeafCert(t, ca, "Leaf")

	_, err = v.VerifyIDevID(cert)
	if !errors.Is(err, ErrTrustStoreQuery) {
		t.Errorf("error = %v, want %v", err, ErrTrustStoreQuery)
	}
}

// --- Purpose trust level mapping tests ---

func TestPurposeTrustLevels(t *testing.T) {
	tests := []struct {
		purpose truststore.CertPurpose
		want    TrustLevel
	}{
		{truststore.PurposeTPMManufacturer, TrustLevelHardware},
		{truststore.PurposeAndroidHardware, TrustLevelHardware},
		{truststore.PurposeIDevIDIssuer, TrustLevelHardware},
		{truststore.PurposeUserCA, TrustLevelExternalCA},
		{truststore.PurposeBootstrapCA, TrustLevelExternalCA},
		{truststore.PurposeGeneral, TrustLevelUnknown},
	}

	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			got, ok := purposeTrustLevels[tt.purpose]
			if !ok {
				t.Fatalf("purposeTrustLevels[%q] not found", tt.purpose)
			}
			if got != tt.want {
				t.Errorf("purposeTrustLevels[%q] = %q, want %q", tt.purpose, got, tt.want)
			}
		})
	}
}

// --- VerificationResult field tests ---

func TestVerificationResult_FailureFields(t *testing.T) {
	trustedCA := generateTestCA(t, "Trusted CA")
	untrustedCA := generateTestCA(t, "Untrusted CA")

	store := newMockTrustStore()
	store.addCertForPurpose(trustedCA.cert, truststore.PurposeTPMManufacturer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ekCert := generateLeafCert(t, untrustedCA, "Bad EK Cert")

	result, _ := v.VerifyTPMAttestation(ekCert)
	if result == nil {
		t.Fatal("expected non-nil result on verification failure")
	}
	if result.Verified {
		t.Error("Verified = true, want false")
	}
	if result.TrustLevel != TrustLevelUnknown {
		t.Errorf("TrustLevel = %q, want %q", result.TrustLevel, TrustLevelUnknown)
	}
	if result.Subject == "" {
		t.Error("Subject is empty, want non-empty")
	}
	if result.Issuer == "" {
		t.Error("Issuer is empty, want non-empty")
	}
	if result.Message == "" {
		t.Error("Message is empty, want non-empty failure message")
	}
}

func TestVerificationResult_SuccessFields(t *testing.T) {
	rootCA := generateTestCA(t, "Good Root CA")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeTPMManufacturer)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	ekCert := generateLeafCert(t, rootCA, "Good EK")

	result, err := v.VerifyTPMAttestation(ekCert)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation() error: %v", err)
	}
	if result.Subject == "" {
		t.Error("Subject is empty, want non-empty")
	}
	if result.Issuer == "" {
		t.Error("Issuer is empty, want non-empty")
	}
	if result.Message == "" {
		t.Error("Message is empty, want non-empty success message")
	}
	if result.ChainLength < 2 {
		t.Errorf("ChainLength = %d, want >= 2 (leaf + root)", result.ChainLength)
	}
}

// --- Multi-level chain tests ---

func TestVerifyChain_ThreeLevelChain(t *testing.T) {
	rootCA := generateTestCA(t, "Root CA")
	intermediateCA := generateIntermediateCA(t, rootCA, "Intermediate CA")
	leaf := generateLeafCert(t, intermediateCA, "End Entity")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeUserCA)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, intermediateCA.cert}

	result, err := v.VerifyChain(chain, truststore.PurposeUserCA)
	if err != nil {
		t.Fatalf("VerifyChain() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.ChainLength < 3 {
		t.Errorf("ChainLength = %d, want >= 3 (leaf + intermediate + root)", result.ChainLength)
	}
}

func TestVerifyAndroidAttestation_ThreeLevelChain(t *testing.T) {
	rootCA := generateTestCA(t, "Android Root")
	intermediateCA := generateIntermediateCA(t, rootCA, "Android Intermediate")
	leaf := generateLeafCert(t, intermediateCA, "Android Key Leaf")

	store := newMockTrustStore()
	store.addCertForPurpose(rootCA.cert, truststore.PurposeAndroidHardware)

	v, err := NewVerifier(store, nil)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	chain := []*x509.Certificate{leaf, intermediateCA.cert, rootCA.cert}

	result, err := v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.ChainLength < 3 {
		t.Errorf("ChainLength = %d, want >= 3", result.ChainLength)
	}
}

// --- Embedded loader only for specific purposes ---

func TestEmbeddedLoader_PurposeFiltering(t *testing.T) {
	tpmCA := generateTestCA(t, "Embedded TPM CA")
	androidCA := generateTestCA(t, "Embedded Android CA")

	store := newMockTrustStore()

	loader := func(purpose truststore.CertPurpose) []*x509.Certificate {
		purposeRoots := map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {tpmCA.cert},
			truststore.PurposeAndroidHardware: {androidCA.cert},
		}
		return purposeRoots[purpose]
	}

	v, err := NewVerifier(store, loader)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	// TPM leaf should verify against TPM embedded root.
	tpmLeaf := generateLeafCert(t, tpmCA, "TPM Leaf")
	result, err := v.VerifyTPMAttestation(tpmLeaf)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("TPM verification: Verified = false, want true")
	}

	// Android leaf should verify against Android embedded root.
	androidLeaf := generateLeafCert(t, androidCA, "Android Leaf")
	chain := []*x509.Certificate{androidLeaf}
	result, err = v.VerifyAndroidAttestation(chain, nil)
	if err != nil {
		t.Fatalf("VerifyAndroidAttestation() error: %v", err)
	}
	if !result.Verified {
		t.Error("Android verification: Verified = false, want true")
	}

	// TPM leaf should NOT verify as Android attestation.
	chain = []*x509.Certificate{tpmLeaf}
	result, err = v.VerifyAndroidAttestation(chain, nil)
	if err == nil {
		t.Error("VerifyAndroidAttestation(tpmLeaf) should fail")
	}
	if result != nil && result.Verified {
		t.Error("cross-purpose: Verified = true, want false")
	}
}
