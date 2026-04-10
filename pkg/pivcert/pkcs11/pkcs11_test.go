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

//go:build pkcs11

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// ---------------------------------------------------------------------------
// Mock HardwareCertStorage
// ---------------------------------------------------------------------------

// Compile-time interface check.
var _ hardware.HardwareCertStorage = (*mockHWCertStorage)(nil)

// mockHWCertStorage is an in-memory mock of hardware.HardwareCertStorage.
type mockHWCertStorage struct {
	mu     sync.RWMutex
	certs  map[string]*x509.Certificate
	chains map[string][]*x509.Certificate
	closed bool
}

func newMockHWCertStorage() *mockHWCertStorage {
	return &mockHWCertStorage{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
	}
}

func (m *mockHWCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[id] = cert
	return nil
}

func (m *mockHWCertStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return cert, nil
}

func (m *mockHWCertStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[id]; !ok {
		return errors.New("not found")
	}
	delete(m.certs, id)
	return nil
}

func (m *mockHWCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chains[id] = chain
	return nil
}

func (m *mockHWCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	chain, ok := m.chains[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return chain, nil
}

func (m *mockHWCertStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *mockHWCertStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.certs[id]
	return ok, nil
}

func (m *mockHWCertStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockHWCertStorage) GetCapacity() (int, int, error) {
	return 25, 25 - len(m.certs), nil
}

func (m *mockHWCertStorage) SupportsChains() bool {
	return true
}

func (m *mockHWCertStorage) IsHardwareBacked() bool {
	return true
}

func (m *mockHWCertStorage) Compact() error {
	return nil
}

// ---------------------------------------------------------------------------
// Test Certificate Helpers
// ---------------------------------------------------------------------------

// generateTestCert creates a self-signed ECDSA P-256 certificate for testing.
func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// generateRSATestCert creates a self-signed RSA certificate for testing.
func generateRSATestCert(t *testing.T, bits int) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "RSA Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create RSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse RSA certificate: %v", err)
	}

	return cert
}

// generateECDSATestCert creates a self-signed ECDSA certificate with a specific curve.
func generateECDSATestCert(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "ECDSA Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create ECDSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse ECDSA certificate: %v", err)
	}

	return cert
}

// newTestStorage creates a PKCS11CertStorage backed by the in-memory mock.
func newTestStorage() (*PKCS11CertStorage, *mockHWCertStorage) {
	hw := newMockHWCertStorage()
	return &PKCS11CertStorage{hw: hw, closed: false}, hw
}

// ---------------------------------------------------------------------------
// 1. TestPivID - verify pivID() returns correct single-byte strings
// ---------------------------------------------------------------------------

func TestPivID(t *testing.T) {
	tests := []struct {
		name     string
		slot     pivcert.PIVSlot
		wantByte byte
	}{
		{"authentication 9a", pivcert.PIVSlotAuthentication, 0x01},
		{"digital signature 9c", pivcert.PIVSlotDigitalSignature, 0x02},
		{"key management 9d", pivcert.PIVSlotKeyManagement, 0x03},
		{"card authentication 9e", pivcert.PIVSlotCardAuthentication, 0x04},
		{"attestation f9", pivcert.PIVSlotAttestation, 0x19},
		{"retired 1 (82)", pivcert.PIVSlotRetired1, 0x05},
		{"retired 2 (83)", pivcert.PIVSlotRetired2, 0x06},
		{"retired 3 (84)", pivcert.PIVSlotRetired3, 0x07},
		{"retired 4 (85)", pivcert.PIVSlotRetired4, 0x08},
		{"retired 5 (86)", pivcert.PIVSlotRetired5, 0x09},
		{"retired 6 (87)", pivcert.PIVSlotRetired6, 0x0a},
		{"retired 7 (88)", pivcert.PIVSlotRetired7, 0x0b},
		{"retired 8 (89)", pivcert.PIVSlotRetired8, 0x0c},
		{"retired 9 (8a)", pivcert.PIVSlotRetired9, 0x0d},
		{"retired 10 (8b)", pivcert.PIVSlotRetired10, 0x0e},
		{"retired 11 (8c)", pivcert.PIVSlotRetired11, 0x0f},
		{"retired 12 (8d)", pivcert.PIVSlotRetired12, 0x10},
		{"retired 13 (8e)", pivcert.PIVSlotRetired13, 0x11},
		{"retired 14 (8f)", pivcert.PIVSlotRetired14, 0x12},
		{"retired 15 (90)", pivcert.PIVSlotRetired15, 0x13},
		{"retired 16 (91)", pivcert.PIVSlotRetired16, 0x14},
		{"retired 17 (92)", pivcert.PIVSlotRetired17, 0x15},
		{"retired 18 (93)", pivcert.PIVSlotRetired18, 0x16},
		{"retired 19 (94)", pivcert.PIVSlotRetired19, 0x17},
		{"retired 20 (95)", pivcert.PIVSlotRetired20, 0x18},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := pivID(tt.slot)
			if err != nil {
				t.Fatalf("pivID(%s) unexpected error: %v", tt.slot, err)
			}
			if len(id) != 1 {
				t.Fatalf("pivID(%s) returned %d bytes, want 1", tt.slot, len(id))
			}
			if id[0] != tt.wantByte {
				t.Errorf("pivID(%s) = 0x%02x, want 0x%02x", tt.slot, id[0], tt.wantByte)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. TestPivID_InvalidSlot - verify pivID returns error for unknown slot
// ---------------------------------------------------------------------------

func TestPivID_InvalidSlot(t *testing.T) {
	tests := []struct {
		name string
		slot pivcert.PIVSlot
	}{
		{"empty slot", pivcert.PIVSlot("")},
		{"unknown slot ff", pivcert.PIVSlot("ff")},
		{"uppercase 9A", pivcert.PIVSlot("9A")},
		{"garbage string", pivcert.PIVSlot("invalid")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pivID(tt.slot)
			if !errors.Is(err, pivcert.ErrInvalidSlot) {
				t.Errorf("pivID(%q) error = %v, want ErrInvalidSlot", tt.slot, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. TestParseCertificate_DER - parse a DER-encoded cert
// ---------------------------------------------------------------------------

func TestParseCertificate_DER(t *testing.T) {
	cert := generateTestCert(t)

	parsed, err := parseCertificate(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER)
	if err != nil {
		t.Fatalf("parseCertificate(DER) unexpected error: %v", err)
	}
	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("parseCertificate(DER) subject = %q, want %q",
			parsed.Subject.CommonName, cert.Subject.CommonName)
	}
}

// ---------------------------------------------------------------------------
// 4. TestParseCertificate_PEM - parse a PEM-encoded cert
// ---------------------------------------------------------------------------

func TestParseCertificate_PEM(t *testing.T) {
	cert := generateTestCert(t)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	parsed, err := parseCertificate(pivcert.PIVSlotAuthentication, pemData, pivcert.FormatPEM)
	if err != nil {
		t.Fatalf("parseCertificate(PEM) unexpected error: %v", err)
	}
	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("parseCertificate(PEM) subject = %q, want %q",
			parsed.Subject.CommonName, cert.Subject.CommonName)
	}
}

// ---------------------------------------------------------------------------
// 5. TestParseCertificate_InvalidFormat - unknown format returns error
// ---------------------------------------------------------------------------

func TestParseCertificate_InvalidFormat(t *testing.T) {
	cert := generateTestCert(t)

	_, err := parseCertificate(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.CertFormat(99))
	if !errors.Is(err, pivcert.ErrInvalidFormat) {
		t.Errorf("parseCertificate(unknown format) error = %v, want ErrInvalidFormat", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("parseCertificate(unknown format) error should be PIVStorageError")
	}
	if storageErr.Op != "Import" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Import")
	}
}

// ---------------------------------------------------------------------------
// 6. TestParseCertificate_InvalidData - garbage data returns error
// ---------------------------------------------------------------------------

func TestParseCertificate_InvalidData(t *testing.T) {
	t.Run("invalid DER", func(t *testing.T) {
		garbage := []byte("this is not a valid DER certificate")
		_, err := parseCertificate(pivcert.PIVSlotAuthentication, garbage, pivcert.FormatDER)
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("parseCertificate(invalid DER) error = %v, want ErrInvalidCertificate", err)
		}
	})

	t.Run("invalid PEM block type", func(t *testing.T) {
		wrongType := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})
		_, err := parseCertificate(pivcert.PIVSlotAuthentication, wrongType, pivcert.FormatPEM)
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("parseCertificate(wrong PEM type) error = %v, want ErrInvalidFormat", err)
		}
	})

	t.Run("malformed PEM", func(t *testing.T) {
		malformed := []byte("-----BEGIN SOMETHING-----\nnot-valid-base64!!!\n-----END SOMETHING-----\n")
		_, err := parseCertificate(pivcert.PIVSlotAuthentication, malformed, pivcert.FormatPEM)
		if !errors.Is(err, pivcert.ErrInvalidFormat) {
			t.Errorf("parseCertificate(malformed PEM) error = %v, want ErrInvalidFormat", err)
		}
	})

	t.Run("valid PEM block with invalid cert bytes", func(t *testing.T) {
		badCert := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a real certificate"),
		})
		_, err := parseCertificate(pivcert.PIVSlotAuthentication, badCert, pivcert.FormatPEM)
		if !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Errorf("parseCertificate(bad cert in PEM) error = %v, want ErrInvalidCertificate", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 7. TestKeyAlgorithmName - RSA, ECDSA, Ed25519, unknown
// ---------------------------------------------------------------------------

func TestKeyAlgorithmName(t *testing.T) {
	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		want      string
	}{
		{"RSA", x509.RSA, "RSA"},
		{"ECDSA", x509.ECDSA, "ECDSA"},
		{"Ed25519", x509.Ed25519, "Ed25519"},
		{"Unknown", x509.PublicKeyAlgorithm(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{PublicKeyAlgorithm: tt.algorithm}
			got := keyAlgorithmName(cert)
			if got != tt.want {
				t.Errorf("keyAlgorithmName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. TestKeySize - RSA 2048, ECDSA P-256, Ed25519
// ---------------------------------------------------------------------------

func TestKeySize(t *testing.T) {
	t.Run("RSA 2048", func(t *testing.T) {
		cert := generateRSATestCert(t, 2048)
		got := keySize(cert)
		if got != 2048 {
			t.Errorf("keySize(RSA-2048) = %d, want 2048", got)
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		cert := generateECDSATestCert(t, elliptic.P256())
		got := keySize(cert)
		if got != 256 {
			t.Errorf("keySize(ECDSA P-256) = %d, want 256", got)
		}
	})

	t.Run("ECDSA P-384", func(t *testing.T) {
		cert := generateECDSATestCert(t, elliptic.P384())
		got := keySize(cert)
		if got != 384 {
			t.Errorf("keySize(ECDSA P-384) = %d, want 384", got)
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		// Ed25519 falls through to the default case that checks PublicKeyAlgorithm.
		cert := &x509.Certificate{
			PublicKeyAlgorithm: x509.Ed25519,
			PublicKey:          nil,
		}
		got := keySize(cert)
		if got != 256 {
			t.Errorf("keySize(Ed25519) = %d, want 256", got)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		cert := &x509.Certificate{
			PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99),
			PublicKey:          nil,
		}
		got := keySize(cert)
		if got != 0 {
			t.Errorf("keySize(Unknown) = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 9. TestCkaIDToPIVSlotMap - verify reverse mapping is consistent
// ---------------------------------------------------------------------------

func TestCkaIDToPIVSlotMap(t *testing.T) {
	// Verify both maps have the same cardinality.
	if len(pivSlotToCKAIDMap) != len(ckaIDToPIVSlotMap) {
		t.Fatalf("map size mismatch: pivSlotToCKAIDMap=%d, ckaIDToPIVSlotMap=%d",
			len(pivSlotToCKAIDMap), len(ckaIDToPIVSlotMap))
	}

	// Verify round-trip for every entry.
	for slot, ckaID := range pivSlotToCKAIDMap {
		reverseSlot, ok := ckaIDToPIVSlotMap[ckaID]
		if !ok {
			t.Errorf("ckaIDToPIVSlotMap missing entry for CKA_ID 0x%02x (slot %s)", ckaID, slot)
			continue
		}
		if reverseSlot != slot {
			t.Errorf("round-trip failed: slot %s -> CKA_ID 0x%02x -> slot %s", slot, ckaID, reverseSlot)
		}
	}

	// Verify all known slots from AllSlots() are covered.
	allSlots := pivcert.AllSlots()
	for _, slot := range allSlots {
		if _, ok := pivSlotToCKAIDMap[slot]; !ok {
			t.Errorf("pivSlotToCKAIDMap missing entry for slot %s", slot)
		}
	}
}

// ---------------------------------------------------------------------------
// 10. TestPKCS11CertStorage_Store_Closed
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Store_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Store() on closed storage error = %v, want ErrStorageClosed", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Store() on closed storage should return PIVStorageError")
	}
	if storageErr.Op != "Store" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Store")
	}
}

// ---------------------------------------------------------------------------
// 11. TestPKCS11CertStorage_Store_InvalidSlot
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Store_InvalidSlot(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlot("invalid"), cert)
	if !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Store(invalid slot) error = %v, want ErrInvalidSlot", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Store(invalid slot) should return PIVStorageError")
	}
	if storageErr.Op != "Store" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Store")
	}
}

// ---------------------------------------------------------------------------
// 12. TestPKCS11CertStorage_Store_NilCert
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Store_NilCert(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Store(pivcert.PIVSlotAuthentication, nil)
	if !errors.Is(err, pivcert.ErrInvalidCertificate) {
		t.Errorf("Store(nil cert) error = %v, want ErrInvalidCertificate", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Store(nil cert) should return PIVStorageError")
	}
	if storageErr.Op != "Store" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Store")
	}
	if storageErr.Slot != pivcert.PIVSlotAuthentication {
		t.Errorf("PIVStorageError.Slot = %q, want %q", storageErr.Slot, pivcert.PIVSlotAuthentication)
	}
}

// ---------------------------------------------------------------------------
// 13. TestPKCS11CertStorage_Retrieve_Closed
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Retrieve_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}

	_, err := s.Retrieve(pivcert.PIVSlotAuthentication)
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Retrieve() on closed storage error = %v, want ErrStorageClosed", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Retrieve() on closed storage should return PIVStorageError")
	}
	if storageErr.Op != "Retrieve" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Retrieve")
	}
}

// ---------------------------------------------------------------------------
// 14. TestPKCS11CertStorage_Delete_Closed
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Delete_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}

	err := s.Delete(pivcert.PIVSlotAuthentication)
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Delete() on closed storage error = %v, want ErrStorageClosed", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Delete() on closed storage should return PIVStorageError")
	}
	if storageErr.Op != "Delete" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Delete")
	}
}

// ---------------------------------------------------------------------------
// 15. TestPKCS11CertStorage_List_Closed
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_List_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}

	_, err := s.List()
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("List() on closed storage error = %v, want ErrStorageClosed", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("List() on closed storage should return PIVStorageError")
	}
	if storageErr.Op != "List" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "List")
	}
}

// ---------------------------------------------------------------------------
// 16. TestPKCS11CertStorage_Close_Idempotent
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Close_Idempotent(t *testing.T) {
	s, _ := newTestStorage()

	// First close should succeed.
	err := s.Close()
	if err != nil {
		t.Fatalf("first Close() unexpected error: %v", err)
	}

	// Second close should return ErrStorageClosed.
	err = s.Close()
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("second Close() error = %v, want ErrStorageClosed", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("second Close() should return PIVStorageError")
	}
	if storageErr.Op != "Close" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "Close")
	}
	if storageErr.StorageType != pivcert.StorageTypePKCS11 {
		t.Errorf("PIVStorageError.StorageType = %q, want %q",
			storageErr.StorageType, pivcert.StorageTypePKCS11)
	}
}

// ---------------------------------------------------------------------------
// 17. TestPKCS11CertStorage_Type
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Type(t *testing.T) {
	s := &PKCS11CertStorage{}
	got := s.Type()
	if got != pivcert.StorageTypePKCS11 {
		t.Errorf("Type() = %q, want %q", got, pivcert.StorageTypePKCS11)
	}
}

// ---------------------------------------------------------------------------
// 18. TestNewFromSession_NilCtx
// ---------------------------------------------------------------------------

func TestNewFromSession_NilCtx(t *testing.T) {
	_, err := NewFromSession(nil, 0, 0)
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Errorf("NewFromSession(nil) error = %v, want ErrInvalidConfig", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("NewFromSession(nil) error should be PIVStorageError")
	}
	if storageErr.Op != "NewFromSession" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "NewFromSession")
	}
}

// ---------------------------------------------------------------------------
// 19. TestNew_NilConfig
// ---------------------------------------------------------------------------

func TestNew_NilConfig(t *testing.T) {
	_, err := New(nil)
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Errorf("New(nil) error = %v, want ErrInvalidConfig", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("New(nil) error should be PIVStorageError")
	}
	if storageErr.Op != "New" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "New")
	}
}

// ---------------------------------------------------------------------------
// 20. TestNew_InvalidConfig - missing library path
// ---------------------------------------------------------------------------

func TestNew_InvalidConfig(t *testing.T) {
	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: "",
	}
	_, err := New(config)
	if !errors.Is(err, pivcert.ErrMissingLibraryPath) {
		t.Errorf("New(empty library) error = %v, want ErrMissingLibraryPath", err)
	}
}

// ---------------------------------------------------------------------------
// Store/Retrieve/Delete/List with mock HW - happy path
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_StoreAndRetrieve(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if err != nil {
		t.Fatalf("Store() unexpected error: %v", err)
	}

	got, err := s.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() unexpected error: %v", err)
	}
	if got.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("Retrieve() subject = %q, want %q", got.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestPKCS11CertStorage_Delete(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if err != nil {
		t.Fatalf("Store() unexpected error: %v", err)
	}

	err = s.Delete(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	// Retrieve after delete should fail.
	_, err = s.Retrieve(pivcert.PIVSlotAuthentication)
	if !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Retrieve() after delete error = %v, want ErrCertificateNotFound", err)
	}
}

func TestPKCS11CertStorage_Delete_NotFound(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Delete(pivcert.PIVSlotAuthentication)
	if !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Delete(empty) error = %v, want ErrCertificateNotFound", err)
	}
}

func TestPKCS11CertStorage_List(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	// Store certs in two slots.
	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if err != nil {
		t.Fatalf("Store(9a) unexpected error: %v", err)
	}
	err = s.Store(pivcert.PIVSlotDigitalSignature, cert)
	if err != nil {
		t.Fatalf("Store(9c) unexpected error: %v", err)
	}

	infos, err := s.List()
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("List() returned %d entries, want 2", len(infos))
	}

	// Verify each entry has populated fields.
	for _, info := range infos {
		if info.Slot == "" {
			t.Error("PIVSlotInfo.Slot is empty")
		}
		if info.Subject == "" {
			t.Error("PIVSlotInfo.Subject is empty")
		}
		if info.Algorithm == "" {
			t.Error("PIVSlotInfo.Algorithm is empty")
		}
		if info.Fingerprint == "" {
			t.Error("PIVSlotInfo.Fingerprint is empty")
		}
		if info.KeySize == 0 {
			t.Error("PIVSlotInfo.KeySize is 0")
		}
	}
}

func TestPKCS11CertStorage_List_Empty(t *testing.T) {
	s, _ := newTestStorage()

	infos, err := s.List()
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("List() on empty storage returned %d entries, want 0", len(infos))
	}
}

// ---------------------------------------------------------------------------
// Import/Export with mock HW
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_ImportExport_DER(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	err := s.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER)
	if err != nil {
		t.Fatalf("Import(DER) unexpected error: %v", err)
	}

	exported, err := s.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
	if err != nil {
		t.Fatalf("Export(DER) unexpected error: %v", err)
	}

	parsed, err := x509.ParseCertificate(exported)
	if err != nil {
		t.Fatalf("ParseCertificate(exported DER) unexpected error: %v", err)
	}
	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("exported cert subject = %q, want %q",
			parsed.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestPKCS11CertStorage_ImportExport_PEM(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	err := s.Import(pivcert.PIVSlotAuthentication, pemData, pivcert.FormatPEM)
	if err != nil {
		t.Fatalf("Import(PEM) unexpected error: %v", err)
	}

	exported, err := s.Export(pivcert.PIVSlotAuthentication, pivcert.FormatPEM)
	if err != nil {
		t.Fatalf("Export(PEM) unexpected error: %v", err)
	}

	block, _ := pem.Decode(exported)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("Export(PEM) did not produce a valid PEM CERTIFICATE block")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(exported PEM) unexpected error: %v", err)
	}
	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("exported cert subject = %q, want %q",
			parsed.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestPKCS11CertStorage_Import_EmptyData(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Import(pivcert.PIVSlotAuthentication, []byte{}, pivcert.FormatDER)
	if !errors.Is(err, pivcert.ErrInvalidCertificate) {
		t.Errorf("Import(empty data) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestPKCS11CertStorage_Import_NilData(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Import(pivcert.PIVSlotAuthentication, nil, pivcert.FormatDER)
	if !errors.Is(err, pivcert.ErrInvalidCertificate) {
		t.Errorf("Import(nil data) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestPKCS11CertStorage_Export_InvalidFormat(t *testing.T) {
	s, _ := newTestStorage()
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if err != nil {
		t.Fatalf("Store() unexpected error: %v", err)
	}

	_, err = s.Export(pivcert.PIVSlotAuthentication, pivcert.CertFormat(99))
	if !errors.Is(err, pivcert.ErrInvalidFormat) {
		t.Errorf("Export(invalid format) error = %v, want ErrInvalidFormat", err)
	}
}

func TestPKCS11CertStorage_Export_NotFound(t *testing.T) {
	s, _ := newTestStorage()

	_, err := s.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
	if !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Export(not found) error = %v, want ErrCertificateNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Retrieve/Delete invalid slot
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Retrieve_InvalidSlot(t *testing.T) {
	s, _ := newTestStorage()

	_, err := s.Retrieve(pivcert.PIVSlot("invalid"))
	if !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Retrieve(invalid slot) error = %v, want ErrInvalidSlot", err)
	}
}

func TestPKCS11CertStorage_Delete_InvalidSlot(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Delete(pivcert.PIVSlot("invalid"))
	if !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Delete(invalid slot) error = %v, want ErrInvalidSlot", err)
	}
}

// ---------------------------------------------------------------------------
// NewFromPool nil
// ---------------------------------------------------------------------------

func TestNewFromPool_NilPool(t *testing.T) {
	_, err := NewFromPool(nil, "label")
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Errorf("NewFromPool(nil) error = %v, want ErrInvalidConfig", err)
	}

	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("NewFromPool(nil) error should be PIVStorageError")
	}
	if storageErr.Op != "NewFromPool" {
		t.Errorf("PIVStorageError.Op = %q, want %q", storageErr.Op, "NewFromPool")
	}
}

// ---------------------------------------------------------------------------
// isPKCS11Error
// ---------------------------------------------------------------------------

func TestIsPKCS11Error(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		if isPKCS11Error(nil, 0) {
			t.Error("isPKCS11Error(nil) = true, want false")
		}
	})

	t.Run("non-pkcs11 error", func(t *testing.T) {
		if isPKCS11Error(errors.New("plain error"), 0) {
			t.Error("isPKCS11Error(plain error) = true, want false")
		}
	})
}

// ---------------------------------------------------------------------------
// Import/Export on closed storage
// ---------------------------------------------------------------------------

func TestPKCS11CertStorage_Import_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}
	cert := generateTestCert(t)

	err := s.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER)
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Import() on closed storage error = %v, want ErrStorageClosed", err)
	}
}

func TestPKCS11CertStorage_Export_Closed(t *testing.T) {
	s := &PKCS11CertStorage{closed: true}

	_, err := s.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER)
	if !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Export() on closed storage error = %v, want ErrStorageClosed", err)
	}
}
