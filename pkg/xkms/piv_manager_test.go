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

package xkms

import (
	"context"
	"crypto"
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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock PIV Key Generator ---

type mockPIVKeyGenerator struct {
	signer    crypto.Signer
	err       error
	signerErr error // separate error for GetPIVSigner
}

func (m *mockPIVKeyGenerator) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.signer, nil
}

func (m *mockPIVKeyGenerator) GetPIVSigner(_ pivcert.PIVSlot, _ string) (crypto.Signer, error) {
	if m.signerErr != nil {
		return nil, m.signerErr
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.signer, nil
}

// --- failingSigner returns a signer that fails on Sign but has a valid public key ---

type failingSigner struct {
	pub crypto.PublicKey
	err error
}

func (f *failingSigner) Public() crypto.PublicKey {
	return f.pub
}

func (f *failingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, f.err
}

// --- Backend resolver and PIV backend tests ---

func TestSetPIVBackendResolver(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	resolver := func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{}, nil
	}

	err = SetPIVBackendResolver(resolver)
	require.NoError(t, err)
}

func TestSetPIVBackendResolver_NotInitialized(t *testing.T) {
	ResetPIV()

	resolver := func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{}, nil
	}

	err := SetPIVBackendResolver(resolver)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestPivBackendWithResolver(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	expectedGen := &mockPIVKeyGenerator{}
	resolver := func(backendName string) (PIVKeyGenerator, error) {
		assert.Equal(t, "test-backend", backendName)
		return expectedGen, nil
	}

	err = SetPIVBackendResolver(resolver)
	require.NoError(t, err)

	gen, err := pivBackend("test-backend")
	require.NoError(t, err)
	assert.Equal(t, expectedGen, gen)
}

func TestPivBackendWithoutResolver(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	gen, err := pivBackend("anything")
	require.NoError(t, err)

	// Should return a softwarePIVKeyGenerator as fallback
	_, ok := gen.(*softwarePIVKeyGenerator)
	assert.True(t, ok, "expected *softwarePIVKeyGenerator fallback, got %T", gen)
}

func TestPivBackendResolverError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	resolverErr := errors.New("resolver failed")
	resolver := func(_ string) (PIVKeyGenerator, error) {
		return nil, resolverErr
	}

	err = SetPIVBackendResolver(resolver)
	require.NoError(t, err)

	gen, err := pivBackend("test")
	assert.Nil(t, gen)
	require.Error(t, err)
	assert.ErrorIs(t, err, resolverErr)
}

// TestPIVBackendNotInitialized verifies that pivBackend returns
// ErrPIVNotInitialized when the PIV manager singleton is nil.
func TestPIVBackendNotInitialized(t *testing.T) {
	ResetPIV()

	gen, err := pivBackend("any-backend")
	assert.Nil(t, gen)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// TestPIVSetBackendResolverNotInitialized covers the nil pivManager guard
// in SetPIVBackendResolver using a test name that matches the coverage regex.
func TestPIVSetBackendResolverNotInitialized(t *testing.T) {
	ResetPIV()

	err := SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return nil, nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// TestPIVSetBackendResolverSuccess covers the success path of
// SetPIVBackendResolver using a test name that matches the coverage regex.
func TestPIVSetBackendResolverSuccess(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	called := false
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		called = true
		return &mockPIVKeyGenerator{}, nil
	})
	require.NoError(t, err)

	// Verify the resolver was stored by calling pivBackend
	gen, err := pivBackend("test")
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.True(t, called)
}

func TestPivSlotCNMapping(t *testing.T) {
	tests := []struct {
		slot string
		want string
	}{
		{"9a", "piv-9a"},
		{"9c", "piv-9c"},
		{"9d", "piv-9d"},
		{"9e", "piv-9e"},
		{"f9", "piv-f9"},
	}
	for _, tt := range tests {
		t.Run(tt.slot, func(t *testing.T) {
			cn := PivSlotCN(pivcert.PIVSlot(tt.slot))
			assert.Equal(t, tt.want, cn)
		})
	}
}

func TestPivSlotCNMappingRetired(t *testing.T) {
	retiredSlots := []string{
		"82", "83", "84", "85", "86", "87", "88", "89",
		"8a", "8b", "8c", "8d", "8e", "8f",
		"90", "91", "92", "93", "94", "95",
	}
	for _, slot := range retiredSlots {
		t.Run(slot, func(t *testing.T) {
			cn := PivSlotCN(pivcert.PIVSlot(slot))
			assert.Equal(t, "piv-"+slot, cn)
		})
	}
}

func TestPivSlotCNMappingUnknown(t *testing.T) {
	cn := PivSlotCN(pivcert.PIVSlot("xx"))
	assert.Equal(t, "piv-xx", cn)
}

func TestGeneratePIVKeyWithBackendResolver(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"test-backend": store,
		},
	})
	require.NoError(t, err)

	// Generate a real key for the mock generator
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockGen := &mockPIVKeyGenerator{signer: key}
	resolver := func(_ string) (PIVKeyGenerator, error) {
		return mockGen, nil
	}

	err = SetPIVBackendResolver(resolver)
	require.NoError(t, err)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "test-backend",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.PublicKey)
	assert.Equal(t, "9a", resp.Slot)

	// Verify cert was stored
	_, certErr := store.Retrieve(pivcert.PIVSlotAuthentication)
	assert.NoError(t, certErr)
}

func TestGeneratePIVCSRWithBackendSigner(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"test-backend": store,
		},
	})
	require.NoError(t, err)

	// Generate a real key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockGen := &mockPIVKeyGenerator{signer: key}
	resolver := func(_ string) (PIVKeyGenerator, error) {
		return mockGen, nil
	}

	err = SetPIVBackendResolver(resolver)
	require.NoError(t, err)

	// First generate a key (creates the cert)
	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "test-backend",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.NoError(t, err)

	// Now generate a CSR using the same backend
	csrResp, err := GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "test-backend",
		Slot:    "9a",
		Subject: "Test CSR",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, csrResp.CSR)
	assert.Equal(t, "9a", csrResp.Slot)

	// Parse and verify the CSR signature
	block, _ := pem.Decode(csrResp.CSR)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "Test CSR", csr.Subject.CommonName)

	err = csr.CheckSignature()
	assert.NoError(t, err)
}

func TestParseCertFormat_ValidFormats(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantOK bool
	}{
		{"pem lowercase", "pem", true},
		{"PEM uppercase", "PEM", true},
		{"der lowercase", "der", true},
		{"DER uppercase", "DER", true},
		{"invalid format", "pkcs12", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCertFormat(tt.input)
			if tt.wantOK && result < 0 {
				t.Fatalf("expected valid format for %q, got -1", tt.input)
			}
			if !tt.wantOK && result >= 0 {
				t.Fatalf("expected invalid format for %q, got %d", tt.input, result)
			}
		})
	}
}

// --- Mock PIV Certificate Storage ---

type mockPIVCertStorage struct {
	certs     map[pivcert.PIVSlot]*x509.Certificate
	listErr   error
	storeErr  error
	exportErr error
}

func newMockPIVCertStorage() *mockPIVCertStorage {
	return &mockPIVCertStorage{
		certs: make(map[pivcert.PIVSlot]*x509.Certificate),
	}
}

func (m *mockPIVCertStorage) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.certs[slot] = cert
	return nil
}

func (m *mockPIVCertStorage) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	cert, ok := m.certs[slot]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (m *mockPIVCertStorage) Delete(slot pivcert.PIVSlot) error {
	if _, ok := m.certs[slot]; !ok {
		return errors.New("certificate not found")
	}
	delete(m.certs, slot)
	return nil
}

func (m *mockPIVCertStorage) List() ([]pivcert.PIVSlotInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var infos []pivcert.PIVSlotInfo
	for slot, cert := range m.certs {
		infos = append(infos, pivcert.PIVSlotInfo{
			Slot:      slot,
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			Algorithm: cert.PublicKeyAlgorithm.String(),
		})
	}
	return infos, nil
}

func (m *mockPIVCertStorage) Import(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) error {
	return nil
}

func (m *mockPIVCertStorage) Export(slot pivcert.PIVSlot, format pivcert.CertFormat) ([]byte, error) {
	if m.exportErr != nil {
		return nil, m.exportErr
	}
	cert, ok := m.certs[slot]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	if format == pivcert.FormatPEM {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
	}
	return cert.Raw, nil
}

func (m *mockPIVCertStorage) Close() error { return nil }

func (m *mockPIVCertStorage) Type() pivcert.PIVStorageType { return "mock" }

// --- PIV Manager lifecycle tests ---

func TestInitializePIV_Success(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)
}

func TestInitializePIV_NilConfig(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestInitializePIV_NilStores(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{Stores: nil})
	require.NoError(t, err)
}

// TestPIVInitializeNilConfig covers the nil config error path inside
// pivInitOnce.Do with a test name matching the coverage regex.
func TestPIVInitializeNilConfig(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestRegisterPIVStore_Success(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	store := newMockPIVCertStorage()
	err = RegisterPIVStore("tpm2", store)
	require.NoError(t, err)
}

func TestRegisterPIVStore_NotInitialized(t *testing.T) {
	ResetPIV()

	err := RegisterPIVStore("tpm2", newMockPIVCertStorage())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// TestRegisterPIVStore_ThenRetrieve verifies a registered store can be
// used to store and retrieve certificates through the PIV manager.
func TestRegisterPIVStore_ThenRetrieve(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	store := newMockPIVCertStorage()
	err = RegisterPIVStore("dynamic-backend", store)
	require.NoError(t, err)

	// Verify the registered store is accessible via pivStore
	retrieved, err := pivStore("dynamic-backend")
	require.NoError(t, err)
	assert.Equal(t, store, retrieved)
}

func TestPivStore_Success(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	s, err := pivStore("software")
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestPivStore_NotInitialized(t *testing.T) {
	ResetPIV()

	_, err := pivStore("software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestPivStore_BackendNotFound(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)

	_, err = pivStore("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVBackendNotFound)
}

// --- PIV functional tests ---

func setupPIVWithStore(t *testing.T) *mockPIVCertStorage {
	t.Helper()
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)
	return store
}

// setupPIVWithMockResolver initializes the PIV manager with a store and
// mock key generator resolver. Returns the store and mock generator.
func setupPIVWithMockResolver(t *testing.T) (*mockPIVCertStorage, *mockPIVKeyGenerator) {
	t.Helper()
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockGen := &mockPIVKeyGenerator{signer: key}
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return mockGen, nil
	})
	require.NoError(t, err)

	return store, mockGen
}

// createPIVTestCert generates a self-signed certificate for PIV tests.
func createPIVTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-piv-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestListPIVSlots_Success(t *testing.T) {
	store := setupPIVWithStore(t)
	cert := createPIVTestCert(t)
	store.certs[pivcert.PIVSlotAuthentication] = cert

	resp, err := ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "software",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Slots)

	// At least one slot should have a cert
	found := false
	for _, s := range resp.Slots {
		if s.HasCert {
			found = true
			assert.Equal(t, "9a", s.Slot)
		}
	}
	assert.True(t, found)
}

func TestListPIVSlots_MissingBackend(t *testing.T) {
	setupPIVWithStore(t)

	_, err := ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVBackendNotFound)
}

// TestListPIVSlots_StoreListError verifies that ListPIVSlots propagates
// errors from the underlying store's List operation.
func TestListPIVSlots_StoreListError(t *testing.T) {
	store := setupPIVWithStore(t)
	store.listErr = errors.New("list operation failed")

	_, err := ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list operation failed")
}

func TestGetPIVCertificate_Success(t *testing.T) {
	store := setupPIVWithStore(t)
	cert := createPIVTestCert(t)
	store.certs[pivcert.PIVSlotAuthentication] = cert

	resp, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pem",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.Equal(t, "9a", resp.Slot)
}

func TestGetPIVCertificate_InvalidSlot(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "invalid-slot",
		Format:  "pem",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestGetPIVCertificate_InvalidFormat(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pkcs12",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidFormat)
}

func TestGetPIVCertificate_MissingBackend(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "nonexistent",
		Slot:    "9a",
		Format:  "pem",
	})
	require.Error(t, err)
}

// TestGetPIVCertificate_ExportError verifies that GetPIVCertificate propagates
// errors from the underlying store's Export operation.
func TestGetPIVCertificate_ExportError(t *testing.T) {
	store := setupPIVWithStore(t)
	store.exportErr = errors.New("export operation failed")

	_, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "export operation failed")
}

func TestStorePIVCertificate_Success(t *testing.T) {
	setupPIVWithStore(t)

	err := StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Certificate: []byte("cert-data"),
		Format:      "der",
	})
	require.NoError(t, err)
}

func TestStorePIVCertificate_InvalidSlot(t *testing.T) {
	setupPIVWithStore(t)

	err := StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "invalid",
		Certificate: []byte("cert-data"),
		Format:      "der",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestStorePIVCertificate_InvalidFormat(t *testing.T) {
	setupPIVWithStore(t)

	err := StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Certificate: []byte("cert-data"),
		Format:      "p7b",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidFormat)
}

func TestDeletePIVCertificate_Success(t *testing.T) {
	store := setupPIVWithStore(t)
	cert := createPIVTestCert(t)
	store.certs[pivcert.PIVSlotAuthentication] = cert

	err := DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
}

func TestDeletePIVCertificate_InvalidSlot(t *testing.T) {
	setupPIVWithStore(t)

	err := DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "invalid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestDeletePIVCertificate_MissingBackend(t *testing.T) {
	setupPIVWithStore(t)

	err := DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "nonexistent",
		Slot:    "9a",
	})
	require.Error(t, err)
}

func TestGeneratePIVKey_Success(t *testing.T) {
	setupPIVWithStore(t)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.PublicKey)
	assert.Equal(t, "9a", resp.Slot)
}

func TestGeneratePIVKey_DefaultAlgorithm(t *testing.T) {
	setupPIVWithStore(t)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9c",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.PublicKey)
	assert.Equal(t, "9c", resp.Slot)
}

func TestGeneratePIVKey_WithSubject(t *testing.T) {
	setupPIVWithStore(t)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
		Subject:   "My Custom Subject",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)

	// Parse the certificate and verify subject
	block, _ := pem.Decode(resp.Certificate)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "My Custom Subject", cert.Subject.CommonName)
}

func TestGeneratePIVKey_InvalidSlot(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "invalid",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestGeneratePIVKey_InvalidAlgorithm(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "invalid-algo",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
}

func TestGeneratePIVKey_MissingBackend(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "nonexistent",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
}

// TestGeneratePIVKey_BackendResolverError verifies that GeneratePIVKey
// propagates errors from the backend resolver.
func TestGeneratePIVKey_BackendResolverError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	resolverErr := errors.New("backend unavailable")
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return nil, resolverErr
	})
	require.NoError(t, err)

	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, resolverErr)
}

// TestGeneratePIVKey_GeneratorError verifies that GeneratePIVKey propagates
// errors from the PIVKeyGenerator.GeneratePIVKey method.
func TestGeneratePIVKey_GeneratorError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	genErr := errors.New("key generation failed")
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{err: genErr}, nil
	})
	require.NoError(t, err)

	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, genErr)
}

// TestGeneratePIVKey_StoreError verifies that GeneratePIVKey propagates
// errors from the certificate store's Store operation.
func TestGeneratePIVKey_StoreError(t *testing.T) {
	store, _ := setupPIVWithMockResolver(t)
	store.storeErr = errors.New("store write failed")

	_, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store write failed")
}

// TestGeneratePIVKey_CreateCertificateError verifies that GeneratePIVKey
// propagates errors from x509.CreateCertificate when the signer fails during signing.
func TestGeneratePIVKey_CreateCertificateError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	// Create a signer with a valid public key but a failing Sign method.
	// x509.CreateCertificate will call Sign and receive this error.
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signErr := errors.New("signing operation failed")
	brokenSigner := &failingSigner{
		pub: &realKey.PublicKey,
		err: signErr,
	}

	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{signer: brokenSigner}, nil
	})
	require.NoError(t, err)

	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.Error(t, err)
}

func TestGeneratePIVCSR_Success(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	// Create a persistent mock generator so CSR can find the signer
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockGen := &mockPIVKeyGenerator{signer: key}
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return mockGen, nil
	})
	require.NoError(t, err)

	// Generate key first (required for CSR to find signer)
	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "ecdsap256",
	})
	require.NoError(t, err)

	resp, err := GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Test CSR Subject",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CSR)
	assert.Equal(t, "9a", resp.Slot)
}

func TestGeneratePIVCSR_DefaultSubject(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockGen := &mockPIVKeyGenerator{signer: key}
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return mockGen, nil
	})
	require.NoError(t, err)

	// Generate key first
	_, err = GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)

	resp, err := GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CSR)

	// Parse the CSR and verify the default subject
	block, _ := pem.Decode(resp.CSR)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Contains(t, csr.Subject.CommonName, "PIV Slot 9a")
}

func TestGeneratePIVCSR_InvalidSlot(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "invalid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestGeneratePIVCSR_MissingBackend(t *testing.T) {
	setupPIVWithStore(t)

	_, err := GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "nonexistent",
		Slot:    "9a",
	})
	require.Error(t, err)
}

// TestGeneratePIVCSR_BackendResolverError verifies that GeneratePIVCSR
// propagates errors from the backend resolver.
func TestGeneratePIVCSR_BackendResolverError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	resolverErr := errors.New("backend unavailable for CSR")
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return nil, resolverErr
	})
	require.NoError(t, err)

	_, err = GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, resolverErr)
}

// TestGeneratePIVCSR_SignerError verifies that GeneratePIVCSR propagates
// errors from the PIVKeyGenerator.GetPIVSigner method.
func TestGeneratePIVCSR_SignerError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	signerErr := errors.New("signer unavailable")
	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{signerErr: signerErr}, nil
	})
	require.NoError(t, err)

	_, err = GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, signerErr)
}

// TestGeneratePIVCSR_CreateCSRError verifies that GeneratePIVCSR propagates
// errors from x509.CreateCertificateRequest when the signer fails during signing.
func TestGeneratePIVCSR_CreateCSRError(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	require.NoError(t, err)

	// Create a signer with a valid public key but a failing Sign method.
	// x509.CreateCertificateRequest will call Sign and receive this error.
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signErr := errors.New("csr signing failed")
	brokenSigner := &failingSigner{
		pub: &realKey.PublicKey,
		err: signErr,
	}

	err = SetPIVBackendResolver(func(_ string) (PIVKeyGenerator, error) {
		return &mockPIVKeyGenerator{signer: brokenSigner}, nil
	})
	require.NoError(t, err)

	_, err = GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
		Subject: "Test CSR",
	})
	require.Error(t, err)
}

func TestImportPIVCertificate_DelegatesToStore(t *testing.T) {
	setupPIVWithStore(t)

	err := ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend:     "software",
		Slot:        "9a",
		Certificate: []byte("cert-data"),
		Format:      "der",
	})
	require.NoError(t, err)
}

func TestExportPIVCertificate_DelegatesToGetPIVCertificate(t *testing.T) {
	store := setupPIVWithStore(t)
	cert := createPIVTestCert(t)
	store.certs[pivcert.PIVSlotAuthentication] = cert

	resp, err := ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "der",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
}

func TestResetPIV_ClearsState(t *testing.T) {
	store := newMockPIVCertStorage()
	err := InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": store,
		},
	})
	// May error if already initialized from prior tests
	_ = err

	ResetPIV()

	// After reset, pivStore should return not initialized
	_, err = pivStore("software")
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestGeneratePIVKey_RSA2048(t *testing.T) {
	setupPIVWithStore(t)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9a",
		Algorithm: "rsa2048",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.PublicKey)
}

func TestGeneratePIVKey_Ed25519(t *testing.T) {
	setupPIVWithStore(t)

	resp, err := GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend:   "software",
		Slot:      "9d",
		Algorithm: "ed25519",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.NotEmpty(t, resp.PublicKey)
}

func TestGetPIVCertificate_DERFormat(t *testing.T) {
	store := setupPIVWithStore(t)
	cert := createPIVTestCert(t)
	store.certs[pivcert.PIVSlotAuthentication] = cert

	resp, err := GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "DER",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
	assert.Equal(t, "DER", resp.Format)
}
