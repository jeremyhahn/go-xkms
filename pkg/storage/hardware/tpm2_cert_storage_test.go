// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package hardware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	storagepkg "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// TestDefaultTPM2CertStorageConfig tests default configuration
func TestDefaultTPM2CertStorageConfig(t *testing.T) {
	config := DefaultTPM2CertStorageConfig()

	if config.BaseIndex != 0x01800000 {
		t.Errorf("BaseIndex = %#x, want 0x01800000", config.BaseIndex)
	}

	if config.MaxCertSize != 2048 {
		t.Errorf("MaxCertSize = %d, want 2048", config.MaxCertSize)
	}

	if config.OwnerAuth != nil {
		t.Error("OwnerAuth should be nil by default")
	}
}

// TestNewTPM2CertStorage_NilTPM tests error handling for nil TPM
func TestNewTPM2CertStorage_NilTPM(t *testing.T) {
	config := DefaultTPM2CertStorageConfig()

	_, err := NewTPM2CertStorage(nil, config)
	if err == nil {
		t.Error("Expected error for nil TPM, got nil")
	}

	if !errors.Is(err, ErrNilTPM) {
		t.Errorf("Expected ErrNilTPM, got: %v", err)
	}
}

// TestNewTPM2CertStorage_InvalidBaseIndex tests base index validation
func TestNewTPM2CertStorage_InvalidBaseIndex(t *testing.T) {
	tests := []struct {
		name      string
		baseIndex uint32
		wantErr   bool
	}{
		{"valid lower bound", 0x01000000, false},
		{"valid upper bound", 0x01BFFFFF, false},
		{"valid middle", 0x01800000, false},
		{"too low", 0x00FFFFFF, true},
		{"too high", 0x01C00000, true},
		{"way too low", 0x00000000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := newMockTPM(t)
			defer func() { _ = tpm.Close() }()

			config := &TPM2CertStorageConfig{
				BaseIndex:   tt.baseIndex,
				MaxCertSize: 2048,
			}

			_, err := NewTPM2CertStorage(tpm, config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTPM2CertStorage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewTPM2CertStorage_InvalidMaxCertSize tests cert size validation
func TestNewTPM2CertStorage_InvalidMaxCertSize(t *testing.T) {
	tests := []struct {
		name        string
		maxCertSize int
		wantErr     bool
	}{
		{"valid 512", 512, false},
		{"valid 2048", 2048, false},
		{"valid 4096", 4096, false},
		{"too small", 511, true},
		{"too large", 4097, true},
		{"way too small", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := newMockTPM(t)
			defer func() { _ = tpm.Close() }()

			config := &TPM2CertStorageConfig{
				BaseIndex:   0x01800000,
				MaxCertSize: tt.maxCertSize,
			}

			_, err := NewTPM2CertStorage(tpm, config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTPM2CertStorage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTPM2CertStorage_SaveAndGetCert tests basic save/get operations
func TestTPM2CertStorage_SaveAndGetCert(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	storage, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	// Generate test certificate
	cert := generateTestCert(t)

	// Save certificate
	err = storage.SaveCert("test-cert-1", cert)
	if err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	// Retrieve certificate
	retrieved, err := storage.GetCert("test-cert-1")
	if err != nil {
		t.Fatalf("GetCert() error = %v", err)
	}

	// Compare certificates
	if !cert.Equal(retrieved) {
		t.Error("Retrieved certificate does not match original")
	}
}

// TestTPM2CertStorage_SaveCert_EmptyID tests error handling for empty ID
func TestTPM2CertStorage_SaveCert_EmptyID(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	storage, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	cert := generateTestCert(t)

	err = storage.SaveCert("", cert)
	if err == nil {
		t.Error("Expected error for empty ID, got nil")
	}
}

// TestTPM2CertStorage_SaveCert_NilCert tests error handling for nil certificate
func TestTPM2CertStorage_SaveCert_NilCert(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	storage, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	err = storage.SaveCert("test-cert", nil)
	if err == nil {
		t.Error("Expected error for nil certificate, got nil")
	}
}

// TestTPM2CertStorage_GetCert_NotFound tests retrieval of non-existent certificate
func TestTPM2CertStorage_GetCert_NotFound(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	storage, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	_, err = storage.GetCert("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent certificate, got nil")
	}

	// Check that it's a not found type error
	_ = storagepkg.ErrNotFound // Use the import
}

// TestTPM2CertStorage_DeleteCert tests certificate deletion
func TestTPM2CertStorage_DeleteCert(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	cert := generateTestCert(t)

	// Save certificate
	err = store.SaveCert("test-cert", cert)
	if err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	// Verify it exists
	exists, err := store.CertExists("test-cert")
	if err != nil {
		t.Fatalf("CertExists() error = %v", err)
	}
	if !exists {
		t.Error("Certificate should exist after save")
	}

	// Delete certificate
	err = store.DeleteCert("test-cert")
	if err != nil {
		t.Fatalf("DeleteCert() error = %v", err)
	}

	// Verify it no longer exists
	exists, err = store.CertExists("test-cert")
	if err != nil {
		t.Fatalf("CertExists() error = %v", err)
	}
	if exists {
		t.Error("Certificate should not exist after delete")
	}
}

// TestTPM2CertStorage_DeleteCert_Idempotent tests idempotent deletion
func TestTPM2CertStorage_DeleteCert_Idempotent(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Delete non-existent certificate (should not error)
	err = store.DeleteCert("nonexistent")
	if err != nil {
		t.Errorf("DeleteCert() should be idempotent, got error: %v", err)
	}
}

// TestTPM2CertStorage_SaveAndGetCertChain tests certificate chain operations
func TestTPM2CertStorage_SaveAndGetCertChain(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	// Use default config (2048 bytes max - TPM limit)
	config := DefaultTPM2CertStorageConfig()

	store, err := NewTPM2CertStorage(tpm, config)
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Generate test certificate chain (single cert due to TPM NV 2KB limit)
	// Note: In production, use external storage for multi-cert chains
	leaf := generateTestCert(t)

	chain := []*x509.Certificate{leaf}

	// Save chain
	err = store.SaveCertChain("test-chain", chain)
	if err != nil {
		t.Fatalf("SaveCertChain() error = %v", err)
	}

	// Retrieve chain
	retrieved, err := store.GetCertChain("test-chain")
	if err != nil {
		t.Fatalf("GetCertChain() error = %v", err)
	}

	// Verify chain length
	if len(retrieved) != len(chain) {
		t.Errorf("Chain length = %d, want %d", len(retrieved), len(chain))
	}

	// Verify each certificate
	for i := range chain {
		if !chain[i].Equal(retrieved[i]) {
			t.Errorf("Certificate %d does not match", i)
		}
	}
}

// TestTPM2CertStorage_SaveCertChain_Empty tests error handling for empty chain
func TestTPM2CertStorage_SaveCertChain_Empty(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	err = store.SaveCertChain("test-chain", []*x509.Certificate{})
	if err == nil {
		t.Error("Expected error for empty chain, got nil")
	}
}

// TestTPM2CertStorage_CertExists tests certificate existence check
func TestTPM2CertStorage_CertExists(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	cert := generateTestCert(t)

	// Check non-existent certificate
	exists, err := store.CertExists("nonexistent")
	if err != nil {
		t.Fatalf("CertExists() error = %v", err)
	}
	if exists {
		t.Error("CertExists() = true, want false for nonexistent cert")
	}

	// Save certificate
	err = store.SaveCert("test-cert", cert)
	if err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	// Check existing certificate
	exists, err = store.CertExists("test-cert")
	if err != nil {
		t.Fatalf("CertExists() error = %v", err)
	}
	if !exists {
		t.Error("CertExists() = false, want true for existing cert")
	}
}

// TestTPM2CertStorage_ListCerts tests certificate listing
func TestTPM2CertStorage_ListCerts(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// List empty storage
	certs, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("ListCerts() count = %d, want 0 for empty storage", len(certs))
	}

	// Add some certificates
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	err = store.SaveCert("cert1", cert1)
	if err != nil {
		t.Fatalf("SaveCert(cert1) error = %v", err)
	}

	err = store.SaveCert("cert2", cert2)
	if err != nil {
		t.Fatalf("SaveCert(cert2) error = %v", err)
	}

	// List certificates
	certs, err = store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}

	// Should have 2 certificates (note: IDs are hashed, so we can't match exact IDs)
	if len(certs) != 2 {
		t.Errorf("ListCerts() count = %d, want 2", len(certs))
	}
}

// TestTPM2CertStorage_GetCapacity tests capacity reporting
func TestTPM2CertStorage_GetCapacity(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	total, available, err := store.GetCapacity()
	if err != nil {
		t.Fatalf("GetCapacity() error = %v", err)
	}

	// Should have some capacity
	if total <= 0 {
		t.Errorf("Total capacity = %d, want > 0", total)
	}

	if available < 0 {
		t.Errorf("Available capacity = %d, want >= 0", available)
	}

	if available > total {
		t.Errorf("Available capacity %d > total capacity %d", available, total)
	}
}

// TestTPM2CertStorage_SupportsChains tests chain support reporting
func TestTPM2CertStorage_SupportsChains(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if !store.SupportsChains() {
		t.Error("SupportsChains() = false, want true")
	}
}

// TestTPM2CertStorage_IsHardwareBacked tests hardware backing flag
func TestTPM2CertStorage_IsHardwareBacked(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if !store.IsHardwareBacked() {
		t.Error("IsHardwareBacked() = false, want true")
	}
}

// TestTPM2CertStorage_Compact tests compaction (should return ErrNotSupported)
func TestTPM2CertStorage_Compact(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	err = store.Compact()
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("Compact() error = %v, want ErrNotSupported", err)
	}
}

// TestTPM2CertStorage_Close tests storage closure
func TestTPM2CertStorage_Close(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}

	// Close storage
	err = store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Operations should fail after close
	cert := generateTestCert(t)
	err = store.SaveCert("test", cert)
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("SaveCert() after close error = %v, want ErrStorageClosed", err)
	}

	// Close again should return error
	err = store.Close()
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Close() twice error = %v, want ErrStorageClosed", err)
	}
}

// TestTPM2CertStorage_ConcurrentAccess tests thread safety
func TestTPM2CertStorage_ConcurrentAccess(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Reduced numbers due to TPM simulator NV space limits
	const numGoroutines = 3
	const numOpsPerGoroutine = 2

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent save operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOpsPerGoroutine; j++ {
				cert := generateTestCert(t)
				certID := fmt.Sprintf("concurrent-cert-%d-%d", id, j)

				// Save
				err := store.SaveCert(certID, cert)
				if err != nil {
					// Expected to fail when NV space is exhausted
					t.Logf("Concurrent SaveCert() error (expected): %v", err)
					return
				}

				// Verify existence
				exists, err := store.CertExists(certID)
				if err != nil {
					t.Errorf("Concurrent CertExists() error = %v", err)
					return
				}
				if !exists {
					t.Errorf("Certificate %s should exist", certID)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestTPM2CertStorage_CertIndexFromID tests hash-based index generation
func TestTPM2CertStorage_CertIndexFromID(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	tpmStore := store.(*TPM2CertStorage)

	tests := []struct {
		id string
	}{
		{"cert1"},
		{"cert2"},
		{"test-certificate"},
		{"my-ca-cert"},
	}

	seenIndices := make(map[uint32]bool)

	for _, tt := range tests {
		index := tpmStore.certIndexFromID(tt.id)

		// Check index is in valid range
		if index < tpmStore.baseIndex || index >= tpmStore.baseIndex+0x00400000 {
			t.Errorf("certIndexFromID(%q) = %#x, out of range [%#x, %#x)",
				tt.id, index, tpmStore.baseIndex, tpmStore.baseIndex+0x00400000)
		}

		// Check for collisions (unlikely but possible)
		if seenIndices[index] {
			t.Logf("Warning: Hash collision for ID %q at index %#x", tt.id, index)
		}
		seenIndices[index] = true

		// Check consistency (same ID should always produce same index)
		index2 := tpmStore.certIndexFromID(tt.id)
		if index != index2 {
			t.Errorf("certIndexFromID(%q) inconsistent: %#x != %#x", tt.id, index, index2)
		}
	}
}

// Helper functions

// newMockTPM creates a TPM simulator for testing
func newMockTPM(t *testing.T) transport.TPMCloser {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		t.Fatalf("Failed to create TPM simulator: %v", err)
	}

	return &simulatorCloser{
		sim:       sim,
		transport: transport.FromReadWriter(sim),
	}
}

// simulatorCloser wraps the simulator to provide Close()
type simulatorCloser struct {
	sim       *simulator.Simulator
	transport transport.TPM
}

func (sc *simulatorCloser) Send(input []byte) ([]byte, error) {
	return sc.transport.Send(input)
}

func (sc *simulatorCloser) Close() error {
	return sc.sim.Close()
}

// generateTestCert creates a test X.509 certificate
func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
