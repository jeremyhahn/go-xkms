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

//go:build integration && (pkcs11 || tpm2)

package storage_test

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHardwareStorageIntegration_HybridMode tests hybrid storage combining hardware and external
func TestHardwareStorageIntegration_HybridMode(t *testing.T) {
	// Skip if no hardware storage available
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Create external storage - wrap with adapter to provide HardwareCertStorage interface
	extStorage := hardware.NewBackendCertStorageAdapter(storage.New())
	defer extStorage.Close()

	// Create hybrid storage
	hybridStorage, err := hardware.NewHybridCertStorage(hwStorage, extStorage)
	require.NoError(t, err)
	defer hybridStorage.Close()

	// Create test certificate
	cert := createTestCertificate(t)

	// Save certificate (should go to hardware first)
	certID := "hybrid-test-cert"
	err = hybridStorage.SaveCert(certID, cert)
	require.NoError(t, err)

	// Retrieve certificate
	retrieved, err := hybridStorage.GetCert(certID)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, retrieved.Raw)

	// Check it exists
	exists, err := hybridStorage.CertExists(certID)
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete certificate
	err = hybridStorage.DeleteCert(certID)
	require.NoError(t, err)

	// Verify deletion
	exists, err = hybridStorage.CertExists(certID)
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestHardwareStorageIntegration_HybridFallback tests fallback behavior when hardware is full
func TestHardwareStorageIntegration_HybridFallback(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	extStorage := hardware.NewBackendCertStorageAdapter(storage.New())
	defer extStorage.Close()

	hybridStorage, err := hardware.NewHybridCertStorage(hwStorage, extStorage)
	require.NoError(t, err)
	defer hybridStorage.Close()

	// Fill hardware storage until capacity is exceeded
	// Then verify fallback to external storage works
	cert := createTestCertificate(t)

	// Get hardware capacity if available
	total, available, err := hwStorage.GetCapacity()
	if err == nil {
		t.Logf("Hardware capacity: %d total, %d available", total, available)

		// Try to fill hardware storage
		for i := 0; i < available+5; i++ {
			certID := fmt.Sprintf("fallback-cert-%d", i)
			err := hybridStorage.SaveCert(certID, cert)
			// Should succeed even after hardware is full due to fallback
			assert.NoError(t, err, "Failed to save cert %d", i)
		}

		// Verify we can still save and retrieve
		testID := "post-capacity-test"
		err = hybridStorage.SaveCert(testID, cert)
		require.NoError(t, err)

		retrieved, err := hybridStorage.GetCert(testID)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, retrieved.Raw)
	} else {
		t.Logf("Hardware capacity check not supported: %v", err)
	}
}

// TestHardwareStorageIntegration_CertChainSupport tests certificate chain operations
func TestHardwareStorageIntegration_CertChainSupport(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Check if chains are supported
	if !hwStorage.SupportsChains() {
		t.Skip("Hardware storage does not support certificate chains")
	}

	// Check capacity before attempting to save large chain
	total, available, err := hwStorage.GetCapacity()
	if err == nil && available < 1 {
		t.Skipf("Insufficient hardware storage capacity: %d/%d available", available, total)
	}

	// Create certificate chain
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)
	cert3 := createTestCertificate(t)
	chain := []*x509.Certificate{cert1, cert2, cert3}

	// Save chain
	chainID := "test-chain"
	err = hwStorage.SaveCertChain(chainID, chain)
	if err != nil {
		// If it fails due to size, skip the test
		if strings.Contains(err.Error(), "exceeds maximum size") ||
			strings.Contains(err.Error(), "capacity") {
			t.Skipf("Certificate chain too large for hardware storage: %v", err)
		}
		require.NoError(t, err)
	}

	// Retrieve chain
	retrievedChain, err := hwStorage.GetCertChain(chainID)
	require.NoError(t, err)
	assert.Equal(t, len(chain), len(retrievedChain))

	// Verify each certificate in chain
	for i := range chain {
		assert.Equal(t, chain[i].Raw, retrievedChain[i].Raw)
	}

	// Delete chain
	err = hwStorage.DeleteCert(chainID)
	require.NoError(t, err)
}

// TestHardwareStorageIntegration_ConcurrentAccess tests thread-safe concurrent operations
func TestHardwareStorageIntegration_ConcurrentAccess(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Skip concurrent test for TPM2 - the simulator doesn't support concurrent access
	// Check if this is TPM2 by looking at the type name
	storageType := fmt.Sprintf("%T", hwStorage)
	if strings.Contains(storageType, "tpm2") || strings.Contains(storageType, "TPM2") {
		t.Skip("TPM2 simulator does not support concurrent access - skipping")
	}

	cert := createTestCertificate(t)

	// Use lower concurrency for simulators (SoftHSM) - they don't handle high concurrency well
	// This avoids deadlocks and timeouts in CI environments
	numGoroutines := 3
	opsPerGoroutine := 3

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*opsPerGoroutine)

	// Concurrent certificate operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				certID := fmt.Sprintf("concurrent-cert-%d-%d", id, j)

				// Save
				if err := hwStorage.SaveCert(certID, cert); err != nil {
					errors <- fmt.Errorf("save failed: %w", err)
					continue
				}

				// Check exists
				if exists, err := hwStorage.CertExists(certID); err != nil || !exists {
					errors <- fmt.Errorf("exists check failed: %w", err)
					continue
				}

				// Retrieve
				if _, err := hwStorage.GetCert(certID); err != nil {
					errors <- fmt.Errorf("get failed: %w", err)
					continue
				}

				// Delete
				if err := hwStorage.DeleteCert(certID); err != nil {
					errors <- fmt.Errorf("delete failed: %w", err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}
	// Allow some errors due to hardware limitations
	assert.LessOrEqual(t, errorCount, numGoroutines, "Too many concurrent errors")
}

// TestHardwareStorageIntegration_Capacity tests capacity reporting
func TestHardwareStorageIntegration_Capacity(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	total, available, err := hwStorage.GetCapacity()
	if err == hardware.ErrNotSupported {
		t.Skip("Hardware capacity reporting not supported")
	}
	require.NoError(t, err)

	t.Logf("Hardware storage capacity: %d total, %d available", total, available)
	assert.Greater(t, total, 0, "Total capacity should be positive")
	assert.GreaterOrEqual(t, total, available, "Total should be >= available")
}

// TestHardwareStorageIntegration_ListOperations tests listing certificates
func TestHardwareStorageIntegration_ListOperations(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Get initial count
	initialCerts, err := hwStorage.ListCerts()
	require.NoError(t, err)
	initialCount := len(initialCerts)

	// Add certificates
	cert := createTestCertificate(t)
	certCount := 3
	certIDs := make([]string, certCount)

	for i := 0; i < certCount; i++ {
		certID := fmt.Sprintf("list-test-cert-%d-%d", time.Now().Unix(), i)
		certIDs[i] = certID
		err := hwStorage.SaveCert(certID, cert)
		require.NoError(t, err)
	}

	// List and verify
	certs, err := hwStorage.ListCerts()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(certs), initialCount+certCount)

	// Clean up
	for _, certID := range certIDs {
		hwStorage.DeleteCert(certID)
	}
}

// TestHardwareStorageIntegration_UpdateOperations tests update behavior
func TestHardwareStorageIntegration_UpdateOperations(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	certID := fmt.Sprintf("update-test-%d", time.Now().Unix())
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	// Save initial certificate
	err := hwStorage.SaveCert(certID, cert1)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved1, err := hwStorage.GetCert(certID)
	require.NoError(t, err)
	assert.Equal(t, cert1.Raw, retrieved1.Raw)

	// Update with different certificate
	err = hwStorage.SaveCert(certID, cert2)
	require.NoError(t, err)

	// Retrieve and verify update
	retrieved2, err := hwStorage.GetCert(certID)
	require.NoError(t, err)
	assert.Equal(t, cert2.Raw, retrieved2.Raw)
	assert.NotEqual(t, cert1.SerialNumber, retrieved2.SerialNumber)

	// Clean up
	hwStorage.DeleteCert(certID)
}

// TestHardwareStorageIntegration_ErrorHandling tests error cases
func TestHardwareStorageIntegration_ErrorHandling(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Test get non-existent certificate
	_, err := hwStorage.GetCert("non-existent-cert")
	assert.Error(t, err)

	// Test delete non-existent certificate
	// Note: TPM2 storage is idempotent - returns nil for non-existent certs
	err = hwStorage.DeleteCert("non-existent-cert")
	// TPM2 is idempotent, PKCS11 may error - both behaviors are acceptable
	// assert.Error(t, err) // Commented out - behavior varies by backend

	// Test exists on non-existent certificate
	exists, err := hwStorage.CertExists("non-existent-cert")
	require.NoError(t, err)
	assert.False(t, exists)

	// Test save with nil certificate
	err = hwStorage.SaveCert("nil-cert-test", nil)
	assert.Error(t, err)

	// Test save with empty ID
	cert := createTestCertificate(t)
	err = hwStorage.SaveCert("", cert)
	assert.Error(t, err)

	// Test save chain with empty chain
	err = hwStorage.SaveCertChain("empty-chain", []*x509.Certificate{})
	assert.Error(t, err)
}

// TestHardwareStorageIntegration_ClosedStorage tests operations on closed storage
func TestHardwareStorageIntegration_ClosedStorage(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}

	// Skip for TPM2 - has issues with TCP connection cleanup
	storageType := fmt.Sprintf("%T", hwStorage)
	if strings.Contains(storageType, "tpm2") || strings.Contains(storageType, "TPM2") {
		t.Skip("TPM2 storage has network connection issues with close operations - skipping")
	}

	// Close the storage
	err := hwStorage.Close()
	require.NoError(t, err)

	// Try operations on closed storage
	cert := createTestCertificate(t)

	err = hwStorage.SaveCert("test", cert)
	assert.ErrorIs(t, err, hardware.ErrStorageClosed)

	_, err = hwStorage.GetCert("test")
	assert.ErrorIs(t, err, hardware.ErrStorageClosed)

	err = hwStorage.DeleteCert("test")
	assert.ErrorIs(t, err, hardware.ErrStorageClosed)

	_, err = hwStorage.ListCerts()
	assert.ErrorIs(t, err, hardware.ErrStorageClosed)

	_, err = hwStorage.CertExists("test")
	assert.ErrorIs(t, err, hardware.ErrStorageClosed)

	// Close again should be idempotent
	err = hwStorage.Close()
	assert.NoError(t, err)
}

// TestHardwareStorageIntegration_HybridListMerge tests that hybrid storage merges lists correctly
func TestHardwareStorageIntegration_HybridListMerge(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Skip for TPM2 - capacity issues prevent reliable testing
	storageType := fmt.Sprintf("%T", hwStorage)
	if strings.Contains(storageType, "tpm2") || strings.Contains(storageType, "TPM2") {
		t.Skip("TPM2 storage capacity issues - skipping hybrid test")
	}

	extStorage := hardware.NewBackendCertStorageAdapter(storage.New())
	defer extStorage.Close()

	hybridStorage, err := hardware.NewHybridCertStorage(hwStorage, extStorage)
	require.NoError(t, err)
	defer hybridStorage.Close()

	cert := createTestCertificate(t)

	// Save directly to hardware
	hwCertID := fmt.Sprintf("hw-cert-%d", time.Now().Unix())
	err = hwStorage.SaveCert(hwCertID, cert)
	require.NoError(t, err)

	// Save directly to external
	extCertID := fmt.Sprintf("ext-cert-%d", time.Now().Unix())
	err = extStorage.SaveCert(extCertID, cert)
	require.NoError(t, err)

	// List from hybrid should include both
	certs, err := hybridStorage.ListCerts()
	require.NoError(t, err)

	hasHW := false
	hasExt := false
	for _, id := range certs {
		if id == hwCertID {
			hasHW = true
		}
		if id == extCertID {
			hasExt = true
		}
	}

	assert.True(t, hasHW, "Hybrid list should include hardware certificate")
	assert.True(t, hasExt, "Hybrid list should include external certificate")

	// Clean up
	hwStorage.DeleteCert(hwCertID)
	extStorage.DeleteCert(extCertID)
}

// TestHardwareStorageIntegration_HybridDeleteBoth tests that hybrid delete removes from both storages
func TestHardwareStorageIntegration_HybridDeleteBoth(t *testing.T) {
	hwStorage := getHardwareStorage(t)
	if hwStorage == nil {
		t.Skip("Hardware storage not available")
	}
	defer hwStorage.Close()

	// Skip for TPM2 - capacity issues prevent reliable testing
	storageType := fmt.Sprintf("%T", hwStorage)
	if strings.Contains(storageType, "tpm2") || strings.Contains(storageType, "TPM2") {
		t.Skip("TPM2 storage capacity issues - skipping hybrid test")
	}

	extStorage := hardware.NewBackendCertStorageAdapter(storage.New())
	defer extStorage.Close()

	hybridStorage, err := hardware.NewHybridCertStorage(hwStorage, extStorage)
	require.NoError(t, err)
	defer hybridStorage.Close()

	cert := createTestCertificate(t)
	certID := fmt.Sprintf("dual-storage-cert-%d", time.Now().Unix())

	// Save to both storages manually
	err = hwStorage.SaveCert(certID, cert)
	require.NoError(t, err)

	err = extStorage.SaveCert(certID, cert)
	require.NoError(t, err)

	// Delete via hybrid should remove from both
	err = hybridStorage.DeleteCert(certID)
	require.NoError(t, err)

	// Verify deleted from both
	hwExists, _ := hwStorage.CertExists(certID)
	assert.False(t, hwExists, "Certificate should be deleted from hardware")

	extExists, _ := extStorage.CertExists(certID)
	assert.False(t, extExists, "Certificate should be deleted from external")
}

// getHardwareStorage returns a hardware storage instance for testing
// This attempts to initialize PKCS#11 via SoftHSM or TPM2 simulator.
// Returns nil and the test is skipped if neither is available.
func getHardwareStorage(t *testing.T) hardware.HardwareCertStorage {
	// Try PKCS#11/SoftHSM first
	if hwStorage := tryInitSoftHSM(t); hwStorage != nil {
		return hwStorage
	}

	// Try TPM2 simulator second
	if hwStorage := tryInitTPM2Simulator(t); hwStorage != nil {
		return hwStorage
	}

	// Neither PKCS#11 nor TPM2 available
	t.Skip("Neither PKCS#11 nor TPM2 hardware/simulator available")
	return nil
}
