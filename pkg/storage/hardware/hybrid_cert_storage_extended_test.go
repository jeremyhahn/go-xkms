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

package hardware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertForHybrid creates a test certificate
func generateTestCertForHybrid(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestNewHybridCertStorageFromBackend tests the constructor using a storage.Backend
func TestNewHybridCertStorageFromBackend(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		backend := storage.NewMemory()

		hybrid, err := NewHybridCertStorageFromBackend(hw, backend)
		require.NoError(t, err)
		require.NotNil(t, hybrid)
	})

	t.Run("NilHardware", func(t *testing.T) {
		backend := storage.NewMemory()

		hybrid, err := NewHybridCertStorageFromBackend(nil, backend)
		require.Error(t, err)
		require.Nil(t, hybrid)
		assert.ErrorIs(t, err, ErrNilStorage)
	})

	t.Run("NilBackend", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)

		hybrid, err := NewHybridCertStorageFromBackend(hw, nil)
		require.Error(t, err)
		require.Nil(t, hybrid)
		assert.ErrorIs(t, err, ErrNilStorage)
	})
}

// TestHybridCertStorage_GetCapacity tests GetCapacity operation
func TestHybridCertStorage_GetCapacity(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		total, available, err := hybrid.GetCapacity()
		require.NoError(t, err)
		assert.Equal(t, 10, total)
		assert.Equal(t, 10, available)
	})

	t.Run("AfterSavingCert", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		cert := generateTestCertForHybrid(t, "test")
		err = hybrid.SaveCert("test-cert", cert)
		require.NoError(t, err)

		total, available, err := hybrid.GetCapacity()
		require.NoError(t, err)
		assert.Equal(t, 10, total)
		assert.Equal(t, 9, available) // One slot used
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		err = hybrid.Close()
		require.NoError(t, err)

		_, _, err = hybrid.GetCapacity()
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_SupportsChains tests SupportsChains operation
func TestHybridCertStorage_SupportsChains(t *testing.T) {
	t.Run("SupportsChains", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.supportsChains = true
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		assert.True(t, hybrid.SupportsChains())
	})

	t.Run("DoesNotSupportChains", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.supportsChains = false
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		assert.False(t, hybrid.SupportsChains())
	})
}

// TestHybridCertStorage_IsHardwareBacked tests IsHardwareBacked operation
func TestHybridCertStorage_IsHardwareBacked(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	assert.True(t, hybrid.IsHardwareBacked())
}

// TestHybridCertStorage_Compact tests Compact operation
func TestHybridCertStorage_Compact(t *testing.T) {
	t.Run("ReturnsHardwareError", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		// Mock returns ErrNotSupported for Compact
		err = hybrid.Compact()
		require.Error(t, err)
		assert.Equal(t, ErrNotSupported, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)

		err = hybrid.Close()
		require.NoError(t, err)

		err = hybrid.Compact()
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_SaveCert_NonCapacityHardwareError tests hardware save errors
// that are not capacity-related
func TestHybridCertStorage_SaveCert_NonCapacityHardwareError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.failSave = true // Generic save failure, not capacity
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")

	// Should return error without falling back to external
	err = hybrid.SaveCert("test-cert", cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware storage failed")

	// Verify NOT stored in external
	_, err = ext.GetCert("test-cert")
	assert.Equal(t, storage.ErrNotFound, err)
}

// TestHybridCertStorage_GetCert_HardwareError tests hardware get errors
func TestHybridCertStorage_GetCert_HardwareError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.failGet = true // Non-transient error
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")

	// Save to external
	err = ext.SaveCert("test-cert", cert)
	require.NoError(t, err)

	// Get should fail because hardware error is not ErrNotFound
	_, err = hybrid.GetCert("test-cert")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware storage failed")
}

// TestHybridCertStorage_GetCert_ExternalError tests external get errors
func TestHybridCertStorage_GetCert_ExternalError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := newMockExternalCertStorage()
	ext.failGet = true
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	// Certificate not in hardware, external fails
	_, err = hybrid.GetCert("test-cert")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external storage failed")
}

// TestHybridCertStorage_SaveCertChain_NonCapacityHardwareError tests chain save with
// non-capacity hardware errors
func TestHybridCertStorage_SaveCertChain_NonCapacityHardwareError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.failSave = true // Generic error
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")
	chain := []*x509.Certificate{cert}

	err = hybrid.SaveCertChain("test-chain", chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware storage failed")
}

// TestHybridCertStorage_SaveCertChain_InvalidID tests empty ID validation
func TestHybridCertStorage_SaveCertChain_InvalidID(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")
	chain := []*x509.Certificate{cert}

	err = hybrid.SaveCertChain("", chain)
	require.Error(t, err)
	assert.Equal(t, storage.ErrInvalidID, err)
}

// TestHybridCertStorage_GetCertChain_InvalidID tests empty ID validation
func TestHybridCertStorage_GetCertChain_InvalidID(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	_, err = hybrid.GetCertChain("")
	require.Error(t, err)
	assert.Equal(t, storage.ErrInvalidID, err)
}

// TestHybridCertStorage_GetCertChain_HardwareError tests hardware chain get errors
func TestHybridCertStorage_GetCertChain_HardwareError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.failGet = true
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	_, err = hybrid.GetCertChain("test-chain")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware storage failed")
}

// TestHybridCertStorage_GetCertChain_ExternalError tests external chain get errors
func TestHybridCertStorage_GetCertChain_ExternalError(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := newMockExternalCertStorage()
	ext.failGet = true
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	// Not in hardware
	_, err = hybrid.GetCertChain("test-chain")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external storage failed")
}

// TestHybridCertStorage_SaveCertChain_BothFail tests both storages failing
func TestHybridCertStorage_SaveCertChain_BothFail(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.returnCapacity = true
	ext := newMockExternalCertStorage()
	ext.failSave = true
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")
	chain := []*x509.Certificate{cert}

	err = hybrid.SaveCertChain("test-chain", chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware storage failed")
	assert.Contains(t, err.Error(), "external storage failed")
}

// TestHybridCertStorage_Close_HardwareFails tests close when hardware fails
func TestHybridCertStorage_Close_HardwareFails(t *testing.T) {
	hw := &mockHardwareCertStorageWithCloseError{
		mockHardwareCertStorage: newMockHardwareCertStorage(10),
		closeErr:                errors.New("hardware close error"),
	}
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	err = hybrid.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware close failed")
}

// TestHybridCertStorage_Close_ExternalFails tests close when external fails
func TestHybridCertStorage_Close_ExternalFails(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	ext := &mockExternalCertStorageWithCloseError{
		mockExternalCertStorage: newMockExternalCertStorage(),
		closeErr:                errors.New("external close error"),
	}
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	err = hybrid.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external close failed")
}

// TestHybridCertStorage_Close_BothFail tests close when both fail
func TestHybridCertStorage_Close_BothFail(t *testing.T) {
	hw := &mockHardwareCertStorageWithCloseError{
		mockHardwareCertStorage: newMockHardwareCertStorage(10),
		closeErr:                errors.New("hardware close error"),
	}
	ext := &mockExternalCertStorageWithCloseError{
		mockExternalCertStorage: newMockExternalCertStorage(),
		closeErr:                errors.New("external close error"),
	}
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	err = hybrid.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardware close failed")
	assert.Contains(t, err.Error(), "external close failed")
}

// TestHybridCertStorage_CertExists_HardwareCheckFails tests existence check when
// hardware returns error but exists in external
func TestHybridCertStorage_CertExists_HardwareCheckFails(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	hw.failExists = true
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	cert := generateTestCertForHybrid(t, "test")
	err = ext.SaveCert("test-cert", cert)
	require.NoError(t, err)

	// Should still find in external
	exists, err := hybrid.CertExists("test-cert")
	require.NoError(t, err)
	assert.True(t, exists)
}

// mockHardwareCertStorageWithCloseError wraps mockHardwareCertStorage to return error on Close
type mockHardwareCertStorageWithCloseError struct {
	*mockHardwareCertStorage
	closeErr error
}

func (m *mockHardwareCertStorageWithCloseError) Close() error {
	if m.closeErr != nil {
		return m.closeErr
	}
	return m.mockHardwareCertStorage.Close()
}

// mockExternalCertStorageWithCloseError wraps mockExternalCertStorage to return error on Close
type mockExternalCertStorageWithCloseError struct {
	*mockExternalCertStorage
	closeErr error
}

func (m *mockExternalCertStorageWithCloseError) Close() error {
	if m.closeErr != nil {
		return m.closeErr
	}
	return m.mockExternalCertStorage.Close()
}

// TestHybridCertStorage_FullWorkflow tests complete workflow
func TestHybridCertStorage_FullWorkflow(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	backend := storage.NewMemory()
	hybrid, err := NewHybridCertStorageFromBackend(hw, backend)
	require.NoError(t, err)

	// Save certificates
	cert1 := generateTestCertForHybrid(t, "cert1")
	cert2 := generateTestCertForHybrid(t, "cert2")

	err = hybrid.SaveCert("cert-1", cert1)
	require.NoError(t, err)

	err = hybrid.SaveCert("cert-2", cert2)
	require.NoError(t, err)

	// Save chain
	chain := []*x509.Certificate{cert1, cert2}
	err = hybrid.SaveCertChain("my-chain", chain)
	require.NoError(t, err)

	// Check existence
	exists, err := hybrid.CertExists("cert-1")
	require.NoError(t, err)
	assert.True(t, exists)

	// List certificates
	ids, err := hybrid.ListCerts()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ids), 2)

	// Get certificate
	retrieved, err := hybrid.GetCert("cert-1")
	require.NoError(t, err)
	assert.True(t, cert1.Equal(retrieved))

	// Get chain
	retrievedChain, err := hybrid.GetCertChain("my-chain")
	require.NoError(t, err)
	assert.Len(t, retrievedChain, 2)

	// Get capacity
	total, available, err := hybrid.GetCapacity()
	require.NoError(t, err)
	assert.Equal(t, 10, total)
	assert.Less(t, available, total)

	// Delete certificate
	err = hybrid.DeleteCert("cert-1")
	require.NoError(t, err)

	exists, err = hybrid.CertExists("cert-1")
	require.NoError(t, err)
	assert.False(t, exists)

	// Close
	err = hybrid.Close()
	require.NoError(t, err)
}

// TestHybridCertStorage_ThreadSafety_Extended tests thread safety with more operations
func TestHybridCertStorage_ThreadSafety_Extended(t *testing.T) {
	hw := newMockHardwareCertStorage(100)
	ext := newMockExternalCertStorage()
	hybrid, err := NewHybridCertStorage(hw, ext)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 5
	numOps := 20

	// Concurrent save/get/delete operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				cert := generateTestCertForHybrid(t, "test")
				certID := "thread-cert"

				// Save
				_ = hybrid.SaveCert(certID, cert)

				// Get
				_, _ = hybrid.GetCert(certID)

				// Exists
				_, _ = hybrid.CertExists(certID)

				// List
				_, _ = hybrid.ListCerts()

				// Capacity
				_, _, _ = hybrid.GetCapacity()

				// Delete
				_ = hybrid.DeleteCert(certID)
			}
		}(i)
	}

	wg.Wait()
}

// TestHybridCertStorage_InterfaceCompliance verifies interface implementation
func TestHybridCertStorage_InterfaceCompliance(t *testing.T) {
	var _ HardwareCertStorage = (*HybridCertStorage)(nil)
}
