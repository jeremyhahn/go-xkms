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

//go:build tpm2 || pkcs11

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

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHardwareCertStorage is a mock implementation of HardwareCertStorage for testing
type mockHardwareCertStorage struct {
	certs             map[string]*x509.Certificate
	chains            map[string][]*x509.Certificate
	capacity          int
	available         int
	supportsChains    bool
	closed            bool
	failSave          bool
	failGet           bool
	failDelete        bool
	failList          bool
	failExists        bool
	returnNotFound    bool
	returnCapacity    bool
	returnUnavailable bool
	mu                sync.RWMutex
}

func newMockHardwareCertStorage(capacity int) *mockHardwareCertStorage {
	return &mockHardwareCertStorage{
		certs:          make(map[string]*x509.Certificate),
		chains:         make(map[string][]*x509.Certificate),
		capacity:       capacity,
		available:      capacity,
		supportsChains: true,
		closed:         false,
	}
}

func (m *mockHardwareCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}
	if m.failSave {
		return errors.New("mock save error")
	}
	if m.returnUnavailable {
		return ErrHardwareUnavailable
	}
	if m.returnCapacity {
		return ErrCapacityExceeded
	}
	if m.available <= 0 {
		return ErrCapacityExceeded
	}
	if id == "" {
		return storage.ErrInvalidID
	}
	if cert == nil {
		return storage.ErrInvalidData
	}

	_, exists := m.certs[id]
	if !exists {
		m.available--
	}
	m.certs[id] = cert
	return nil
}

func (m *mockHardwareCertStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}
	if m.failGet {
		return nil, errors.New("mock get error")
	}
	if m.returnUnavailable {
		return nil, ErrHardwareUnavailable
	}
	if id == "" {
		return nil, storage.ErrInvalidID
	}
	if m.returnNotFound {
		return nil, storage.ErrNotFound
	}

	cert, exists := m.certs[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (m *mockHardwareCertStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}
	if m.failDelete {
		return errors.New("mock delete error")
	}
	if id == "" {
		return storage.ErrInvalidID
	}

	_, certExists := m.certs[id]
	_, chainExists := m.chains[id]

	if !certExists && !chainExists {
		return storage.ErrNotFound
	}

	if certExists {
		delete(m.certs, id)
		m.available++
	}
	if chainExists {
		delete(m.chains, id)
		m.available++
	}

	return nil
}

func (m *mockHardwareCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}
	if m.failSave {
		return errors.New("mock save error")
	}
	if m.returnUnavailable {
		return ErrHardwareUnavailable
	}
	if m.returnCapacity {
		return ErrCapacityExceeded
	}
	if m.available <= 0 {
		return ErrCapacityExceeded
	}
	if id == "" {
		return storage.ErrInvalidID
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	for _, cert := range chain {
		if cert == nil {
			return storage.ErrInvalidData
		}
	}

	_, exists := m.chains[id]
	if !exists {
		m.available--
	}

	// Make a copy
	chainCopy := make([]*x509.Certificate, len(chain))
	copy(chainCopy, chain)
	m.chains[id] = chainCopy
	return nil
}

func (m *mockHardwareCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}
	if m.failGet {
		return nil, errors.New("mock get error")
	}
	if m.returnUnavailable {
		return nil, ErrHardwareUnavailable
	}
	if id == "" {
		return nil, storage.ErrInvalidID
	}
	if m.returnNotFound {
		return nil, storage.ErrNotFound
	}

	chain, exists := m.chains[id]
	if !exists {
		return nil, storage.ErrNotFound
	}

	// Return a copy
	chainCopy := make([]*x509.Certificate, len(chain))
	copy(chainCopy, chain)
	return chainCopy, nil
}

func (m *mockHardwareCertStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}
	if m.failList {
		return nil, errors.New("mock list error")
	}

	// Use a map to deduplicate
	idMap := make(map[string]bool)
	for id := range m.certs {
		idMap[id] = true
	}
	for id := range m.chains {
		idMap[id] = true
	}

	result := make([]string, 0, len(idMap))
	for id := range idMap {
		result = append(result, id)
	}
	return result, nil
}

func (m *mockHardwareCertStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, ErrStorageClosed
	}
	if m.failExists {
		return false, errors.New("mock exists error")
	}
	if id == "" {
		return false, storage.ErrInvalidID
	}

	_, certExists := m.certs[id]
	_, chainExists := m.chains[id]
	return certExists || chainExists, nil
}

func (m *mockHardwareCertStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.certs = nil
	m.chains = nil
	return nil
}

func (m *mockHardwareCertStorage) GetCapacity() (total int, available int, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.capacity, m.available, nil
}

func (m *mockHardwareCertStorage) SupportsChains() bool {
	return m.supportsChains
}

func (m *mockHardwareCertStorage) IsHardwareBacked() bool {
	return true
}

func (m *mockHardwareCertStorage) Compact() error {
	return ErrNotSupported
}

// mockExternalCertStorage is a simple mock for external storage
type mockExternalCertStorage struct {
	certs      map[string]*x509.Certificate
	chains     map[string][]*x509.Certificate
	closed     bool
	failSave   bool
	failGet    bool
	failDelete bool
	failList   bool
	failExists bool
	mu         sync.RWMutex
}

func newMockExternalCertStorage() *mockExternalCertStorage {
	return &mockExternalCertStorage{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
		closed: false,
	}
}

func (m *mockExternalCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return storage.ErrClosed
	}
	if m.failSave {
		return errors.New("mock external save error")
	}
	if id == "" {
		return storage.ErrInvalidID
	}
	if cert == nil {
		return storage.ErrInvalidData
	}

	m.certs[id] = cert
	return nil
}

func (m *mockExternalCertStorage) GetCert(id string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, storage.ErrClosed
	}
	if m.failGet {
		return nil, errors.New("mock external get error")
	}
	if id == "" {
		return nil, storage.ErrInvalidID
	}

	cert, exists := m.certs[id]
	if !exists {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (m *mockExternalCertStorage) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return storage.ErrClosed
	}
	if m.failDelete {
		return errors.New("mock external delete error")
	}
	if id == "" {
		return storage.ErrInvalidID
	}

	_, certExists := m.certs[id]
	_, chainExists := m.chains[id]

	if !certExists && !chainExists {
		return storage.ErrNotFound
	}

	delete(m.certs, id)
	delete(m.chains, id)
	return nil
}

func (m *mockExternalCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return storage.ErrClosed
	}
	if m.failSave {
		return errors.New("mock external save error")
	}
	if id == "" {
		return storage.ErrInvalidID
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	for _, cert := range chain {
		if cert == nil {
			return storage.ErrInvalidData
		}
	}

	chainCopy := make([]*x509.Certificate, len(chain))
	copy(chainCopy, chain)
	m.chains[id] = chainCopy
	return nil
}

func (m *mockExternalCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, storage.ErrClosed
	}
	if m.failGet {
		return nil, errors.New("mock external get error")
	}
	if id == "" {
		return nil, storage.ErrInvalidID
	}

	chain, exists := m.chains[id]
	if !exists {
		return nil, storage.ErrNotFound
	}

	chainCopy := make([]*x509.Certificate, len(chain))
	copy(chainCopy, chain)
	return chainCopy, nil
}

func (m *mockExternalCertStorage) ListCerts() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, storage.ErrClosed
	}
	if m.failList {
		return nil, errors.New("mock external list error")
	}

	idMap := make(map[string]bool)
	for id := range m.certs {
		idMap[id] = true
	}
	for id := range m.chains {
		idMap[id] = true
	}

	result := make([]string, 0, len(idMap))
	for id := range idMap {
		result = append(result, id)
	}
	return result, nil
}

func (m *mockExternalCertStorage) CertExists(id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, storage.ErrClosed
	}
	if m.failExists {
		return false, errors.New("mock external exists error")
	}
	if id == "" {
		return false, storage.ErrInvalidID
	}

	_, certExists := m.certs[id]
	_, chainExists := m.chains[id]
	return certExists || chainExists, nil
}

func (m *mockExternalCertStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.certs = nil
	m.chains = nil
	return nil
}

func (m *mockExternalCertStorage) GetCapacity() (total int, available int, err error) {
	return 0, 0, ErrNotSupported
}

func (m *mockExternalCertStorage) SupportsChains() bool {
	return true
}

func (m *mockExternalCertStorage) IsHardwareBacked() bool {
	return false
}

func (m *mockExternalCertStorage) Compact() error {
	return ErrNotSupported
}

// Helper function to create a test certificate
func createTestCertificate(cn string) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// TestNewHybridCertStorage tests the constructor
func TestNewHybridCertStorage(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()

		hybrid, err := NewHybridCertStorage(hw, ext)
		require.NoError(t, err)
		require.NotNil(t, hybrid)
	})

	t.Run("NilHardware", func(t *testing.T) {
		ext := newMockExternalCertStorage()

		hybrid, err := NewHybridCertStorage(nil, ext)
		require.Error(t, err)
		require.Nil(t, hybrid)
		assert.ErrorIs(t, err, ErrNilStorage)
	})

	t.Run("NilExternal", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)

		hybrid, err := NewHybridCertStorage(hw, nil)
		require.Error(t, err)
		require.Nil(t, hybrid)
		assert.ErrorIs(t, err, ErrNilStorage)
	})
}

// TestHybridCertStorage_SaveCert tests certificate saving
func TestHybridCertStorage_SaveCert(t *testing.T) {
	t.Run("SaveToHardwareSuccess", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		err = hybrid.SaveCert("test", cert)
		require.NoError(t, err)

		// Should be in hardware
		hwCert, err := hw.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, hwCert)

		// Should NOT be in external
		_, err = ext.GetCert("test")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("FallbackToExternalOnCapacity", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.returnCapacity = true // Simulate capacity exceeded
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		err = hybrid.SaveCert("test", cert)
		require.NoError(t, err)

		// Should be in external
		extCert, err := ext.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, extCert)
	})

	t.Run("FallbackToExternalOnHardwareUnavailable", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.returnUnavailable = true
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		err = hybrid.SaveCert("test", cert)
		require.NoError(t, err)

		// Should be in external
		extCert, err := ext.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, extCert)
	})

	t.Run("BothStoragesFail", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.returnCapacity = true
		ext := newMockExternalCertStorage()
		ext.failSave = true
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		err = hybrid.SaveCert("test", cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware storage failed")
		assert.Contains(t, err.Error(), "external storage failed")
	})

	t.Run("InvalidID", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		err = hybrid.SaveCert("", cert)
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("NilCertificate", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.SaveCert("test", nil)
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidData, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		hybrid.Close()

		err = hybrid.SaveCert("test", cert)
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_GetCert tests certificate retrieval
func TestHybridCertStorage_GetCert(t *testing.T) {
	t.Run("GetFromHardware", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to hardware
		err = hw.SaveCert("test", cert)
		require.NoError(t, err)

		// Get should find it in hardware
		retrieved, err := hybrid.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, retrieved)
	})

	t.Run("GetFromExternalWhenNotInHardware", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to external only
		err = ext.SaveCert("test", cert)
		require.NoError(t, err)

		// Get should fall back to external
		retrieved, err := hybrid.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, retrieved)
	})

	t.Run("GetFromExternalWhenHardwareUnavailable", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.returnUnavailable = true
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to external
		err = ext.SaveCert("test", cert)
		require.NoError(t, err)

		// Get should fall back to external
		retrieved, err := hybrid.GetCert("test")
		require.NoError(t, err)
		assert.Equal(t, cert, retrieved)
	})

	t.Run("NotFoundInBothStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.GetCert("nonexistent")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("InvalidID", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.GetCert("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		hybrid.Close()

		_, err := hybrid.GetCert("test")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_DeleteCert tests certificate deletion
func TestHybridCertStorage_DeleteCert(t *testing.T) {
	t.Run("DeleteFromBothStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to both
		hw.SaveCert("test", cert)
		ext.SaveCert("test", cert)

		// Delete should remove from both
		err = hybrid.DeleteCert("test")
		require.NoError(t, err)

		// Verify removed from both
		_, err = hw.GetCert("test")
		assert.Equal(t, storage.ErrNotFound, err)

		_, err = ext.GetCert("test")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("DeleteFromHardwareOnly", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to hardware only
		hw.SaveCert("test", cert)

		// Delete should succeed
		err = hybrid.DeleteCert("test")
		require.NoError(t, err)

		// Verify removed
		_, err = hw.GetCert("test")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("DeleteFromExternalOnly", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		// Save to external only
		ext.SaveCert("test", cert)

		// Delete should succeed
		err = hybrid.DeleteCert("test")
		require.NoError(t, err)

		// Verify removed
		_, err = ext.GetCert("test")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("DeleteNonexistent", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.DeleteCert("nonexistent")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("BothDeletesFail", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.failDelete = true
		ext := newMockExternalCertStorage()
		ext.failDelete = true
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, err := createTestCertificate("test")
		require.NoError(t, err)

		hw.failDelete = false
		ext.failDelete = false
		hw.SaveCert("test", cert)
		ext.SaveCert("test", cert)
		hw.failDelete = true
		ext.failDelete = true

		err = hybrid.DeleteCert("test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware delete failed")
		assert.Contains(t, err.Error(), "external delete failed")
	})

	t.Run("InvalidID", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.DeleteCert("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		hybrid.Close()

		err := hybrid.DeleteCert("test")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_SaveCertChain tests certificate chain saving
func TestHybridCertStorage_SaveCertChain(t *testing.T) {
	t.Run("SaveChainToHardwareSuccess", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")
		chain := []*x509.Certificate{cert1, cert2}

		err := hybrid.SaveCertChain("test", chain)
		require.NoError(t, err)

		// Should be in hardware
		hwChain, err := hw.GetCertChain("test")
		require.NoError(t, err)
		assert.Len(t, hwChain, 2)
	})

	t.Run("FallbackToExternalOnCapacity", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.returnCapacity = true
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")
		chain := []*x509.Certificate{cert1, cert2}

		err := hybrid.SaveCertChain("test", chain)
		require.NoError(t, err)

		// Should be in external
		extChain, err := ext.GetCertChain("test")
		require.NoError(t, err)
		assert.Len(t, extChain, 2)
	})

	t.Run("EmptyChain", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.SaveCertChain("test", []*x509.Certificate{})
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidData, err)
	})

	t.Run("NilCertInChain", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		chain := []*x509.Certificate{cert1, nil}

		err := hybrid.SaveCertChain("test", chain)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate at index 1 is nil")
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		chain := []*x509.Certificate{cert1}

		hybrid.Close()

		err := hybrid.SaveCertChain("test", chain)
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_GetCertChain tests certificate chain retrieval
func TestHybridCertStorage_GetCertChain(t *testing.T) {
	t.Run("GetChainFromHardware", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")
		chain := []*x509.Certificate{cert1, cert2}

		hw.SaveCertChain("test", chain)

		retrieved, err := hybrid.GetCertChain("test")
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
	})

	t.Run("GetChainFromExternalWhenNotInHardware", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")
		chain := []*x509.Certificate{cert1, cert2}

		ext.SaveCertChain("test", chain)

		retrieved, err := hybrid.GetCertChain("test")
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
	})

	t.Run("ChainNotFoundInBothStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.GetCertChain("nonexistent")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		hybrid.Close()

		_, err := hybrid.GetCertChain("test")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_ListCerts tests certificate listing
func TestHybridCertStorage_ListCerts(t *testing.T) {
	t.Run("ListFromBothStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")
		cert3, _ := createTestCertificate("cert3")

		hw.SaveCert("test1", cert1)
		hw.SaveCert("test2", cert2)
		ext.SaveCert("test3", cert3)

		list, err := hybrid.ListCerts()
		require.NoError(t, err)
		assert.Len(t, list, 3)
		assert.Contains(t, list, "test1")
		assert.Contains(t, list, "test2")
		assert.Contains(t, list, "test3")
	})

	t.Run("DeduplicateIDs", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		cert2, _ := createTestCertificate("cert2")

		// Save same IDs to both storages
		hw.SaveCert("test1", cert1)
		ext.SaveCert("test1", cert2)

		list, err := hybrid.ListCerts()
		require.NoError(t, err)
		assert.Len(t, list, 1)
		assert.Contains(t, list, "test1")
	})

	t.Run("EmptyStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		list, err := hybrid.ListCerts()
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("HardwareListFails", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.failList = true
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert1, _ := createTestCertificate("cert1")
		ext.SaveCert("test1", cert1)

		// Should still succeed with external list
		list, err := hybrid.ListCerts()
		require.NoError(t, err)
		assert.Len(t, list, 1)
	})

	t.Run("BothListsFail", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.failList = true
		ext := newMockExternalCertStorage()
		ext.failList = true
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.ListCerts()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware list failed")
		assert.Contains(t, err.Error(), "external list failed")
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		hybrid.Close()

		_, err := hybrid.ListCerts()
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_CertExists tests certificate existence checking
func TestHybridCertStorage_CertExists(t *testing.T) {
	t.Run("ExistsInHardware", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, _ := createTestCertificate("cert1")
		hw.SaveCert("test", cert)

		exists, err := hybrid.CertExists("test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("ExistsInExternal", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		cert, _ := createTestCertificate("cert1")
		ext.SaveCert("test", cert)

		exists, err := hybrid.CertExists("test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("DoesNotExist", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		exists, err := hybrid.CertExists("nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("BothChecksFail", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.failExists = true
		ext := newMockExternalCertStorage()
		ext.failExists = true
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.CertExists("test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware check failed")
		assert.Contains(t, err.Error(), "external check failed")
	})

	t.Run("InvalidID", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		_, err := hybrid.CertExists("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		hybrid.Close()

		_, err := hybrid.CertExists("test")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestHybridCertStorage_Close tests storage closing
func TestHybridCertStorage_Close(t *testing.T) {
	t.Run("CloseBothStorages", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.Close()
		require.NoError(t, err)

		// Verify both closed
		assert.True(t, hw.closed)
		assert.True(t, ext.closed)
	})

	t.Run("CloseIdempotent", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		ext := newMockExternalCertStorage()
		hybrid, _ := NewHybridCertStorage(hw, ext)

		err := hybrid.Close()
		require.NoError(t, err)

		// Close again
		err = hybrid.Close()
		require.NoError(t, err)
	})
}

// TestHybridCertStorage_Concurrent tests thread safety
func TestHybridCertStorage_Concurrent(t *testing.T) {
	hw := newMockHardwareCertStorage(100)
	ext := newMockExternalCertStorage()
	hybrid, _ := NewHybridCertStorage(hw, ext)

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cert, _ := createTestCertificate("test")
				certID := fmt.Sprintf("cert-%d-%d", id, j)
				_ = hybrid.SaveCert(certID, cert)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				certID := fmt.Sprintf("cert-%d-%d", id, j)
				_, _ = hybrid.GetCert(certID)
			}
		}(i)
	}

	// Concurrent list operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, _ = hybrid.ListCerts()
			}
		}()
	}

	wg.Wait()
}
