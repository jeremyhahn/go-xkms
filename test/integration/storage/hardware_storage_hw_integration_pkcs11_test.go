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

//go:build hw_integration && pkcs11

package storage_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealPKCS11Hardware tests against actual PKCS#11 hardware
// This requires real hardware (YubiKey, Nitrokey, etc.) connected to the host
func TestRealPKCS11Hardware(t *testing.T) {
	hwStorage := initRealPKCS11Hardware(t)
	if hwStorage == nil {
		t.Skip("Real PKCS#11 hardware not available")
	}
	defer hwStorage.Close()

	// Run basic CRUD test
	t.Run("BasicCRUD", func(t *testing.T) {
		cert := createTestCertificate(t)
		certID := "real-hw-test-cert"

		// Save
		err := hwStorage.SaveCert(certID, cert)
		require.NoError(t, err)

		// Retrieve
		retrieved, err := hwStorage.GetCert(certID)
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, retrieved.Raw)

		// Delete
		err = hwStorage.DeleteCert(certID)
		require.NoError(t, err)

		// Verify deleted
		exists, err := hwStorage.CertExists(certID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test capacity
	t.Run("Capacity", func(t *testing.T) {
		total, available, err := hwStorage.GetCapacity()
		require.NoError(t, err)
		t.Logf("Real hardware capacity: total=%d, available=%d", total, available)
		assert.Greater(t, total, 0, "Total capacity should be greater than 0")
	})
}

// initRealPKCS11Hardware initializes connection to real PKCS#11 hardware
// Returns nil if hardware is not available
func initRealPKCS11Hardware(t *testing.T) hardware.HardwareCertStorage {
	// Check for PKCS#11 library path (must be set for real hardware)
	pkcs11Lib := os.Getenv("PKCS11_LIB")
	if pkcs11Lib == "" {
		t.Log("PKCS11_LIB environment variable not set")
		return nil
	}

	// Check for PIN (must be set for real hardware)
	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		t.Log("PKCS11_PIN environment variable not set")
		return nil
	}

	// Verify library exists
	if _, err := os.Stat(pkcs11Lib); err != nil {
		t.Logf("PKCS#11 library not found at %s: %v", pkcs11Lib, err)
		return nil
	}

	// Initialize PKCS#11 context
	ctx := pkcs11.New(pkcs11Lib)
	if ctx == nil {
		t.Logf("Failed to create PKCS#11 context for %s", pkcs11Lib)
		return nil
	}

	// Initialize
	err := ctx.Initialize()
	if err != nil {
		t.Logf("Failed to initialize PKCS#11: %v", err)
		ctx.Finalize()
		return nil
	}

	// Find slots
	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Logf("No PKCS#11 slots found: %v", err)
		ctx.Finalize()
		return nil
	}

	// Use first available slot
	slot := slots[0]

	// Open session
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Logf("Failed to open PKCS#11 session: %v", err)
		ctx.Finalize()
		return nil
	}

	// Login with provided PIN
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		t.Logf("Failed to login to PKCS#11 token: %v", err)
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil
	}

	// Create hardware storage
	hwStorage, err := hardware.NewPKCS11CertStorage(ctx, session, "real-hw-token", slot)
	if err != nil {
		t.Logf("Failed to create PKCS#11 cert storage: %v", err)
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil
	}

	// Wrap storage with cleanup information
	return &realPKCS11StorageWrapper{
		storage: hwStorage,
		ctx:     ctx,
		session: session,
	}
}

// realPKCS11StorageWrapper wraps PKCS#11 storage for real hardware with cleanup logic
type realPKCS11StorageWrapper struct {
	storage hardware.HardwareCertStorage
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func (w *realPKCS11StorageWrapper) SaveCert(id string, cert *x509.Certificate) error {
	return w.storage.SaveCert(id, cert)
}

func (w *realPKCS11StorageWrapper) GetCert(id string) (*x509.Certificate, error) {
	return w.storage.GetCert(id)
}

func (w *realPKCS11StorageWrapper) DeleteCert(id string) error {
	return w.storage.DeleteCert(id)
}

func (w *realPKCS11StorageWrapper) CertExists(id string) (bool, error) {
	return w.storage.CertExists(id)
}

func (w *realPKCS11StorageWrapper) ListCerts() ([]string, error) {
	return w.storage.ListCerts()
}

func (w *realPKCS11StorageWrapper) SaveCertChain(id string, chain []*x509.Certificate) error {
	return w.storage.SaveCertChain(id, chain)
}

func (w *realPKCS11StorageWrapper) GetCertChain(id string) ([]*x509.Certificate, error) {
	return w.storage.GetCertChain(id)
}

func (w *realPKCS11StorageWrapper) GetCapacity() (total int, available int, err error) {
	return w.storage.GetCapacity()
}

func (w *realPKCS11StorageWrapper) SupportsChains() bool {
	return w.storage.SupportsChains()
}

func (w *realPKCS11StorageWrapper) IsHardwareBacked() bool {
	return w.storage.IsHardwareBacked()
}

func (w *realPKCS11StorageWrapper) Compact() error {
	return w.storage.Compact()
}

func (w *realPKCS11StorageWrapper) Close() error {
	// Close the storage
	_ = w.storage.Close()

	// Cleanup PKCS#11 resources
	_ = w.ctx.Logout(w.session)
	_ = w.ctx.CloseSession(w.session)
	_ = w.ctx.Finalize()

	return nil
}
