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

//go:build hw_integration

package storage_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealTPM2Hardware tests against actual TPM2 hardware
// This requires a real TPM2 chip (/dev/tpm0 or /dev/tpmrm0)
func TestRealTPM2Hardware(t *testing.T) {
	hwStorage := initRealTPM2Hardware(t)
	if hwStorage == nil {
		t.Fatal("Real TPM2 hardware not available")
	}
	defer hwStorage.Close()

	// Run basic CRUD test
	t.Run("BasicCRUD", func(t *testing.T) {
		cert := createTestCertificate(t)
		certID := "real-tpm2-test-cert"

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
		t.Logf("Real TPM2 capacity: total=%d, available=%d", total, available)
		assert.Greater(t, total, 0, "Total capacity should be greater than 0")
	})
}

// initRealTPM2Hardware initializes connection to real TPM2 hardware
// Returns nil if hardware is not available
func initRealTPM2Hardware(t *testing.T) hardware.HardwareCertStorage {
	// Try common TPM2 device paths
	devPaths := []string{
		"/dev/tpmrm0", // Resource Manager (preferred)
		"/dev/tpm0",   // Direct access
	}

	var tpmConn transport.TPMCloser
	var devicePath string

	for _, path := range devPaths {
		if file, err := os.Open(path); err == nil {
			tpmConn = &realTPMFileCloser{
				file:      file,
				transport: transport.FromReadWriter(file),
			}
			devicePath = path
			t.Logf("Using TPM2 device: %s", devicePath)
			break
		}
	}

	if tpmConn == nil {
		t.Log("No TPM2 device found (/dev/tpm0 or /dev/tpmrm0)")
		return nil
	}

	// Create storage with default config
	config := hardware.DefaultTPM2CertStorageConfig()
	hwStorage, err := hardware.NewTPM2CertStorage(tpmConn, config)
	if err != nil {
		t.Logf("Failed to create TPM2 cert storage: %v", err)
		tpmConn.Close()
		return nil
	}

	// Wrap storage with cleanup information
	return &realTPM2StorageWrapper{
		storage: hwStorage,
		conn:    tpmConn,
	}
}

// realTPMFileCloser wraps a file descriptor for real TPM2 communication
type realTPMFileCloser struct {
	file      *os.File
	transport transport.TPM
}

func (f *realTPMFileCloser) Send(input []byte) ([]byte, error) {
	return f.transport.Send(input)
}

func (f *realTPMFileCloser) Close() error {
	return f.file.Close()
}

// realTPM2StorageWrapper wraps TPM2 storage for real hardware with cleanup logic
type realTPM2StorageWrapper struct {
	storage hardware.HardwareCertStorage
	conn    transport.TPMCloser
}

func (w *realTPM2StorageWrapper) SaveCert(id string, cert *x509.Certificate) error {
	return w.storage.SaveCert(id, cert)
}

func (w *realTPM2StorageWrapper) GetCert(id string) (*x509.Certificate, error) {
	return w.storage.GetCert(id)
}

func (w *realTPM2StorageWrapper) DeleteCert(id string) error {
	return w.storage.DeleteCert(id)
}

func (w *realTPM2StorageWrapper) CertExists(id string) (bool, error) {
	return w.storage.CertExists(id)
}

func (w *realTPM2StorageWrapper) ListCerts() ([]string, error) {
	return w.storage.ListCerts()
}

func (w *realTPM2StorageWrapper) SaveCertChain(id string, chain []*x509.Certificate) error {
	return w.storage.SaveCertChain(id, chain)
}

func (w *realTPM2StorageWrapper) GetCertChain(id string) ([]*x509.Certificate, error) {
	return w.storage.GetCertChain(id)
}

func (w *realTPM2StorageWrapper) GetCapacity() (total int, available int, err error) {
	return w.storage.GetCapacity()
}

func (w *realTPM2StorageWrapper) SupportsChains() bool {
	return w.storage.SupportsChains()
}

func (w *realTPM2StorageWrapper) IsHardwareBacked() bool {
	return w.storage.IsHardwareBacked()
}

func (w *realTPM2StorageWrapper) Compact() error {
	return w.storage.Compact()
}

func (w *realTPM2StorageWrapper) Close() error {
	// Close the storage
	_ = w.storage.Close()

	// Close the connection
	if w.conn != nil {
		return w.conn.Close()
	}
	return nil
}
