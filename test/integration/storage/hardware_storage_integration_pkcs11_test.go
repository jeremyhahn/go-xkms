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

//go:build integration && pkcs11

package storage_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/miekg/pkcs11"
)

// tryInitSoftHSM attempts to initialize PKCS#11 storage via SoftHSM.
// Returns nil if SoftHSM is not available in the test environment.
func tryInitSoftHSM(t *testing.T) hardware.HardwareCertStorage {
	// Check for SOFTHSM2_CONF environment variable
	softhsmConf := os.Getenv("SOFTHSM2_CONF")
	if softhsmConf == "" {
		return nil
	}

	// Check for PKCS#11 library path
	pkcs11Lib := os.Getenv("PKCS11_LIB")
	if pkcs11Lib == "" {
		pkcs11Lib = "/usr/lib/softhsm/libsofthsm2.so"
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

	// Open session on first available slot
	session, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Logf("Failed to open PKCS#11 session: %v", err)
		ctx.Finalize()
		return nil
	}

	// Login to token (use default SoftHSM test PIN)
	err = ctx.Login(session, pkcs11.CKU_USER, "1234")
	if err != nil {
		t.Logf("Failed to login to PKCS#11 token: %v", err)
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil
	}

	// Create hardware storage
	hwStorage, err := hardware.NewPKCS11CertStorage(ctx, session, "test-token", slots[0])
	if err != nil {
		t.Logf("Failed to create PKCS#11 cert storage: %v", err)
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil
	}

	// Wrap storage with cleanup information
	return &pkcs11StorageWrapper{
		storage: hwStorage,
		ctx:     ctx,
		session: session,
	}
}

// pkcs11StorageWrapper wraps PKCS#11 storage with cleanup logic
type pkcs11StorageWrapper struct {
	storage hardware.HardwareCertStorage
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func (w *pkcs11StorageWrapper) SaveCert(id string, cert *x509.Certificate) error {
	return w.storage.SaveCert(id, cert)
}

func (w *pkcs11StorageWrapper) GetCert(id string) (*x509.Certificate, error) {
	return w.storage.GetCert(id)
}

func (w *pkcs11StorageWrapper) DeleteCert(id string) error {
	return w.storage.DeleteCert(id)
}

func (w *pkcs11StorageWrapper) CertExists(id string) (bool, error) {
	return w.storage.CertExists(id)
}

func (w *pkcs11StorageWrapper) ListCerts() ([]string, error) {
	return w.storage.ListCerts()
}

func (w *pkcs11StorageWrapper) SaveCertChain(id string, chain []*x509.Certificate) error {
	return w.storage.SaveCertChain(id, chain)
}

func (w *pkcs11StorageWrapper) GetCertChain(id string) ([]*x509.Certificate, error) {
	return w.storage.GetCertChain(id)
}

func (w *pkcs11StorageWrapper) GetCapacity() (total int, available int, err error) {
	return w.storage.GetCapacity()
}

func (w *pkcs11StorageWrapper) SupportsChains() bool {
	return w.storage.SupportsChains()
}

func (w *pkcs11StorageWrapper) IsHardwareBacked() bool {
	return w.storage.IsHardwareBacked()
}

func (w *pkcs11StorageWrapper) Compact() error {
	return w.storage.Compact()
}

func (w *pkcs11StorageWrapper) Close() error {
	// Close the storage
	_ = w.storage.Close()

	// Cleanup PKCS#11 resources
	_ = w.ctx.Logout(w.session)
	_ = w.ctx.CloseSession(w.session)
	_ = w.ctx.Finalize()

	return nil
}
