// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// errorHWCertStorage is a hardware.HardwareCertStorage stand-in whose every
// method fails with a configured error, standing in for a token that
// rejects a write/read/list (full, locked, revoked session, I/O failure)
// (go-xkms#705). mockHWCertStorage (pkcs11_test.go) is a well-behaved
// in-memory store and never returns an error from SaveCert/GetCert/
// DeleteCert/ListCerts, so PKCS11CertStorage's own error-translation
// branches around each hw call have never run.
type errorHWCertStorage struct {
	err error
}

var _ hardware.HardwareCertStorage = (*errorHWCertStorage)(nil)

func (e *errorHWCertStorage) SaveCert(id string, cert *x509.Certificate) error { return e.err }
func (e *errorHWCertStorage) GetCert(id string) (*x509.Certificate, error)     { return nil, e.err }
func (e *errorHWCertStorage) DeleteCert(id string) error                       { return e.err }
func (e *errorHWCertStorage) DeleteCertChain(id string) error                  { return e.err }
func (e *errorHWCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	return e.err
}
func (e *errorHWCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	return nil, e.err
}
func (e *errorHWCertStorage) ListCerts() ([]string, error)       { return nil, e.err }
func (e *errorHWCertStorage) CertExists(id string) (bool, error) { return false, e.err }
func (e *errorHWCertStorage) Close() error                       { return e.err }
func (e *errorHWCertStorage) GetCapacity() (int, int, error)     { return 0, 0, e.err }
func (e *errorHWCertStorage) SupportsChains() bool               { return false }
func (e *errorHWCertStorage) IsHardwareBacked() bool             { return true }
func (e *errorHWCertStorage) Compact() error                     { return e.err }

// TestStore_CertificateTooLarge proves Store rejects a certificate whose
// raw DER exceeds pivcert.MaxCertSizePKCS11 before ever reaching the
// hardware layer -- a token limit this backend enforces itself since
// PKCS#11 has no uniform way to report it consistently across vendors.
func TestStore_CertificateTooLarge(t *testing.T) {
	s, _ := newTestStorage()
	oversized := &x509.Certificate{Raw: make([]byte, pivcert.MaxCertSizePKCS11+1)}

	err := s.Store(pivcert.PIVSlotAuthentication, oversized)
	if !errors.Is(err, pivcert.ErrCertificateTooLarge) {
		t.Errorf("Store() with an oversized certificate error = %v, want ErrCertificateTooLarge", err)
	}
}

// TestStore_HardwareSaveError proves Store surfaces a hardware SaveCert
// failure wrapped in a PIVStorageError, rather than reporting success for a
// certificate the token never actually stored.
func TestStore_HardwareSaveError(t *testing.T) {
	s := &PKCS11CertStorage{hw: &errorHWCertStorage{err: errors.New("token write failed")}}
	cert := generateTestCert(t)

	err := s.Store(pivcert.PIVSlotAuthentication, cert)
	if err == nil {
		t.Fatal("Store() expected error when the hardware layer fails, got nil")
	}
	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("Store() with a hardware failure should return PIVStorageError")
	}
}

// TestDelete_HardwareErrorOtherThanNotFound proves Delete surfaces a
// hardware DeleteCert failure that is NOT storage.ErrNotFound unchanged,
// rather than misclassifying it as ErrCertificateNotFound the way
// TestPKCS11CertStorage_Delete_NotFound's genuine not-found case is.
func TestDelete_HardwareErrorOtherThanNotFound(t *testing.T) {
	tokenErr := errors.New("token locked")
	s := &PKCS11CertStorage{hw: &errorHWCertStorage{err: tokenErr}}

	err := s.Delete(pivcert.PIVSlotAuthentication)
	if errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Error("Delete() must not translate a non-ErrNotFound hardware failure into ErrCertificateNotFound")
	}
	if err == nil {
		t.Fatal("Delete() expected error when the hardware layer fails, got nil")
	}
}

// TestList_HardwareListError proves List surfaces a hardware ListCerts
// failure wrapped in a PIVStorageError, rather than an empty, silently
// successful result.
func TestList_HardwareListError(t *testing.T) {
	s := &PKCS11CertStorage{hw: &errorHWCertStorage{err: errors.New("token unavailable")}}

	_, err := s.List()
	if err == nil {
		t.Fatal("List() expected error when the hardware layer fails, got nil")
	}
	var storageErr *pivcert.PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Fatal("List() with a hardware failure should return PIVStorageError")
	}
}

// listIDsHWCertStorage reports a fixed set of IDs from ListCerts and serves
// GetCert only for IDs present in certs, so a test can drive List's
// per-ID skip branches (an ID that isn't a single byte, one that doesn't
// map to a known PIV slot, and one whose GetCert independently fails)
// without a real PKCS#11 token.
type listIDsHWCertStorage struct {
	*mockHWCertStorage
	ids []string
}

func (m *listIDsHWCertStorage) ListCerts() ([]string, error) {
	return m.ids, nil
}

// TestList_SkipsUnmappableIDs proves List silently skips IDs that cannot be
// mapped back to a PIV slot -- a multi-byte ID, an ID whose single byte
// isn't a known CKA_ID, and an ID GetCert fails to resolve -- rather than
// erroring the whole call or including a bogus entry, while still
// returning the one genuinely resolvable certificate.
func TestList_SkipsUnmappableIDs(t *testing.T) {
	base := newMockHWCertStorage()
	cert := generateTestCert(t)

	// A resolvable entry: single-byte ID that maps to a known PIV slot.
	goodID, err := pivID(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("pivID() error = %v", err)
	}
	if err := base.SaveCert(goodID, cert); err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	// An ID whose single byte GetCert will fail to resolve (never saved).
	const unresolvableID = "\x09"

	hw := &listIDsHWCertStorage{
		mockHWCertStorage: base,
		ids:               []string{"multi-byte-id", "\xff", unresolvableID, goodID},
	}
	s := &PKCS11CertStorage{hw: hw}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() returned %d entries, want 1 (only the resolvable ID)", len(entries))
	}
	if entries[0].Slot != pivcert.PIVSlotAuthentication {
		t.Errorf("List()[0].Slot = %v, want %v", entries[0].Slot, pivcert.PIVSlotAuthentication)
	}
}

// TestResolveSlot_ExplicitSlotID proves resolveSlot returns config.SlotID
// directly without touching ctx at all when it is non-negative -- the
// branch every other resolveSlot test in this package (which all use
// SlotID: -1 to reach the "resolve via token label" path) never takes.
func TestResolveSlot_ExplicitSlotID(t *testing.T) {
	got, err := resolveSlot(nil, &pivcert.PKCS11StorageConfig{SlotID: 7})
	if err != nil {
		t.Fatalf("resolveSlot() error = %v", err)
	}
	if got != 7 {
		t.Errorf("resolveSlot() = %d, want 7", got)
	}
}

// TestECCurveFromOID_ValidButUnrecognized proves ecCurveFromOID returns ""
// for a syntactically valid ASN.1 OID that simply isn't one of the three
// curves this package recognizes -- distinct from
// TestECCurveFromOID's malformed-DER case, which fails to even parse.
func TestECCurveFromOID_ValidButUnrecognized(t *testing.T) {
	// DER encoding of OID 1.2.3.4 (an arbitrary, unrecognized curve OID).
	der := []byte{0x06, 0x03, 0x2a, 0x03, 0x04}
	if got := ecCurveFromOID(der); got != "" {
		t.Errorf("ecCurveFromOID() = %q, want \"\" for a valid but unrecognized OID", got)
	}
}

// TestPKCS11CertStorage_Import_MalformedData proves Import surfaces
// parseCertificate's own decode failure for non-empty data that isn't a
// valid certificate, rather than only ever being exercised by the
// empty/nil-data guard ahead of it (TestPKCS11CertStorage_Import_EmptyData,
// TestPKCS11CertStorage_Import_NilData).
func TestPKCS11CertStorage_Import_MalformedData(t *testing.T) {
	s, _ := newTestStorage()

	err := s.Import(pivcert.PIVSlotAuthentication, []byte("not a valid certificate"), pivcert.FormatDER)
	if err == nil {
		t.Error("Import() expected error for malformed non-empty certificate data, got nil")
	}
}
