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

package tpm2

import (
	"crypto/x509"
	"errors"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// fakeCertStorage is an in-memory hardware.HardwareCertStorage used to drive
// the adapter through failures a TPM only produces under conditions a test
// cannot arrange on demand, such as a record that lists but will not read.
type fakeCertStorage struct {
	certs map[string]*x509.Certificate

	saveErr   error
	getErr    error
	deleteErr error
	listErr   error
	existsErr error
	closeErr  error
}

// newFakeCertStorage creates an empty fake store.
func newFakeCertStorage() *fakeCertStorage {
	return &fakeCertStorage{certs: make(map[string]*x509.Certificate)}
}

func (f *fakeCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.certs[id] = cert
	return nil
}

func (f *fakeCertStorage) GetCert(id string) (*x509.Certificate, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	cert, ok := f.certs[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cert, nil
}

func (f *fakeCertStorage) DeleteCert(id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.certs, id)
	return nil
}

func (f *fakeCertStorage) DeleteCertChain(id string) error { return f.DeleteCert(id) }

func (f *fakeCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}
	f.certs[id] = chain[0]
	return nil
}

func (f *fakeCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	cert, err := f.GetCert(id)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (f *fakeCertStorage) ListCerts() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	ids := make([]string, 0, len(f.certs))
	for id := range f.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *fakeCertStorage) CertExists(id string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	_, ok := f.certs[id]
	return ok, nil
}

func (f *fakeCertStorage) Close() error                       { return f.closeErr }
func (f *fakeCertStorage) GetCapacity() (int, int, error)     { return 4, 4 - len(f.certs), nil }
func (f *fakeCertStorage) SupportsChains() bool               { return true }
func (f *fakeCertStorage) IsHardwareBacked() bool             { return true }
func (f *fakeCertStorage) Compact() error                     { return hardware.ErrNotSupported }
func (f *fakeCertStorage) put(id string, c *x509.Certificate) { f.certs[id] = c }

// newFakeStore builds an adapter over a fake certificate store.
func newFakeStore(t *testing.T) (*TPM2CertStorage, *fakeCertStorage) {
	t.Helper()

	fake := newFakeCertStorage()
	store, err := NewFromCertStorage(fake)
	if err != nil {
		t.Fatalf("NewFromCertStorage() error = %v", err)
	}
	return store, fake
}

// TestStore_TranslatesHardwareFailures verifies each hardware failure surfaces
// as the pivcert sentinel the interface documents, with the original error
// still reachable for diagnostics.
func TestStore_TranslatesHardwareFailures(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x30, 0x00}}

	tests := []struct {
		name    string
		saveErr error
		want    error
	}{
		{"NV index taken by another record", hardware.ErrNVIndexUnavailable, pivcert.ErrStorageFull},
		{"NV RAM exhausted", hardware.NewOperationError("define", gotpm2.TPMRCNVSpace), pivcert.ErrStorageFull},
		{"record exceeds NV budget", hardware.ErrCertificateTooLarge, pivcert.ErrCertificateTooLarge},
		{"owner authorization rejected", hardware.NewOperationError("define", gotpm2.TPMRCBadAuth), pivcert.ErrPermissionDenied},
		{"hardware storage closed", hardware.ErrStorageClosed, pivcert.ErrStorageClosed},
		{"TPM unreachable", hardware.NewOperationError("define", errors.New("device disconnected")), pivcert.ErrTPMNotAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, fake := newFakeStore(t)
			fake.saveErr = tt.saveErr

			err := store.Store(pivcert.PIVSlotAuthentication, cert)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Store() error = %v, want %v", err, tt.want)
			}
			if !errors.Is(err, tt.saveErr) {
				t.Errorf("Store() error lost its cause: %v", err)
			}
		})
	}
}

// TestRetrieve_TranslatesHardwareFailures verifies read failures keep their
// classification instead of collapsing into "not found".
func TestRetrieve_TranslatesHardwareFailures(t *testing.T) {
	tests := []struct {
		name   string
		getErr error
		want   error
	}{
		{"empty slot", storage.ErrNotFound, pivcert.ErrCertificateNotFound},
		{"owner authorization rejected", hardware.NewOperationError("read", gotpm2.TPMRCBadAuth), pivcert.ErrPermissionDenied},
		{"corrupted record", hardware.ErrInvalidCertificate, pivcert.ErrInvalidCertificate},
		{"TPM unreachable", hardware.NewOperationError("read", errors.New("device disconnected")), pivcert.ErrTPMNotAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, fake := newFakeStore(t)
			fake.getErr = tt.getErr

			_, err := store.Retrieve(pivcert.PIVSlotAuthentication)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Retrieve() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestDelete_TranslatesHardwareFailures covers the two TPM round trips deletion
// makes: the existence check and the undefine.
func TestDelete_TranslatesHardwareFailures(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x30, 0x00}}

	t.Run("existence check fails", func(t *testing.T) {
		store, fake := newFakeStore(t)
		fake.existsErr = hardware.NewOperationError("read", errors.New("device disconnected"))

		if err := store.Delete(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
			t.Fatalf("Delete() error = %v, want ErrTPMNotAvailable", err)
		}
	})

	t.Run("undefine fails", func(t *testing.T) {
		store, fake := newFakeStore(t)
		id, _ := PIVSlotToCertID(pivcert.PIVSlotAuthentication)
		fake.put(id, cert)
		fake.deleteErr = hardware.NewOperationError("undefine", gotpm2.TPMRCBadAuth)

		if err := store.Delete(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrPermissionDenied) {
			t.Fatalf("Delete() error = %v, want ErrPermissionDenied", err)
		}
	})
}

// TestList_TranslatesHardwareFailures verifies List reports failures instead of
// quietly returning a short list, which a caller would read as empty slots.
func TestList_TranslatesHardwareFailures(t *testing.T) {
	t.Run("enumeration fails", func(t *testing.T) {
		store, fake := newFakeStore(t)
		fake.listErr = hardware.NewOperationError("query", errors.New("device disconnected"))

		if _, err := store.List(); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
			t.Fatalf("List() error = %v, want ErrTPMNotAvailable", err)
		}
	})

	t.Run("listed record cannot be read", func(t *testing.T) {
		store, fake := newFakeStore(t)
		id, _ := PIVSlotToCertID(pivcert.PIVSlotKeyManagement)
		fake.put(id, &x509.Certificate{Raw: []byte{0x30, 0x00}})
		fake.getErr = hardware.ErrInvalidCertificate

		if _, err := store.List(); !errors.Is(err, pivcert.ErrInvalidCertificate) {
			t.Fatalf("List() error = %v, want ErrInvalidCertificate", err)
		}
	})
}

// TestClose_ReportsHardwareFailure verifies a failing hardware close is
// reported rather than swallowed, while the store still refuses further use.
func TestClose_ReportsHardwareFailure(t *testing.T) {
	store, fake := newFakeStore(t)
	fake.closeErr = hardware.ErrStorageClosed

	if err := store.Close(); !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Fatalf("Close() error = %v, want ErrStorageClosed", err)
	}
	if err := store.Store(pivcert.PIVSlotAuthentication, &x509.Certificate{}); !errors.Is(err, pivcert.ErrStorageClosed) {
		t.Errorf("Store() after failed Close error = %v, want ErrStorageClosed", err)
	}
}

// TestSlotModel_NextAvailableExhaustsSlots verifies allocation order: retired
// slots first, then the non-authentication primary slots, then a refusal.
func TestSlotModel_NextAvailableExhaustsSlots(t *testing.T) {
	fake := newFakeCertStorage()
	cert := &x509.Certificate{Raw: []byte{0x30, 0x00}}

	// Occupy every retired slot.
	for _, slot := range pivcert.RetiredSlots() {
		id, ok := PIVSlotToCertID(slot)
		if !ok {
			t.Fatalf("no certificate ID for %q", slot)
		}
		fake.put(id, cert)
	}

	model, err := NewPIVSlotModel(fake)
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	// With the retired slots full, allocation falls to the primary slots that
	// are not reserved for authentication.
	next, err := model.NextAvailable()
	if err != nil {
		t.Fatalf("NextAvailable() error = %v", err)
	}
	if next != pivcert.PIVSlotDigitalSignature {
		t.Errorf("NextAvailable() = %q, want %q", next, pivcert.PIVSlotDigitalSignature)
	}

	// Occupy every slot in the registry.
	for _, slot := range pivcert.AllSlots() {
		id, ok := PIVSlotToCertID(slot)
		if !ok {
			t.Fatalf("no certificate ID for %q", slot)
		}
		fake.put(id, cert)
	}
	if err := model.Refresh(); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if _, err := model.NextAvailable(); !errors.Is(err, pivcert.ErrNoAvailableSlot) {
		t.Fatalf("NextAvailable() on a full store error = %v, want ErrNoAvailableSlot", err)
	}

	occupied, err := model.OccupiedSlots()
	if err != nil {
		t.Fatalf("OccupiedSlots() error = %v", err)
	}
	if len(occupied) != len(pivcert.AllSlots()) {
		t.Errorf("OccupiedSlots() returned %d slots, want %d", len(occupied), len(pivcert.AllSlots()))
	}

	available, err := model.AvailableSlots()
	if err != nil {
		t.Fatalf("AvailableSlots() error = %v", err)
	}
	if len(available) != 0 {
		t.Errorf("AvailableSlots() = %v, want none", available)
	}
}

// TestSlotModel_NextAvailableSkipsAuthenticationSlots verifies 9a and 9e are
// never auto-allocated even when they are the only free slots.
func TestSlotModel_NextAvailableSkipsAuthenticationSlots(t *testing.T) {
	fake := newFakeCertStorage()
	cert := &x509.Certificate{Raw: []byte{0x30, 0x00}}

	for _, slot := range pivcert.AllSlots() {
		if slot == pivcert.PIVSlotAuthentication || slot == pivcert.PIVSlotCardAuthentication {
			continue
		}
		id, ok := PIVSlotToCertID(slot)
		if !ok {
			t.Fatalf("no certificate ID for %q", slot)
		}
		fake.put(id, cert)
	}

	model, err := NewPIVSlotModel(fake)
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	if slot, err := model.NextAvailable(); !errors.Is(err, pivcert.ErrNoAvailableSlot) {
		t.Fatalf("NextAvailable() = (%q, %v), want ErrNoAvailableSlot", slot, err)
	}

	// They are still reported as free, just not auto-allocated.
	free, err := model.IsOccupied(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("IsOccupied() error = %v", err)
	}
	if free {
		t.Error("IsOccupied(9a) = true, want false")
	}
}

// TestSlotModel_RefreshTranslatesFailures verifies enumeration failures are
// reported instead of being read as an empty store.
func TestSlotModel_RefreshTranslatesFailures(t *testing.T) {
	fake := newFakeCertStorage()
	fake.listErr = hardware.NewOperationError("query", errors.New("device disconnected"))

	model, err := NewPIVSlotModel(fake)
	if !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Fatalf("NewPIVSlotModel() error = %v, want ErrTPMNotAvailable", err)
	}
	if model != nil {
		t.Error("NewPIVSlotModel() returned a model alongside the error")
	}
}

// TestSlotModel_RefreshTreatsEmptyStoreAsNoOccupancy verifies a store that
// reports no records at all leaves every slot free rather than failing.
func TestSlotModel_RefreshTreatsEmptyStoreAsNoOccupancy(t *testing.T) {
	fake := newFakeCertStorage()
	fake.listErr = storage.ErrNotFound

	model, err := NewPIVSlotModel(fake)
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	available, err := model.AvailableSlots()
	if err != nil {
		t.Fatalf("AvailableSlots() error = %v", err)
	}
	if len(available) != len(pivcert.AllSlots()) {
		t.Errorf("AvailableSlots() returned %d slots, want %d", len(available), len(pivcert.AllSlots()))
	}
}

// TestSlotModel_IgnoresUnknownCertIDs verifies records belonging to other
// subsystems never mark a PIV slot occupied.
func TestSlotModel_IgnoresUnknownCertIDs(t *testing.T) {
	fake := newFakeCertStorage()
	fake.put("platform-root-ca", &x509.Certificate{Raw: []byte{0x30, 0x00}})
	fake.put("0x01800000", &x509.Certificate{Raw: []byte{0x30, 0x00}})

	model, err := NewPIVSlotModel(fake)
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	occupied, err := model.OccupiedSlots()
	if err != nil {
		t.Fatalf("OccupiedSlots() error = %v", err)
	}
	if len(occupied) != 0 {
		t.Errorf("OccupiedSlots() = %v, want none", occupied)
	}
}
