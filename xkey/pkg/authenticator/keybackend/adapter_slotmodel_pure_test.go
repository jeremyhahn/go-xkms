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

package keybackend

import (
	"encoding/hex"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// fakeSlotModel is a minimal in-process xkms.PIVSlotModel: no smart card, no
// PKCS#11 module. It reports one fixed "next available" slot (or a fixed
// failure) and counts Refresh calls so a test can observe that
// GenerateCredentialKey re-reads occupancy after a successful allocation.
type fakeSlotModel struct {
	next         xkms.PIVSlot
	nextErr      error
	refreshErr   error
	refreshCalls int
}

func (f *fakeSlotModel) AllSlots() []xkms.PIVSlot                { return []xkms.PIVSlot{f.next} }
func (f *fakeSlotModel) AvailableSlots() ([]xkms.PIVSlot, error) { return []xkms.PIVSlot{f.next}, nil }
func (f *fakeSlotModel) OccupiedSlots() ([]xkms.PIVSlot, error)  { return nil, nil }
func (f *fakeSlotModel) IsOccupied(xkms.PIVSlot) (bool, error)   { return false, nil }
func (f *fakeSlotModel) SlotOccupancy(s xkms.PIVSlot) (*xkms.PIVSlotOccupancyInfo, error) {
	return &xkms.PIVSlotOccupancyInfo{Slot: s, Occupied: false}, nil
}
func (f *fakeSlotModel) Refresh() error { f.refreshCalls++; return f.refreshErr }
func (f *fakeSlotModel) NextAvailable() (xkms.PIVSlot, error) {
	if f.nextErr != nil {
		return "", f.nextErr
	}
	return f.next, nil
}

// TestBackendAdapter_SetSlotModel_AutoAllocatesSlot verifies that once
// SetSlotModel attaches a slot model, GenerateCredentialKey allocates the
// next available slot, records it in the adapter's slot cache keyed by the
// credential ID, and refreshes occupancy after the key is generated.
func TestBackendAdapter_SetSlotModel_AutoAllocatesSlot(t *testing.T) {
	adapter := newSoftwareBackendAdapter(t)
	slots := &fakeSlotModel{next: xkms.PIVSlotRetired1}
	adapter.SetSlotModel(slots)

	credentialID := []byte{1, 2, 3, 4}
	if _, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credentialID); err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v", err)
	}

	got, ok := adapter.slotCache.Load(hex.EncodeToString(credentialID))
	if !ok {
		t.Fatal("expected the credential's allocated slot to be cached")
	}
	if got != string(xkms.PIVSlotRetired1) {
		t.Errorf("cached slot = %v, want %v", got, xkms.PIVSlotRetired1)
	}
	if slots.refreshCalls != 1 {
		t.Errorf("Refresh() called %d times, want 1", slots.refreshCalls)
	}
}

// TestBackendAdapter_SetSlotModel_RefreshFailureKeepsTheCredential proves a
// failed occupancy refresh after generation does not discard the credential:
// the key already exists on the device, so the caller gets it back and can
// sign with it.
func TestBackendAdapter_SetSlotModel_RefreshFailureKeepsTheCredential(t *testing.T) {
	adapter := newSoftwareBackendAdapter(t)
	slots := &fakeSlotModel{next: xkms.PIVSlotRetired2, refreshErr: errors.New("token removed")}
	adapter.SetSlotModel(slots)

	credentialID := []byte{5, 6, 7, 8}
	handle, publicKeyCOSE, err := adapter.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v, want the credential despite the refresh failure", err)
	}
	if len(publicKeyCOSE) == 0 {
		t.Fatal("expected a COSE public key")
	}
	if slots.refreshCalls != 1 {
		t.Errorf("Refresh() called %d times, want 1", slots.refreshCalls)
	}
	if _, err := adapter.Sign(handle, COSEAlgES256, []byte("data")); err != nil {
		t.Errorf("Sign() with the credential on its allocated slot: error = %v", err)
	}
}

// TestBackendAdapter_SetSlotModel_NoAvailableSlotFailsGeneration verifies a
// full slot model fails key generation up front, before the provider is ever
// asked to create a key nobody could reach through a PIV slot.
func TestBackendAdapter_SetSlotModel_NoAvailableSlotFailsGeneration(t *testing.T) {
	adapter := newSoftwareBackendAdapter(t)
	slotErr := errors.New("all slots occupied")
	adapter.SetSlotModel(&fakeSlotModel{nextErr: slotErr})

	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, []byte{9, 9, 9, 9})
	if !errors.Is(err, ErrKeyGenerationFailed) {
		t.Fatalf("GenerateCredentialKey() error = %v, want ErrKeyGenerationFailed", err)
	}
	if !errors.Is(err, slotErr) {
		t.Errorf("errors.Is(err, slotErr) = false, want true (cause must be reachable)")
	}
}
