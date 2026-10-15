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

//go:build pkcs11

package keybackend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSlotModel implements xkms.PIVSlotModel for testing slot allocation logic.
type mockSlotModel struct {
	nextSlot      xkms.PIVSlot
	nextErr       error
	refreshCount  atomic.Int32
	nextCallCount atomic.Int32
	allSlots      []xkms.PIVSlot
	occupied      map[xkms.PIVSlot]bool
}

func newMockSlotModel(nextSlot xkms.PIVSlot) *mockSlotModel {
	return &mockSlotModel{
		nextSlot: nextSlot,
		allSlots: []xkms.PIVSlot{
			xkms.PIVSlotRetired1,
			xkms.PIVSlotRetired2,
			xkms.PIVSlotRetired3,
		},
		occupied: make(map[xkms.PIVSlot]bool),
	}
}

func (m *mockSlotModel) AllSlots() []xkms.PIVSlot { return m.allSlots }

func (m *mockSlotModel) AvailableSlots() ([]xkms.PIVSlot, error) {
	var avail []xkms.PIVSlot
	for _, s := range m.allSlots {
		if !m.occupied[s] {
			avail = append(avail, s)
		}
	}
	return avail, nil
}

func (m *mockSlotModel) OccupiedSlots() ([]xkms.PIVSlot, error) {
	var occ []xkms.PIVSlot
	for _, s := range m.allSlots {
		if m.occupied[s] {
			occ = append(occ, s)
		}
	}
	return occ, nil
}

func (m *mockSlotModel) IsOccupied(slot xkms.PIVSlot) (bool, error) {
	return m.occupied[slot], nil
}

func (m *mockSlotModel) NextAvailable() (xkms.PIVSlot, error) {
	m.nextCallCount.Add(1)
	return m.nextSlot, m.nextErr
}

func (m *mockSlotModel) SlotOccupancy(slot xkms.PIVSlot) (*xkms.PIVSlotOccupancyInfo, error) {
	return &xkms.PIVSlotOccupancyInfo{
		Slot:     slot,
		Occupied: m.occupied[slot],
	}, nil
}

func (m *mockSlotModel) Refresh() error {
	m.refreshCount.Add(1)
	return nil
}

// Compile-time interface check.
var _ xkms.PIVSlotModel = (*mockSlotModel)(nil)

// recordingKeyProvider implements xkms.KeyProvider and records what
// GenerateKey receives so tests can inspect the KeyAttributes.
type recordingKeyProvider struct {
	lastAttrs   *xkms.KeyAttributes
	generateErr error
	signerErr   error
	getKeyErr   error
	deleteErr   error
}

func (p *recordingKeyProvider) Type() xkms.BackendType {
	return xkms.BackendTypePKCS11
}

func (p *recordingKeyProvider) Capabilities() xkms.Capabilities {
	return xkms.Capabilities{
		Keys:           true,
		Signing:        true,
		HardwareBacked: true,
	}
}

func (p *recordingKeyProvider) GenerateKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	p.lastAttrs = attrs
	if p.generateErr != nil {
		return nil, p.generateErr
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (p *recordingKeyProvider) GetKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if p.getKeyErr != nil {
		return nil, p.getKeyErr
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (p *recordingKeyProvider) DeleteKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return p.deleteErr
}

func (p *recordingKeyProvider) ListKeys(ctx context.Context) ([]*xkms.KeyAttributes, error) {
	return nil, nil
}

func (p *recordingKeyProvider) Signer(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	if p.signerErr != nil {
		return nil, p.signerErr
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (p *recordingKeyProvider) Decrypter(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}

func (p *recordingKeyProvider) RotateKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return errors.New("not supported")
}

func (p *recordingKeyProvider) Close() error {
	return nil
}

// Compile-time interface check.
var _ xkms.KeyProvider = (*recordingKeyProvider)(nil)

// TestAdapter_GenerateCredentialAttrs_WithSlotModel verifies that when a
// SlotModel is attached, GenerateCredentialKey allocates the next available
// PIV slot and passes it through KeyAttributes to the provider.
func TestAdapter_GenerateCredentialAttrs_WithSlotModel(t *testing.T) {
	provider := &recordingKeyProvider{}
	sm := newMockSlotModel(xkms.PIVSlotRetired1) // NextAvailable returns "82"

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	credID := []byte("test-cred-with-slot")
	handle, pubKey, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)

	require.NoError(t, err)
	require.NotNil(t, handle)
	require.NotEmpty(t, pubKey)

	// Verify the provider received PIVSlot="82" in its KeyAttributes.
	require.NotNil(t, provider.lastAttrs)
	assert.Equal(t, string(xkms.PIVSlotRetired1), provider.lastAttrs.PIVSlot)

	// Verify the handle metadata is correct.
	assert.Equal(t, credID, handle.CredentialID())
	assert.Equal(t, COSEAlgES256, handle.Algorithm())
	assert.Equal(t, xkms.BackendTypePKCS11, handle.BackendID())

	// NextAvailable should have been called exactly once.
	assert.Equal(t, int32(1), sm.nextCallCount.Load())
}

// TestAdapter_GenerateCredentialAttrs_NoSlotModel verifies that without a
// SlotModel, GenerateCredentialKey succeeds and the KeyAttributes has an
// empty PIVSlot field.
func TestAdapter_GenerateCredentialAttrs_NoSlotModel(t *testing.T) {
	provider := &recordingKeyProvider{}

	adapter := NewBackendAdapter(provider, xkms.BackendTypeSoftware)
	// No SetSlotModel call -- slotModel remains nil.

	credID := []byte("test-cred-no-slot")
	handle, pubKey, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)

	require.NoError(t, err)
	require.NotNil(t, handle)
	require.NotEmpty(t, pubKey)

	// Verify the provider received empty PIVSlot.
	require.NotNil(t, provider.lastAttrs)
	assert.Empty(t, provider.lastAttrs.PIVSlot)
}

// TestAdapter_LookupCredentialAttrs_NeverAllocates verifies that lookup-path
// operations (LoadKey, Sign, DeleteKey) never call NextAvailable on the
// SlotModel. Slot allocation is reserved for GenerateCredentialKey only.
func TestAdapter_LookupCredentialAttrs_NeverAllocates(t *testing.T) {
	provider := &recordingKeyProvider{}
	sm := newMockSlotModel(xkms.PIVSlotRetired1)

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	credID := []byte("test-cred-lookup")
	handle := &adapterKeyHandle{
		credentialID: credID,
		algorithm:    COSEAlgES256,
		backendType:  xkms.BackendTypePKCS11,
	}

	// LoadKey -- lookup path, must NOT call NextAvailable.
	_, err := adapter.LoadKey(credID, COSEAlgES256)
	require.NoError(t, err)

	// Sign -- lookup path, must NOT call NextAvailable.
	_, err = adapter.Sign(handle, COSEAlgES256, []byte("data-to-sign"))
	require.NoError(t, err)

	// DeleteKey -- lookup path, must NOT call NextAvailable.
	err = adapter.DeleteKey(handle)
	require.NoError(t, err)

	// NextAvailable must never have been called.
	assert.Equal(t, int32(0), sm.nextCallCount.Load(),
		"NextAvailable must not be called during lookup operations")

	// Refresh also must not have been called (only called after generate).
	assert.Equal(t, int32(0), sm.refreshCount.Load(),
		"Refresh must not be called during lookup operations")
}

// TestAdapter_GenerateCredentialAttrs_AllSlotsFull verifies that when all PIV
// slots are occupied, GenerateCredentialKey returns ErrKeyGenerationFailed
// with the ErrNoAvailableSlot message.
func TestAdapter_GenerateCredentialAttrs_AllSlotsFull(t *testing.T) {
	provider := &recordingKeyProvider{}
	sm := newMockSlotModel("")
	sm.nextErr = xkms.ErrPIVNoAvailableSlot

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	credID := []byte("test-cred-full")
	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyGenerationFailed,
		"error should wrap ErrKeyGenerationFailed")
	// The adapter attaches the slot-allocation failure as the cause of
	// ErrKeyGenerationFailed. Verify the inner error message is present
	// in the error string.
	assert.Contains(t, err.Error(), xkms.ErrPIVNoAvailableSlot.Error(),
		"error message should contain ErrNoAvailableSlot text")

	// Provider.GenerateKey must NOT have been called when slot allocation fails.
	assert.Nil(t, provider.lastAttrs,
		"GenerateKey should not be called when slot allocation fails")
}

// TestAdapter_SlotModelRefreshAfterGenerate verifies that Refresh is called
// on the SlotModel after a successful key generation to update occupancy.
func TestAdapter_SlotModelRefreshAfterGenerate(t *testing.T) {
	provider := &recordingKeyProvider{}
	sm := newMockSlotModel(xkms.PIVSlotRetired2) // "83"

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	credID := []byte("test-cred-refresh")
	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
	require.NoError(t, err)

	assert.Equal(t, int32(1), sm.refreshCount.Load(),
		"Refresh should be called exactly once after successful key generation")
}

// TestAdapter_SlotModelRefreshAfterGenerate_ProviderFails verifies that
// Refresh is NOT called when the provider's GenerateKey fails.
func TestAdapter_SlotModelRefreshAfterGenerate_ProviderFails(t *testing.T) {
	provider := &recordingKeyProvider{
		generateErr: errors.New("hardware failure"),
	}
	sm := newMockSlotModel(xkms.PIVSlotRetired1)

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	credID := []byte("test-cred-fail-refresh")
	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyGenerationFailed)

	// Refresh must NOT be called when GenerateKey fails.
	assert.Equal(t, int32(0), sm.refreshCount.Load(),
		"Refresh must not be called when GenerateKey fails")
}

// TestAdapter_SetSlotModel_Nil verifies that setting SlotModel to nil
// disables slot allocation and GenerateCredentialKey works without one.
func TestAdapter_SetSlotModel_Nil(t *testing.T) {
	provider := &recordingKeyProvider{}
	sm := newMockSlotModel(xkms.PIVSlotRetired1)

	adapter := NewBackendAdapter(provider, xkms.BackendTypePKCS11)
	adapter.SetSlotModel(sm)

	// Now set it to nil.
	adapter.SetSlotModel(nil)

	credID := []byte("test-cred-nil-slot")
	handle, pubKey, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)

	require.NoError(t, err)
	require.NotNil(t, handle)
	require.NotEmpty(t, pubKey)

	// No slot allocation should have happened.
	assert.Empty(t, provider.lastAttrs.PIVSlot,
		"PIVSlot should be empty when SlotModel is nil")
	assert.Equal(t, int32(0), sm.nextCallCount.Load(),
		"NextAvailable must not be called when SlotModel is nil")
	assert.Equal(t, int32(0), sm.refreshCount.Load(),
		"Refresh must not be called when SlotModel is nil")
}
