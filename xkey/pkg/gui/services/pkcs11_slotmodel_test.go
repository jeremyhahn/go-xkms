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

package services

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSlotModel implements xkms.PIVSlotModel with a fixed slot list and
// configurable occupancy/refresh behavior, for exercising
// PKCS11Service.GetSlotOccupancy and HasSlotModel without a real token.
type fakeSlotModel struct {
	slots        []xkms.PIVSlot
	occupancy    map[xkms.PIVSlot]*xkms.PIVSlotOccupancyInfo
	refreshErr   error
	refreshCalls int
}

func (m *fakeSlotModel) AllSlots() []xkms.PIVSlot { return m.slots }
func (m *fakeSlotModel) AvailableSlots() ([]xkms.PIVSlot, error) {
	return nil, errMockNotImplemented
}
func (m *fakeSlotModel) OccupiedSlots() ([]xkms.PIVSlot, error) {
	return nil, errMockNotImplemented
}
func (m *fakeSlotModel) IsOccupied(_ xkms.PIVSlot) (bool, error) {
	return false, errMockNotImplemented
}
func (m *fakeSlotModel) NextAvailable() (xkms.PIVSlot, error) {
	return "", errMockNotImplemented
}
func (m *fakeSlotModel) SlotOccupancy(slot xkms.PIVSlot) (*xkms.PIVSlotOccupancyInfo, error) {
	info, ok := m.occupancy[slot]
	if !ok {
		return nil, errors.New("fakeSlotModel: no occupancy info for slot")
	}
	return info, nil
}
func (m *fakeSlotModel) Refresh() error {
	m.refreshCalls++
	return m.refreshErr
}

// fakeSlotModelBackend implements xkms.PKCS11ManagerBackend and additionally
// exposes SlotModel(), satisfying the unexported slotModelProvider interface
// PKCS11Service type-asserts for.
type fakeSlotModelBackend struct {
	slotModel xkms.PIVSlotModel
}

func (b *fakeSlotModelBackend) Type() types.BackendType          { return types.BackendType("pkcs11") }
func (b *fakeSlotModelBackend) Capabilities() types.Capabilities { return types.Capabilities{} }
func (b *fakeSlotModelBackend) GenerateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errMockNotImplemented
}
func (b *fakeSlotModelBackend) Get(_ *types.KeyAttributes, _ types.FSExtension) ([]byte, error) {
	return nil, errMockNotImplemented
}
func (b *fakeSlotModelBackend) Delete(_ *types.KeyAttributes) error { return errMockNotImplemented }
func (b *fakeSlotModelBackend) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errMockNotImplemented
}
func (b *fakeSlotModelBackend) Close() error                 { return nil }
func (b *fakeSlotModelBackend) SlotModel() xkms.PIVSlotModel { return b.slotModel }

// fakeConnManager implements xkms.PKCS11Manager, returning a fixed
// connection/module list so GetSlotOccupancy, HasSlotModel, and the
// registry-aware branch of Close can be exercised without a real PKCS#11
// library.
type fakeConnManager struct {
	conn       *xkms.PKCS11Connection
	connErr    error
	modules    []xkms.PKCS11ModuleInfo
	closeErr   error
	closeCalls int
}

func (m *fakeConnManager) IsAvailable() bool { return true }
func (m *fakeConnManager) RegisterModule(_, _ string) (string, error) {
	return "", errMockNotImplemented
}
func (m *fakeConnManager) UnregisterModule(_ string) error { return errMockNotImplemented }
func (m *fakeConnManager) RefreshSlots(_ string) ([]xkms.PKCS11SlotInfo, error) {
	return nil, errMockNotImplemented
}
func (m *fakeConnManager) GetModule(_ string) (*xkms.PKCS11ModuleInfo, error) {
	return nil, errMockNotImplemented
}
func (m *fakeConnManager) ListModules() []xkms.PKCS11ModuleInfo { return m.modules }
func (m *fakeConnManager) ListTokens() []xkms.PKCS11TokenInfo   { return nil }
func (m *fakeConnManager) InitializeToken(_ string, _ uint, _, _, _ string) error {
	return errMockNotImplemented
}
func (m *fakeConnManager) TestLogin(_ string, _ uint, _ string) error {
	return errMockNotImplemented
}
func (m *fakeConnManager) Connect(_ string, _ uint, _, _ string) (xkms.PKCS11ManagerBackend, error) {
	return nil, errMockNotImplemented
}
func (m *fakeConnManager) Disconnect(_ string, _ uint) error { return errMockNotImplemented }
func (m *fakeConnManager) GetConnection(_ string, _ uint) (*xkms.PKCS11Connection, error) {
	return m.conn, m.connErr
}
func (m *fakeConnManager) ListConnections() []*xkms.PKCS11Connection { return nil }
func (m *fakeConnManager) Close() error {
	m.closeCalls++
	return m.closeErr
}

var _ xkms.PKCS11Manager = (*fakeConnManager)(nil)
var _ xkms.PKCS11ManagerBackend = (*fakeSlotModelBackend)(nil)
var _ xkms.PIVSlotModel = (*fakeSlotModel)(nil)

func TestPKCS11Service_GetSlotOccupancy_ConnectionNotFound(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{connErr: errors.New("no such connection")})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.Error(t, err)
	assert.Nil(t, occupancy)
}

func TestPKCS11Service_GetSlotOccupancy_NilBackend(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{ModuleID: "mod", SlotID: 0}})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.NoError(t, err)
	assert.Nil(t, occupancy)
}

func TestPKCS11Service_GetSlotOccupancy_BackendWithoutSlotModel(t *testing.T) {
	svc := NewPKCS11Service()
	// A backend that does not implement slotModelProvider (generic PKCS#11).
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{
		ModuleID: "mod", SlotID: 0, Backend: &noSlotModelBackend{},
	}})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.NoError(t, err)
	assert.Nil(t, occupancy)
}

func TestPKCS11Service_GetSlotOccupancy_NilSlotModel(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{
		ModuleID: "mod", SlotID: 0, Backend: &fakeSlotModelBackend{slotModel: nil},
	}})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.NoError(t, err)
	assert.Nil(t, occupancy)
}

func TestPKCS11Service_GetSlotOccupancy_Success(t *testing.T) {
	sm := &fakeSlotModel{
		slots: []xkms.PIVSlot{"9a", "9c"},
		occupancy: map[xkms.PIVSlot]*xkms.PIVSlotOccupancyInfo{
			"9a": {Slot: "9a", Name: "PIV Authentication", Occupied: true, KeyAlgorithm: "ECDSA P-256", HasCert: true},
			// "9c" intentionally omitted to exercise the per-slot error->continue path.
		},
	}
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{
		ModuleID: "mod", SlotID: 0, Backend: &fakeSlotModelBackend{slotModel: sm},
	}})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.NoError(t, err)
	require.Len(t, occupancy, 1)
	assert.Equal(t, "9a", occupancy[0].Slot)
	assert.Equal(t, "PIV Authentication", occupancy[0].Name)
	assert.True(t, occupancy[0].Occupied)
	assert.True(t, occupancy[0].HasCert)
	assert.Equal(t, 1, sm.refreshCalls)
}

func TestPKCS11Service_GetSlotOccupancy_RefreshErrorIsNonFatal(t *testing.T) {
	sm := &fakeSlotModel{
		slots:      []xkms.PIVSlot{"9a"},
		occupancy:  map[xkms.PIVSlot]*xkms.PIVSlotOccupancyInfo{"9a": {Slot: "9a"}},
		refreshErr: errors.New("token removed"),
	}
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{
		ModuleID: "mod", SlotID: 0, Backend: &fakeSlotModelBackend{slotModel: sm},
	}})

	occupancy, err := svc.GetSlotOccupancy("mod", 0)
	require.NoError(t, err, "a refresh failure is logged, not propagated")
	require.Len(t, occupancy, 1)
}

func TestPKCS11Service_HasSlotModel_ConnectionNotFound(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{connErr: errors.New("no such connection")})
	assert.False(t, svc.HasSlotModel("mod", 0))
}

func TestPKCS11Service_HasSlotModel_NilBackend(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{ModuleID: "mod", SlotID: 0}})
	assert.False(t, svc.HasSlotModel("mod", 0))
}

func TestPKCS11Service_HasSlotModel_True(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetManager(&fakeConnManager{conn: &xkms.PKCS11Connection{
		ModuleID: "mod", SlotID: 0,
		Backend: &fakeSlotModelBackend{slotModel: &fakeSlotModel{}},
	}})
	assert.True(t, svc.HasSlotModel("mod", 0))
}

func TestPKCS11Service_Close_WithRegistry_UnregistersEachModule(t *testing.T) {
	mgr := &fakeConnManager{
		modules: []xkms.PKCS11ModuleInfo{{ID: "mod-1"}, {ID: "mod-2"}},
	}
	svc := NewPKCS11Service()
	svc.SetManager(mgr)
	svc.SetRegistry(backendregistry.NewMemoryRegistry())

	require.NoError(t, svc.Close())
	assert.Equal(t, 1, mgr.closeCalls)
}

// noSlotModelBackend implements xkms.PKCS11ManagerBackend but not
// slotModelProvider, modeling a generic PKCS#11 token with no predefined
// PIV slot layout.
type noSlotModelBackend struct{}

func (b *noSlotModelBackend) Type() types.BackendType          { return types.BackendType("pkcs11") }
func (b *noSlotModelBackend) Capabilities() types.Capabilities { return types.Capabilities{} }
func (b *noSlotModelBackend) GenerateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errMockNotImplemented
}
func (b *noSlotModelBackend) Get(_ *types.KeyAttributes, _ types.FSExtension) ([]byte, error) {
	return nil, errMockNotImplemented
}
func (b *noSlotModelBackend) Delete(_ *types.KeyAttributes) error { return errMockNotImplemented }
func (b *noSlotModelBackend) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errMockNotImplemented
}
func (b *noSlotModelBackend) Close() error { return nil }

var _ xkms.PKCS11ManagerBackend = (*noSlotModelBackend)(nil)
