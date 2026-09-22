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
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPCRPolicyStore creates a pcrpolicy.DAOStore backed by in-memory
// storage, exactly as the CLI and the GUI composition root construct it
// (xkms.NewFileStorageBackend/NewStorageMemory -> xkms.NewKVStoreAdapter ->
// pcrpolicy.NewDAOStore), so tests exercise the same store implementation
// used in production.
func newTestPCRPolicyStore(t *testing.T) pcrpolicy.PolicyStore {
	t.Helper()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	require.NoError(t, err)

	store, err := pcrpolicy.NewDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	return store
}

// ---------------------------------------------------------------------------
// pcrPolicyToEntity
// ---------------------------------------------------------------------------

func TestPCRPolicyToEntity_Success(t *testing.T) {
	p := PCRPolicy{
		Name:          "boot-policy",
		Description:   "Secure boot PCRs",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
		PCRDigests: map[string]string{
			"sha256:0": "aabbccdd",
			"sha256:7": "11223344",
		},
		IsPlatformPolicy: true,
		CreatedAt:        "2026-01-01T00:00:00Z",
	}

	entity, err := pcrPolicyToEntity(p)
	require.NoError(t, err)
	assert.Equal(t, "boot-policy", entity.Name)
	assert.Equal(t, "Secure boot PCRs", entity.Description)
	assert.Equal(t, "SHA256", entity.Bank)
	assert.True(t, entity.IsPlatformPolicy)
	require.Len(t, entity.PCRs, 2)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, entity.PCRs[0])
	assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, entity.PCRs[7])
	assert.Equal(t, 2026, entity.CreatedAt.Year())
}

func TestPCRPolicyToEntity_MixedBanksRejected(t *testing.T) {
	p := PCRPolicy{
		Name: "mixed",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha384"},
		},
	}

	entity, err := pcrPolicyToEntity(p)
	assert.Nil(t, entity)
	assert.ErrorIs(t, err, ErrTPMPolicyMixedBanks)
}

func TestPCRPolicyToEntity_EmptyName(t *testing.T) {
	p := PCRPolicy{PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}
	entity, err := pcrPolicyToEntity(p)
	assert.Nil(t, entity)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestPCRPolicyToEntity_NoSelections(t *testing.T) {
	p := PCRPolicy{Name: "no-selections"}
	entity, err := pcrPolicyToEntity(p)
	assert.Nil(t, entity)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

// ---------------------------------------------------------------------------
// entityToPCRPolicy
// ---------------------------------------------------------------------------

func TestEntityToPCRPolicy_Success(t *testing.T) {
	now := time.Now().UTC()
	entity := &pcrpolicy.PCRPolicyEntity{
		Name:        "boot-policy",
		Description: "Secure boot PCRs",
		Bank:        "SHA256",
		PCRs: map[uint][]byte{
			0: {0xAA, 0xBB, 0xCC, 0xDD},
			7: {0x11, 0x22, 0x33, 0x44},
		},
		IsPlatformPolicy: true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	p := entityToPCRPolicy(entity)
	assert.Equal(t, "boot-policy", p.Name)
	assert.Equal(t, "Secure boot PCRs", p.Description)
	assert.True(t, p.IsPlatformPolicy)
	require.Len(t, p.PCRSelections, 2)
	assert.Equal(t, "sha256", p.PCRSelections[0].Bank)
	assert.Equal(t, "aabbccdd", p.PCRDigests["sha256:0"])
	assert.Equal(t, "11223344", p.PCRDigests["sha256:7"])
	assert.NotEmpty(t, p.CreatedAt)
}

func TestEntityToPCRPolicy_NoDigestsOmitsMap(t *testing.T) {
	entity := &pcrpolicy.PCRPolicyEntity{
		Name: "no-digests",
		Bank: "SHA256",
		PCRs: map[uint][]byte{0: nil},
	}

	p := entityToPCRPolicy(entity)
	assert.Nil(t, p.PCRDigests, "no captured digest values should not produce an empty non-nil map")
	require.Len(t, p.PCRSelections, 1)
}

// ---------------------------------------------------------------------------
// TPMService <-> unified pcr_policy store round-trip (requirement #3)
// ---------------------------------------------------------------------------

func TestTPMService_PolicyStore_CRUDRoundTrip(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetPolicyStore(newTestPCRPolicyStore(t))

	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "unified-policy",
		Description:   "round trip test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))

	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "unified-policy", policies[0].Name)
	assert.Equal(t, "round trip test", policies[0].Description)

	got, err := svc.GetPolicy("unified-policy")
	require.NoError(t, err)
	assert.Equal(t, "unified-policy", got.Name)

	require.NoError(t, svc.DeletePolicy("unified-policy"))
	_, err = svc.GetPolicy("unified-policy")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTPMService_PolicyStore_CreateDuplicateFails(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetPolicyStore(newTestPCRPolicyStore(t))

	policy := &PCRPolicy{Name: "dupe", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}
	require.NoError(t, svc.CreatePolicy(policy))
	err := svc.CreatePolicy(policy)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

// ---------------------------------------------------------------------------
// PCR policy CRUD requires an explicitly wired store (no file fallback)
// ---------------------------------------------------------------------------

func TestTPMService_ListPolicies_NoStoreConfiguredReturnsTypedError(t *testing.T) {
	svc := newServiceWithMock(&mockTPM{})
	svc.SetDataDir(t.TempDir())

	_, err := svc.ListPolicies()
	assert.ErrorIs(t, err, ErrTPMPolicyStoreNotSet)
}

func TestTPMService_CreatePolicy_NoStoreConfiguredReturnsTypedError(t *testing.T) {
	svc := newServiceWithMock(&mockTPM{})
	svc.SetDataDir(t.TempDir())

	err := svc.CreatePolicy(&PCRPolicy{Name: "no-store", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}})
	assert.ErrorIs(t, err, ErrTPMPolicyStoreNotSet)
}

func TestTPMService_SyncPoliciesToStore_Error(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetPolicyStore(newTestPCRPolicyStore(t))

	// An empty-name policy cannot be converted to an entity, so the sync
	// must surface the conversion error rather than silently dropping it.
	err := svc.savePolicies([]PCRPolicy{{Name: "", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// getPolicyStore
// ---------------------------------------------------------------------------

func TestTPMService_GetPolicyStore_NilByDefault(t *testing.T) {
	svc := NewTPMService()
	assert.Nil(t, svc.getPolicyStore())
}

func TestTPMService_GetPolicyStore_ReturnsConfiguredStore(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	store := newTestPCRPolicyStore(t)
	svc.SetPolicyStore(store)
	assert.Equal(t, store, svc.getPolicyStore())
}
