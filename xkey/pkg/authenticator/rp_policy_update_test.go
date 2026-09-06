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

package authenticator

import (
	"context"
	"encoding/json"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPPolicyUpdate_Validate_Valid(t *testing.T) {
	uv := "required"
	att := "direct"
	up := true
	enterprise := true
	blocked := false
	update := &RPPolicyUpdate{
		RPID:                "rp.example",
		UVOverride:          &uv,
		UPOverride:          &up,
		AttestationOverride: &att,
		Enterprise:          &enterprise,
		Blocked:             &blocked,
	}
	require.NoError(t, update.Validate())

	// An update carrying only the RPID is valid: it changes nothing.
	require.NoError(t, (&RPPolicyUpdate{RPID: "rp.example"}).Validate())

	// Explicit empty overrides are valid (they clear the override).
	empty := ""
	require.NoError(t, (&RPPolicyUpdate{RPID: "rp.example", UVOverride: &empty, AttestationOverride: &empty}).Validate())
}

func TestRPPolicyUpdate_Validate_Invalid(t *testing.T) {
	var nilUpdate *RPPolicyUpdate
	require.ErrorIs(t, nilUpdate.Validate(), ErrRPPolicyUpdateNil)

	require.ErrorIs(t, (&RPPolicyUpdate{}).Validate(), ErrRPPolicyInvalidRPID)

	badUV := "always"
	require.ErrorIs(t, (&RPPolicyUpdate{RPID: "rp.example", UVOverride: &badUV}).Validate(), ErrInvalidParameter)

	badAtt := "self"
	require.ErrorIs(t, (&RPPolicyUpdate{RPID: "rp.example", AttestationOverride: &badAtt}).Validate(), ErrInvalidParameter)
}

func TestApplyRPPolicyUpdate_NilExisting(t *testing.T) {
	blocked := true
	merged := applyRPPolicyUpdate(nil, &RPPolicyUpdate{RPID: "new.example", Blocked: &blocked})

	assert.Equal(t, "new.example", merged.RPID)
	assert.True(t, merged.Blocked)
	assert.Equal(t, "", merged.UVOverride)
	assert.Nil(t, merged.UPOverride)
	assert.False(t, merged.Enterprise)
}

func TestApplyRPPolicyUpdate_EmptyUpdatePreservesEverything(t *testing.T) {
	existing := fullTestRPPolicy("rp.example")
	existing.Blocked = true

	merged := applyRPPolicyUpdate(existing, &RPPolicyUpdate{RPID: "rp.example"})

	assert.Equal(t, existing.UVOverride, merged.UVOverride)
	require.NotNil(t, merged.UPOverride)
	assert.Equal(t, *existing.UPOverride, *merged.UPOverride)
	assert.Equal(t, existing.AttestationOverride, merged.AttestationOverride)
	assert.Equal(t, existing.Enterprise, merged.Enterprise)
	assert.Equal(t, existing.Blocked, merged.Blocked)
}

func TestApplyRPPolicyUpdate_DoesNotAliasInputs(t *testing.T) {
	existing := fullTestRPPolicy("rp.example")
	up := false
	merged := applyRPPolicyUpdate(existing, &RPPolicyUpdate{RPID: "rp.example", UPOverride: &up})

	// The merged policy must not share pointers with the existing policy or
	// the update, so later mutation of either cannot corrupt stored state.
	require.NotNil(t, merged.UPOverride)
	assert.NotSame(t, existing.UPOverride, merged.UPOverride)
	assert.NotSame(t, &up, merged.UPOverride)
	assert.False(t, *merged.UPOverride)
	assert.True(t, *existing.UPOverride, "existing policy must be unmodified")
}

func TestMemoryRPPolicyStore_UpdatePolicy_PartialPreservesStoredFields(t *testing.T) {
	store := NewMemoryRPPolicyStore()
	t.Cleanup(func() { _ = store.Close() })

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("rp.example")))

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", Blocked: &blocked}))

	loaded, err := store.GetPolicy("rp.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride)
	require.NotNil(t, loaded.UPOverride)
	assert.True(t, *loaded.UPOverride)
	assert.Equal(t, "direct", loaded.AttestationOverride)
	assert.True(t, loaded.Enterprise)
	assert.True(t, loaded.Blocked)
}

func TestMemoryRPPolicyStore_UpdatePolicy_CreatesWhenAbsent(t *testing.T) {
	store := NewMemoryRPPolicyStore()
	t.Cleanup(func() { _ = store.Close() })

	uv := "required"
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "new.example", UVOverride: &uv}))

	loaded, err := store.GetPolicy("new.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride)
	assert.False(t, loaded.Blocked)
}

func TestMemoryRPPolicyStore_UpdatePolicy_Errors(t *testing.T) {
	store := NewMemoryRPPolicyStore()

	require.ErrorIs(t, store.UpdatePolicy(nil), ErrRPPolicyUpdateNil)
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{}), ErrRPPolicyInvalidRPID)

	require.NoError(t, store.Close())
	blocked := true
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", Blocked: &blocked}), ErrRPPolicyStoreClosed)
}

func newTestBackendRPPolicyStore(t *testing.T) (*BackendRPPolicyStore, xkms.StorageBackend) {
	t.Helper()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { backend.Close() })

	store, err := NewBackendRPPolicyStore(backend, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	return store, backend
}

func TestBackendRPPolicyStore_UpdatePolicy_PartialPreservesStoredFields(t *testing.T) {
	store, _ := newTestBackendRPPolicyStore(t)

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("rp.example")))

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", Blocked: &blocked}))

	loaded, err := store.GetPolicy("rp.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride)
	require.NotNil(t, loaded.UPOverride)
	assert.True(t, *loaded.UPOverride)
	assert.Equal(t, "direct", loaded.AttestationOverride)
	assert.True(t, loaded.Enterprise)
	assert.True(t, loaded.Blocked)
}

func TestBackendRPPolicyStore_UpdatePolicy_CreatesWhenAbsent(t *testing.T) {
	store, _ := newTestBackendRPPolicyStore(t)

	enterprise := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "new.example", Enterprise: &enterprise}))

	loaded, err := store.GetPolicy("new.example")
	require.NoError(t, err)
	assert.True(t, loaded.Enterprise)
	assert.False(t, loaded.Blocked)
}

func TestBackendRPPolicyStore_UpdatePolicy_Errors(t *testing.T) {
	store, backend := newTestBackendRPPolicyStore(t)

	require.ErrorIs(t, store.UpdatePolicy(nil), ErrRPPolicyUpdateNil)
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{}), ErrRPPolicyInvalidRPID)

	// A stored record that no longer parses must surface a typed error, not
	// be silently replaced.
	require.NoError(t, backend.Put(context.Background(), store.policyKey("corrupt.example"), []byte("{not json")))
	blocked := true
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "corrupt.example", Blocked: &blocked}), ErrDeserializationFailed)

	require.NoError(t, store.Close())
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", Blocked: &blocked}), ErrRPPolicyStoreClosed)
}

func TestRPPolicyEntity_VersionAccessors(t *testing.T) {
	entity := &RPPolicyEntity{}
	assert.Equal(t, int64(0), entity.GetVersion(), "zero value must report version 0")

	entity.SetVersion(7)
	assert.Equal(t, int64(7), entity.GetVersion())
}

func TestRPPolicyEntity_VersionSerializes(t *testing.T) {
	entity := &RPPolicyEntity{RPID: "rp.example"}
	entity.SetVersion(3)

	data, err := json.Marshal(entity)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"version":3`, "Version must round-trip through the DAO's JSON codec")

	var decoded RPPolicyEntity
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, int64(3), decoded.GetVersion())
}
