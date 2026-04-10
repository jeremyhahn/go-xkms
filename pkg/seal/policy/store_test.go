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

package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestDefinition(name string) *PolicyDefinition {
	now := time.Now()
	return &PolicyDefinition{
		Name:       name,
		Bank:       "sha256",
		PCRIndices: []int{0, 1, 7},
		PCRValues: map[int][]byte{
			0: {0xaa, 0xbb, 0xcc},
			1: {0xdd, 0xee, 0xff},
			7: {0x11, 0x22, 0x33},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestMemoryPolicyStore_SaveAndLoad(t *testing.T) {
	store := NewMemoryPolicyStore()
	def := newTestDefinition("boot-policy")

	err := store.SavePolicy("boot-policy", def)
	require.NoError(t, err)

	loaded, err := store.LoadPolicy("boot-policy")
	require.NoError(t, err)
	assert.Equal(t, def.Name, loaded.Name)
	assert.Equal(t, def.Bank, loaded.Bank)
	assert.Equal(t, def.PCRIndices, loaded.PCRIndices)
	assert.Equal(t, def.PCRValues, loaded.PCRValues)
}

func TestMemoryPolicyStore_LoadNotFound(t *testing.T) {
	store := NewMemoryPolicyStore()

	loaded, err := store.LoadPolicy("nonexistent")
	assert.Nil(t, loaded)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestMemoryPolicyStore_DeleteSuccess(t *testing.T) {
	store := NewMemoryPolicyStore()
	def := newTestDefinition("delete-me")

	err := store.SavePolicy("delete-me", def)
	require.NoError(t, err)

	err = store.DeletePolicy("delete-me")
	require.NoError(t, err)

	loaded, err := store.LoadPolicy("delete-me")
	assert.Nil(t, loaded)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestMemoryPolicyStore_DeleteNotFound(t *testing.T) {
	store := NewMemoryPolicyStore()

	err := store.DeletePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestMemoryPolicyStore_ListEmpty(t *testing.T) {
	store := NewMemoryPolicyStore()

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestMemoryPolicyStore_ListReturnsAll(t *testing.T) {
	store := NewMemoryPolicyStore()

	err := store.SavePolicy("policy-a", newTestDefinition("policy-a"))
	require.NoError(t, err)

	err = store.SavePolicy("policy-b", newTestDefinition("policy-b"))
	require.NoError(t, err)

	err = store.SavePolicy("policy-c", newTestDefinition("policy-c"))
	require.NoError(t, err)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 3)

	names := make(map[string]bool)
	for _, p := range policies {
		names[p.Name] = true
	}
	assert.True(t, names["policy-a"])
	assert.True(t, names["policy-b"])
	assert.True(t, names["policy-c"])
}

func TestMemoryPolicyStore_Overwrite(t *testing.T) {
	store := NewMemoryPolicyStore()

	original := newTestDefinition("overwrite")
	err := store.SavePolicy("overwrite", original)
	require.NoError(t, err)

	updated := newTestDefinition("overwrite")
	updated.Bank = "sha384"
	updated.PCRValues = map[int][]byte{
		0: {0x00, 0x00, 0x00},
		1: {0x11, 0x11, 0x11},
		7: {0x22, 0x22, 0x22},
	}
	err = store.SavePolicy("overwrite", updated)
	require.NoError(t, err)

	loaded, err := store.LoadPolicy("overwrite")
	require.NoError(t, err)
	assert.Equal(t, "sha384", loaded.Bank)
	assert.Equal(t, updated.PCRValues, loaded.PCRValues)
}
