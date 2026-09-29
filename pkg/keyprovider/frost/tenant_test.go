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

//go:build frost

package frost

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tenantKeyAttrs names a 2-of-3 participant-1 FROST key cn owned by tenantID.
func tenantKeyAttrs(tenantID, cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:        cn,
		TenantID:  tenantID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			Algorithm:     types.FrostAlgorithmEd25519,
			ParticipantID: 1,
		},
	}
}

func TestStorageKeyID(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		cn       string
		want     string
	}{
		{name: "platform key is its common name", cn: "k1", want: "k1"},
		{name: "tenant key is prefixed", tenantID: "tenant-a", cn: "k1", want: "tenant-a:k1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StorageKeyID(tt.tenantID, tt.cn)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStorageKeyID_RefusesUnsafeIDs(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		cn       string
	}{
		{name: "traversal in common name", cn: "../tenant-b/k1"},
		{name: "separator in common name", tenantID: "tenant-a", cn: "tenant-b:k1"},
		{name: "slash in common name", cn: "a/b"},
		{name: "separator in tenant", tenantID: "a:b", cn: "k1"},
		{name: "traversal in tenant", tenantID: "..", cn: "k1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := StorageKeyID(tt.tenantID, tt.cn)
			var idErr *KeyIDError
			require.ErrorAs(t, err, &idErr)
			assert.ErrorIs(t, err, ErrInvalidAttributes)
		})
	}

	_, err := StorageKeyID("tenant-a", "")
	var cfgErr *ConfigError
	assert.ErrorAs(t, err, &cfgErr, "an empty common name keeps its ConfigError")
}

func TestValidateStorageKeyID(t *testing.T) {
	assert.NoError(t, validateStorageKeyID("k1"))
	assert.NoError(t, validateStorageKeyID("tenant-a:k1"))
	assert.ErrorIs(t, validateStorageKeyID(":k1"), ErrInvalidAttributes)
	assert.ErrorIs(t, validateStorageKeyID("tenant-a:../k1"), ErrInvalidAttributes)
	assert.ErrorIs(t, validateStorageKeyID("a:b:c"), ErrInvalidAttributes)
}

// TestFrostBackend_TenantsHaveIndependentNamespaces proves two tenants can
// hold a key under the same common name without either seeing, replacing or
// deleting the other's, and that a platform key of that name is a third,
// separate key.
func TestFrostBackend_TenantsHaveIndependentNamespaces(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)

	a, err := backend.GenerateKey(ctx, tenantKeyAttrs("tenant-a", "shared"))
	require.NoError(t, err)
	b, err := backend.GenerateKey(ctx, tenantKeyAttrs("tenant-b", "shared"))
	require.NoError(t, err)
	_, err = backend.GenerateKey(ctx, tenantKeyAttrs("", "shared"))
	require.NoError(t, err)

	assert.Equal(t, "shared", a.(*FrostKeyHandle).KeyID, "the handle carries the common name")
	assert.NotEqual(t, a.(*FrostKeyHandle).GroupPublicKey, b.(*FrostKeyHandle).GroupPublicKey)

	gotB, err := backend.GetKey(ctx, tenantKeyAttrs("tenant-b", "shared"))
	require.NoError(t, err)
	assert.Equal(t, b.(*FrostKeyHandle).GroupPublicKey, gotB.(*FrostKeyHandle).GroupPublicKey)

	listed, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	owners := map[string]bool{}
	for _, k := range listed {
		assert.Equal(t, "shared", k.CN)
		owners[k.TenantID] = true
	}
	assert.Equal(t, map[string]bool{"tenant-a": true, "tenant-b": true, "": true}, owners,
		"ListKeys must report each key's owning tenant")

	require.NoError(t, backend.DeleteKey(ctx, tenantKeyAttrs("tenant-a", "shared")))
	_, err = backend.GetKey(ctx, tenantKeyAttrs("tenant-a", "shared"))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = backend.GetKey(ctx, tenantKeyAttrs("tenant-b", "shared"))
	assert.NoError(t, err, "deleting tenant A's key must not touch tenant B's")
	_, err = backend.GetKey(ctx, tenantKeyAttrs("", "shared"))
	assert.NoError(t, err, "deleting tenant A's key must not touch the platform key")
}

// TestFrostBackend_OtherTenantsKeyIsNotFound proves a key is reachable only
// through the tenant that owns it.
func TestFrostBackend_OtherTenantsKeyIsNotFound(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)
	_, err := backend.GenerateKey(ctx, tenantKeyAttrs("tenant-b", "b-key"))
	require.NoError(t, err)

	_, err = backend.GetKey(ctx, tenantKeyAttrs("tenant-a", "b-key"))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = backend.GetKey(ctx, tenantKeyAttrs("", "b-key"))
	assert.ErrorIs(t, err, ErrKeyNotFound, "a bare common name names a platform key")
	assert.ErrorIs(t, backend.DeleteKey(ctx, tenantKeyAttrs("tenant-a", "b-key")), ErrKeyNotFound)
	_, err = backend.Signer(ctx, tenantKeyAttrs("tenant-a", "b-key"))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.ErrorIs(t, backend.RotateKey(ctx, tenantKeyAttrs("tenant-a", "b-key")), ErrKeyNotFound)

	scoped, err := StorageKeyID("tenant-a", "b-key")
	require.NoError(t, err)
	_, err = backend.GenerateNonces(scoped)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestFrostBackend_RoundAPIAddressesTenantKeysByStorageKeyID proves the round
// API reaches a tenant's key through its storage key ID and nothing else.
func TestFrostBackend_RoundAPIAddressesTenantKeysByStorageKeyID(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)
	_, err := backend.GenerateKey(ctx, tenantKeyAttrs("tenant-a", "k1"))
	require.NoError(t, err)

	scoped, err := StorageKeyID("tenant-a", "k1")
	require.NoError(t, err)
	nonces, err := backend.GenerateNonces(scoped)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), nonces.ParticipantID)

	_, err = backend.GenerateNonces("k1")
	assert.ErrorIs(t, err, ErrKeyNotFound, "the bare common name is the platform namespace")
}

func TestFrostBackend_RoundAPIRefusesUnsafeKeyIDs(t *testing.T) {
	backend := createTestBackend(t)
	const unsafe = "tenant-a:../tenant-b:k1"

	_, err := backend.GenerateNonces(unsafe)
	assert.ErrorIs(t, err, ErrInvalidAttributes)
	_, err = backend.SignRound(unsafe, []byte("m"), &NoncePackage{}, []*Commitment{{}})
	assert.ErrorIs(t, err, ErrInvalidAttributes)
	_, err = backend.Aggregate(unsafe, []byte("m"), nil, nil)
	assert.ErrorIs(t, err, ErrInvalidAttributes)
	assert.ErrorIs(t, backend.Verify(unsafe, []byte("m"), []byte("s")), ErrInvalidAttributes)
}

// TestFrostBackend_ImportKeyPackage covers the tenant-stamping import: the
// package lands under the caller's tenant, replaces only a key of the same
// tenant and name, and reports its metadata through ListKeys.
func TestFrostBackend_ImportKeyPackage(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)
	_, err := backend.GenerateKey(ctx, tenantKeyAttrs("tenant-b", "k1"))
	require.NoError(t, err)
	before, err := backend.GetKey(ctx, tenantKeyAttrs("tenant-b", "k1"))
	require.NoError(t, err)

	packages, pub, err := NewTrustedDealer().Generate(FrostConfig{
		Threshold: 2, Total: 3, Algorithm: types.FrostAlgorithmEd25519, ParticipantID: 1,
	})
	require.NoError(t, err)

	attrs := tenantKeyAttrs("tenant-a", "k1")
	attrs.FrostAttributes.Participants = []string{"p1", "p2", "p3"}
	require.NoError(t, backend.ImportKeyPackage(ctx, attrs, packages[1]))

	imported, err := backend.GetKey(ctx, tenantKeyAttrs("tenant-a", "k1"))
	require.NoError(t, err)
	assert.Equal(t, pub.GroupPublicKey, imported.(*FrostKeyHandle).GroupPublicKey)
	assert.Equal(t, uint32(2), imported.(*FrostKeyHandle).ParticipantID)

	after, err := backend.GetKey(ctx, tenantKeyAttrs("tenant-b", "k1"))
	require.NoError(t, err)
	assert.Equal(t, before.(*FrostKeyHandle).GroupPublicKey, after.(*FrostKeyHandle).GroupPublicKey,
		"an import must not replace another tenant's key")

	listed, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	var found bool
	for _, k := range listed {
		if k.TenantID == "tenant-a" && k.CN == "k1" {
			found = true
			assert.Equal(t, 2, k.FrostAttributes.Threshold)
			assert.Equal(t, 3, k.FrostAttributes.Total)
			assert.Equal(t, []string{"p1", "p2", "p3"}, k.FrostAttributes.Participants)
		}
	}
	assert.True(t, found, "the imported key must be listed under tenant A")
}

func TestFrostBackend_ImportKeyPackage_Errors(t *testing.T) {
	ctx := context.Background()
	backend := createTestBackend(t)
	packages, _, err := NewTrustedDealer().Generate(FrostConfig{
		Threshold: 2, Total: 3, Algorithm: types.FrostAlgorithmEd25519, ParticipantID: 1,
	})
	require.NoError(t, err)

	assert.ErrorIs(t, backend.ImportKeyPackage(ctx, nil, packages[0]), ErrInvalidAttributes)
	assert.ErrorIs(t, backend.ImportKeyPackage(ctx, tenantKeyAttrs("tenant-a", "../x"), packages[0]), ErrInvalidAttributes)
	assert.ErrorIs(t, backend.ImportKeyPackage(ctx, tenantKeyAttrs("tenant-a", "k1"), nil), ErrInvalidAttributes)

	require.NoError(t, backend.Close())
	err = backend.ImportKeyPackage(ctx, tenantKeyAttrs("tenant-a", "k1"), packages[0])
	assert.True(t, errors.Is(err, ErrBackendClosed))
}
