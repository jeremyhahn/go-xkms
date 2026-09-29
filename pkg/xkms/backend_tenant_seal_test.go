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

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tenantSealFixture returns a tenant view over a mock backend whose key
// provider records the options each seal and unseal receives.
func tenantSealFixture(storeType types.StoreType) (*TenantScopedBackend, *mockSealerKeyProvider) {
	sealer := newMockSealerKeyProvider(types.BackendTypeSoftware)
	base := newMockKeyStore("software")
	base.backend = sealer
	base.storeType = storeType
	return NewTenantScopedBackend(base, "acme"), sealer
}

func TestTenantScopedBackend_SealStampsTheTenantOnTheKey(t *testing.T) {
	scoped, sealer := tenantSealFixture(types.StoreSoftware)
	callerAttrs := &types.KeyAttributes{CN: "vault-key"}

	_, err := scoped.Seal(context.Background(), []byte("secret"),
		&types.SealOptions{KeyAttributes: callerAttrs, AAD: []byte("aad")})
	require.NoError(t, err)
	require.NotNil(t, sealer.lastSealOpts.KeyAttributes)
	assert.Equal(t, "acme", sealer.lastSealOpts.KeyAttributes.TenantID)
	assert.Equal(t, "vault-key", sealer.lastSealOpts.KeyAttributes.CN)
	assert.Equal(t, []byte("aad"), sealer.lastSealOpts.AAD)
	assert.Empty(t, callerAttrs.TenantID, "the caller's attributes must not be mutated")

	_, err = scoped.Unseal(context.Background(), &types.SealedData{Backend: types.BackendTypeSoftware},
		&types.UnsealOptions{KeyAttributes: callerAttrs})
	require.NoError(t, err)
	require.NotNil(t, sealer.lastUnsealOpts.KeyAttributes)
	assert.Equal(t, "acme", sealer.lastUnsealOpts.KeyAttributes.TenantID)
}

func TestTenantScopedBackend_SealWithoutOptionsReachesTheBaseUnchanged(t *testing.T) {
	scoped, sealer := tenantSealFixture(types.StoreSoftware)

	_, err := scoped.Seal(context.Background(), []byte("secret"), nil)
	require.NoError(t, err)
	assert.Nil(t, sealer.lastSealOpts, "no options means no key to scope")

	_, err = scoped.Unseal(context.Background(), &types.SealedData{}, nil)
	require.NoError(t, err)
	assert.Nil(t, sealer.lastUnsealOpts)
}

func TestTenantScopedBackend_RefusesUnboundTPM2Sealing(t *testing.T) {
	scoped, sealer := tenantSealFixture(types.StoreTPM2)

	_, err := scoped.Seal(context.Background(), []byte("secret"), &types.SealOptions{})
	require.ErrorIs(t, err, ErrSealNotTenantBound)
	var unsupported *ErrBackendUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, string(types.StoreTPM2), unsupported.Backend)

	_, err = scoped.Unseal(context.Background(), &types.SealedData{}, &types.UnsealOptions{})
	require.ErrorIs(t, err, ErrSealNotTenantBound)

	assert.Nil(t, sealer.lastSealOpts, "the TPM must not be reached")
	assert.Nil(t, sealer.lastUnsealOpts)
}
