// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package tenancy

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func rsaAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
}

// TestTenantKeyProvider_ScopesEveryOperation proves each key operation the
// view performs lands in its tenant's namespace: the same common name in two
// views is two keys, each visible, usable and deletable only through its own
// view.
func TestTenantKeyProvider_ScopesEveryOperation(t *testing.T) {
	ctx := context.Background()
	base, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	a := &tenantKeyProvider{base: base, tenantID: tenantA}
	b := &tenantKeyProvider{base: base, tenantID: tenantB}

	assert.Equal(t, base.Type(), a.Type())
	assert.Equal(t, base.Capabilities(), a.Capabilities())

	attrs := rsaAttrs("shared-cn")
	_, err = a.GenerateKey(ctx, attrs)
	require.NoError(t, err)
	assert.Empty(t, attrs.TenantID, "the caller's attributes must not be mutated")

	_, err = b.GetKey(ctx, rsaAttrs("shared-cn"))
	require.Error(t, err, "tenant B must not reach tenant A's key")
	_, err = b.GenerateKey(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err, "tenant B's same-named key is its own")

	_, err = a.GetKey(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err)
	_, err = a.Decrypter(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err)
	_, err = a.Signer(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err)
	require.NoError(t, a.RotateKey(ctx, rsaAttrs("shared-cn")))

	listed, err := a.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, tenantA, listed[0].TenantID)

	require.NoError(t, a.DeleteKey(ctx, rsaAttrs("shared-cn")))
	_, err = a.GetKey(ctx, rsaAttrs("shared-cn"))
	require.Error(t, err)
	_, err = b.GetKey(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err, "deleting tenant A's key must leave tenant B's")

	// Close releases nothing: the shared base keeps serving.
	require.NoError(t, a.Close())
	_, err = b.GetKey(ctx, rsaAttrs("shared-cn"))
	require.NoError(t, err)

	assert.Nil(t, a.scoped(nil))
}

// failingProvider reports a listing failure, to prove the view propagates it.
type failingProvider struct {
	types.KeyProvider
}

var errListFailed = errors.New("list failed")

func (failingProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	return nil, errListFailed
}

func TestTenantKeyProvider_ListKeysError(t *testing.T) {
	view := &tenantKeyProvider{base: failingProvider{}, tenantID: tenantA}
	_, err := view.ListKeys(context.Background())
	require.ErrorIs(t, err, errListFailed)
}
