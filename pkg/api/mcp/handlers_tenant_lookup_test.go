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

package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Tenant scoping for key resolution by common name.
//
// A common name is unique only within a tenant, so a lookup that scans an
// unscoped backend and takes the first CN match resolves whichever tenant's
// key happens to be listed first. On the export path that handed one tenant
// another tenant's wrapped key material.
// ===========================================================================

// tenantIEProvider is a fakeIEProvider whose exported material names the
// tenant and common name of the attributes it was handed, so a test can tell
// *which* tenant's key was exported rather than merely that an export
// happened.
type tenantIEProvider struct {
	*fakeIEProvider
}

func newTenantIEProvider(keys ...*types.KeyAttributes) *tenantIEProvider {
	return &tenantIEProvider{fakeIEProvider: newFakeIEProvider(keys...)}
}

func (p *tenantIEProvider) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{
		WrappedKey: []byte("material:" + attrs.TenantID + "/" + attrs.CN),
		Algorithm:  algorithm,
	}, nil
}

var _ backend.ImportExportBackend = (*tenantIEProvider)(nil)

// tenantKey returns key attributes for keyID owned by tenantID.
func tenantKey(tenantID, keyID string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:         keyID,
		TenantID:   tenantID,
		KeyType:    types.KeyTypeEncryption,
		StoreType:  types.StoreSoftware,
		Exportable: true,
	}
}

// newTenantLookupServer registers provider under both the default "software"
// backend and a second name, so the handlers' explicit-backend and
// default-backend paths are both reachable.
func newTenantLookupServer(t *testing.T, keys ...*types.KeyAttributes) (*Server, *tenantIEProvider) {
	t.Helper()
	provider := newTenantIEProvider(keys...)
	return newKeyOpsServer(t, map[string]types.KeyProvider{"software": provider}), provider
}

// TestHandler_ExportKey_RefusesAnotherTenantsKey is the security case from
// issue #166: tenant "globex" asks to export "payments-dek", a key that only
// tenant "acme" owns, and must be told it does not exist rather than handed
// acme's wrapped material.
func TestHandler_ExportKey_RefusesAnotherTenantsKey(t *testing.T) {
	server, _ := newTenantLookupServer(t, tenantKey("acme", "payments-dek"))

	result, err := server.handleExportKey(tenantContext("globex"),
		keyOpsRequest(t, "xkms.exportKey", &ExportKeyParams{
			KeyID:     "payments-dek",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}))

	require.Error(t, err, "a key owned by another tenant must not be exportable")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "key not found: payments-dek")
}

// TestHandler_ExportKey_ExportsOwnTenantsKey is the positive control for the
// refusal above: without it, a handler that refused every export would pass.
func TestHandler_ExportKey_ExportsOwnTenantsKey(t *testing.T) {
	server, _ := newTenantLookupServer(t, tenantKey("acme", "payments-dek"))

	result, err := server.handleExportKey(tenantContext("acme"),
		keyOpsRequest(t, "xkms.exportKey", &ExportKeyParams{
			KeyID:     "payments-dek",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}))

	require.NoError(t, err)
	exported, ok := result.(ExportKeyResult)
	require.True(t, ok, "unexpected result type %T", result)
	assert.Equal(t, "material:acme/payments-dek", string(exported.WrappedKey))
}

// TestHandler_ExportKey_ResolvesTheCallersOwnDuplicateCN proves the lookup
// selects by tenant rather than by list order: both tenants own a key with the
// same common name, and the first one listed is not the caller's.
func TestHandler_ExportKey_ResolvesTheCallersOwnDuplicateCN(t *testing.T) {
	server, _ := newTenantLookupServer(t,
		tenantKey("acme", "payments-dek"),
		tenantKey("globex", "payments-dek"))

	result, err := server.handleExportKey(tenantContext("globex"),
		keyOpsRequest(t, "xkms.exportKey", &ExportKeyParams{
			KeyID:     "payments-dek",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}))

	require.NoError(t, err)
	exported, ok := result.(ExportKeyResult)
	require.True(t, ok, "unexpected result type %T", result)
	assert.Equal(t, "material:globex/payments-dek", string(exported.WrappedKey),
		"the caller must receive its own key, not the first CN match")
}

// TestHandler_FindKeyInBackend_TenantScoped covers the shared lookup directly,
// so the predicate is proven where it lives rather than only through the one
// handler that motivated it.
func TestHandler_FindKeyInBackend_TenantScoped(t *testing.T) {
	server, _ := newTenantLookupServer(t,
		tenantKey("acme", "payments-dek"),
		tenantKey("globex", "billing-dek"))

	t.Run("own key resolves", func(t *testing.T) {
		attrs, err := server.findKeyInBackend(tenantContext("acme"), "payments-dek", "software")
		require.NoError(t, err)
		assert.Equal(t, "acme", attrs.TenantID)
	})

	t.Run("another tenant's key does not resolve", func(t *testing.T) {
		_, err := server.findKeyInBackend(tenantContext("globex"), "payments-dek", "software")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found: payments-dek")
	})

	t.Run("an unscoped caller still sees every key", func(t *testing.T) {
		attrs, err := server.findKeyInBackend(tenantContext(""), "payments-dek", "software")
		require.NoError(t, err, "the system scope is not a tenant and must not be filtered")
		assert.Equal(t, "acme", attrs.TenantID)
	})
}

// TestHandler_FindKeyByCN_TenantScoped covers the default-keystore lookup,
// which the issue names alongside findKeyInBackend: fixing only one leaves the
// same first-match-on-CN hazard for every caller of the other.
func TestHandler_FindKeyByCN_TenantScoped(t *testing.T) {
	server, _ := newTenantLookupServer(t,
		tenantKey("acme", "payments-dek"),
		tenantKey("globex", "billing-dek"))

	t.Run("own key resolves", func(t *testing.T) {
		attrs, err := server.findKeyByCN(tenantContext("globex"), "billing-dek")
		require.NoError(t, err)
		assert.Equal(t, "globex", attrs.TenantID)
	})

	t.Run("another tenant's key does not resolve", func(t *testing.T) {
		_, err := server.findKeyByCN(tenantContext("globex"), "payments-dek")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found: payments-dek")
	})

	t.Run("an unscoped caller still sees every key", func(t *testing.T) {
		attrs, err := server.findKeyByCN(tenantContext(""), "payments-dek")
		require.NoError(t, err)
		assert.Equal(t, "acme", attrs.TenantID)
	})
}

// TestHandler_ListKeys_TenantScoped proves the listing agrees with the lookup.
// A listing that shows a key the lookup then reports as missing is not merely
// a disclosure of another tenant's key IDs; it is a contradiction the caller
// cannot resolve.
func TestHandler_ListKeys_TenantScoped(t *testing.T) {
	server, _ := newTenantLookupServer(t,
		tenantKey("acme", "payments-dek"),
		tenantKey("globex", "billing-dek"))

	result, err := server.handleListKeys(tenantContext("globex"),
		keyOpsRequest(t, "xkms.listKeys", &ListKeysParams{Backend: "software"}))
	require.NoError(t, err)

	listed, ok := result.(ListKeysResult)
	require.True(t, ok, "unexpected result type %T", result)
	require.Len(t, listed.Keys, 1)
	assert.Equal(t, "billing-dek", listed.Keys[0].KeyID)
}

// TestHandler_Unseal_RefusesAnotherTenantsKey covers the third and fourth
// copies of the first-match-on-CN lookup, which handleSeal and handleUnseal
// carried inline. Unsealing under another tenant's key attributes is the same
// cross-boundary use of key material as exporting it.
func TestHandler_Unseal_RefusesAnotherTenantsKey(t *testing.T) {
	server, _ := newTenantLookupServer(t, tenantKey("acme", "payments-dek"))

	_, err := server.handleUnseal(tenantContext("globex"),
		keyOpsRequest(t, "xkms.unseal", &UnsealParams{
			Backend:    "software",
			KeyID:      "payments-dek",
			Ciphertext: []byte("ciphertext"),
		}))

	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrKeyNotFound, "another tenant's key reads as a key nobody holds")
}

// TestHandler_Seal_RefusesAnotherTenantsKey is the seal-side counterpart.
func TestHandler_Seal_RefusesAnotherTenantsKey(t *testing.T) {
	server, _ := newTenantLookupServer(t, tenantKey("acme", "payments-dek"))

	_, err := server.handleSeal(tenantContext("globex"),
		keyOpsRequest(t, "xkms.seal", &SealParams{
			Backend: "software",
			KeyID:   "payments-dek",
			Data:    []byte("plaintext"),
		}))

	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrKeyNotFound, "another tenant's key reads as a key nobody holds")
}
