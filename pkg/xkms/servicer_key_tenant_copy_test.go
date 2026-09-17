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

package xkms

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests pin XKMSService.CopyKey as the one copy implementation every
// transport delegates to (go-xkms#222): the source is resolved and the
// destination is written through the caller's tenant-scoped backend, so a
// tenant's copy lands in the tenant's own namespace, an untenanted copy is
// unchanged, and a tenant cannot copy a key it does not own.
//
// They also pin the ceremony itself against the software backend. The service
// used to ask the destination for fresh import parameters and overwrite the
// exported material's import token with theirs. ExportKey wraps under a
// wrapping key the exporting backend mints for that export and names it by
// that token, so the override pointed ImportKey at a different wrapping key
// than the material was wrapped under, and every copy through a backend that
// honours its tokens failed to unwrap. Asserting that the copy holds the
// source's key material is what catches that: it can only pass if the unwrap
// actually succeeded.

const copyWrapAlgorithm = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

// storeExportableRSAKey generates an exportable RSA-2048 key under cn through
// tenantID's view of the software backend (unscoped for ""), so the key lands
// exactly where that tenant's own key generation would place it, and returns
// its public half.
func storeExportableRSAKey(t *testing.T, svc *XKMSService, tenantID, cn string) *rsa.PublicKey {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", tenantID)
	require.NoError(t, err)

	priv, err := b.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	})
	require.NoError(t, err)
	return rsaPublicOf(t, priv)
}

// storedRSAPublicKey reads back the public half of the key attrs describes,
// through tenantID's view of the software backend.
func storedRSAPublicKey(t *testing.T, svc *XKMSService, tenantID string, attrs *types.KeyAttributes) *rsa.PublicKey {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", tenantID)
	require.NoError(t, err)
	priv, err := b.GetKey(context.Background(), attrs)
	require.NoError(t, err)
	return rsaPublicOf(t, priv)
}

// TestCopyKeyTenantScoped proves a tenant's copy is written into the tenant's
// own namespace: the copy carries the tenant prefix, holds the source's key
// material, is visible to the copying tenant, and is invisible to every other
// tenant and to the untenanted namespace.
func TestCopyKeyTenantScoped(t *testing.T) {
	svc := setupDeriveService(t)
	source := storeExportableRSAKey(t, svc, "acme", "payments-kek")

	resp, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "payments-kek",
		DestBackend:   "software",
		DestKeyID:     "payments-kek-copy",
		Algorithm:     copyWrapAlgorithm,
		TenantID:      "acme",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "payments-kek-copy", resp.KeyID)

	copied := listedKey(t, svc, "payments-kek-copy", "acme")
	require.NotNil(t, copied, "the copy must be stored under the copying tenant")
	assert.True(t, strings.HasPrefix(copied.ID(), "acme:"),
		"the stored identifier must carry the tenant prefix, got %q", copied.ID())
	assert.Equal(t, source.N, storedRSAPublicKey(t, svc, "acme", copied).N,
		"the copy must hold the source's key material")

	assert.Nil(t, listedKey(t, svc, "payments-kek-copy", ""),
		"a tenant's copy must not land in the untenanted namespace")
	assert.True(t, tenantSeesKey(t, svc, "acme", "payments-kek-copy"))
	assert.False(t, tenantSeesKey(t, svc, "globex", "payments-kek-copy"),
		"no other tenant may see acme's copy")
}

// TestCopyKeyUntenantedUnchanged is the control: an untenanted copy still
// lands in the untenanted namespace, with no tenant prefix and no fallback.
func TestCopyKeyUntenantedUnchanged(t *testing.T) {
	svc := setupDeriveService(t)
	source := storeExportableRSAKey(t, svc, "", "shared-kek")

	_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "shared-kek",
		DestBackend:   "software",
		DestKeyID:     "shared-kek-copy",
		Algorithm:     copyWrapAlgorithm,
	})
	require.NoError(t, err)

	copied := listedKey(t, svc, "shared-kek-copy", "")
	require.NotNil(t, copied, "an untenanted copy must land in the untenanted namespace")
	assert.False(t, strings.Contains(copied.ID(), "acme:"))
	assert.Equal(t, source.N, storedRSAPublicKey(t, svc, "", copied).N)
}

// TestCopyKeyRefusesAnotherTenantsKey proves the source is resolved inside the
// caller's tenant: globex asking to copy acme's key is told the key does not
// exist, and nothing is written anywhere.
func TestCopyKeyRefusesAnotherTenantsKey(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "acme", "payments-kek")

	_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "payments-kek",
		DestBackend:   "software",
		DestKeyID:     "stolen-kek",
		Algorithm:     copyWrapAlgorithm,
		TenantID:      "globex",
	})
	require.Error(t, err, "a key owned by another tenant must not be copyable")
	assert.True(t, errors.Is(err, ErrKeyNotFound), "unexpected error: %v", err)

	var role *ErrCopyKeyBackend
	require.True(t, errors.As(err, &role))
	assert.Equal(t, "source key", role.Role)

	assert.Nil(t, listedKey(t, svc, "stolen-kek", "globex"))
	assert.Nil(t, listedKey(t, svc, "stolen-kek", "acme"))
	assert.Nil(t, listedKey(t, svc, "stolen-kek", ""))
}

// TestCopyKeyRejectsAnInvalidTenant proves the tenant is validated before any
// backend is touched, through the same predicate every other operation uses.
func TestCopyKeyRejectsAnInvalidTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeExportableRSAKey(t, svc, "", "shared-kek")

	_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "shared-kek",
		DestBackend:   "software",
		DestKeyID:     "shared-kek-copy",
		Algorithm:     copyWrapAlgorithm,
		TenantID:      "acme:evil",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTenantIDRequired), "unexpected error: %v", err)
	assert.Nil(t, listedKey(t, svc, "shared-kek-copy", ""))
}
