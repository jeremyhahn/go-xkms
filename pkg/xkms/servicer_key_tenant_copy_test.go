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
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests pin XKMSService.CopyKey as the one copy implementation every
// transport delegates to (go-xkms#222): the source is resolved and the
// destination is written through the caller's tenant-scoped backend, so a
// tenant's copy lands in the tenant's own namespace, an untenanted copy is
// unchanged, and a tenant cannot copy a key it does not own.
//
// They also pin the ceremony itself against the software backend. CopyKey
// asks the DESTINATION for its own import parameters, then has the source
// wrap the material for those exact parameters via ExportKeyTo -- never for
// a wrapping key the source mints and tracks for itself, the way plain
// ExportKey does (go-xkms#154). Asserting that the copy holds the source's
// key material is what catches a regression here: it can only pass if the
// unwrap actually succeeded, which requires the material to have been
// wrapped under the key ImportKey unwraps it with.
//
// TestCopyKeyAcrossDistinctSoftwareBackends below is the one test in this
// file that registers two independent software.Backend instances rather
// than two tenant-scoped views of the same one, so the wrapping keys really
// do differ end to end.

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

// TestCopyKeyAcrossDistinctSoftwareBackends proves a copy between two
// independent software.Backend instances succeeds end to end. The two
// instances share no state -- each has its own in-memory map of minted
// wrapping keys -- so this can only pass if ExportKeyTo genuinely wrapped
// the material under the DESTINATION's own import parameters rather than a
// wrapping key the source mints and tracks for itself the way plain
// ExportKey does (go-xkms#154).
func TestCopyKeyAcrossDistinctSoftwareBackends(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcProvider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	srcBackend, err := New(&BackendConfig{Backend: srcProvider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	dstProvider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	dstBackend, err := New(&BackendConfig{Backend: dstProvider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software-a": srcBackend,
			"software-b": dstBackend,
		},
		DefaultBackend: "software-a",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	priv, err := srcBackend.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "cross-instance-kek",
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	})
	require.NoError(t, err)
	sourcePub := rsaPublicOf(t, priv)

	resp, err := svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software-a",
		SourceKeyID:   "cross-instance-kek",
		DestBackend:   "software-b",
		DestKeyID:     "cross-instance-kek-copy",
		Algorithm:     copyWrapAlgorithm,
	})
	require.NoError(t, err)
	require.True(t, resp.Success)

	dstKeys, err := dstBackend.ListKeys(ctx)
	require.NoError(t, err)
	var dstAttrs *types.KeyAttributes
	for _, a := range dstKeys {
		if a != nil && a.CN == "cross-instance-kek-copy" {
			dstAttrs = a
			break
		}
	}
	require.NotNil(t, dstAttrs, "the copy must be reachable in the independent destination backend")

	dstPriv, err := dstBackend.GetKey(ctx, dstAttrs)
	require.NoError(t, err)
	assert.Equal(t, sourcePub.N, rsaPublicOf(t, dstPriv).N,
		"the copy in the independent destination backend must hold the source's key material")
}

// TestCopyKeyExportToUnsupportedLeavesDestinationUntouched proves that when
// the source backend cannot re-wrap for the destination's own import
// parameters, CopyKey surfaces the typed refusal and never reaches the
// destination's ImportKey.
func TestCopyKeyExportToUnsupportedLeavesDestinationUntouched(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcKP := newBoostIEKeyProvider()
	srcKP.exportErr = backend.ErrExportToUnsupported
	srcStore := newMockKeyStore("hw-source")
	srcStore.backend = srcKP

	dstKP := newBoostIEKeyProvider()
	dstStore := newMockKeyStore("software-dest")
	dstStore.backend = dstKP

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"hw-source":     srcStore,
			"software-dest": dstStore,
		},
		DefaultBackend: "software-dest",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	boostGenIEKey(t, srcStore, srcKP, &types.KeyAttributes{
		CN:           "hw-key",
		KeyAlgorithm: x509.ECDSA,
	})

	_, err = svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "hw-source",
		SourceKeyID:   "hw-key",
		DestBackend:   "software-dest",
		DestKeyID:     "hw-key-copy",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrExportToUnsupported), "unexpected error: %v", err)

	_, imported := dstKP.importedKeys["hw-key-copy"]
	assert.False(t, imported,
		"the destination must never receive an import when the source cannot re-wrap for it")
}

// TestCopyKeyRefusesSubFloorRSASource proves CopyKey re-validates the copied
// key's RSA modulus against the RSAKeySize2048 floor before ever touching
// export or import: a source whose stored attributes carry a sub-2048 RSA
// size -- generated before the floor existed, or imported from a backend that
// never enforced it -- is refused with a client-facing validation error
// rather than propagated to a new backend under a new name (go-xkms#1223).
// #1220 tried the source attributes' own Validate() for this and broke
// copies of keys with a store type or backend that Validate requires but a
// copy's reconstructed attributes don't carry; this checks
// types.ValidateRSAKeySize directly instead.
func TestCopyKeyRefusesSubFloorRSASource(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcKP := newBoostIEKeyProvider()
	srcStore := newMockKeyStore("hw-source")
	srcStore.backend = srcKP

	dstKP := newBoostIEKeyProvider()
	dstStore := newMockKeyStore("software-dest")
	dstStore.backend = dstKP

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"hw-source":     srcStore,
			"software-dest": dstStore,
		},
		DefaultBackend: "software-dest",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	boostGenIEKey(t, srcStore, srcKP, &types.KeyAttributes{
		CN:            "weak-rsa-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 1024},
		Exportable:    true,
	})

	_, err = svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "hw-source",
		SourceKeyID:   "weak-rsa-key",
		DestBackend:   "software-dest",
		DestKeyID:     "weak-rsa-key-copy",
	})
	require.Error(t, err)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation, "unexpected error: %v", err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))

	_, imported := dstKP.importedKeys["weak-rsa-key-copy"]
	assert.False(t, imported,
		"the destination must never receive an import of a source key that fails the RSA floor")
}
