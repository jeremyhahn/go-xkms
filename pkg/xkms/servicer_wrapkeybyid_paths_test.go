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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// currentKeyMaterial returns the raw material of the current version of the
// software backend's key keyID, as the tenant sees it.
func currentKeyMaterial(t *testing.T, svc *XKMSService, tenantID, keyID string) []byte {
	t.Helper()
	ctx := context.Background()
	b, err := svc.resolveTenantBackend("software", tenantID)
	require.NoError(t, err)
	k, err := svc.resolveKey(ctx, b, "software", keyID)
	require.NoError(t, err)
	v, err := k.current()
	require.NoError(t, err)
	require.True(t, v.attrs.IsSymmetric(), "the stored attributes of %q must carry its symmetric algorithm", keyID)
	exporter, ok := exportBackendFor(b)
	require.True(t, ok)
	raw, err := exporter.ExportKeyMaterial(ctx, v.attrs)
	require.NoError(t, err)
	return raw
}

// assertWrapRoundTrip wraps targetKeyID under a fresh AES-256 KEK with
// WrapKeyByID, unwraps it with UnwrapKeyByID into a new key, and asserts the
// new key holds the target's material.
func assertWrapRoundTrip(t *testing.T, svc *XKMSService, tenantID, targetKeyID string) {
	t.Helper()
	ctx := context.Background()

	const kekID = "paths-kek"
	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: kekID, Backend: "software", Algorithm: "aes-256-gcm", TenantID: tenantID,
	})
	require.NoError(t, err)

	wrapResp, err := svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software", WrappingKeyID: kekID,
		TargetKeyBackend: "software", TargetKeyID: targetKeyID,
		Algorithm: string(types.WrapAESKW), TenantID: tenantID,
	})
	require.NoError(t, err)

	const recoveredID = "paths-recovered"
	_, err = svc.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyBackend: "software", UnwrappingKeyID: kekID,
		Algorithm:        string(types.WrapAESKW),
		TargetKeyBackend: "software", TargetKeyID: recoveredID,
		TargetKeyType: "aes", TargetExportable: true, TenantID: tenantID,
	})
	require.NoError(t, err)

	want := currentKeyMaterial(t, svc, tenantID, targetKeyID)
	got := currentKeyMaterial(t, svc, tenantID, recoveredID)
	assert.Len(t, got, 32)
	assert.Equal(t, want, got, "the unwrapped key must hold the wrapped key's material")
}

// TestWrapKeyByID_SymmetricCreatePaths proves every public path that creates
// an exportable AES-256-GCM secret key stores attributes WrapKeyByID accepts,
// untenanted and tenant-scoped (go-xkms#1634).
func TestWrapKeyByID_SymmetricCreatePaths(t *testing.T) {
	const targetID = "paths-target"

	paths := map[string]func(t *testing.T, svc *XKMSService, tenantID string){
		"GenerateSymmetricKey": func(t *testing.T, svc *XKMSService, tenantID string) {
			b, err := svc.resolveTenantBackend("software", tenantID)
			require.NoError(t, err)
			_, err = generateKeyWithAttributes(context.Background(), b, "software", &types.KeyAttributes{
				CN: targetID, KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware,
				SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true,
			})
			require.NoError(t, err)
		},
		"GenerateKey secret aes-256-gcm": generateTarget(targetID, "secret", "aes-256-gcm", 0),
		"GenerateKey AES_256_GCM":        generateTarget(targetID, "", "AES_256_GCM", 0),
		"GenerateKey aes256-gcm":         generateTarget(targetID, "secret", "aes256-gcm", 0),
		"GenerateKey symmetric 256":      generateTarget(targetID, "secret", "symmetric", 256),
		"GenerateKey partitioned": func(t *testing.T, svc *XKMSService, tenantID string) {
			_, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
				KeyID: targetID, Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm",
				Partition: "p1", Exportable: true, TenantID: tenantID,
			})
			require.NoError(t, err)
		},
		"ImportKey aes": func(t *testing.T, svc *XKMSService, tenantID string) {
			material := make([]byte, 32)
			_, err := rand.Read(material)
			require.NoError(t, err)
			require.NoError(t, runImportCeremony(t, svc, tenantID, targetID, "aes", 256, "",
				string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256), material))
		},
		"RotateKey": func(t *testing.T, svc *XKMSService, tenantID string) {
			generateTarget(targetID, "secret", "aes-256-gcm", 0)(t, svc, tenantID)
			resp, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{
				KeyID: targetID, Backend: "software", TenantID: tenantID,
			})
			require.NoError(t, err)
			require.Equal(t, uint32(2), resp.KeyVersion)
		},
	}

	for name, create := range paths {
		for _, tenantID := range []string{"", "acme"} {
			t.Run(name+"/tenant="+tenantID, func(t *testing.T) {
				svc := setupDeriveService(t)
				create(t, svc, tenantID)
				assertWrapRoundTrip(t, svc, tenantID, targetID)
			})
		}
	}
}

// generateTarget returns a create path that generates an exportable key
// through GenerateKey with the request fields a transport passes through.
func generateTarget(keyID, keyType, algorithm string, keySize int) func(t *testing.T, svc *XKMSService, tenantID string) {
	return func(t *testing.T, svc *XKMSService, tenantID string) {
		_, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
			KeyID: keyID, Backend: "software", KeyType: keyType, Algorithm: algorithm,
			KeySize: keySize, Exportable: true, TenantID: tenantID,
		})
		require.NoError(t, err)
	}
}

// TestUnwrapKeyByID_WrongWrappingKey proves a key wrapped under KEK A with an
// authenticated algorithm is refused under KEK B with the typed ciphertext
// rejection, and no key is imported.
func TestUnwrapKeyByID_WrongWrappingKey(t *testing.T) {
	for _, algorithm := range []types.KeyWrapAlgorithm{types.WrapAESKW, types.WrapAESGCM} {
		t.Run(string(algorithm), func(t *testing.T) {
			svc := setupDeriveService(t)
			ctx := context.Background()
			for _, id := range []string{"kek-a", "kek-b", "wrong-kek-target"} {
				generateTarget(id, "secret", "aes-256-gcm", 0)(t, svc, "")
			}

			wrapResp, err := svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
				WrappingKeyBackend: "software", WrappingKeyID: "kek-a",
				TargetKeyBackend: "software", TargetKeyID: "wrong-kek-target",
				Algorithm: string(algorithm),
			})
			require.NoError(t, err)

			_, err = svc.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
				WrappedKey:           wrapResp.WrappedKey,
				UnwrappingKeyBackend: "software", UnwrappingKeyID: "kek-b",
				Algorithm:        string(algorithm),
				TargetKeyBackend: "software", TargetKeyID: "wrong-kek-recovered",
				TargetKeyType: "aes", TargetExportable: true,
			})
			require.ErrorIs(t, err, ErrUnwrapCiphertextRejected)
			var authErr *ErrUnwrapAuthenticationFailed
			require.ErrorAs(t, err, &authErr)
			require.Error(t, authErr.Err, "the mechanism's cause is kept")
			var opErr *ErrKeyOperation
			require.ErrorAs(t, err, &opErr)
			assert.Equal(t, "unwrap key", opErr.Operation)

			b, err := svc.resolveTenantBackend("software", "")
			require.NoError(t, err)
			_, err = svc.resolveKey(ctx, b, "software", "wrong-kek-recovered")
			assert.ErrorIs(t, err, ErrKeyNotFound, "a refused unwrap must import nothing")
		})
	}
}

// TestWrapKeyByID_RefusesAsymmetricTarget proves a stored target without a
// symmetric algorithm is refused with the typed ErrWrapTarget before any
// material is exported (go-xkms#1634).
func TestWrapKeyByID_RefusesAsymmetricTarget(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	generateTarget("refuse-kek", "secret", "aes-256-gcm", 0)(t, svc, "")
	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "refuse-target", Backend: "software", Algorithm: "ecdsa", Exportable: true,
	})
	require.NoError(t, err)

	_, err = svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software", WrappingKeyID: "refuse-kek",
		TargetKeyBackend: "software", TargetKeyID: "refuse-target",
		Algorithm: string(types.WrapAESKW),
	})
	require.ErrorIs(t, err, ErrWrapTargetNotSymmetric)
	var targetErr *ErrWrapTarget
	require.ErrorAs(t, err, &targetErr)
	assert.Equal(t, "refuse-target", targetErr.KeyID)
	assert.NotErrorIs(t, err, backend.ErrAsymmetricKeyExportNotAllowed, "the refusal must come before ExportKeyMaterial")
}
