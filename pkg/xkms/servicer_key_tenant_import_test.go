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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests prove the fix for go-xkms#163: XKMSService.ImportKey used the
// request's TenantID to resolve a tenant-scoped backend and then discarded it,
// because reaching backend.ImportExportBackend required KeyProvider(), which
// returns the base provider and drops the TenantScopedBackend wrapper. A
// tenant's import therefore landed on the untenanted identifier, could
// silently collide with an untenanted key of the same name, and was invisible
// to the importing tenant's own ListKeys. The wrapper now offers the
// import/export capability itself and stamps the tenant via scopeAttrs, the
// way every other key operation already did.

// runImportCeremony runs the full BYOK ceremony — parameters, wrap, import —
// through the service as tenantID, and returns the final ImportKey error so
// callers can assert on collisions. The parameter and wrap steps are expected
// to succeed for every case these tests construct.
func runImportCeremony(t *testing.T, svc *XKMSService, tenantID, keyID, keyType string, keySize int, curve, wrapAlgorithm string, keyMaterial []byte) error {
	t.Helper()
	ctx := context.Background()

	params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     keyID,
		Algorithm: wrapAlgorithm,
		KeyType:   keyType,
		KeySize:   keySize,
		Curve:     curve,
		TenantID:  tenantID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, params.WrappingPublicKey)

	wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           "software",
		KeyMaterial:       keyMaterial,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: params.WrappingPublicKey,
		ImportToken:       params.ImportToken,
		KeySpec:           params.KeySpec,
		TenantID:          tenantID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, wrapped.WrappedKeyMaterial)

	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "software",
		KeyID:              keyID,
		KeyType:            keyType,
		KeySize:            keySize,
		Curve:              curve,
		WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
		Algorithm:          wrapped.Algorithm,
		ImportToken:        params.ImportToken,
		TenantID:           tenantID,
	})
	return err
}

// listedKey returns the ListKeys entry for cn owned by tenantID from an
// UNSCOPED view of the software backend, or nil when no such entry exists.
func listedKey(t *testing.T, svc *XKMSService, cn, tenantID string) *types.KeyAttributes {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)
	all, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, attr := range all {
		if attr != nil && attr.CN == cn && attr.TenantID == tenantID {
			return attr
		}
	}
	return nil
}

// tenantSeesKey reports whether tenantID's scoped ListKeys view contains cn.
func tenantSeesKey(t *testing.T, svc *XKMSService, tenantID, cn string) bool {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", tenantID)
	require.NoError(t, err)
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, attr := range keys {
		if attr != nil && attr.CN == cn {
			return true
		}
	}
	return false
}

// rawSymmetricMaterial reads the stored bytes of the symmetric key attrs
// addresses, straight from the software backend's key provider.
func rawSymmetricMaterial(t *testing.T, svc *XKMSService, attrs *types.KeyAttributes) []byte {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)
	provider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	require.True(t, ok)
	key, err := provider.GetSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)
	raw, err := key.Raw()
	require.NoError(t, err)
	return raw
}

// TestImportKeyTenantScoped is the collision half of go-xkms#163: a tenant's
// import must land on the tenant-prefixed identifier, must NOT silently
// overwrite an untenanted key of the same name and algorithm, must be visible
// to the importing tenant's ListKeys, and must be invisible to every other
// tenant's.
//
// On the unfixed code the tenant's import addressed the untenanted identifier,
// so the second import below was refused as a duplicate of the untenanted key
// (and before go-xkms#165 would have silently destroyed it).
func TestImportKeyTenantScoped(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	const cn = "shared-aes"
	const wrapAlg = string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	untenantedMaterial := make([]byte, 32)
	_, err := rand.Read(untenantedMaterial)
	require.NoError(t, err)
	tenantMaterial := make([]byte, 32)
	_, err = rand.Read(tenantMaterial)
	require.NoError(t, err)

	// An operator imports an untenanted key first, then tenant acme imports a
	// key under the very same name and algorithm. Both must succeed: the two
	// live in different namespaces.
	require.NoError(t, runImportCeremony(t, svc, "", cn, "aes", 256, "", wrapAlg, untenantedMaterial))
	require.NoError(t, runImportCeremony(t, svc, "acme", cn, "aes", 256, "", wrapAlg, tenantMaterial),
		"the tenant's import must not collide with the untenanted key of the same name")

	// The stored identifier carries the tenant prefix.
	tenantAttrs := listedKey(t, svc, cn, "acme")
	require.NotNil(t, tenantAttrs, "the tenant's key must be stored with its TenantID")
	assert.True(t, strings.HasPrefix(tenantAttrs.ID(), "acme:"),
		"the stored identifier must carry the tenant prefix, got %q", tenantAttrs.ID())

	// The untenanted key still exists, in the untenanted namespace, holding
	// the untenanted material — proof the tenant's import overwrote nothing.
	untenantedAttrs := listedKey(t, svc, cn, "")
	require.NotNil(t, untenantedAttrs, "the untenanted key must survive the tenant's import")
	assert.False(t, strings.HasPrefix(untenantedAttrs.ID(), "acme:"))
	assert.Equal(t, untenantedMaterial, rawSymmetricMaterial(t, svc, untenantedAttrs))
	assert.Equal(t, tenantMaterial, rawSymmetricMaterial(t, svc, tenantAttrs))

	// The importing tenant sees its key; another tenant does not.
	assert.True(t, tenantSeesKey(t, svc, "acme", cn), "the importing tenant must see its own import")
	assert.False(t, tenantSeesKey(t, svc, "globex", cn), "no other tenant may see acme's key")

	// The export leg addresses the tenant's key through the same seam: acme
	// can export it wrapped, globex cannot even find it.
	exported, err := svc.ExportKey(ctx, &transport.ExportKeyRequest{
		Backend:   "software",
		KeyID:     cn,
		Algorithm: wrapAlg,
		TenantID:  "acme",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, exported.WrappedKeyMaterial)

	_, err = svc.ExportKey(ctx, &transport.ExportKeyRequest{
		Backend:   "software",
		KeyID:     cn,
		Algorithm: wrapAlg,
		TenantID:  "globex",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestImportKeyTenantMetadataRoundTrip is the go-xkms#162 half: an imported
// ASYMMETRIC key must come back from the read path with the TenantID it was
// imported under. The reader prefers the key's metadata record, so this
// passes only when import both stamps the tenant into the attributes AND
// persists the metadata record — dropping either loses the tenant on the way
// out, which on the unfixed code made the key invisible to the tenant that
// imported it and unusable for signing.
func TestImportKeyTenantMetadataRoundTrip(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	const cn = "tenant-ec"
	const wrapAlg = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyMaterial, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	require.NoError(t, runImportCeremony(t, svc, "acme", cn, "ecdsa", 0, "P-256", wrapAlg, keyMaterial))

	// The read path reports the key as acme's: the listing entry carries the
	// TenantID from the metadata record.
	attrs := listedKey(t, svc, cn, "acme")
	require.NotNil(t, attrs, "the imported key must read back with the tenant it was imported under")
	assert.Equal(t, "acme", attrs.TenantID)
	assert.True(t, strings.HasPrefix(attrs.ID(), "acme:"))
	assert.True(t, tenantSeesKey(t, svc, "acme", cn))

	// The key is usable BY the tenant: a signature made through acme's scope
	// verifies under the public key generated outside the service.
	message := []byte("tenant metadata round trip")
	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend:  "software",
		KeyID:    cn,
		Data:     message,
		TenantID: "acme",
	})
	require.NoError(t, err, "the importing tenant must be able to use its own key")
	digest := sha256.Sum256(message)
	assert.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signResp.Signature))

	// And by nobody else's scope.
	_, err = svc.Sign(ctx, &transport.SignRequest{
		Backend:  "software",
		KeyID:    cn,
		Data:     message,
		TenantID: "globex",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestImportKeyUntenantedUnchanged is the regression guard: an import with an
// empty TenantID behaves exactly as before the fix — the key lands in the
// untenanted namespace under an identifier with no tenant prefix, and no
// tenant's scoped view can see it.
func TestImportKeyUntenantedUnchanged(t *testing.T) {
	svc := setupDeriveService(t)
	const cn = "plain-aes"
	const wrapAlg = string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	material := make([]byte, 32)
	_, err := rand.Read(material)
	require.NoError(t, err)

	require.NoError(t, runImportCeremony(t, svc, "", cn, "aes", 256, "", wrapAlg, material))

	attrs := listedKey(t, svc, cn, "")
	require.NotNil(t, attrs)
	assert.Empty(t, attrs.TenantID)
	assert.True(t, strings.HasPrefix(attrs.ID(), "software:"),
		"an untenanted identifier begins with the store type, got %q", attrs.ID())
	assert.Equal(t, material, rawSymmetricMaterial(t, svc, attrs))
	assert.False(t, tenantSeesKey(t, svc, "acme", cn))
}

// setupImportUnsupportedService builds a service whose "mock" backend's key
// provider does not implement backend.ImportExportBackend, alongside the real
// software backend as the default.
func setupImportUnsupportedService(t *testing.T) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": b,
			"mock":     newMockKeyStore("mock"),
		},
		DefaultBackend: "software",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// TestImportKeyUnsupportedProvider proves the typed refusal for a backend
// whose provider lacks the import/export capability is unchanged by the seam:
// the same *ErrBackendUnsupported carrying ErrOperationNotSupported surfaces
// whether the request is untenanted or tenant-scoped. The tenant case matters
// because the wrapper now answers the capability probe, and it must answer it
// the way its base does rather than claiming a capability the provider lacks.
func TestImportKeyUnsupportedProvider(t *testing.T) {
	svc := setupImportUnsupportedService(t)
	ctx := context.Background()

	for _, tenantID := range []string{"", "acme"} {
		name := "untenanted"
		if tenantID != "" {
			name = "tenant " + tenantID
		}
		t.Run(name, func(t *testing.T) {
			_, err := svc.ImportKey(ctx, &transport.ImportKeyRequest{
				Backend:            "mock",
				KeyID:              "any-key",
				KeyType:            "aes",
				KeySize:            256,
				WrappedKeyMaterial: []byte("wrapped"),
				Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
				ImportToken:        []byte("token"),
				TenantID:           tenantID,
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrOperationNotSupported)
			var unsupported *ErrBackendUnsupported
			require.ErrorAs(t, err, &unsupported)
			assert.Equal(t, "mock", unsupported.Backend)
		})
	}
}

// TestTenantScopedBackendImportExportUnsupported exercises the wrapper's own
// refusal: every import/export method on a TenantScopedBackend whose base
// provider lacks the capability returns the typed ErrImportExportNotSupported
// rather than panicking or silently unwrapping.
func TestTenantScopedBackendImportExportUnsupported(t *testing.T) {
	ctx := context.Background()
	scoped := NewTenantScopedBackend(newMockKeyStore("mock"), "acme")
	attrs := &types.KeyAttributes{CN: "any-key", SymmetricAlgorithm: types.SymmetricAES256GCM}

	_, err := scoped.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)

	_, err = scoped.WrapKey(ctx, []byte("material"), &backend.ImportParameters{})
	assert.ErrorIs(t, err, ErrImportExportNotSupported)

	_, err = scoped.UnwrapKey(ctx, &backend.WrappedKeyMaterial{}, &backend.ImportParameters{})
	assert.ErrorIs(t, err, ErrImportExportNotSupported)

	err = scoped.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{})
	assert.ErrorIs(t, err, ErrImportExportNotSupported)

	_, err = scoped.ExportKey(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)

	_, err = scoped.ExportKeyMaterial(ctx, attrs)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
}

// TestTenantScopedBackendExportKeyMaterialScopes proves the wrapper stamps the
// tenant on the export side at the Backend layer itself: with two keys of the
// same name — one untenanted, one acme's — a scoped ExportKeyMaterial call
// whose attributes carry no tenant at all must return the TENANT's bytes.
// Before the fix there was no scoped export path, and reaching the capability
// through KeyProvider() addressed the untenanted key.
func TestTenantScopedBackendExportKeyMaterialScopes(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	const cn = "material-aes"
	const wrapAlg = string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	untenantedMaterial := make([]byte, 32)
	_, err := rand.Read(untenantedMaterial)
	require.NoError(t, err)
	tenantMaterial := make([]byte, 32)
	_, err = rand.Read(tenantMaterial)
	require.NoError(t, err)

	require.NoError(t, runImportCeremony(t, svc, "", cn, "aes", 256, "", wrapAlg, untenantedMaterial))
	require.NoError(t, runImportCeremony(t, svc, "acme", cn, "aes", 256, "", wrapAlg, tenantMaterial))

	base, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)
	scoped := NewTenantScopedBackend(base, "acme")

	// The attributes deliberately carry no TenantID: the wrapper must supply it.
	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.StoreSoftware,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	got, err := scoped.ExportKeyMaterial(ctx, attrs)
	require.NoError(t, err)
	assert.Equal(t, tenantMaterial, got, "the scoped export must return the tenant's key, not the untenanted one")
}
