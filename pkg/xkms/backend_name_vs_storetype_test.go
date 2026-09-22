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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers go-xkms#312: the registry is keyed by backend NAME, and
// StoreType is a label the resolved backend reports about itself, never a
// second name for the same registry entry. "token-a" is used throughout as
// the canonical non-keyword name -- a name #297 measured MCP rejecting and
// #312 traced to BackendFor resolving GetBackend(string(attrs.StoreType))
// instead of GetBackend(attrs.Backend).

// newRealSoftwareBackend returns a real, independently-storaged software
// Backend -- not a mock -- so Type() and ID() are exercised through the
// actual compositeBackend/backendTypeToStoreType path a production backend
// uses, not a test double's approximation of it.
func newRealSoftwareBackend(t *testing.T) Backend {
	t.Helper()

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)

	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	return b
}

// setupTokenABackendService registers two independent real software backends:
// the default under "software", and a second under "token-a" -- a legal,
// registrable name that is not one of the store-type keywords ParseStoreType
// recognises, exactly like a second PKCS#11 token beside "token-b" would be.
func setupTokenABackendService(t *testing.T) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": newRealSoftwareBackend(t),
			"token-a":  newRealSoftwareBackend(t),
		},
		DefaultBackend: "software",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// ===========================================================================
// Backend.Type()
// ===========================================================================

// TestCompositeBackend_Type pins that a real composite backend reports its
// composed key provider's kind, mapped through backendTypeToStoreType,
// regardless of the name it is registered under.
func TestCompositeBackend_Type(t *testing.T) {
	b := newRealSoftwareBackend(t)
	assert.Equal(t, types.StoreSoftware, b.Type())
}

// TestTenantScopedBackend_Type pins that the tenant-scoping wrapper answers
// Type() by delegating to its base backend, without unwrapping to
// KeyProvider() -- the seam go-xkms#163 was about (a tenant-scoped backend
// must be able to answer "what kind is this" without discarding its scope).
func TestTenantScopedBackend_Type(t *testing.T) {
	base := newRealSoftwareBackend(t)
	scoped := NewTenantScopedBackend(base, "tenant-a")
	assert.Equal(t, base.Type(), scoped.Type())
	assert.Equal(t, types.StoreSoftware, scoped.Type())
}

// ===========================================================================
// BackendFor / getBackendForKID resolution
// ===========================================================================

// TestBackendFor_ResolvesNonKeywordBackendName is the #312 regression case:
// a backend registered under a name that is not a store-type keyword must
// still resolve by that name. StoreType is deliberately left at its
// (incorrect, stale) legacy value to prove Backend, not StoreType, is what
// wins when both are present.
func TestBackendFor_ResolvesNonKeywordBackendName(t *testing.T) {
	setupTokenABackendService(t)

	want, err := LookupBackendForTest("token-a")
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:        "some-key",
		Backend:   "token-a",
		StoreType: types.StoreUnknown, // stale/wrong on purpose
	}
	got, err := BackendFor(attrs)
	require.NoError(t, err)
	assert.Same(t, want, got, "Backend must be the field BackendFor resolves by")
}

// TestBackendFor_StoreTypeAloneIsNotAName proves the StoreType-as-name
// fallback is gone: attributes that carry only StoreType, with no Backend,
// resolve to DefaultBackend rather than to whichever registered backend
// happens to report that StoreType. Registering "token-a" as the default
// makes the point unambiguous -- if any StoreType-keyed guess survived, this
// would resolve to "software" (the backend that actually reports
// StoreSoftware) instead of the configured default.
func TestBackendFor_StoreTypeAloneIsNotAName(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": newRealSoftwareBackend(t),
			"token-a":  newRealSoftwareBackend(t),
		},
		DefaultBackend: "token-a",
	}))

	want, err := LookupBackendForTest("token-a")
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:        "no-backend-key",
		StoreType: types.StoreSoftware,
		// Backend intentionally left empty.
	}
	got, err := BackendFor(attrs)
	require.NoError(t, err)
	assert.Same(t, want, got, "StoreType alone must not resolve a name; DefaultBackend must win")
}

// TestBackendFor_NoBackendOrStoreType_UsesDefault covers the case neither
// field is set -- unchanged from before #312.
func TestBackendFor_NoBackendOrStoreType_UsesDefault(t *testing.T) {
	setupTokenABackendService(t)

	want, err := LookupBackendForTest("software")
	require.NoError(t, err)

	got, err := BackendFor(&types.KeyAttributes{CN: "no-backend-key"})
	require.NoError(t, err)
	assert.Same(t, want, got)
}

// TestGetBackendForKID_SetsBackendFromKeyword pins that the Key-ID-string
// entry point resolves through Backend, not a StoreType fallback:
// ParseKeyIDToAttributes sets attrs.Backend from the kid's backend segment,
// so getBackendForKID resolves the registry entry directly by that name.
// The 4-part kid format is still restricted to store-type keywords -- it has
// no segment for a non-keyword registry name like "token-a" -- but the name
// it does carry now reaches BackendFor as Backend, not as a StoreType guess.
func TestGetBackendForKID_SetsBackendFromKeyword(t *testing.T) {
	setupTokenABackendService(t)

	want, err := LookupBackendForTest("software")
	require.NoError(t, err)

	got, attrs, err := getBackendForKID("software:::mykey")
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Equal(t, "software", attrs.Backend, "the kid's backend segment must set Backend directly")
	assert.Equal(t, types.StoreSoftware, attrs.StoreType)
}

// LookupBackendForTest exposes LookupBackend to this file's helpers without
// duplicating the lookup-by-name logic under test.
func LookupBackendForTest(name string) (Backend, error) {
	svc, err := Get()
	if err != nil {
		return nil, err
	}
	return svc.LookupBackend(name)
}

// ===========================================================================
// End-to-end: generate, import, copy and unwrap through a non-keyword name
// ===========================================================================

// TestGenerateKey_NonKeywordBackendName_StoreTypeSurvivesPersistence pins the
// new-key improvement #312 makes possible: a key generated in a backend
// registered under a non-keyword name is persisted with its backend's real
// StoreType, not the "unknown" ParseStoreType("token-a") used to produce --
// and that improvement survives a round trip through the backend's own
// storage, not just the in-memory attrs from the call that created it.
func TestGenerateKey_NonKeywordBackendName_StoreTypeSurvivesPersistence(t *testing.T) {
	svc := setupTokenABackendService(t)
	ctx := context.Background()

	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:     "token-a-key",
		Backend:   "token-a",
		Algorithm: "ecdsa",
	})
	require.NoError(t, err)

	b, err := svc.LookupBackend("token-a")
	require.NoError(t, err)
	keys, err := b.ListKeys(ctx)
	require.NoError(t, err)

	var found *types.KeyAttributes
	for _, k := range keys {
		if k.CN == "token-a-key" {
			found = k
			break
		}
	}
	require.NotNil(t, found, "the named backend must hold the generated key")
	assert.Equal(t, types.StoreSoftware, found.StoreType,
		"StoreType must report the backend's real kind (software), never 'unknown' or the literal name")
	assert.NotEqual(t, types.StoreType("token-a"), found.StoreType,
		"a raw cast of the registry name must never reach StoreType")
}

// TestImportKey_NonKeywordBackendName proves the import ceremony -- the half
// #297 measured MCP rejecting for exactly this shape of name -- completes
// end to end against a backend registered as "token-a", and that the
// imported key's StoreType reports the backend's real kind.
func TestImportKey_NonKeywordBackendName(t *testing.T) {
	svc := setupTokenABackendService(t)
	ctx := context.Background()
	const wrapAlgorithm = string(backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyMaterial, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "token-a",
		KeyID:     "imported-token-a-key",
		Algorithm: wrapAlgorithm,
		KeyType:   "ecdsa",
		Curve:     "P-256",
	})
	require.NoError(t, err)
	require.NotEmpty(t, params.WrappingPublicKey)

	wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           "token-a",
		KeyMaterial:       keyMaterial,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: params.WrappingPublicKey,
		ImportToken:       params.ImportToken,
		KeySpec:           params.KeySpec,
	})
	require.NoError(t, err)
	require.NotEmpty(t, wrapped.WrappedKeyMaterial)

	importResp, err := svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "token-a",
		KeyID:              "imported-token-a-key",
		KeyType:            "ecdsa",
		Curve:              "P-256",
		WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
		Algorithm:          wrapped.Algorithm,
		ImportToken:        params.ImportToken,
	})
	require.NoError(t, err)
	require.True(t, importResp.Success)

	b, err := svc.LookupBackend("token-a")
	require.NoError(t, err)
	keys, err := b.ListKeys(ctx)
	require.NoError(t, err)
	var found *types.KeyAttributes
	for _, k := range keys {
		if k.CN == "imported-token-a-key" {
			found = k
			break
		}
	}
	require.NotNil(t, found, "the imported key must be reachable in the backend it was addressed by name")
	assert.Equal(t, types.StoreSoftware, found.StoreType,
		"an imported key's StoreType must report the backend's real kind")
}

// TestCopyKey_ToNonKeywordBackendName proves CopyKey's destination attributes
// carry the destination's own Backend and StoreType (go-xkms#312): copying a
// key into a backend registered as "token-a" stamps Backend "token-a" and
// StoreType StorePKCS11 -- the destination's own reported kind -- not
// StoreSoftware (the source's kind) and not a cast of the name "token-a"
// itself, which is not a defined StoreType at all.
//
// This uses the same boostIEKeyProvider-backed fixture as
// TestBoostCopyKey_IEBackend_Success rather than two real software.Backend
// instances so the assertion stays on Backend/StoreType stamping alone,
// without also exercising real PKCS#8/RSA wrapping -- that cross-backend
// crypto path (ExportKeyTo wrapping under the destination's own minted
// import parameters, go-xkms#154) has its own dedicated coverage in
// TestCopyKeyAcrossDistinctSoftwareBackends.
func TestCopyKey_ToNonKeywordBackendName(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcKP := newBoostIEKeyProvider()
	srcStore := newMockKeyStore("software")
	srcStore.backend = srcKP

	dstKP := newBoostIEKeyProvider()
	dstStore := newMockKeyStore("token-a")
	dstStore.backend = dstKP
	dstStore.storeType = types.StorePKCS11

	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": srcStore,
			"token-a":  dstStore,
		},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	boostGenIEKey(t, srcStore, srcKP, &types.KeyAttributes{
		CN:           "copy-source-key",
		KeyAlgorithm: x509.ECDSA,
	})

	resp, err := svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "copy-source-key",
		DestBackend:   "token-a",
		DestKeyID:     "copy-dest-key",
	})
	require.NoError(t, err)
	require.True(t, resp.Success)

	found, ok := dstKP.keyAttrs["copy-dest-key"]
	require.True(t, ok, "the copy must land in the named destination backend")
	assert.Equal(t, "token-a", found.Backend,
		"the copy's Backend must name the destination, not the source")
	assert.Equal(t, types.StorePKCS11, found.StoreType,
		"the copy's StoreType must be the destination backend's real kind, not the source's")
}
