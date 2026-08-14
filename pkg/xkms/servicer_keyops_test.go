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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Capability-bearing key providers
//
// Each provider embeds boostIEKeyProvider (a complete
// backend.ImportExportBackend) and adds exactly one hardware capability, so a
// test can prove both the supported path and the unsupported path of a single
// capability without the other capabilities interfering.
// ===========================================================================

// materialProvider releases raw symmetric key material, which the base
// import/export provider refuses to do.
type materialProvider struct {
	*boostIEKeyProvider
	material    []byte
	materialErr error

	// released holds every buffer ExportKeyMaterial handed out, so a test can
	// see what the service did with the plaintext after it was handed over --
	// specifically that it was wiped (servicer_wrapkey_zeroize_test.go).
	released [][]byte
}

func newMaterialProvider(material []byte) *materialProvider {
	return &materialProvider{boostIEKeyProvider: newBoostIEKeyProvider(), material: material}
}

// ExportKeyMaterial releases a copy of the key material, which is what every
// backend implementing this method does: the software backend returns
// types.SymmetricKey.Raw's defensive copy and the symmetric key provider
// returns a freshly deserialised buffer, while the TPM, PKCS#11, cloud KMS and
// phone backends refuse the call outright. None of them exposes a live
// internal buffer, so the caller owns what it receives and is free to wipe it.
func (p *materialProvider) ExportKeyMaterial(_ context.Context, _ *types.KeyAttributes) ([]byte, error) {
	if p.materialErr != nil {
		return nil, p.materialErr
	}
	released := append([]byte(nil), p.material...)
	p.released = append(p.released, released)
	return released, nil
}

// attestingProvider satisfies types.AttestingKeyProvider.
type attestingProvider struct {
	*boostIEKeyProvider
	result      interface{}
	attestErr   error
	seenNonce   []byte
	seenKeyName string
}

func newAttestingProvider(result interface{}) *attestingProvider {
	return &attestingProvider{boostIEKeyProvider: newBoostIEKeyProvider(), result: result}
}

func (p *attestingProvider) AttestKey(_ context.Context, attrs *types.KeyAttributes, nonce []byte) (interface{}, error) {
	p.seenNonce = nonce
	p.seenKeyName = attrs.CN
	if p.attestErr != nil {
		return nil, p.attestErr
	}
	return p.result, nil
}

// agreementProvider satisfies types.KeyAgreementProvider.
type agreementProvider struct {
	*boostIEKeyProvider
	derived   []byte
	deriveErr error
	seenPeer  []byte
	seenKDF   *types.KDFParams
}

func newAgreementProvider(derived []byte) *agreementProvider {
	return &agreementProvider{boostIEKeyProvider: newBoostIEKeyProvider(), derived: derived}
}

func (p *agreementProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, peerPublicKey []byte, params *types.KDFParams) ([]byte, error) {
	p.seenPeer = peerPublicKey
	p.seenKDF = params
	if p.deriveErr != nil {
		return nil, p.deriveErr
	}
	return p.derived, nil
}

func (p *agreementProvider) SupportedCurves() []string {
	return []string{"P-256", "P-384"}
}

// ===========================================================================
// Setup helpers
// ===========================================================================

// setupKeyOpsService initializes the global service with one backend per named
// provider plus a capability-free "software" default backend, and returns the
// backends keyed by name.
func setupKeyOpsService(t *testing.T, providers map[string]types.KeyProvider) map[string]*mockKeyStore {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	stores := map[string]*mockKeyStore{"software": newMockKeyStore("software")}
	backends := map[string]Backend{"software": stores["software"]}
	for name, provider := range providers {
		store := newMockKeyStore(name)
		store.backend = provider
		stores[name] = store
		backends[name] = store
	}

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       backends,
		DefaultBackend: "software",
	}))
	return stores
}

// addKeyOpsKey registers a key with the backend so findKeyAttrs and ListKeys
// resolve it.
func addKeyOpsKey(t *testing.T, store *mockKeyStore, attrs *types.KeyAttributes) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	store.keys[attrs.CN] = key
	store.keyAttrs[attrs.CN] = attrs
}

// addKeyOpsRSAKey registers a real RSA key directly on a *mockKeyStore's own
// key/attrs maps -- the maps *mockKeyStore.GetKey/Decrypter/ListKeys read
// from directly (mockKeyStore.KeyProvider() only returns the separate
// `.backend` field set by setupKeyOpsService, which the wrap/unwrap RSA path
// never consults; see rsaWrappingPublicKey/unwrapRSAOAEP in
// servicer_wrapkey.go, both of which resolve the key through the base
// Backend interface). This is what lets a WrapKeyByID/UnwrapKeyByID test use
// a wrapping/unwrapping key without needing a custom KeyProvider at all.
func addKeyOpsRSAKey(t *testing.T, store *mockKeyStore, attrs *types.KeyAttributes) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store.keys[attrs.CN] = key
	store.keyAttrs[attrs.CN] = attrs
	return key
}

func keyOpsService(t *testing.T) *XKMSService {
	t.Helper()
	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// ===========================================================================
// ExportKeyMaterial
// ===========================================================================

func TestExportKeyMaterial_Success(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	provider := newMaterialProvider(material)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	resp, err := keyOpsService(t).ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		KeyID:   "aes-key",
		Backend: "hsm",
	})
	require.NoError(t, err)
	assert.Equal(t, material, resp.KeyMaterial)
	assert.Equal(t, string(types.SymmetricAES256GCM), resp.KeyType)
	// key_size is documented as bits. SymmetricAlgorithm.KeySize() already
	// returns bits, so AES-256-GCM must report exactly 256 — not 2048, which is
	// what an extra factor-of-8 conversion produced.
	assert.Equal(t, 256, resp.KeySize)
	assert.Equal(t, types.SymmetricAES256GCM.KeySize(), resp.KeySize)
}

// TestExportKeyMaterial_KeySizeIsBits pins the key_size unit across every
// symmetric algorithm so a byte/bit conversion cannot be reintroduced.
func TestExportKeyMaterial_KeySizeIsBits(t *testing.T) {
	cases := []struct {
		algorithm types.SymmetricAlgorithm
		wantBits  int
	}{
		{types.SymmetricAES128GCM, 128},
		{types.SymmetricAES192GCM, 192},
		{types.SymmetricAES256GCM, 256},
		{types.SymmetricChaCha20Poly1305, 256},
	}

	for _, tc := range cases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			provider := newMaterialProvider(make([]byte, tc.wantBits/8))
			stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
			addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{
				CN:                 "sym-key",
				KeyType:            types.KeyTypeSecret,
				SymmetricAlgorithm: tc.algorithm,
			})

			resp, err := keyOpsService(t).ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
				KeyID:   "sym-key",
				Backend: "hsm",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantBits, resp.KeySize)
			assert.Equal(t, len(resp.KeyMaterial)*8, resp.KeySize,
				"reported key_size must match the actual material length in bits")
		})
	}
}

func TestExportKeyMaterial_ValidationAndLookupFailures(t *testing.T) {
	provider := newMaterialProvider([]byte("material"))
	setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	svc := keyOpsService(t)
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(ctx, nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})

	t.Run("missing key id", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: "hsm"})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{KeyID: "aes-key"})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "backend is required")
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{KeyID: "aes-key", Backend: "nope"})
		assert.ErrorIs(t, err, ErrBackendNotFound)
		var role *ErrRoleLookup
		require.True(t, errors.As(err, &role))
		assert.Equal(t, "backend", role.Role)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{KeyID: "absent", Backend: "hsm"})
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})
}

func TestExportKeyMaterial_BackendRefusesRelease(t *testing.T) {
	provider := newMaterialProvider(nil)
	provider.materialErr = errors.New("key is not exportable")
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{
		CN:                 "sealed-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	_, err := keyOpsService(t).ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		KeyID:   "sealed-key",
		Backend: "hsm",
	})
	assert.ErrorIs(t, err, ErrExportKeyMaterialFailed)
	assert.Contains(t, err.Error(), "key is not exportable")
}

// ===========================================================================
// WrapKeyByID
// ===========================================================================

// TestWrapKeyByID_Success proves the real wrap dispatch (servicer_wrapkey.go)
// wraps the target key's material under the caller's own designated RSA
// wrapping key using genuine RSA-OAEP -- not the import ceremony's ephemeral
// wrapping key. The oracle is rsa.DecryptOAEP with the real KEK's private
// half: it must recover exactly the target key's material, proving the
// response is a real OAEP ciphertext under the key that was named, not a
// canned or ephemeral value.
func TestWrapKeyByID_Success(t *testing.T) {
	targetMaterial := []byte("target-key-material")
	target := newMaterialProvider(targetMaterial)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"target-be": target, "kek-be": nil})
	addKeyOpsKey(t, stores["target-be"], &types.KeyAttributes{CN: "target-key", Exportable: true})
	kekKey := addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})

	resp, err := keyOpsService(t).WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          string(types.WrapRSAOAEPSHA256),
	})
	require.NoError(t, err)
	assert.Equal(t, string(types.WrapRSAOAEPSHA256), resp.Algorithm)

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, kekKey, resp.WrappedKey, nil)
	require.NoError(t, err)
	assert.Equal(t, targetMaterial, recovered)
}

func TestWrapKeyByID_ValidationFailures(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	ctx := context.Background()

	complete := transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          "AES_KEY_WRAP",
	}

	tests := []struct {
		name    string
		mutate  func(*transport.WrapKeyByIDRequest)
		wantMsg string
	}{
		{"wrapping key id", func(r *transport.WrapKeyByIDRequest) { r.WrappingKeyID = "" }, "wrapping_key_id is required"},
		{"wrapping key backend", func(r *transport.WrapKeyByIDRequest) { r.WrappingKeyBackend = "" }, "wrapping_key_backend is required"},
		{"target key id", func(r *transport.WrapKeyByIDRequest) { r.TargetKeyID = "" }, "target_key_id is required"},
		{"target key backend", func(r *transport.WrapKeyByIDRequest) { r.TargetKeyBackend = "" }, "target_key_backend is required"},
		{"algorithm", func(r *transport.WrapKeyByIDRequest) { r.Algorithm = "" }, "algorithm is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := complete
			tt.mutate(&req)
			_, err := svc.WrapKeyByID(ctx, &req)
			assert.ErrorIs(t, err, ErrMissingRequiredField)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.WrapKeyByID(ctx, nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})
}

func TestWrapKeyByID_RoleQualifiedLookupFailures(t *testing.T) {
	target := newMaterialProvider([]byte("target-key-material"))
	kek := newMaterialProvider([]byte("kek-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"target-be": target, "kek-be": kek})
	addKeyOpsKey(t, stores["target-be"], &types.KeyAttributes{CN: "target-key", Exportable: true})
	svc := keyOpsService(t)
	ctx := context.Background()

	base := transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          "AES_KEY_WRAP",
	}

	t.Run("target backend", func(t *testing.T) {
		req := base
		req.TargetKeyBackend = "nope"
		_, err := svc.WrapKeyByID(ctx, &req)
		var role *ErrRoleLookup
		require.True(t, errors.As(err, &role))
		assert.Equal(t, "target key backend", role.Role)
		assert.ErrorIs(t, err, ErrBackendNotFound)
	})

	t.Run("wrapping backend", func(t *testing.T) {
		req := base
		req.WrappingKeyBackend = "nope"
		_, err := svc.WrapKeyByID(ctx, &req)
		var role *ErrRoleLookup
		require.True(t, errors.As(err, &role))
		assert.Equal(t, "wrapping key backend", role.Role)
	})

	t.Run("target key", func(t *testing.T) {
		req := base
		req.TargetKeyID = "absent"
		_, err := svc.WrapKeyByID(ctx, &req)
		var role *ErrRoleLookup
		require.True(t, errors.As(err, &role))
		assert.Equal(t, "target key", role.Role)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("wrapping key", func(t *testing.T) {
		req := base
		_, err := svc.WrapKeyByID(ctx, &req)
		var role *ErrRoleLookup
		require.True(t, errors.As(err, &role))
		assert.Equal(t, "wrapping key", role.Role)
	})
}

func TestWrapKeyByID_BackendCapabilityBoundaries(t *testing.T) {
	target := newMaterialProvider([]byte("target-key-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"target-be": target})
	addKeyOpsKey(t, stores["target-be"], &types.KeyAttributes{CN: "target-key", Exportable: true})
	svc := keyOpsService(t)
	ctx := context.Background()

	t.Run("target backend cannot import or export", func(t *testing.T) {
		_, err := svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
			WrappingKeyID:      "kek",
			WrappingKeyBackend: "target-be",
			TargetKeyID:        "target-key",
			TargetKeyBackend:   "software",
			Algorithm:          "AES_KEY_WRAP",
		})
		assert.ErrorIs(t, err, ErrOperationNotSupported)
		assert.Contains(t, err.Error(), "target key backend")
	})

	// The wrapping key backend no longer needs to implement
	// backend.ImportExportBackend at all -- wrapKeyMaterial resolves the
	// wrapping key through the base Backend interface (GetKey/Decrypter for
	// RSA, types.SymmetricKeyProvider for AES). Its capability boundary is
	// now about the *key*, not the backend: an ECDSA key has no OAEP
	// operation to perform.
	t.Run("wrapping key is not usable for the requested algorithm", func(t *testing.T) {
		addKeyOpsKey(t, stores["software"], &types.KeyAttributes{CN: "ecdsa-kek"})
		_, err := svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
			WrappingKeyID:      "ecdsa-kek",
			WrappingKeyBackend: "software",
			TargetKeyID:        "target-key",
			TargetKeyBackend:   "target-be",
			Algorithm:          string(types.WrapRSAOAEPSHA256),
		})
		assert.ErrorIs(t, err, ErrInvalidKeyType)
		assert.Contains(t, err.Error(), "not RSA")
	})
}

func TestWrapKeyByID_TargetKeyNotExportable(t *testing.T) {
	target := newMaterialProvider(nil)
	target.materialErr = errors.New("CKA_EXTRACTABLE is false")
	kek := newMaterialProvider([]byte("kek-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"target-be": target, "kek-be": kek})
	addKeyOpsKey(t, stores["target-be"], &types.KeyAttributes{CN: "target-key"})
	addKeyOpsKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})

	_, err := keyOpsService(t).WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          "AES_KEY_WRAP",
	})
	assert.ErrorIs(t, err, ErrExportKeyMaterialFailed)
	assert.Contains(t, err.Error(), "CKA_EXTRACTABLE is false")
}

// ===========================================================================
// UnwrapKeyByID
// ===========================================================================

// newUnwrapRequest returns a template request. WrappedKey is a placeholder:
// tests that need the unwrap step to actually succeed (rather than fail
// before or during it) must replace it with a real ciphertext under the
// registered unwrapping key -- see TestUnwrapKeyByID_Success.
func newUnwrapRequest() transport.UnwrapKeyByIDRequest {
	return transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-blob"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "kek-be",
		Algorithm:            string(types.WrapRSAOAEPSHA256),
		TargetKeyID:          "imported-key",
		TargetKeyBackend:     "target-be",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	}
}

// TestUnwrapKeyByID_Success proves the real unwrap dispatch
// (servicer_wrapkey.go) recovers the target key material by decrypting with
// the caller's own designated unwrapping key's real private half -- not an
// ephemeral key generated by the import ceremony. The oracle is the
// plaintext itself: WrappedKey is a genuine RSA-OAEP ciphertext built here
// independently of the service, and the material actually imported into the
// target backend must equal it exactly.
func TestUnwrapKeyByID_Success(t *testing.T) {
	targetProvider := newMaterialProvider([]byte("target-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": nil, "target-be": targetProvider})
	kekKey := addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})

	plaintext := []byte("unwrapped-key-material-32-bytes")
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kekKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	req := newUnwrapRequest()
	req.WrappedKey = wrapped
	resp, err := keyOpsService(t).UnwrapKeyByID(context.Background(), &req)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyID)
	assert.Equal(t, "target-be", resp.Backend)
	assert.Contains(t, resp.Message, "imported-key")

	imported, ok := targetProvider.importedKeys["imported-key"]
	require.True(t, ok, "unwrapped material must be imported into the target backend")

	// The material reaches the target backend through its own import ceremony,
	// wrapped under a key only that backend can open -- never in the clear.
	// That is what lets C_UnwrapKey work identically on a TPM, an HSM or a
	// cloud KMS, where handing over plaintext key material is precisely what
	// the ceremony exists to avoid.
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, imported.Algorithm)
	assert.NotEqual(t, plaintext, imported.WrappedKey,
		"the imported material must be wrapped, not plaintext")

	// The oracle: unwrapping with the target backend's private half must give
	// back exactly the key the caller wrapped.
	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
		targetProvider.wrappingKey, imported.WrappedKey, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered,
		"the re-wrapped material must decrypt back to the originally wrapped key")
}

func TestUnwrapKeyByID_ValidationFailures(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		mutate  func(*transport.UnwrapKeyByIDRequest)
		wantMsg string
	}{
		{"wrapped key", func(r *transport.UnwrapKeyByIDRequest) { r.WrappedKey = nil }, "wrapped_key is required"},
		{"unwrapping key id", func(r *transport.UnwrapKeyByIDRequest) { r.UnwrappingKeyID = "" }, "unwrapping_key_id is required"},
		{"unwrapping key backend", func(r *transport.UnwrapKeyByIDRequest) { r.UnwrappingKeyBackend = "" }, "unwrapping_key_backend is required"},
		{"algorithm", func(r *transport.UnwrapKeyByIDRequest) { r.Algorithm = "" }, "algorithm is required"},
		{"target key id", func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeyID = "" }, "target_key_id is required"},
		{"target key backend", func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeyBackend = "" }, "target_key_backend is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newUnwrapRequest()
			tt.mutate(&req)
			_, err := svc.UnwrapKeyByID(ctx, &req)
			assert.ErrorIs(t, err, ErrMissingRequiredField)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.UnwrapKeyByID(ctx, nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})
}

func TestUnwrapKeyByID_BackendCapabilityBoundaries(t *testing.T) {
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": nil})
	kekKey := addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})
	addKeyOpsKey(t, stores["kek-be"], &types.KeyAttributes{CN: "ecdsa-kek"})
	svc := keyOpsService(t)
	ctx := context.Background()

	// The unwrapping key backend no longer needs backend.ImportExportBackend
	// -- unwrapKeyMaterial resolves it through the base Backend interface
	// (crypto.Decrypter for RSA, types.SymmetricKeyProvider for AES). Its
	// capability boundary is now about the key itself: an ECDSA key has no
	// RSA-OAEP decrypt operation.
	t.Run("unwrapping key is not usable for the requested algorithm", func(t *testing.T) {
		req := newUnwrapRequest()
		req.UnwrappingKeyID = "ecdsa-kek"
		req.UnwrappingKeyBackend = "kek-be"
		_, err := svc.UnwrapKeyByID(ctx, &req)
		require.Error(t, err)
	})

	t.Run("target backend cannot import or export", func(t *testing.T) {
		plaintext := []byte("target-material")
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kekKey.PublicKey, plaintext, nil)
		require.NoError(t, err)

		req := newUnwrapRequest()
		req.UnwrappingKeyBackend = "kek-be"
		req.WrappedKey = wrapped
		req.TargetKeyBackend = "software"
		_, err = svc.UnwrapKeyByID(ctx, &req)
		assert.ErrorIs(t, err, ErrOperationNotSupported)
		assert.Contains(t, err.Error(), "target key backend")
	})
}

func TestUnwrapKeyByID_UnwrappingKeyNotFound(t *testing.T) {
	kek := newMaterialProvider([]byte("kek-material"))
	// Register the target backend too, so the only thing wrong with this
	// request is the missing unwrapping key. A fixture that also omits the
	// target backend cannot tell which of the two failures it observed.
	target := newMaterialProvider([]byte("target-material"))
	setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": kek, "target-be": target})

	req := newUnwrapRequest()
	_, err := keyOpsService(t).UnwrapKeyByID(context.Background(), &req)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	var role *ErrRoleLookup
	require.True(t, errors.As(err, &role))
	assert.Equal(t, "unwrapping key", role.Role)
}

// TestUnwrapKeyByID_UnwrapFailurePropagates proves a genuine unwrap failure
// (WrappedKey that is not a valid OAEP ciphertext for the registered key --
// a real RSA integrity/padding check failure, not a canned mock error)
// propagates as an error and, critically, that no key is imported into the
// target backend when it does.
func TestUnwrapKeyByID_UnwrapFailurePropagates(t *testing.T) {
	targetProvider := newMaterialProvider([]byte("target-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": nil, "target-be": targetProvider})
	addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})

	req := newUnwrapRequest()
	req.WrappedKey = []byte("not a valid rsa-oaep ciphertext for this key")
	_, err := keyOpsService(t).UnwrapKeyByID(context.Background(), &req)
	require.Error(t, err)

	_, imported := targetProvider.importedKeys["imported-key"]
	assert.False(t, imported, "no key may be imported when unwrapping fails")
}

func TestUnwrapTargetAttributes(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*transport.UnwrapKeyByIDRequest)
		verify  func(*testing.T, *types.KeyAttributes)
		wantErr error
	}{
		{
			name:   "aes 256 by default size",
			mutate: func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeySize = 0 },
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, types.SymmetricAES256GCM, a.SymmetricAlgorithm)
				assert.Equal(t, types.KeyTypeSecret, a.KeyType)
			},
		},
		{
			name:   "aes 128",
			mutate: func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeySize = 128 },
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, types.SymmetricAES128GCM, a.SymmetricAlgorithm)
			},
		},
		{
			name: "rsa defaults to 2048",
			mutate: func(r *transport.UnwrapKeyByIDRequest) {
				r.TargetKeyType = "RSA"
				r.TargetKeySize = 0
			},
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, x509.RSA, a.KeyAlgorithm)
				require.NotNil(t, a.RSAAttributes)
				assert.Equal(t, types.RSAKeySize2048, a.RSAAttributes.KeySize)
			},
		},
		{
			name: "ecdsa defaults to P-256",
			mutate: func(r *transport.UnwrapKeyByIDRequest) {
				r.TargetKeyType = "ECDSA"
				r.TargetCurve = ""
			},
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, a.KeyAlgorithm)
				require.NotNil(t, a.ECCAttributes)
				assert.Equal(t, elliptic.P256(), a.ECCAttributes.Curve)
			},
		},
		{
			name:   "ed25519",
			mutate: func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeyType = "Ed25519" },
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, x509.Ed25519, a.KeyAlgorithm)
			},
		},
		{
			name: "key type inferred from size",
			mutate: func(r *transport.UnwrapKeyByIDRequest) {
				r.TargetKeyType = ""
				r.TargetKeySize = 192
			},
			verify: func(t *testing.T, a *types.KeyAttributes) {
				assert.Equal(t, types.SymmetricAES192GCM, a.SymmetricAlgorithm)
			},
		},
		{
			name: "key type required without size",
			mutate: func(r *transport.UnwrapKeyByIDRequest) {
				r.TargetKeyType = ""
				r.TargetKeySize = 0
			},
			wantErr: ErrMissingRequiredField,
		},
		{
			name:    "invalid symmetric size",
			mutate:  func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeySize = 512 },
			wantErr: ErrInvalidKeyAttributes,
		},
		{
			name: "invalid curve",
			mutate: func(r *transport.UnwrapKeyByIDRequest) {
				r.TargetKeyType = "ECDSA"
				r.TargetCurve = "P-999"
			},
			wantErr: ErrInvalidCurve,
		},
		{
			name:    "unsupported key type",
			mutate:  func(r *transport.UnwrapKeyByIDRequest) { r.TargetKeyType = "kyber" },
			wantErr: ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newUnwrapRequest()
			tt.mutate(&req)
			// 32 bytes stands in for the recovered material: the length only
			// matters when the request omits a key size, which the size-derivation
			// case below exercises explicitly.
			attrs, err := unwrapTargetAttributes(&req, 32)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "imported-key", attrs.CN)
			tt.verify(t, attrs)
		})
	}
}

// ===========================================================================
// AttestKey
// ===========================================================================

func testAttestationStatement(t *testing.T) *attestation.AttestationStatement {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "attesting-key", key)

	return &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestationData:    []byte("TPM2_Certify output"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
}

func TestAttestKey_Success(t *testing.T) {
	stmt := testAttestationStatement(t)
	provider := newAttestingProvider(stmt)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
	addKeyOpsKey(t, stores["tpm2"], &types.KeyAttributes{CN: "idevid", KeyAlgorithm: x509.ECDSA})

	resp, err := keyOpsService(t).AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "tpm2",
		KeyID:   "idevid",
		Nonce:   []byte("challenge"),
	})
	require.NoError(t, err)
	assert.Equal(t, "tpm2", resp.Format)
	assert.Equal(t, "tpm2", resp.Backend)
	assert.Equal(t, stmt.AttestationData, resp.AttestationData)
	assert.Equal(t, stmt.Signature, resp.Signature)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), resp.SignatureAlgorithm)
	assert.Equal(t, []byte("challenge"), resp.Nonce)
	require.Len(t, resp.CertificateChain, 1)
	assert.Equal(t, stmt.CertificateChain[0].Raw, resp.CertificateChain[0])

	// The nonce must reach the hardware unmodified or freshness is unprovable.
	assert.Equal(t, []byte("challenge"), provider.seenNonce)
	assert.Equal(t, "idevid", provider.seenKeyName)
}

func TestAttestKey_ValidationAndLookupFailures(t *testing.T) {
	provider := newAttestingProvider(testAttestationStatement(t))
	setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
	svc := keyOpsService(t)
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.AttestKey(ctx, nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.AttestKey(ctx, &transport.AttestKeyRequest{KeyID: "idevid"})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "backend is required")
	})

	t.Run("missing key id", func(t *testing.T) {
		_, err := svc.AttestKey(ctx, &transport.AttestKeyRequest{Backend: "tpm2"})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.AttestKey(ctx, &transport.AttestKeyRequest{Backend: "nope", KeyID: "idevid"})
		assert.ErrorIs(t, err, ErrBackendNotFound)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := svc.AttestKey(ctx, &transport.AttestKeyRequest{Backend: "tpm2", KeyID: "absent"})
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})
}

func TestAttestKey_BackendFailures(t *testing.T) {
	t.Run("attestation error", func(t *testing.T) {
		provider := newAttestingProvider(nil)
		provider.attestErr = errors.New("TPM_RC_POLICY_FAIL")
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
		addKeyOpsKey(t, stores["tpm2"], &types.KeyAttributes{CN: "idevid"})

		_, err := keyOpsService(t).AttestKey(context.Background(), &transport.AttestKeyRequest{
			Backend: "tpm2", KeyID: "idevid",
		})
		assert.ErrorIs(t, err, ErrAttestationFailed)
		assert.Contains(t, err.Error(), "TPM_RC_POLICY_FAIL")
	})

	t.Run("unexpected statement type", func(t *testing.T) {
		provider := newAttestingProvider("not-a-statement")
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
		addKeyOpsKey(t, stores["tpm2"], &types.KeyAttributes{CN: "idevid"})

		_, err := keyOpsService(t).AttestKey(context.Background(), &transport.AttestKeyRequest{
			Backend: "tpm2", KeyID: "idevid",
		})
		assert.ErrorIs(t, err, ErrAttestationFailed)
		assert.Contains(t, err.Error(), "unexpected attestation result type")
	})

	t.Run("list keys error", func(t *testing.T) {
		provider := newAttestingProvider(testAttestationStatement(t))
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
		stores["tpm2"].listKeysErr = errors.New("device busy")

		_, err := keyOpsService(t).AttestKey(context.Background(), &transport.AttestKeyRequest{
			Backend: "tpm2", KeyID: "idevid",
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrKeyNotFound)
		assert.Contains(t, err.Error(), "device busy")
	})
}

// ===========================================================================
// DeriveKeyECDH
// ===========================================================================

func TestDeriveKeyECDH_Success(t *testing.T) {
	derived := []byte("derived-shared-secret-32-bytes!!")
	provider := newAgreementProvider(derived)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

	resp, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
		KDFAlgorithm:  "hkdf",
		KDFHash:       "sha384",
		KDFSalt:       []byte("salt"),
		KDFInfo:       []byte("info"),
		KeyLength:     16,
	})
	require.NoError(t, err)
	assert.Equal(t, derived, resp.DerivedKey)

	assert.Equal(t, []byte("peer-public-key"), provider.seenPeer)
	require.NotNil(t, provider.seenKDF)
	assert.Equal(t, types.KDFAlgorithmHKDF, provider.seenKDF.Algorithm)
	assert.Equal(t, "SHA-384", provider.seenKDF.Hash)
	assert.Equal(t, []byte("salt"), provider.seenKDF.Salt)
	assert.Equal(t, []byte("info"), provider.seenKDF.Info)
	assert.Equal(t, 16, provider.seenKDF.KeyLength)
}

// TestDeriveKeyECDH_SP800108ParameterMapping covers the explicit mapping from
// the HKDF-shaped wire fields onto the SP 800-108 inputs. SP 800-108 has no
// salt and no HKDF info, so the wire "info" becomes the Context and, in
// feedback mode only, the wire "salt" becomes K(0).
func TestDeriveKeyECDH_SP800108ParameterMapping(t *testing.T) {
	t.Run("counter mode maps info to context", func(t *testing.T) {
		provider := newAgreementProvider([]byte("derived-shared-secret-32-bytes!!"))
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
		addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

		_, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
			KeyID:         "ecdh-key",
			Backend:       "hsm",
			PeerPublicKey: []byte("peer-public-key"),
			KDFAlgorithm:  "sp800-108-counter",
			KDFHash:       "sha384",
			KDFInfo:       []byte("info"),
			KeyLength:     16,
		})
		require.NoError(t, err)
		require.NotNil(t, provider.seenKDF)
		assert.Equal(t, types.KDFAlgorithmSP800108Counter, provider.seenKDF.Algorithm)
		assert.Equal(t, []byte("info"), provider.seenKDF.Context)
		assert.Empty(t, provider.seenKDF.Salt)
		assert.Empty(t, provider.seenKDF.Info)
		assert.Empty(t, provider.seenKDF.IV)
	})

	t.Run("feedback mode maps salt to the IV", func(t *testing.T) {
		provider := newAgreementProvider([]byte("derived-shared-secret-32-bytes!!"))
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
		addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

		_, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
			KeyID:         "ecdh-key",
			Backend:       "hsm",
			PeerPublicKey: []byte("peer-public-key"),
			KDFAlgorithm:  "sp800-108-feedback",
			KDFSalt:       []byte("initial-value"),
			KDFInfo:       []byte("info"),
			KeyLength:     16,
		})
		require.NoError(t, err)
		require.NotNil(t, provider.seenKDF)
		assert.Equal(t, types.KDFAlgorithmSP800108Feedback, provider.seenKDF.Algorithm)
		assert.Equal(t, []byte("info"), provider.seenKDF.Context)
		assert.Equal(t, []byte("initial-value"), provider.seenKDF.IV)
		assert.Empty(t, provider.seenKDF.Salt)
	})

	// A salt has no SP 800-108 counter-mode input to become. Rejecting it is
	// the point: dropping it would derive a key from parameters the caller
	// did not choose.
	t.Run("counter mode rejects a salt", func(t *testing.T) {
		provider := newAgreementProvider([]byte("derived-shared-secret-32-bytes!!"))
		stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
		addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

		_, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
			KeyID:         "ecdh-key",
			Backend:       "hsm",
			PeerPublicKey: []byte("peer-public-key"),
			KDFAlgorithm:  "sp800-108-counter",
			KDFSalt:       []byte("salt"),
			KeyLength:     16,
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
		assert.Nil(t, provider.seenKDF)
	})
}

func TestDeriveKeyECDH_KDFDefaults(t *testing.T) {
	provider := newAgreementProvider([]byte("derived"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

	_, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
	})
	require.NoError(t, err)
	require.NotNil(t, provider.seenKDF)
	assert.Equal(t, types.KDFAlgorithmHKDF, provider.seenKDF.Algorithm)
	assert.Equal(t, "SHA-256", provider.seenKDF.Hash)
	assert.Equal(t, defaultECDHKeyLength, provider.seenKDF.KeyLength)
}

func TestDeriveKeyECDH_ValidationAndLookupFailures(t *testing.T) {
	provider := newAgreementProvider([]byte("derived"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "rsa-key", KeyAlgorithm: x509.RSA})
	svc := keyOpsService(t)
	ctx := context.Background()

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})

	t.Run("missing key id", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			Backend: "hsm", PeerPublicKey: []byte("pk"),
		})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			KeyID: "ecdh-key", PeerPublicKey: []byte("pk"),
		})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "backend is required")
	})

	t.Run("missing peer public key", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			KeyID: "ecdh-key", Backend: "hsm",
		})
		assert.ErrorIs(t, err, ErrMissingRequiredField)
		assert.Contains(t, err.Error(), "peer_public_key is required")
	})

	t.Run("backend not found", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			KeyID: "ecdh-key", Backend: "nope", PeerPublicKey: []byte("pk"),
		})
		assert.ErrorIs(t, err, ErrBackendNotFound)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			KeyID: "absent", Backend: "hsm", PeerPublicKey: []byte("pk"),
		})
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("non-ECDSA key rejected", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
			KeyID: "rsa-key", Backend: "hsm", PeerPublicKey: []byte("pk"),
		})
		assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
		assert.Contains(t, err.Error(), "key must be an ECDSA key for ECDH")
	})
}

func TestDeriveKeyECDH_BackendFailurePropagates(t *testing.T) {
	provider := newAgreementProvider(nil)
	provider.deriveErr = errors.New("curve mismatch")
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

	_, err := keyOpsService(t).DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
	})
	assert.ErrorIs(t, err, ErrKeyAgreementFailed)
	assert.Contains(t, err.Error(), "curve mismatch")
}

// ===========================================================================
// KDF parameter parsing
// ===========================================================================

func TestParseKDFAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected types.KDFAlgorithm
	}{
		{"", types.KDFAlgorithmHKDF},
		{"HKDF", types.KDFAlgorithmHKDF},
		{"hkdf", types.KDFAlgorithmHKDF},
		{"SP800-108-COUNTER", types.KDFAlgorithmSP800108Counter},
		{"SP800-108-FEEDBACK", types.KDFAlgorithmSP800108Feedback},
		{"SP800-56A", types.KDFAlgorithmSP80056A},
		{"X963", types.KDFAlgorithmX963},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseKDFAlgorithm(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestParseKDFAlgorithm_UnknownNameIsAnError is the regression guard for the
// silent-fallback failure mode. An unrecognized KDF name used to resolve to
// HKDF, so a caller that asked for SP 800-108 — or misspelled it — received
// HKDF keying material and a success response, with nothing to distinguish it
// from the derivation it asked for. Only the empty name may default.
func TestParseKDFAlgorithm_UnknownNameIsAnError(t *testing.T) {
	for _, name := range []string{
		"unknown-algo",
		"SP800-108-COUNTR",          // misspelling
		"SP800_108_COUNTER",         // wrong separator
		"sp800-108-double-pipeline", // not an ECDH KDF
		"PBKDF2",
		" HKDF",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseKDFAlgorithm(name)
			require.Error(t, err, "an unrecognized KDF name must not resolve to HKDF")
			assert.ErrorIs(t, err, ErrInvalidKDFAlgorithm)
			assert.Equal(t, types.KDFAlgorithm(""), got)
		})
	}
}

func TestParseKDFHash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "SHA-256"},
		{"SHA256", "SHA-256"},
		{"SHA-256", "SHA-256"},
		{"sha256", "SHA-256"},
		{"SHA384", "SHA-384"},
		{"SHA512", "SHA-512"},
		{"SHA3-256", "SHA3-256"},
		{"SHA3-384", "SHA3-384"},
		{"SHA3-512", "SHA3-512"},
		{"BLAKE2b", "BLAKE2b"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseKDFHash(tt.input))
		})
	}
}

// ===========================================================================
// Role-qualified lookup error
// ===========================================================================

func TestErrRoleLookup(t *testing.T) {
	t.Run("wraps the underlying lookup error", func(t *testing.T) {
		err := &ErrRoleLookup{Role: "target key backend", Name: "hsm", Err: ErrBackendNotFound}
		assert.Contains(t, err.Error(), "target key backend not found: hsm")
		assert.ErrorIs(t, err, ErrBackendNotFound)
	})

	t.Run("without an underlying error", func(t *testing.T) {
		err := &ErrRoleLookup{Role: "key", Name: "k1"}
		assert.Equal(t, "key not found: k1", err.Error())
		assert.Nil(t, errors.Unwrap(err))
	})

	t.Run("validation errors are not reclassified as missing objects", func(t *testing.T) {
		validation := &ErrValidation{Sentinel: ErrTenantIDRequired, Detail: "bad tenant"}
		assert.Same(t, error(validation), roleLookupError("backend", "hsm", validation))
	})
}

// TestUnwrapTargetAttributes_DerivesSymmetricSizeFromMaterial proves an unwrap
// template may omit the key size.
//
// PKCS#11 v3.2 §5.18.6 does not require CKA_VALUE_LEN in a C_UnwrapKey
// template: the recovered material's own length settles the size, and a caller
// unwrapping a key it did not create has no way to know that length up front.
// Requiring it made C_UnwrapKey fail for every such template — which is most of
// them — with a key-size validation error that named a size the caller never
// supplied.
func TestUnwrapTargetAttributes_DerivesSymmetricSizeFromMaterial(t *testing.T) {
	tests := []struct {
		name        string
		materialLen int
		want        types.SymmetricAlgorithm
	}{
		{"AES-128 from 16 bytes", 16, types.SymmetricAES128GCM},
		{"AES-192 from 24 bytes", 24, types.SymmetricAES192GCM},
		{"AES-256 from 32 bytes", 32, types.SymmetricAES256GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newUnwrapRequest()
			req.TargetKeyType = string(types.AlgorithmAES)
			req.TargetKeySize = 0

			attrs, err := unwrapTargetAttributes(&req, tt.materialLen)
			require.NoError(t, err)
			assert.Equal(t, tt.want, attrs.SymmetricAlgorithm)
		})
	}

	t.Run("rejects material that is not a valid AES key length", func(t *testing.T) {
		req := newUnwrapRequest()
		req.TargetKeyType = string(types.AlgorithmAES)
		req.TargetKeySize = 0

		_, err := unwrapTargetAttributes(&req, 7)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("an explicit key size still wins", func(t *testing.T) {
		req := newUnwrapRequest()
		req.TargetKeyType = string(types.AlgorithmAES)
		req.TargetKeySize = 256

		attrs, err := unwrapTargetAttributes(&req, 16)
		require.NoError(t, err)
		assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	})
}
