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

// Tests for the zeroization of plaintext key material on the wrap/unwrap
// path: the key-encryption key rawSymmetricWrappingKey hands out, and the
// plaintext of the key being wrapped or the key just unwrapped.
//
// Each test observes the wipe on the ORIGINAL slice rather than on a copy,
// and pairs it with a cryptographic result computed from that same material,
// so a wipe that happened too early would fail the second assertion and a
// wipe that never happened would fail the first.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSymmetricProvider is a types.SymmetricKeyProvider that keeps the
// exact slices its keys' Raw method handed out, so a test can inspect them
// after the call under test has returned.
//
// Every production types.SymmetricKey.Raw returns a defensive copy (the
// hardware-backed backends refuse the call outright), which is what makes the
// slice the caller's to wipe and makes this observation meaningful.
type recordingSymmetricProvider struct {
	types.SymmetricKeyProvider
	released *[][]byte
}

// GetSymmetricKey wraps the underlying key so its raw bytes are recorded.
func (p *recordingSymmetricProvider) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	key, err := p.SymmetricKeyProvider.GetSymmetricKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return &recordingSymmetricKey{SymmetricKey: key, released: p.released}, nil
}

// recordingSymmetricKey records every slice Raw releases.
type recordingSymmetricKey struct {
	types.SymmetricKey
	released *[][]byte
}

// Raw records the slice the underlying key released and returns it unchanged.
func (k *recordingSymmetricKey) Raw() ([]byte, error) {
	raw, err := k.SymmetricKey.Raw()
	if err != nil {
		return nil, err
	}
	*k.released = append(*k.released, raw)
	return raw, nil
}

// assertWiped fails unless every byte of b is zero.
func assertWiped(t *testing.T, b []byte, what string) {
	t.Helper()
	require.NotEmpty(t, b, "%s: nothing was recorded, so the test proves nothing", what)
	assert.Equal(t, make([]byte, len(b)), b, "%s must be wiped once the operation is done with it", what)
}

// TestRawSymmetricWrappingKey_WipesKEKOnEveryPath proves all four callers of
// rawSymmetricWrappingKey -- wrap and unwrap, for both AES-KW and AES-KWP --
// wipe the key-encryption key they were handed.
//
// The KEK is the one value on this path that protects every key ever wrapped
// under it, and these are the only wrap mechanisms that read it in the clear
// at all: the AEAD and CBC mechanisms go through types.SymmetricEncrypter and
// never see raw bytes.
//
// The independently captured copy is what stops the test passing vacuously.
// It proves the recorded slice was not zero to begin with, and it decrypts the
// blob the wrap produced, which could only have been produced from the live
// KEK -- so the wipe is shown to happen after the mechanism used it, not
// instead.
func TestRawSymmetricWrappingKey_WipesKEKOnEveryPath(t *testing.T) {
	// 16 bytes: block-aligned, so RFC 3394 accepts it and RFC 5649 pads it to
	// the same length. One target serves both mechanisms.
	target := []byte("0123456789ABCDEF")

	cases := []struct {
		algorithm types.KeyWrapAlgorithm
		oracle    func(wrapped, kek []byte) ([]byte, error)
	}{
		{algorithm: types.WrapAESKW, oracle: wrapping.UnwrapAESKW},
		{algorithm: types.WrapAESKWP, oracle: wrapping.UnwrapAESKWP},
	}

	for _, tc := range cases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			ctx := context.Background()
			store, attrs := newAESWrappingBackend(t)

			// Taken before the recorder is installed, so it is a copy the
			// code under test can neither see nor wipe.
			liveKEK := rawKeyBytes(t, store, attrs)
			require.NotEqual(t, make([]byte, len(liveKEK)), liveKEK, "the KEK must be non-zero for the wipe to be observable")

			symProvider, ok := store.KeyProvider().(types.SymmetricKeyProvider)
			require.True(t, ok)
			released := &[][]byte{}
			store.backend = &recordingSymmetricProvider{SymmetricKeyProvider: symProvider, released: released}

			wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, target)
			require.NoError(t, err)
			require.Len(t, *released, 1, "the wrap must have read the KEK exactly once")
			assertWiped(t, (*released)[0], "the KEK read by the wrap")

			// The wrap really did use the live KEK, so the wipe came after it.
			recovered, err := tc.oracle(wrapped, liveKEK)
			require.NoError(t, err, "the blob must decrypt under the live KEK, proving the wipe did not precede the wrap")
			assert.Equal(t, target, recovered)

			unwrapped, err := unwrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, wrapped)
			require.NoError(t, err)
			assert.Equal(t, target, unwrapped)
			require.Len(t, *released, 2, "the unwrap must have read the KEK exactly once")
			assertWiped(t, (*released)[1], "the KEK read by the unwrap")
		})
	}
}

// importMaterialRecorder is a complete backend.ImportExportBackend that keeps
// the slice its import ceremony was handed, which is the service's own
// recovered-plaintext buffer rather than a copy of it.
type importMaterialRecorder struct {
	*boostIEKeyProvider
	seen [][]byte
}

// WrapKey records the material the import ceremony received and then performs
// the real wrap the embedded provider implements.
func (p *importMaterialRecorder) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	p.seen = append(p.seen, keyMaterial)
	return p.boostIEKeyProvider.WrapKey(ctx, keyMaterial, params)
}

// wrapKeyServiceRSA stands up a service whose "software" backend holds an
// RSA-2048 wrapping key under CN "kek", and returns the stores plus that key.
func wrapKeyServiceRSA(t *testing.T, providers map[string]types.KeyProvider) (map[string]*mockKeyStore, *rsa.PrivateKey) {
	t.Helper()
	stores := setupKeyOpsService(t, providers)
	kek := addKeyOpsRSAKey(t, stores["software"], &types.KeyAttributes{
		CN:           "kek",
		KeyType:      types.KeyTypeEncryption,
		KeyAlgorithm: x509.RSA,
	})
	return stores, kek
}

// TestWrapKeyByID_WipesExportedTargetPlaintext proves the plaintext a target
// backend released for wrapping does not survive the call.
//
// The observation is made on the very buffer the backend released -- not a
// copy of it -- which materialProvider keeps a handle on for this purpose. The
// response blob is then decrypted with the wrapping key and compared against
// the material, which is what proves the wipe followed the wrap.
func TestWrapKeyByID_WipesExportedTargetPlaintext(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	original := append([]byte(nil), material...)

	provider := newMaterialProvider(material)
	stores, kek := wrapKeyServiceRSA(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	resp, err := keyOpsService(t).WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "aes-key",
		TargetKeyBackend:   "hsm",
		Algorithm:          string(types.WrapRSAOAEPSHA256),
	})
	require.NoError(t, err)

	require.Len(t, provider.released, 1, "the target backend must have released its material exactly once")
	assertWiped(t, provider.released[0], "the exported target key plaintext")
	assert.Equal(t, original, material, "the backend's own copy must be untouched; only what it released is wiped")

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, kek, resp.WrappedKey, nil)
	require.NoError(t, err, "the blob must decrypt, proving the wipe did not precede the wrap")
	assert.Equal(t, original, recovered)
}

// TestWrapKeyByID_LeavesCallerSuppliedMaterialIntact is the bad-input half of
// the wipe: wiping must not reach back into a request the caller still holds.
//
// WrapKeyByIDRequest.TargetKeyMaterial carries plaintext the caller owns --
// the PKCS#11 C_WrapKey form whose target lives in the caller's own object
// store -- so wrapTargetKeyMaterial copies it rather than aliasing it. Without
// the copy the deferred wipe would zero the caller's buffer underneath it,
// turning a retry of the same request into a wrap of thirty-two zero bytes.
func TestWrapKeyByID_LeavesCallerSuppliedMaterialIntact(t *testing.T) {
	material := []byte("caller-supplied-key-material-32b")
	original := append([]byte(nil), material...)

	_, kek := wrapKeyServiceRSA(t, nil)
	svc := keyOpsService(t)

	request := &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyMaterial:  material,
		Algorithm:          string(types.WrapRSAOAEPSHA256),
	}

	first, err := svc.WrapKeyByID(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, original, material, "the caller's own buffer must be left alone")
	assert.Equal(t, original, request.TargetKeyMaterial)

	// The same request must still wrap the same key the second time.
	second, err := svc.WrapKeyByID(context.Background(), request)
	require.NoError(t, err)

	for _, blob := range [][]byte{first.WrappedKey, second.WrappedKey} {
		recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, kek, blob, nil)
		require.NoError(t, err)
		assert.Equal(t, original, recovered)
	}
}

// TestUnwrapKeyByID_WipesRecoveredPlaintext proves the key material recovered
// from a caller-supplied blob does not survive the call either.
//
// The recorder sees the service's own buffer, because importKeyMaterial passes
// it straight to the target backend's import ceremony. Asserting the ceremony
// received the real material first, and that the buffer is zero afterwards,
// pins the wipe to after the import rather than before it.
func TestUnwrapKeyByID_WipesRecoveredPlaintext(t *testing.T) {
	material := []byte("recovered-key-material-32-bytes!")

	recorder := &importMaterialRecorder{boostIEKeyProvider: newBoostIEKeyProvider()}
	_, kek := wrapKeyServiceRSA(t, map[string]types.KeyProvider{"hsm": recorder})

	blob, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kek.PublicKey, material, nil)
	require.NoError(t, err)

	resp, err := keyOpsService(t).UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{
		WrappedKey:           blob,
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            string(types.WrapRSAOAEPSHA256),
		TargetKeyID:          "imported",
		TargetKeyBackend:     "hsm",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)

	require.Len(t, recorder.seen, 1, "the import ceremony must have run exactly once")
	assert.Len(t, recorder.seen[0], len(material), "the ceremony must have received the recovered material, not a substitute")
	assertWiped(t, recorder.seen[0], "the recovered key plaintext")
}
