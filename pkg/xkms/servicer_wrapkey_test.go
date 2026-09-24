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
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAESWrappingBackend returns a *mockKeyStore backed by a real
// pkg/keyprovider/symmetric.Backend, with a generated AES-256 wrapping key
// under CN "kek" registered so findKeyAttrs-style CN lookups and
// SymmetricEncrypter/GetSymmetricKey both resolve it (same attrs pointer in
// both the mock's own registry and the real backend, since the real backend
// keys storage off attrs.ID()).
func newAESWrappingBackend(t *testing.T) (*mockKeyStore, *types.KeyAttributes) {
	t.Helper()

	symBackend, err := symmetric.NewBackend(&symmetric.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "kek",
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType("kek-be"),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err = symBackend.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	store := newMockKeyStore("kek-be")
	store.backend = symBackend
	store.keys[attrs.CN] = "placeholder"
	store.keyAttrs[attrs.CN] = attrs

	return store, attrs
}

func rawKeyBytes(t *testing.T, store *mockKeyStore, attrs *types.KeyAttributes) []byte {
	t.Helper()
	symProvider, ok := store.KeyProvider().(types.SymmetricKeyProvider)
	require.True(t, ok)
	key, err := symProvider.GetSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)
	raw, err := key.Raw()
	require.NoError(t, err)
	return raw
}

// allowLegacyWrap enables the unauthenticated key-wrap constructions --
// RSA_PKCS1_V1_5, AES_CBC_PAD and AES_CBC -- for the duration of one test, and
// restores the previous policy afterwards.
//
// Those mechanisms are refused by default (see resolveWrapMechanism and
// servicer_wrapkey_policy_test.go), so a test that exercises what they DO must
// first put the process in the configuration where they are performed. The
// policy is process-wide, which is safe here because no test in this package
// calls t.Parallel; the saved-and-restored previous value keeps a test from
// leaking the setting into the next one either way.
//
// The bool return reports whether the policy actually took effect: under
// GODEBUG=fips140=only, SetAllowLegacyKeyWrap(true) is a deliberate no-op
// (see pkg/types/wrappolicy.go) -- the Go Cryptographic Module's
// approved-mechanism boundary is the ceiling this repository's own policy
// switch must never be able to re-open -- so a caller whose whole premise
// is "the legacy mechanism is now enabled" cannot be exercised in that
// mode and must return immediately when this reports false.
func allowLegacyWrap(t *testing.T) bool {
	t.Helper()
	previous := types.AllowLegacyKeyWrap()
	types.SetAllowLegacyKeyWrap(true)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })
	return types.AllowLegacyKeyWrap()
}

// --- wrapAESKeyWrap / unwrapAESKeyWrap ---

// TestWrapUnwrapAESKeyWrap_RoundTrip proves wrapKeyMaterial/unwrapKeyMaterial
// for "aes-kw" produce a real RFC 3394 blob: the oracle is
// wrapping.UnwrapAESKW called directly against the raw KEK bytes (bypassing
// wrapKeyMaterial's own unwrap path entirely), which must recover the exact
// target material.
func TestWrapUnwrapAESKeyWrap_RoundTrip(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF") // 16 bytes, block-aligned for AES-KW

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKW), wrapParams{}, target)
	require.NoError(t, err)

	kek := rawKeyBytes(t, store, attrs)
	oracleRecovered, err := wrapping.UnwrapAESKW(wrapped, kek)
	require.NoError(t, err)
	assert.Equal(t, target, oracleRecovered)

	// unwrapKeyMaterial itself must agree with the oracle.
	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKW), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapAESKeyWrap_BackendNotSymmetric proves a wrapping key backend that
// does not implement types.SymmetricKeyProvider is rejected with a typed
// error rather than panicking or silently producing a bogus wrap.
func TestWrapAESKeyWrap_BackendNotSymmetric(t *testing.T) {
	store := newMockKeyStore("plain-be") // .backend left nil: no SymmetricKeyProvider
	attrs := &types.KeyAttributes{CN: "kek"}

	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKW), wrapParams{}, []byte("0123456789ABCDEF"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSymmetricNotSupported)
}

// --- wrapAESKeyWrapPad / unwrapAESKeyWrapPad ---

// TestWrapUnwrapAESKeyWrapPad_RoundTrip proves "aes-kwp"
// (CKM_AES_KEY_WRAP_PAD, PKCS#11 v3.2 §6.10.5) is routed to a real RFC 5649
// implementation. Before it was routed at all, this algorithm name fell
// through wrapKeyMaterial's default and every wrap failed with
// CKR_FUNCTION_FAILED, at 16, 24 and 32 bytes alike, while the unpadded
// "aes-kw" beside it worked.
//
// The oracle is wrapping.UnwrapAESKWP called directly against the raw KEK,
// bypassing wrapKeyMaterial's own unwrap path; that primitive is in turn
// pinned to the published RFC 5649 section 6 ciphertexts by
// TestWrapAESKWP_RFC5649Vectors, so agreement here means agreement with the
// RFC and not merely with this package.
func TestWrapUnwrapAESKeyWrapPad_RoundTrip(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)
	kek := rawKeyBytes(t, store, attrs)

	// The three AES key lengths a wrapped key may itself have, plus a length
	// that is not a multiple of 8 -- the case only the padded form can carry.
	for _, targetLen := range []int{16, 24, 32, 21} {
		target := bytes.Repeat([]byte{byte(targetLen)}, targetLen)

		wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, target)
		require.NoError(t, err, "wrapping %d bytes with aes-kwp", targetLen)

		oracleRecovered, err := wrapping.UnwrapAESKWP(wrapped, kek)
		require.NoError(t, err)
		assert.Equal(t, target, oracleRecovered)

		recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, wrapped)
		require.NoError(t, err)
		assert.Equal(t, target, recovered)
	}
}

// TestWrapAESKeyWrapPad_IsNotUnpaddedAESKW proves "aes-kwp" is not quietly
// served by the RFC 3394 code beside it. The two constructions differ in
// their initial value and in the extra length-carrying block, so a
// block-aligned input wrapped both ways must produce different blobs; if it
// did not, a peer that took CKM_AES_KEY_WRAP_PAD at its word could not unwrap
// what this token produced.
func TestWrapAESKeyWrapPad_IsNotUnpaddedAESKW(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF") // 16 bytes: valid input to both

	padded, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, target)
	require.NoError(t, err)

	unpadded, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKW), wrapParams{}, target)
	require.NoError(t, err)

	assert.NotEqual(t, unpadded, padded,
		"aes-kwp produced the RFC 3394 blob; the padded mechanism was routed to the unpadded one")
}

// TestWrapAESKeyWrapPad_BackendNotSymmetric is the bad-input counterpart: a
// wrapping key backend with no types.SymmetricKeyProvider is refused with a
// typed error rather than panicking or producing a bogus wrap.
func TestWrapAESKeyWrapPad_BackendNotSymmetric(t *testing.T) {
	store := newMockKeyStore("plain-be") // .backend left nil
	attrs := &types.KeyAttributes{CN: "kek"}

	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, []byte("0123456789ABCDEF"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSymmetricNotSupported)

	_, err = unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, []byte("0123456789ABCDEF"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSymmetricNotSupported)
}

// TestUnwrapAESKeyWrapPad_RejectsCorruptBlob proves a tampered blob is
// refused by the RFC 5649 Alternative Initial Value check rather than
// returning whatever plaintext falls out.
func TestUnwrapAESKeyWrapPad_RejectsCorruptBlob(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs,
		string(types.WrapAESKWP), wrapParams{}, []byte("0123456789ABCDEF"))
	require.NoError(t, err)
	wrapped[0] ^= 0x01

	_, err = unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESKWP), wrapParams{}, wrapped)
	require.Error(t, err, "a corrupted aes-kwp blob was unwrapped without complaint")
}

// --- wrapAESGCM / unwrapAESGCM ---

// TestWrapUnwrapAESGCM_RoundTrip proves "aes-gcm" produces a self-describing
// nonce||ciphertext||tag blob that is genuine AES-GCM: the oracle is
// crypto/cipher's own GCM implementation, used directly against the raw KEK
// bytes to decrypt the blob wrapKeyMaterial returned, independent of
// unwrapKeyMaterial.
func TestWrapUnwrapAESGCM_RoundTrip(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)
	target := []byte("arbitrary length target key material, not block aligned")

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrapParams{}, target)
	require.NoError(t, err)
	require.Len(t, wrapped, 1+aesGCMNonceSize+len(target)+aesGCMTagSize)

	// The independent crypto/cipher oracle below can only check a blob built
	// over the arbitrary-IV construction, which GODEBUG=fips140=only
	// refuses outright: this wrap used cipher.NewGCMWithRandomNonce instead
	// (see docs/fips/README.md "AEAD construction"). The production round
	// trip through unwrapKeyMaterial below still stands as the real
	// assertion in that mode.
	if !fips140.Enforced() {
		kek := rawKeyBytes(t, store, attrs)
		block, err := aes.NewCipher(kek)
		require.NoError(t, err)
		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		nonce := wrapped[1 : 1+aesGCMNonceSize]
		sealed := wrapped[1+aesGCMNonceSize:] // ciphertext||tag, exactly gcm.Seal's own output shape
		oracleRecovered, err := gcm.Open(nil, nonce, sealed, nil)
		require.NoError(t, err)
		assert.Equal(t, target, oracleRecovered)
	}

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestUnwrapAESGCM_TooShort proves a wrapped blob shorter than the minimum
// nonce+tag framing is rejected before ever reaching the AEAD open call,
// rather than slicing out of bounds.
func TestUnwrapAESGCM_TooShort(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)

	_, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrapParams{}, make([]byte, 1+aesGCMNonceSize+aesGCMTagSize-1))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// --- wrapAESCBC / unwrapAESCBC ---

// oracleDecryptCBC decrypts iv||ciphertext with crypto/cipher directly, using
// the raw KEK bytes. It is deliberately not unwrapAESCBC: it is the independent
// check that the blob wrapAESCBC produced is genuine AES-CBC under the
// caller's key, and not merely something this package's own inverse accepts.
func oracleDecryptCBC(t *testing.T, kek, wrapped []byte) []byte {
	t.Helper()
	require.Greater(t, len(wrapped), aesCBCIVSize)
	block, err := aes.NewCipher(kek)
	require.NoError(t, err)
	ciphertext := wrapped[aesCBCIVSize:]
	require.Zero(t, len(ciphertext)%aes.BlockSize, "CBC ciphertext must be block aligned")
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, wrapped[:aesCBCIVSize]).CryptBlocks(plaintext, ciphertext)
	return plaintext
}

// TestWrapUnwrapAESCBC_RoundTrip proves types.WrapAESCBC is served rather than
// refused. PKCS#11 v3.2 §6.10 lists CKM_AES_CBC with CKF_WRAP and the module
// routes it here, but wrapMechanisms had no entry, so every C_WrapKey naming
// CKM_AES_CBC reached the service and came back "unsupported wrap algorithm"
// -- a mechanism advertised by the token and rejected by the service behind it.
//
// The oracle is crypto/cipher's own CBC decrypter over the raw KEK, so the blob
// is checked against the standard construction and not against this package.
func TestWrapUnwrapAESCBC_RoundTrip(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes: block aligned

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC), wrapParams{}, target)
	require.NoError(t, err)
	require.Len(t, wrapped, aesCBCIVSize+len(target),
		"unpadded CBC adds only the IV; §6.10.3 applies no PKCS#7 block")

	kek := rawKeyBytes(t, store, attrs)
	assert.Equal(t, target, oracleDecryptCBC(t, kek, wrapped))

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapUnwrapAESCBCPad_RoundTrip is the CKM_AES_CBC_PAD half: the padded
// mechanism must carry key material whose length is not a multiple of the
// block size, which the unpadded one cannot.
//
// The oracle decrypts with crypto/cipher and strips the PKCS#7 padding by hand,
// so the padding is checked to be real RFC 5652 §6.3 padding rather than
// whatever this package's unpad accepts.
func TestWrapUnwrapAESCBCPad_RoundTrip(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)
	target := []byte("twenty-byte-key-mat!") // 20 bytes: not block aligned

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBCPad), wrapParams{}, target)
	require.NoError(t, err)
	require.Len(t, wrapped, aesCBCIVSize+32, "20 bytes pads up to two AES blocks")

	kek := rawKeyBytes(t, store, attrs)
	padded := oracleDecryptCBC(t, kek, wrapped)
	padLen := int(padded[len(padded)-1])
	require.Positive(t, padLen)
	require.LessOrEqual(t, padLen, aes.BlockSize)
	for _, b := range padded[len(padded)-padLen:] {
		require.Equal(t, byte(padLen), b, "every PKCS#7 pad byte states the pad length")
	}
	assert.Equal(t, target, padded[:len(padded)-padLen])

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBCPad), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapAESCBC_RefusesUnalignedKeyMaterial proves the unpadded mechanism
// refuses key material that is not a whole number of blocks instead of padding
// it silently. §6.10.3 would have the token pad with null bytes, which is
// unrecoverable: the unwrapping side cannot tell a trailing zero of the key
// from a pad byte, so the key would come back a different length than it went
// in. A typed refusal is the only honest answer.
func TestWrapAESCBC_RefusesUnalignedKeyMaterial(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)

	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC), wrapParams{}, []byte("twenty-byte-key-mat!"))
	require.Error(t, err)
	assert.ErrorIs(t, err, symmetric.ErrPlaintextNotBlockAligned)
}

// TestUnwrapAESCBC_TooShort proves a blob with no room for both an IV and at
// least one ciphertext block is rejected before the slice is taken, rather than
// yielding an empty "key".
func TestUnwrapAESCBC_TooShort(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)

	for _, mode := range []types.KeyWrapAlgorithm{types.WrapAESCBC, types.WrapAESCBCPad} {
		_, err := unwrapKeyMaterial(context.Background(), store, attrs, string(mode), wrapParams{}, make([]byte, aesCBCIVSize))
		require.Error(t, err, "%s must refuse an IV with no ciphertext", mode)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	}
}

// TestWrapAESCBC_BackendNotSymmetric proves a wrapping key whose backend is not
// a symmetric provider is refused with a typed error rather than panicking on
// the type assertion.
func TestWrapAESCBC_BackendNotSymmetric(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store := newMockKeyStore("plain-be") // .backend left nil: no SymmetricKeyProvider
	attrs := &types.KeyAttributes{CN: "kek"}

	_, wrapErr := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC), wrapParams{}, []byte("0123456789ABCDEF"))
	require.Error(t, wrapErr)
	assert.ErrorIs(t, wrapErr, ErrSymmetricNotSupported)

	_, unwrapErr := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBCPad), wrapParams{}, make([]byte, aesCBCIVSize+aes.BlockSize))
	require.Error(t, unwrapErr)
	assert.ErrorIs(t, unwrapErr, ErrSymmetricNotSupported)
}

// --- wrapRSAPKCS1v15 / unwrapRSAPKCS1v15 ---

// TestWrapUnwrapRSAPKCS1v15_RoundTrip proves "rsa-pkcs" wraps under the
// real, caller-designated RSA public key (not an ephemeral one): the oracle
// is rsa.DecryptPKCS1v15 called directly with the same private key used to
// register the wrapping key, independent of unwrapKeyMaterial.
func TestWrapUnwrapRSAPKCS1v15_RoundTrip(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store := newMockKeyStore("kek-be")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "kek"}
	store.keys[attrs.CN] = rsaKey
	store.keyAttrs[attrs.CN] = attrs

	target := []byte("target-key-material")
	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, target)
	require.NoError(t, err)

	oracleRecovered, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, wrapped) //nolint:staticcheck // SA1019: verifies the legacy PKCS#1 v1.5 wrap round-trips
	require.NoError(t, err)
	assert.Equal(t, target, oracleRecovered)

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapRSAPKCS1v15_KeyNotRSA proves a non-RSA wrapping key is rejected
// with a typed error rather than a panic on the *rsa.PublicKey assertion.
func TestWrapRSAPKCS1v15_KeyNotRSA(t *testing.T) {
	store, attrs := newAESWrappingBackend(t) // AES key, not RSA

	// The AES-backed store's GetKey is never populated with a
	// crypto.Signer-capable key, so rsaWrappingPublicKey fails resolving
	// the key at all -- this still proves the RSA path refuses a
	// non-RSA-capable wrapping key rather than misusing it.
	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, []byte("data"))
	require.Error(t, err)
}

// --- wrapRSAOAEP / unwrapRSAOAEP ---

// TestWrapUnwrapRSAOAEP_RoundTrip mirrors the PKCS1v15 test for "rsa-oaep",
// with rsa.DecryptOAEP(SHA-256) as the independent oracle.
func TestWrapUnwrapRSAOAEP_RoundTrip(t *testing.T) {
	store := newMockKeyStore("kek-be")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "kek"}
	store.keys[attrs.CN] = rsaKey
	store.keyAttrs[attrs.CN] = attrs

	target := []byte("target-key-material")
	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAOAEPSHA256), wrapParams{}, target)
	require.NoError(t, err)

	oracleRecovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, wrapped, nil)
	require.NoError(t, err)
	assert.Equal(t, target, oracleRecovered)

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAOAEPSHA256), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// --- Unsupported algorithm dispatch ---

// TestWrapKeyMaterial_UnsupportedAlgorithm proves an algorithm name outside
// the four this task implements is refused with ErrOperationNotSupported
// rather than silently falling back to one of them.
func TestWrapKeyMaterial_UnsupportedAlgorithm(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)

	_, err := wrapKeyMaterial(context.Background(), store, attrs, "aes-cbc", wrapParams{}, []byte("data"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

// TestUnwrapKeyMaterial_UnsupportedAlgorithm is the same proof for the
// unwrap dispatch.
func TestUnwrapKeyMaterial_UnsupportedAlgorithm(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)

	_, err := unwrapKeyMaterial(context.Background(), store, attrs, "aes-cbc", wrapParams{}, []byte("data"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}
