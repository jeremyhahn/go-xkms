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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CK_MECHANISM parameters below travel from a PKCS#11 caller through
// WrapKeyByIDRequest into wrapParams. Every test here checks the wrap against
// crypto/cipher or crypto/rsa directly rather than against unwrapKeyMaterial,
// because the failure these parameters caused was invisible to a self-round
// trip: both halves dropped them identically, so the module's own inverse
// accepted a blob no conforming peer could read.

// TestWrapAESGCM_HonoursCallerNonceAADAndTagBits proves CK_GCM_PARAMS reaches
// the cipher: the nonce the caller named is the nonce in the blob, the AAD is
// authenticated, and ulTagBits shortens the tag.
//
// PKCS#11 v3.2 §6.13.3 defines all three, and NIST SP 800-38D §5.2.1.2 defines
// a t-bit tag as the leading t bits of the full tag.
func TestWrapAESGCM_HonoursCallerNonceAADAndTagBits(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	store, attrs := newAESWrappingBackend(t)
	target := []byte("target key material for a parameterised gcm wrap")

	params := wrapParams{
		iv:      []byte("caller-nonce"), // exactly 12 bytes
		aad:     []byte("tenant-42"),
		tagBits: 96,
	}
	require.Len(t, params.iv, aesGCMNonceSize)

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), params, target)
	require.NoError(t, err)

	// Framing: mode-byte || nonce || ciphertext || tag, with the tag at the
	// requested length rather than the full 16 bytes.
	require.Len(t, wrapped, 1+aesGCMNonceSize+len(target)+12)
	assert.Equal(t, params.iv, wrapped[1:1+aesGCMNonceSize],
		"the nonce in the blob must be the CK_GCM_PARAMS.pIv the caller named")

	kek := rawKeyBytes(t, store, attrs)
	block, err := aes.NewCipher(kek)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithTagSize(block, 12)
	require.NoError(t, err)

	oracleRecovered, err := gcm.Open(nil, wrapped[1:1+aesGCMNonceSize], wrapped[1+aesGCMNonceSize:], params.aad)
	require.NoError(t, err, "crypto/cipher must accept the blob under the caller's own nonce, AAD and tag length")
	assert.Equal(t, target, oracleRecovered)

	// The AAD is genuinely bound: crypto/cipher must reject the same blob
	// presented with different associated data.
	_, err = gcm.Open(nil, wrapped[1:1+aesGCMNonceSize], wrapped[1+aesGCMNonceSize:], []byte("tenant-43"))
	assert.Error(t, err, "AAD that was not authenticated would let any value open the blob")

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), params, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestUnwrapAESGCM_RejectsMismatchedParameters is the bad-input half: an unwrap
// that does not repeat the wrap's AAD or tag length must fail rather than
// return material.
func TestUnwrapAESGCM_RejectsMismatchedParameters(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF")

	params := wrapParams{iv: []byte("caller-nonce"), aad: []byte("tenant-42"), tagBits: 96}
	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), params, target)
	require.NoError(t, err)

	t.Run("different AAD", func(t *testing.T) {
		wrong := params
		wrong.aad = []byte("tenant-43")
		_, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrong, wrapped)
		assert.Error(t, err)
	})

	t.Run("different tag length", func(t *testing.T) {
		wrong := params
		wrong.tagBits = 128
		_, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrong, wrapped)
		assert.Error(t, err)
	})

	t.Run("asserted nonce the blob was not produced with", func(t *testing.T) {
		wrong := params
		wrong.iv = []byte("other-nonce!")
		require.Len(t, wrong.iv, aesGCMNonceSize)
		_, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), wrong, wrapped)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes,
			"a caller-asserted nonce that does not match the blob must be refused, not ignored")
	})
}

// TestWrapAESGCM_RejectsInvalidParameters covers the parameter values the
// mechanism does not admit.
func TestWrapAESGCM_RejectsInvalidParameters(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)

	t.Run("nonce of the wrong length", func(t *testing.T) {
		_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM),
			wrapParams{iv: []byte("short")}, []byte("0123456789ABCDEF"))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("tag length outside SP 800-38D", func(t *testing.T) {
		_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM),
			wrapParams{tagBits: 64}, []byte("0123456789ABCDEF"))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})
}

// TestWrapAESCBC_HonoursCallerIV proves CK_AES_CBC's IV parameter reaches the
// cipher and is the IV the blob carries, checked with crypto/cipher directly.
func TestWrapAESCBC_HonoursCallerIV(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF") // one AES block, so the unpadded mode accepts it

	iv := []byte("caller-cbc-iv-16")
	require.Len(t, iv, aesCBCIVSize)

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC),
		wrapParams{iv: iv}, target)
	require.NoError(t, err)
	assert.Equal(t, iv, wrapped[:aesCBCIVSize],
		"the IV in the blob must be the one the caller named")

	assert.Equal(t, target, oracleDecryptCBC(t, rawKeyBytes(t, store, attrs), wrapped))

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC),
		wrapParams{iv: iv}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapAESCBC_RejectsBadIV is the bad-input half: a wrong-length IV on the
// wrap, and an IV asserted on the unwrap that the blob does not carry.
func TestWrapAESCBC_RejectsBadIV(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF")

	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC),
		wrapParams{iv: []byte("too-short")}, target)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC),
		wrapParams{iv: []byte("caller-cbc-iv-16")}, target)
	require.NoError(t, err)

	_, err = unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESCBC),
		wrapParams{iv: []byte("another-cbc-iv16")}, wrapped)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestWrapRSAOAEP_HonoursLabel proves CK_RSA_PKCS_OAEP_PARAMS.pSourceData is
// bound into the ciphertext.
//
// This is the failure that a self-round trip could never see. The oracle is
// crypto/rsa: it must decode the blob with the caller's label and must refuse
// it with the empty label, which is exactly what a peer using the label would
// observe.
func TestWrapRSAOAEP_HonoursLabel(t *testing.T) {
	store := newMockKeyStore("kek-be")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "kek"}
	store.keys[attrs.CN] = rsaKey
	store.keyAttrs[attrs.CN] = attrs

	label := []byte("tenant-42")
	target := []byte("target-key-material")

	wrapped, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAOAEPSHA256),
		wrapParams{oaepLabel: label}, target)
	require.NoError(t, err)

	oracleRecovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, wrapped, label)
	require.NoError(t, err, "crypto/rsa must decode the blob under the label the caller named")
	assert.Equal(t, target, oracleRecovered)

	_, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, wrapped, nil)
	assert.Error(t, err, "a blob encrypted under the empty label would decode here, which is the bug")

	recovered, err := unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAOAEPSHA256),
		wrapParams{oaepLabel: label}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)

	_, err = unwrapKeyMaterial(context.Background(), store, attrs, string(types.WrapRSAOAEPSHA256),
		wrapParams{}, wrapped)
	assert.Error(t, err, "an unwrap that drops the label must fail, not silently succeed")
}

// TestGCMTagBytes covers the tag-length resolver on its own, including the
// values PKCS#11 v3.2 §6.13.3 admits and the ones it does not.
func TestGCMTagBytes(t *testing.T) {
	for _, tc := range []struct {
		bits int
		want int
	}{
		{0, aesGCMTagSize},
		{96, 12},
		{104, 13},
		{112, 14},
		{120, 15},
		{128, 16},
	} {
		got, err := wrapParams{tagBits: tc.bits}.gcmTagBytes()
		require.NoError(t, err, "%d bits", tc.bits)
		assert.Equal(t, tc.want, got, "%d bits", tc.bits)
	}

	for _, bits := range []int{8, 64, 95, 100, 136, -8} {
		_, err := wrapParams{tagBits: bits}.gcmTagBytes()
		assert.Error(t, err, "%d bits must be refused", bits)
	}
}

// TestWrapTargetKeyMaterial_AcceptsInlineMaterial proves a WrapKeyByID request
// may name its target as plaintext rather than as a backend key id.
//
// PKCS#11 C_WrapKey must work on a key imported with C_CreateObject and
// CKA_VALUE, which is resident in no backend. Routing it here rather than
// letting the caller encrypt it is what makes C_WrapKey and C_UnwrapKey agree
// on framing for every mechanism.
func TestWrapTargetKeyMaterial_AcceptsInlineMaterial(t *testing.T) {
	s := &XKMSService{}
	material := []byte("0123456789ABCDEF")

	got, err := s.wrapTargetKeyMaterial(context.Background(), &transport.WrapKeyByIDRequest{
		TargetKeyMaterial: material,
	})
	require.NoError(t, err)
	assert.True(t, bytes.Equal(material, got))
}

// TestWrapTargetKeyMaterial_RejectsBadInput covers the two ways a request can
// fail to name a target: naming both forms, and naming neither.
func TestWrapTargetKeyMaterial_RejectsBadInput(t *testing.T) {
	s := &XKMSService{}

	t.Run("both forms", func(t *testing.T) {
		_, err := s.wrapTargetKeyMaterial(context.Background(), &transport.WrapKeyByIDRequest{
			TargetKeyID:       "some-key",
			TargetKeyMaterial: []byte("0123456789ABCDEF"),
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("neither form", func(t *testing.T) {
		_, err := s.wrapTargetKeyMaterial(context.Background(), &transport.WrapKeyByIDRequest{})
		assert.Error(t, err)
	})

	t.Run("key id without a backend", func(t *testing.T) {
		_, err := s.wrapTargetKeyMaterial(context.Background(), &transport.WrapKeyByIDRequest{
			TargetKeyID: "some-key",
		})
		assert.Error(t, err)
	})
}
