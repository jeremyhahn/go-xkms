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
	"crypto"
	"crypto/fips140"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// cryptoUtilityService returns a service with an AES-256-GCM key "aead" on
// the software backend.
func cryptoUtilityService(t *testing.T) *XKMSService {
	t.Helper()
	svc := setupDeriveService(t)
	genKey(t, svc, "", "aead", "aes-256-gcm", 0)
	return svc
}

// decryptItem turns an encrypt response into the batch item that opens it.
func decryptItem(sealed *transport.EncryptResponse) transport.DecryptBatchItem {
	return transport.DecryptBatchItem{
		Ciphertext:   sealed.Ciphertext,
		Nonce:        sealed.Nonce,
		Tag:          sealed.Tag,
		GCMNonceMode: sealed.GCMNonceMode,
		KeyVersion:   sealed.KeyVersion,
	}
}

// TestRewrap moves a ciphertext from "aead" to a second key and opens it
// under the target.
func TestRewrap(t *testing.T) {
	svc := cryptoUtilityService(t)
	genKey(t, svc, "", "target", "aes-256-gcm", 0)
	ctx := context.Background()

	sealed, err := svc.Encrypt(ctx, &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("secret")})
	require.NoError(t, err)

	resp, err := svc.Rewrap(ctx, &transport.RewrapRequest{
		Source: &transport.DecryptRequest{
			Backend: "software", KeyID: "aead",
			Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, Tag: sealed.Tag, GCMNonceMode: sealed.GCMNonceMode,
		},
		TargetKeyID: "target",
	})
	require.NoError(t, err)
	assert.Equal(t, sealed.KeyVersion, resp.SourceKeyVersion)

	w := resp.Wrapped
	opened, err := svc.Decrypt(ctx, &transport.DecryptRequest{
		Backend: "software", KeyID: "target",
		Ciphertext: w.Ciphertext, Nonce: w.Nonce, Tag: w.Tag, GCMNonceMode: w.GCMNonceMode,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), opened.Plaintext)
}

// TestRewrap_Errors covers a missing source and a target key that does not
// exist.
func TestRewrap_Errors(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	_, err := svc.Rewrap(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	_, err = svc.Rewrap(ctx, &transport.RewrapRequest{TargetKeyID: "aead"})
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	sealed, err := svc.Encrypt(ctx, &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("secret")})
	require.NoError(t, err)
	_, err = svc.Rewrap(ctx, &transport.RewrapRequest{
		Source: &transport.DecryptRequest{
			Backend: "software", KeyID: "aead",
			Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, Tag: sealed.Tag, GCMNonceMode: sealed.GCMNonceMode,
		},
		TargetKeyID: "ghost",
	})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestEncryptDecryptBatch round-trips a batch, and reports a bad item in its
// own slot without failing the others.
func TestEncryptDecryptBatch(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	enc, err := svc.EncryptBatch(ctx, &transport.EncryptBatchRequest{
		Backend: "software", KeyID: "aead",
		Items: []transport.EncryptBatchItem{{Plaintext: []byte("one")}, {Plaintext: []byte("two"), AdditionalData: []byte("aad")}},
	})
	require.NoError(t, err)
	require.Len(t, enc.Results, 2)
	for _, r := range enc.Results {
		require.Empty(t, r.Error)
		require.NotNil(t, r.Result)
	}

	second := decryptItem(enc.Results[1].Result)
	second.AdditionalData = []byte("aad")
	dec, err := svc.DecryptBatch(ctx, &transport.DecryptBatchRequest{
		Backend: "software", KeyID: "aead",
		Items: []transport.DecryptBatchItem{decryptItem(enc.Results[0].Result), second, {Ciphertext: []byte("garbage")}},
	})
	require.NoError(t, err)
	require.Len(t, dec.Results, 3)
	assert.Equal(t, []byte("one"), dec.Results[0].Plaintext)
	assert.Equal(t, []byte("two"), dec.Results[1].Plaintext)
	assert.Empty(t, dec.Results[2].Plaintext)
	assert.NotEmpty(t, dec.Results[2].Error)
}

// TestBatch_Errors covers empty and oversized batches, a nil request and an
// unknown key.
func TestBatch_Errors(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	tooMany := make([]transport.EncryptBatchItem, transport.MaxBatchItems+1)
	for _, items := range [][]transport.EncryptBatchItem{nil, tooMany} {
		_, err := svc.EncryptBatch(ctx, &transport.EncryptBatchRequest{Backend: "software", KeyID: "aead", Items: items})
		assert.ErrorIs(t, err, ErrBatchSize)
	}
	_, err := svc.DecryptBatch(ctx, &transport.DecryptBatchRequest{Backend: "software", KeyID: "aead"})
	assert.ErrorIs(t, err, ErrBatchSize)

	_, err = svc.EncryptBatch(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	_, err = svc.DecryptBatch(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	one := []transport.EncryptBatchItem{{Plaintext: []byte("x")}}
	_, err = svc.EncryptBatch(ctx, &transport.EncryptBatchRequest{Backend: "software", KeyID: "ghost", Items: one})
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = svc.DecryptBatch(ctx, &transport.DecryptBatchRequest{
		Backend: "software", KeyID: "ghost", Items: []transport.DecryptBatchItem{{Ciphertext: []byte("x")}},
	})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestGenerateDataKey returns a data key of the requested size whose wrapped
// form opens to the same bytes; the wrapped-only RPC returns no plaintext.
func TestGenerateDataKey(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	for _, size := range []int{0, 16, 24, 32} {
		resp, err := svc.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "aead", KeySize: size})
		require.NoError(t, err)
		want := size
		if want == 0 {
			want = defaultDataKeySize
		}
		assert.Len(t, resp.Plaintext, want)

		w := resp.Wrapped
		opened, err := svc.Decrypt(ctx, &transport.DecryptRequest{
			Backend: "software", KeyID: "aead",
			Ciphertext: w.Ciphertext, Nonce: w.Nonce, Tag: w.Tag, GCMNonceMode: w.GCMNonceMode,
		})
		require.NoError(t, err)
		assert.Equal(t, resp.Plaintext, opened.Plaintext)
	}

	wrapped, err := svc.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "aead"})
	require.NoError(t, err)
	require.NotNil(t, wrapped.Wrapped)
	assert.NotEmpty(t, wrapped.Wrapped.Ciphertext)
}

// TestGenerateDataKey_Errors covers an unsupported size, a nil request and
// an unknown wrapping key.
func TestGenerateDataKey_Errors(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	_, err := svc.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "aead", KeySize: 20})
	assert.ErrorIs(t, err, ErrDataKeySize)
	_, err = svc.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "aead", KeySize: 64})
	assert.ErrorIs(t, err, ErrDataKeySize)
	_, err = svc.GenerateDataKey(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	_, err = svc.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "ghost"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestGenerateVerifyHMAC computes an HMAC-SHA-256 and verifies it, and
// reports a wrong MAC as invalid rather than as an error.
func TestGenerateVerifyHMAC(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()
	data := []byte("message")

	mac, err := svc.GenerateHMAC(ctx, &transport.GenerateHMACRequest{Backend: "software", KeyID: "aead", Data: data})
	require.NoError(t, err)
	assert.Equal(t, "SHA-256", mac.Hash)
	assert.Len(t, mac.MAC, sha256.Size)

	ok, err := svc.VerifyHMAC(ctx, &transport.VerifyHMACRequest{Backend: "software", KeyID: "aead", Data: data, MAC: mac.MAC})
	require.NoError(t, err)
	assert.True(t, ok.Valid)
	assert.Equal(t, mac.KeyVersion, ok.KeyVersion)

	bad, err := svc.VerifyHMAC(ctx, &transport.VerifyHMACRequest{Backend: "software", KeyID: "aead", Data: []byte("other"), MAC: mac.MAC})
	require.NoError(t, err)
	assert.False(t, bad.Valid)
}

// TestHMAC_Errors covers an unknown hash, the empty "NONE" hash, a nil
// request and an unknown key.
func TestHMAC_Errors(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	for _, h := range []string{"WHIRLPOOL", "NONE"} {
		_, err := svc.GenerateHMAC(ctx, &transport.GenerateHMACRequest{Backend: "software", KeyID: "aead", Hash: h, Data: []byte("m")})
		assert.ErrorIs(t, err, ErrInvalidHashFunction, h)
		_, err = svc.VerifyHMAC(ctx, &transport.VerifyHMACRequest{Backend: "software", KeyID: "aead", Hash: h, Data: []byte("m")})
		assert.ErrorIs(t, err, ErrInvalidHashFunction, h)
	}
	_, err := svc.GenerateHMAC(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	_, err = svc.VerifyHMAC(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	_, err = svc.GenerateHMAC(ctx, &transport.GenerateHMACRequest{Backend: "software", KeyID: "ghost", Data: []byte("m")})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestHmacSum_Refused proves a hash the standard library refuses to MAC
// with surfaces as ErrHMACRefused instead of a panic. Under
// GODEBUG=fips140=only that includes a key shorter than 112 bits.
func TestHmacSum_Refused(t *testing.T) {
	key := make([]byte, 32)
	_, err := hmacSum(0, key, []byte("m"))
	assert.ErrorIs(t, err, ErrHMACRefused)

	mac, err := hmacSum(crypto.SHA256, key, []byte("m"))
	require.NoError(t, err)
	assert.Len(t, mac, sha256.Size)

	if fips140.Enforced() {
		_, err = hmacSum(crypto.SHA256, []byte("key"), []byte("m"))
		assert.ErrorIs(t, err, ErrHMACRefused)
	}
}

// TestGenerateRandom returns the requested number of bytes, and refuses a
// length outside 1 to MaxRandomBytes.
func TestGenerateRandom(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()

	for _, n := range []int{1, 32, transport.MaxRandomBytes} {
		resp, err := svc.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: n})
		require.NoError(t, err)
		assert.Len(t, resp.Random, n)
	}
	for _, n := range []int{0, -1, transport.MaxRandomBytes + 1} {
		_, err := svc.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: n})
		assert.ErrorIs(t, err, ErrRandomLength, n)
	}
	_, err := svc.GenerateRandom(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestHash digests with the default and a named hash, and refuses an
// unknown or empty hash.
func TestHash(t *testing.T) {
	svc := cryptoUtilityService(t)
	ctx := context.Background()
	data := []byte("message")

	resp, err := svc.Hash(ctx, &transport.HashRequest{Data: data})
	require.NoError(t, err)
	want := sha256.Sum256(data)
	assert.Equal(t, want[:], resp.Digest)
	assert.Equal(t, "SHA-256", resp.Hash)

	resp, err = svc.Hash(ctx, &transport.HashRequest{Hash: "SHA-512", Data: data})
	require.NoError(t, err)
	assert.Len(t, resp.Digest, 64)

	for _, h := range []string{"WHIRLPOOL", "NONE"} {
		_, err = svc.Hash(ctx, &transport.HashRequest{Hash: h, Data: data})
		assert.ErrorIs(t, err, ErrInvalidHashFunction, h)
	}
	_, err = svc.Hash(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}
