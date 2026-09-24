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
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uniqueWrapIV returns a 12-byte AES-GCM IV no other test in this package has
// used.
//
// The (key, IV) guard lives for the lifetime of the process and is keyed by the
// wrapping key's material, so a test that is not about reuse must bring either
// fresh key material or a fresh IV. Every fixture here generates its key
// material, and this supplies the other half.
func uniqueWrapIV(t *testing.T) []byte {
	t.Helper()
	iv := make([]byte, aesGCMNonceSize)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	return iv
}

// gcmSealOracle seals with crypto/cipher directly. It is the independent oracle
// these tests measure wrapAESGCM against: verifying a wrap by unwrapping it
// with this service's own unwrap would pass just as well if both halves were
// wrong in the same way.
func gcmSealOracle(t *testing.T, key, nonce, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm.Seal(nil, nonce, plaintext, aad)
}

// gcmOpenOracle opens with crypto/cipher directly, for the same reason.
func gcmOpenOracle(t *testing.T, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// xorWrapBytes returns the byte-wise XOR of a and b, which must be the same
// length.
func xorWrapBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// gcmParams is the CK_GCM_PARAMS a C_WrapKey caller supplies, as
// wrapKeyMaterial receives them.
func gcmParams(iv []byte) wrapParams {
	return wrapParams{iv: iv}
}

// permissiveTracker is a types.AEADSafetyTracker that records nothing and
// refuses nothing.
//
// It is not a convenience: it is the configuration most backends are actually
// in. types.AEADSafetyTracker is optional, and the HSM, TPM and cloud-KMS
// providers keep no such tracker at all -- only pkg/keyprovider/symmetric
// creates one, per backend instance and keyed by key id. Installing this in a
// symmetric backend makes that backend behave the way those do, which is the
// only way a test can show that the service layer's own guard is what refuses a
// repeated (key, IV) pair rather than the provider's bookkeeping.
type permissiveTracker struct{}

func (permissiveTracker) CheckNonce(string, []byte) error  { return nil }
func (permissiveTracker) RecordNonce(string, []byte) error { return nil }
func (permissiveTracker) IncrementBytes(string, int64) error {
	return nil
}
func (permissiveTracker) GetBytesEncrypted(string) (int64, error) { return 0, nil }
func (permissiveTracker) GetAEADOptions(string) (*types.AEADOptions, error) {
	return nil, nil
}
func (permissiveTracker) SetAEADOptions(string, *types.AEADOptions) error { return nil }
func (permissiveTracker) ResetTracking(string) error                      { return nil }

// newUntrackedAESWrappingBackend builds a real symmetric backend holding a
// generated AES-256 wrapping key, with the provider's own optional nonce
// tracking turned off (see permissiveTracker). The store name and common name
// are the caller's so two backends can be told apart -- and so two of them can
// be given one key material.
func newUntrackedAESWrappingBackend(t *testing.T, store, cn string) (*mockKeyStore, *types.KeyAttributes) {
	t.Helper()

	symBackend, err := symmetric.NewBackend(&symmetric.Config{
		KeyStorage: storage.New(),
		Tracker:    permissiveTracker{},
	})
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType(store),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err = symBackend.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	ks := newMockKeyStore(store)
	ks.backend = symBackend
	ks.keys[attrs.CN] = "placeholder"
	ks.keyAttrs[attrs.CN] = attrs

	return ks, attrs
}

// importAESWrappingKey builds a second real symmetric backend holding the
// SAME key material under a different store and common name, through the
// backend's own import ceremony (backend.ImportExportBackend).
//
// This is the alias the guard has to see: one AES key, two names, two backend
// instances, two provider trackers. Nothing about the names says the keys are
// related, and only an identity taken from the material can tell that they are.
func importAESWrappingKey(t *testing.T, store, cn string, material []byte) (*mockKeyStore, *types.KeyAttributes) {
	t.Helper()

	symBackend, err := symmetric.NewBackend(&symmetric.Config{
		KeyStorage: storage.New(),
		Tracker:    permissiveTracker{},
	})
	require.NoError(t, err)

	importer, ok := symBackend.(backend.ImportExportBackend)
	require.True(t, ok, "the symmetric backend must support the import ceremony")

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType(store),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	ctx := context.Background()
	params, err := importer.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := importer.WrapKey(ctx, material, params)
	require.NoError(t, err)
	require.NoError(t, importer.ImportKey(ctx, attrs, wrapped))

	ks := newMockKeyStore(store)
	ks.backend = symBackend
	ks.keys[attrs.CN] = "placeholder"
	ks.keyAttrs[attrs.CN] = attrs

	// The import must have produced the same key, or this fixture proves
	// nothing about aliasing.
	require.Equal(t, material, rawKeyBytes(t, ks, attrs),
		"the imported key must hold the material it was given")

	return ks, attrs
}

// TestWrapAESGCMRefusesAReusedIVUnderOneKey is the probe that demonstrates the
// flaw: one KEK, one caller-supplied IV, two different target keys.
//
// AES-GCM is counter mode underneath, so both wraps encrypt under the identical
// keystream and ct_a XOR ct_b XOR pt_a reproduces pt_b byte for byte. Because
// the plaintext of a key wrap is key material, anyone holding the two blobs
// recovers BOTH wrapped keys, and the GHASH subkey H the two share makes
// forging tags on further blobs under that KEK feasible (NIST SP 800-38D
// section 8.2).
//
// The first half performs that recovery against crypto/cipher and asserts it
// works, so the requirement in the second half is measured against a
// demonstrated attack. The second half requires the service to refuse the
// second wrap, and requires the first blob to equal the standard library's own
// output so the guard cannot pass by emitting something nobody can decrypt.
func TestWrapAESGCMRefusesAReusedIVUnderOneKey(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	store, attrs := newUntrackedAESWrappingBackend(t, "reuse-be", "reuse-kek")
	kek := rawKeyBytes(t, store, attrs)
	iv := uniqueWrapIV(t)

	targetA := []byte("target-key-AAAAAAAAAAAAAAAAAAAAA")
	targetB := []byte("target-key-BBBBBBBBBBBBBBBBBBBBB")

	oracleA := gcmSealOracle(t, kek, iv, targetA, nil)
	oracleB := gcmSealOracle(t, kek, iv, targetB, nil)
	recovered := xorWrapBytes(xorWrapBytes(oracleA[:len(targetA)], oracleB[:len(targetB)]), targetA)
	require.Equal(t, targetB, recovered,
		"the premise of this test: two GCM seals under one (key, IV) leak the XOR of their plaintexts")

	ctx := context.Background()
	blobA, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), targetA)
	require.NoError(t, err, "the first use of an IV under a key is legitimate")
	require.Equal(t, append([]byte{aesGCMWrapModeExplicit}, append(append([]byte{}, iv...), oracleA...)...), blobA,
		"the wrap must agree with the standard library for the same key, IV and plaintext")

	blobB, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), targetB)
	require.Error(t, err, "a second wrap under the same (KEK, IV) discloses both wrapped keys and must be refused")
	assert.Nil(t, blobB, "a refused wrap must return no ciphertext")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse),
		"the refusal must name the reuse, so a caller can tell it from a backend fault: got %v", err)
}

// TestWrapAESGCMRefusesAReusedIVAcrossBackendsAndNames is why the claim is
// keyed by the wrapping key's material and not by its name.
//
// One AES key is reachable here as two keys: two backend instances, two store
// types, two common names, two provider trackers. GCM does not care how many
// names a key has -- the pair repeats and the keystream repeats with it -- and
// this is exactly the alias a guard keyed by key id, backend name or manager
// instance lets through.
func TestWrapAESGCMRefusesAReusedIVAcrossBackendsAndNames(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	first, firstAttrs := newUntrackedAESWrappingBackend(t, "alias-be-one", "alias-kek-one")
	material := rawKeyBytes(t, first, firstAttrs)
	second, secondAttrs := importAESWrappingKey(t, "alias-be-two", "alias-kek-two", material)

	iv := uniqueWrapIV(t)
	target := []byte("aliased-target-32-bytes-of-key!!")
	ctx := context.Background()

	_, err := wrapKeyMaterial(ctx, first, firstAttrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err)

	_, err = wrapKeyMaterial(ctx, second, secondAttrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.Error(t, err,
		"a second name for the same key material is the same key to AES-GCM, so the pair still repeats")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestWrapAESGCMAcceptsAFreshIVUnderTheSameKey is the other half of the guard:
// it must refuse repeats, not refuse everything. A guard that refused every
// wrap would satisfy the two tests above and make CKM_AES_GCM wrapping useless.
func TestWrapAESGCMAcceptsAFreshIVUnderTheSameKey(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	store, attrs := newUntrackedAESWrappingBackend(t, "fresh-be", "fresh-kek")
	kek := rawKeyBytes(t, store, attrs)
	target := []byte("fresh-iv-target-32-bytes-of-key!")
	ctx := context.Background()

	firstIV := uniqueWrapIV(t)
	secondIV := uniqueWrapIV(t)

	blobFirst, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(firstIV), target)
	require.NoError(t, err)

	blobSecond, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(secondIV), target)
	require.NoError(t, err, "a different IV under the same key is exactly what the caller is told to do")
	assert.NotEqual(t, blobFirst, blobSecond, "different IVs must produce different blobs")

	plainFirst, err := gcmOpenOracle(t, kek, firstIV, blobFirst[1+aesGCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainFirst)

	plainSecond, err := gcmOpenOracle(t, kek, secondIV, blobSecond[1+aesGCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainSecond)
}

// TestWrapAESGCMAcceptsOneIVUnderTwoDifferentKeys proves the claim is keyed by
// the key as well as by the nonce. SP 800-38D section 8.2 constrains the PAIR,
// so one IV under two distinct keys is two distinct pairs and is safe; refusing
// it would turn the guard into a global ban on IVs.
func TestWrapAESGCMAcceptsOneIVUnderTwoDifferentKeys(t *testing.T) {
	if fips140.Enforced() {
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	first, firstAttrs := newUntrackedAESWrappingBackend(t, "twokek-be-one", "twokek-kek-one")
	second, secondAttrs := newUntrackedAESWrappingBackend(t, "twokek-be-two", "twokek-kek-two")

	iv := uniqueWrapIV(t)
	target := []byte("two-kek-target-32-bytes-of-key!!")
	ctx := context.Background()

	_, err := wrapKeyMaterial(ctx, first, firstAttrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err)

	_, err = wrapKeyMaterial(ctx, second, secondAttrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err, "one IV under two distinct keys is two distinct pairs and must be allowed")
}

// TestWrapAESGCMDoesNotConsumeTheIVOfARefusedWrap pins where in the sequence
// the pair is claimed: after every check, not before.
//
// The guard is a one-way door -- a pair it has recorded can never be used again
// in this process -- so claiming it for a wrap that was going to be refused
// destroys an IV the caller never got to use. The caller's corrected retry,
// with the same IV it had prepared, would then be refused as a reuse of a wrap
// that never happened.
//
// The refusal used here is an unapproved tag length, which is a property of the
// mechanism parameters and not of the IV, so the identical IV must still be
// good afterwards.
func TestWrapAESGCMDoesNotConsumeTheIVOfARefusedWrap(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "refused-be", "refused-kek")
	kek := rawKeyBytes(t, store, attrs)
	iv := uniqueWrapIV(t)
	target := []byte("refused-then-ok-32-bytes-of-key!")
	ctx := context.Background()

	bad := wrapParams{iv: iv, tagBits: 64} // below the 96-bit floor of SP 800-38D 5.2.1.2
	_, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), bad, target)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidKeyAttributes),
		"the premise of this test is a refusal on the tag length, not on the IV: got %v", err)

	if fips140.Enforced() {
		// The "corrected retry" still supplies a caller nonce, which
		// requires the arbitrary-IV construction GODEBUG=fips140=only
		// refuses outright; see requireGCMWrapRefusedForCallerNonce.
		_, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), target)
		require.Error(t, err)
		return
	}

	blob, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err,
		"the refused wrap must not have claimed the IV: the caller's corrected retry has nothing else to change")

	plaintext, err := gcmOpenOracle(t, kek, iv, blob[1+aesGCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plaintext)
}

// TestWrapAESGCMClaimsAProviderGeneratedNonce proves the guard covers nonces
// the provider produced as well as ones the caller supplied. A service that
// only checked caller-supplied IVs would not notice a provider whose RNG had
// stopped producing fresh values, which is the failure that makes a generated
// IV unsafe in the first place.
func TestWrapAESGCMClaimsAProviderGeneratedNonce(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "generated-be", "generated-kek")
	target := []byte("generated-target-32-bytes-key!!!")
	ctx := context.Background()

	blob, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), wrapParams{}, target)
	require.NoError(t, err)
	require.Len(t, blob, 1+aesGCMNonceSize+len(target)+aesGCMTagSize,
		"the blob carries the nonce the provider generated")

	generated := blob[1 : 1+aesGCMNonceSize]
	_, err = wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(generated), target)
	require.Error(t, err, "the nonce the provider generated is consumed exactly like one the caller supplied")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// sealedSymmetricProvider is a types.SymmetricKeyProvider whose keys refuse to
// release their material, the way every HSM, TPM and cloud-KMS backend does,
// while still performing AES-GCM.
//
// It exists to exercise the one case where the guard cannot key on key
// material. The encryption itself is crypto/cipher, so the blob such a backend
// produces is a real AES-GCM blob a test can check against the same oracle.
type sealedSymmetricProvider struct {
	types.KeyProvider

	key []byte

	// rawErr is what the key answers Raw with. backend.ErrNotSupported is the
	// sealed case; anything else is a backend that failed for another reason
	// and must not be quietly keyed by name.
	rawErr error
}

func (p *sealedSymmetricProvider) GetSymmetricKey(_ context.Context, _ *types.KeyAttributes) (types.SymmetricKey, error) {
	return &sealedSymmetricKey{provider: p}, nil
}

func (p *sealedSymmetricProvider) GenerateSymmetricKey(_ context.Context, _ *types.KeyAttributes) (types.SymmetricKey, error) {
	return &sealedSymmetricKey{provider: p}, nil
}

func (p *sealedSymmetricProvider) SymmetricEncrypter(_ context.Context, _ *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	return &sealedSymmetricEncrypter{key: p.key}, nil
}

type sealedSymmetricKey struct {
	provider *sealedSymmetricProvider
}

func (k *sealedSymmetricKey) Raw() ([]byte, error) { return nil, k.provider.rawErr }
func (k *sealedSymmetricKey) Algorithm() string    { return string(types.SymmetricAES256GCM) }
func (k *sealedSymmetricKey) KeySize() int         { return len(k.provider.key) * 8 }

type sealedSymmetricEncrypter struct {
	key []byte
}

func (e *sealedSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := opts.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	sealed := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)
	split := len(sealed) - gcm.Overhead()
	return &types.EncryptedData{
		Ciphertext: sealed[:split],
		Nonce:      nonce,
		Tag:        sealed[split:],
	}, nil
}

func (e *sealedSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, data.Ciphertext...), data.Tag...)
	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}
	return gcm.Open(nil, data.Nonce, sealed, aad)
}

// newSealedWrappingBackend builds a store whose wrapping key will not release
// its material.
func newSealedWrappingBackend(t *testing.T, store, cn string, rawErr error) (*mockKeyStore, *types.KeyAttributes, []byte) {
	t.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType(store),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	ks := newMockKeyStore(store)
	ks.backend = &sealedSymmetricProvider{key: key, rawErr: rawErr}
	ks.keys[attrs.CN] = "placeholder"
	ks.keyAttrs[attrs.CN] = attrs

	return ks, attrs, key
}

// TestWrapAESGCMGuardsAKeyWhoseMaterialIsSealed proves a wrapping key an HSM
// will not release is still guarded, and still wrapped.
//
// Such a key has no bytes to key on, so it is identified by the store and name
// that reach it. That is sound precisely here and nowhere else: material that
// never leaves the device cannot also be present under a second name, so the
// alias the material-keyed identity exists to catch cannot arise. Refusing
// these wraps outright instead would take CKM_AES_GCM wrapping away from every
// HSM, TPM and cloud-KMS backend.
func TestWrapAESGCMGuardsAKeyWhoseMaterialIsSealed(t *testing.T) {
	if fips140.Enforced() {
		// sealedSymmetricEncrypter (above) builds its AES-GCM AEAD with
		// cipher.NewGCM directly -- the arbitrary-IV constructor -- rather
		// than routing through pkg/crypto/aead.NewGCMForFreshEncrypt the
		// way the real symmetric backend does, so it cannot wrap at all
		// under GODEBUG=fips140=only. This is a fidelity gap in the mock,
		// not in wrapAESGCM.
		requireGCMWrapRefusedForCallerNonce(t)
		return
	}

	store, attrs, key := newSealedWrappingBackend(t, "sealed-be", "sealed-kek", backend.ErrNotSupported)
	iv := uniqueWrapIV(t)
	target := []byte("sealed-target-32-bytes-of-key!!!")
	ctx := context.Background()

	blob, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err, "a sealed wrapping key must still be able to wrap")
	require.Equal(t, append([]byte{aesGCMWrapModeExplicit}, append(append([]byte{}, iv...), gcmSealOracle(t, key, iv, target, nil)...)...), blob,
		"the blob must be a real AES-GCM wrap under the caller's IV")

	_, err = wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.Error(t, err, "the pair repeats even when the identity had to come from the key's name")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)

	// A different sealed key under the same IV is a different pair.
	other, otherAttrs, _ := newSealedWrappingBackend(t, "sealed-be-2", "sealed-kek-2", backend.ErrNotSupported)
	_, err = wrapKeyMaterial(ctx, other, otherAttrs, string(types.WrapAESGCM), gcmParams(iv), target)
	require.NoError(t, err, "one IV under two distinct sealed keys is two distinct pairs")
}

// TestWrapAESGCMRefusesAWrappingKeyThatCannotBeRead is the bad-input half of
// the identity resolution.
//
// A backend that fails to produce the key for any reason other than "this key
// is sealed" has not told us which key this wrap is under. Choosing an identity
// anyway would guard the wrap against a name that may not correspond to the
// bytes the provider is about to encrypt with, so the wrap is refused and the
// backend's own error is reported.
func TestWrapAESGCMRefusesAWrappingKeyThatCannotBeRead(t *testing.T) {
	readErr := errors.New("wrapping key store is offline")
	store, attrs, _ := newSealedWrappingBackend(t, "unreadable-be", "unreadable-kek", readErr)
	ctx := context.Background()

	blob, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM),
		gcmParams(uniqueWrapIV(t)), []byte("unreadable-target-32-bytes-key!!"))
	require.Error(t, err, "a wrapping key that cannot be read must not be wrapped under a guessed identity")
	assert.Nil(t, blob)
	assert.True(t, errors.Is(err, readErr), "the backend's own failure must be reported: got %v", err)
	assert.False(t, errors.Is(err, aead.ErrNonceReuse), "this is not a reuse: got %v", err)
}

// TestGCMWrapKeyIdentityPrefersMaterialOverName proves the identity really is
// the key's bytes wherever they can be had, and that the sealed-key identity is
// a different shape entirely.
//
// Without this, an identity function that always returned the name would still
// pass every refusal test above that uses one backend, and only the aliasing
// test would fail -- which is exactly the defect this change exists to close.
func TestGCMWrapKeyIdentityPrefersMaterialOverName(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "identity-be", "identity-kek")
	material := rawKeyBytes(t, store, attrs)
	ctx := context.Background()

	identity, release, err := gcmWrapKeyIdentity(ctx, store, attrs)
	require.NoError(t, err)
	assert.Equal(t, material, identity, "the identity of a readable key is the key")
	release()

	sealedStore, sealedAttrs, _ := newSealedWrappingBackend(t, "identity-sealed-be", "identity-sealed-kek",
		backend.ErrNotSupported)
	sealedIdentity, sealedRelease, err := gcmWrapKeyIdentity(ctx, sealedStore, sealedAttrs)
	require.NoError(t, err)
	defer sealedRelease()
	assert.Contains(t, string(sealedIdentity), sealedWrapKeyGuardDomain,
		"a name-derived identity is tagged so it cannot collide with a key's own bytes")
	assert.Contains(t, string(sealedIdentity), sealedAttrs.ID(),
		"the name-derived identity must name the store and the key")
}
