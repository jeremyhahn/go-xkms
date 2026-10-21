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
// creates one, per backend instance and keyed by key id, and it tracks only
// the NIST SP 800-38D bytes-encrypted budget (go-xkms#1201 moved nonce-reuse
// tracking out of this interface entirely, into the shared, unconditional
// aead.KeyNonceGuard every backend's Encrypt claims through). Installing this
// in a symmetric backend makes that backend behave the way the trackerless
// providers do, which is the only way a test can show that the guard inside
// Encrypt is what refuses a repeated (key, IV) pair rather than this
// tracker's own bookkeeping.
type permissiveTracker struct{}

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
	assert.True(t, errors.Is(err, generatedNonceReplayErr()), "got %v", err)
}

// A wrapping key that cannot release its material -- PKCS#11, whose key
// never leaves the token -- is no longer guarded generically at the service
// layer: go-xkms#1201 moved the claim inside each backend's own Encrypt
// implementation, which is also where the sealed-vs-material identity
// choice is made (aeadNonceIdentity in pkg/backend/aead_nonce.go). See
// pkg/backend/pkcs11's TestSymmetricEncrypter_RejectsNonceReuse, which
// exercises that identity choice against the backend's own PKCS#11 mock
// rather than a servicer-level test double. TPM2 and Azure Key Vault both
// have their own key material available in process for this same call (see
// pkg/tpm2's TestNonceReuse and pkg/backend/azurekv's
// TestAzureKVBackend_NonceReuse) and so claim by material like every other
// in-process-material backend.
