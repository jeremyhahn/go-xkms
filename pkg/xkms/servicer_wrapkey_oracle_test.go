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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRSAWrappingBackend returns a mock store holding a real 2048-bit RSA key
// under CN "kek", the shape wrapRSAPKCS1v15 / unwrapRSAPKCS1v15 resolve.
func newRSAWrappingBackend(t *testing.T) (*mockKeyStore, *types.KeyAttributes, *rsa.PrivateKey) {
	t.Helper()

	store := newMockKeyStore("kek-be")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "kek"}
	store.keys[attrs.CN] = key
	store.keyAttrs[attrs.CN] = attrs
	return store, attrs, key
}

// chattyDecrypter stands in for a backend that is not crypto/rsa -- a PKCS#11
// token, a cloud KMS -- and reports its own opinion of why a ciphertext was
// no good. Whatever it says must stop at the service boundary.
type chattyDecrypter struct {
	pub crypto.PublicKey
}

const chattyDecrypterDiagnostic = "CKR_ENCRYPTED_DATA_INVALID: block type 02 expected, byte 37 of EM is zero"

func (c *chattyDecrypter) Public() crypto.PublicKey { return c.pub }

func (c *chattyDecrypter) Decrypt(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return nil, errors.New(chattyDecrypterDiagnostic)
}

// TestUnwrapRSAPKCS1v15_CiphertextFailuresAreIndistinguishable is the direct
// check on the Bleichenbacher/Marvin oracle: every way a caller-supplied
// CKM_RSA_PKCS blob can be refused must produce one error value.
//
// RFC 8017 section 7.2.2 requires exactly this ("it is important that ... the
// error message output ... not reveal which check failed"), because the attack
// needs nothing more than a per-ciphertext conformance answer, and
// UnwrapKeyByID hands one out over gRPC, QUIC, MCP, the unix socket and REST.
func TestUnwrapRSAPKCS1v15_CiphertextFailuresAreIndistinguishable(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs, key := newRSAWrappingBackend(t)
	ctx := context.Background()
	modulusLen := key.Size()

	random := make([]byte, modulusLen)
	_, err := rand.Read(random)
	require.NoError(t, err)
	random[0] = 0x00 // keep it below the modulus so the failure is the padding

	blobs := map[string][]byte{
		"random ciphertext":  random,
		"all-zero":           make([]byte, modulusLen),
		"shorter than n":     make([]byte, modulusLen/2),
		"longer than n":      make([]byte, modulusLen+8),
		"single zero octet":  {0x00},
		"conformant, but so": append([]byte{0xFF}, random[1:]...),
	}

	messages := make(map[string]struct{}, len(blobs))
	for name, blob := range blobs {
		_, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, blob)
		require.Errorf(t, err, "%s was accepted", name)
		assert.ErrorIsf(t, err, ErrUnwrapCiphertextRejected, "%s", name)
		assert.NotContainsf(t, err.Error(), "crypto/rsa",
			"%s leaked the decrypter's own diagnostic", name)
		messages[err.Error()] = struct{}{}
	}
	assert.Lenf(t, messages, 1,
		"CKM_RSA_PKCS unwrap must report one error for every rejected ciphertext, got %d: %v",
		len(messages), messages)
}

// TestUnwrapRSAPKCS1v15_RejectsConformantEmptyPayload closes the cheapest hit
// the Bleichenbacher adversary has.
//
// A PKCS#1 v1.5 block of the form 00 02 <non-zero padding> 00 with nothing
// after the separator is perfectly conformant, so rsa.DecryptPKCS1v15 returns
// (empty slice, nil). Before the zero-length guard, unwrapKeyMaterial passed
// that straight back: the caller learned the ciphertext was conformant AND was
// handed a "key" with no bytes in it. It must now be refused, and refused with
// the same error a non-conformant ciphertext gets, or the rejection itself
// becomes the oracle answer.
func TestUnwrapRSAPKCS1v15_RejectsConformantEmptyPayload(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs, key := newRSAWrappingBackend(t)
	ctx := context.Background()

	conformant, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, []byte{}) //nolint:staticcheck // SA1019: the test IS the Bleichenbacher oracle check
	require.NoError(t, err)

	// The premise: this ciphertext really is conformant, so the refusal below
	// is the service's decision and not RSA's.
	recovered, err := rsa.DecryptPKCS1v15(rand.Reader, key, conformant) //nolint:staticcheck // SA1019: the test IS the Bleichenbacher oracle check
	require.NoError(t, err, "the test's premise is that this ciphertext is conformant")
	require.Empty(t, recovered)

	out, conformantErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, conformant)
	require.Error(t, conformantErr, "a conformant ciphertext around an empty payload was accepted as a key")
	assert.Nil(t, out)
	assert.ErrorIs(t, conformantErr, ErrUnwrapCiphertextRejected)

	nonConformant := make([]byte, key.Size())
	_, err = rand.Read(nonConformant)
	require.NoError(t, err)
	nonConformant[0] = 0x00
	_, nonConformantErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, nonConformant)
	require.Error(t, nonConformantErr)

	assert.Equal(t, nonConformantErr.Error(), conformantErr.Error(),
		"a conformant-but-empty ciphertext must be indistinguishable from a non-conformant one")

	// The success counterpart: real key material still unwraps.
	target := []byte("target-key-material")
	wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, target)
	require.NoError(t, err)
	got, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, got)
}

// TestUnwrapRSA_DoesNotLeakBackendDiagnostics covers the half of the leak that
// crypto/rsa's own care cannot fix. The software backend returns one
// rsa.ErrDecryption for every failure; a PKCS#11 token or a cloud KMS returns
// its own error code, and embedding it in ErrKeyOperation.Err used to put that
// straight on the wire.
func TestUnwrapRSA_DoesNotLeakBackendDiagnostics(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store := newMockKeyStore("kek-be")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "kek"}
	store.keys[attrs.CN] = &chattyDecrypter{pub: &key.PublicKey}
	store.keyAttrs[attrs.CN] = attrs

	ctx := context.Background()
	blob := make([]byte, key.Size())

	for _, algorithm := range []types.KeyWrapAlgorithm{types.WrapRSAPKCS1v15, types.WrapRSAOAEPSHA256} {
		_, err := unwrapKeyMaterial(ctx, store, attrs, string(algorithm), wrapParams{}, blob)
		require.Errorf(t, err, "%s accepted a blob the backend refused", algorithm)
		assert.ErrorIsf(t, err, ErrUnwrapCiphertextRejected, "%s", algorithm)
		assert.NotContainsf(t, err.Error(), "CKR_", "%s put the token's error code on the wire", algorithm)
		assert.NotContainsf(t, err.Error(), chattyDecrypterDiagnostic,
			"%s put the backend's diagnostic on the wire", algorithm)
	}
}

// TestUnwrapRSAOAEP_CiphertextFailuresAreIndistinguishable is the OAEP
// counterpart. OAEP is not the Bleichenbacher shape, but RFC 8017 section
// 7.1.2 gives it the same rule for Manger's attack, which distinguishes the
// "ciphertext representative out of range" check from the decoding check.
func TestUnwrapRSAOAEP_CiphertextFailuresAreIndistinguishable(t *testing.T) {
	store, attrs, key := newRSAWrappingBackend(t)
	ctx := context.Background()

	random := make([]byte, key.Size())
	_, err := rand.Read(random)
	require.NoError(t, err)
	random[0] = 0x00

	// A ciphertext wrapped under a DIFFERENT hash decodes to garbage, which is
	// the decoding-check failure; a wrong-length blob is the range failure.
	wrongDigest, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAOAEPSHA512), wrapParams{}, []byte("material"))
	require.NoError(t, err)

	blobs := map[string][]byte{
		"random ciphertext": random,
		"all-zero":          make([]byte, key.Size()),
		"wrong length":      make([]byte, key.Size()-1),
		"wrong OAEP digest": wrongDigest,
		"single zero octet": {0x00},
		"one octet past n": func() []byte {
			b := make([]byte, key.Size()+1)
			b[0] = 0x01
			return b
		}(),
	}

	messages := make(map[string]struct{}, len(blobs))
	for name, blob := range blobs {
		_, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAOAEPSHA256), wrapParams{}, blob)
		require.Errorf(t, err, "%s was accepted", name)
		assert.ErrorIsf(t, err, ErrUnwrapCiphertextRejected, "%s", name)
		assert.NotContainsf(t, err.Error(), "crypto/rsa", "%s leaked the decrypter's diagnostic", name)
		messages[err.Error()] = struct{}{}
	}
	assert.Lenf(t, messages, 1,
		"CKM_RSA_PKCS_OAEP unwrap must report one error for every rejected ciphertext, got %d: %v",
		len(messages), messages)
}

// TestUnwrapAESCBCPad_FailureModesAreIndistinguishable is the Vaudenay
// counterpart. The symmetric provider's unpadPKCS7 already runs in constant
// time and already collapses its own failures into one ErrInvalidPadding, but
// the service used to re-split them on the wire: "symmetric: invalid padding"
// for a bad pad byte against "symmetric: ciphertext is not a whole number of
// AES blocks" for a bad length, plus whatever else a provider might return.
//
// The residual, which no change in this file can remove, is asserted at the
// end: a blob whose padding happens to be valid still unwraps, and that one bit
// is the padding oracle's answer. Closing it means refusing CKM_AES_CBC_PAD for
// C_UnwrapKey, which is a policy decision and not made here.
func TestUnwrapAESCBCPad_FailureModesAreIndistinguishable(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	store, attrs := newAESWrappingBackend(t)
	ctx := context.Background()

	// A blob whose decryption is DETERMINISTICALLY badly padded.
	//
	// This used to be random bytes, which decrypt to random plaintext -- and
	// random plaintext carries VALID PKCS#7 padding whenever its last byte n
	// lands in 1..16 and the final n bytes all equal n. Measured over two
	// million random blocks: 0.3896%, one in 257. So one run in 257 produced a
	// blob that legitimately unwrapped and failed this test, which is a flake
	// by construction rather than a defect in the code under test (#87).
	//
	// Encrypting a chosen plaintext removes the chance. All-zero plaintext
	// decrypts to a last byte of 0x00, and 0 is outside the valid range 1..16,
	// so the padding can never be accepted. The IV is fixed for the same
	// reason the plaintext is: this blob exists only to be rejected, and a
	// random one buys nothing but the flake.
	kek, err := aes.NewCipher(rawKeyBytes(t, store, attrs))
	require.NoError(t, err)

	badPadding := make([]byte, aesCBCIVSize+2*aes.BlockSize)
	cipher.NewCBCEncrypter(kek, badPadding[:aesCBCIVSize]).
		CryptBlocks(badPadding[aesCBCIVSize:], make([]byte, 2*aes.BlockSize))

	// The other two fail on LENGTH, before anything is decrypted, so their
	// contents never mattered and random bytes are fine.
	unaligned := make([]byte, aesCBCIVSize+aes.BlockSize+3)
	_, err = rand.Read(unaligned)
	require.NoError(t, err)

	blobs := map[string][]byte{
		"invalid PKCS#7 padding": badPadding,
		"not block aligned":      unaligned,
		"one octet of payload":   make([]byte, aesCBCIVSize+1),
	}

	messages := make(map[string]struct{}, len(blobs))
	for name, blob := range blobs {
		_, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBCPad), wrapParams{}, blob)
		require.Errorf(t, err, "%s was accepted", name)
		assert.ErrorIsf(t, err, ErrUnwrapCiphertextRejected, "%s", name)
		assert.NotContainsf(t, err.Error(), "padding", "%s named the padding as the reason", name)
		assert.NotContainsf(t, err.Error(), "block", "%s named the alignment as the reason", name)
		messages[err.Error()] = struct{}{}
	}
	assert.Lenf(t, messages, 1,
		"CKM_AES_CBC_PAD unwrap must report one error for every rejected blob, got %d: %v",
		len(messages), messages)

	// Success counterpart: a real wrap still round-trips, so the collapse of
	// the failure modes did not turn into a blanket refusal.
	target := []byte("twenty-byte-key-mat!")
	wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBCPad), wrapParams{}, target)
	require.NoError(t, err)
	recovered, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBCPad), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestUnwrapKeyMaterial_KeyErrorsStayDistinguishable is the counterweight: the
// opaque error covers ciphertext-dependent failures only. An operator who
// named a key that does not exist, or a backend that cannot do symmetric
// cryptography at all, must still be told so -- neither answer depends on the
// blob, so neither is an oracle, and collapsing them would make the service
// undiagnosable for no security gain.
func TestUnwrapKeyMaterial_KeyErrorsStayDistinguishable(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}
	ctx := context.Background()
	store, attrs, key := newRSAWrappingBackend(t)
	blob := make([]byte, key.Size())

	_, missingErr := unwrapKeyMaterial(ctx, store, &types.KeyAttributes{CN: "no-such-key"},
		string(types.WrapRSAPKCS1v15), wrapParams{}, blob)
	require.Error(t, missingErr)
	assert.NotErrorIs(t, missingErr, ErrUnwrapCiphertextRejected)
	assert.True(t, strings.Contains(missingErr.Error(), "unwrapping decrypter"),
		"a key that cannot be resolved must say so, got %q", missingErr)

	_, ciphertextErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAPKCS1v15), wrapParams{}, blob)
	require.Error(t, ciphertextErr)
	assert.NotEqual(t, missingErr.Error(), ciphertextErr.Error())

	plain := newMockKeyStore("plain-be") // no SymmetricKeyProvider
	_, symErr := unwrapKeyMaterial(ctx, plain, &types.KeyAttributes{CN: "kek"},
		string(types.WrapAESCBCPad), wrapParams{}, make([]byte, aesCBCIVSize+aes.BlockSize))
	require.Error(t, symErr)
	assert.ErrorIs(t, symErr, ErrSymmetricNotSupported)
	assert.NotErrorIs(t, symErr, ErrUnwrapCiphertextRejected)
}

// TestUnwrapKeyMaterial_RejectsEmptyResultForAEAD proves the zero-length guard
// is applied to every mechanism and not only to the RSA one that motivated it.
// A CKM_AES_GCM blob that authenticates correctly around an empty plaintext is
// a valid AEAD message and a nonsensical key; it must be refused with the same
// opaque error rather than returned as a key with no bytes.
func TestUnwrapKeyMaterial_RejectsEmptyResultForAEAD(t *testing.T) {
	store, attrs := newAESWrappingBackend(t)
	ctx := context.Background()

	symProvider, ok := store.KeyProvider().(types.SymmetricKeyProvider)
	require.True(t, ok)
	encrypter, err := symProvider.SymmetricEncrypter(ctx, attrs)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte{}, &types.EncryptOptions{})
	require.NoError(t, err, "the premise is that an empty AEAD message is encryptable")
	require.Len(t, encrypted.Nonce, aesGCMNonceSize)
	require.Len(t, encrypted.Tag, aesGCMTagSize)
	require.Empty(t, encrypted.Ciphertext)

	modeByte := aesGCMWrapModeExplicit
	if encrypted.GCMNonceMode == types.GCMNonceModeRandom {
		modeByte = aesGCMWrapModeRandom
	}
	blob := make([]byte, 0, 1+aesGCMNonceSize+aesGCMTagSize)
	blob = append(blob, modeByte)
	blob = append(blob, encrypted.Nonce...)
	blob = append(blob, encrypted.Ciphertext...)
	blob = append(blob, encrypted.Tag...)

	out, emptyErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), wrapParams{}, blob)
	require.Error(t, emptyErr, "an authenticated empty plaintext was returned as key material")
	assert.Nil(t, out)
	assert.ErrorIs(t, emptyErr, ErrUnwrapCiphertextRejected)

	// The guard must report the mechanism's own label, not the caller-supplied
	// algorithm string: for CKM_RSA_PKCS the two labels differing is itself the
	// oracle answer (see TestUnwrapRSAPKCS1v15_RejectsConformantEmptyPayload),
	// and unwrapOperationNames is what keeps them the same everywhere.
	assert.Contains(t, emptyErr.Error(), unwrapOperationNames[kindAESGCM])
	assert.NotContains(t, emptyErr.Error(), string(types.WrapAESGCM)+" unwrap")

	// AES-GCM's own decryption failure deliberately keeps its diagnostic. It is
	// an AEAD: a forger cannot produce a blob that authenticates, so "why did
	// this fail" is not an oracle answer, and collapsing it would cost an
	// operator the one useful thing the error says. Only the unauthenticated
	// mechanisms -- CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_AES_CBC(_PAD) -- are
	// made opaque.
	forged := append([]byte{}, blob...)
	forged[len(forged)-1] ^= 0x01
	_, forgedErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), wrapParams{}, forged)
	require.Error(t, forgedErr)
	assert.NotErrorIs(t, forgedErr, ErrUnwrapCiphertextRejected)

	// Success counterpart: a non-empty AEAD wrap still round-trips.
	target := []byte("aead-target-key-material")
	wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), wrapParams{}, target)
	require.NoError(t, err)
	recovered, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESGCM), wrapParams{}, wrapped)
	require.NoError(t, err)
	assert.Equal(t, target, recovered)
}

// TestWrapMechanisms_TwoRefusalsAreDistinct documents, as an executable fact
// rather than a comment, which mechanisms the table refuses and under which of
// the two rules.
//
// It used to assert the opposite arrangement: RSA-OAEP-SHA1 refused as weak
// while CKM_RSA_PKCS, CKM_AES_CBC_PAD and CKM_AES_CBC -- strictly worse
// constructions, the ones Bleichenbacher's and Vaudenay's attacks were written
// against -- were admitted unconditionally, on the grounds that PKCS#11 v3.2
// sanctions them. Refusing the strongest of the four while admitting the three
// weakest was backwards. The three are now gated instead of admitted, and the
// gate is a setting rather than a rewrite, because the spec does sanction them
// and an operator may need one.
//
// mech.weak and mech.legacy must stay separate fields with separate errors:
// weak is unconditional and legacy is not, and collapsing them would make
// crypto.allow_legacy_key_wrap silently re-admit SHA-1 OAEP too.
func TestWrapMechanisms_TwoRefusalsAreDistinct(t *testing.T) {
	weak := make([]types.KeyWrapAlgorithm, 0, 1)
	legacy := make([]types.KeyWrapAlgorithm, 0, 3)
	for algorithm, mech := range wrapMechanisms {
		if mech.weak {
			weak = append(weak, algorithm)
		}
		if mech.legacy {
			legacy = append(legacy, algorithm)
		}
	}
	sort.Slice(weak, func(i, j int) bool { return weak[i] < weak[j] })
	sort.Slice(legacy, func(i, j int) bool { return legacy[i] < legacy[j] })

	assert.Equal(t, []types.KeyWrapAlgorithm{types.WrapRSAOAEPSHA1}, weak,
		"only RSA-OAEP-SHA1 is refused unconditionally")
	assert.Equal(t, []types.KeyWrapAlgorithm{types.WrapAESCBC, types.WrapAESCBCPad, types.WrapRSAPKCS1v15}, legacy,
		"the gated set is exactly the constructions that authenticate nothing")

	// The gated set here and the gated set types publishes to the operator
	// (compliance gap, log line, refusal reason) must be the same set, or the
	// message would name mechanisms the service still performs.
	names := make([]string, 0, len(legacy))
	for _, algorithm := range legacy {
		assert.Truef(t, types.IsLegacyKeyWrapAlgorithm(algorithm),
			"%s is gated here but types does not know it", algorithm)
		names = append(names, string(algorithm))
	}
	assert.Equal(t, types.LegacyKeyWrapNames(), names,
		"types.LegacyKeyWrapNames feeds the compliance gap and must match the table")

	// The unconditional refusal holds in both policy states.
	for _, allowed := range []bool{false, true} {
		previous := types.AllowLegacyKeyWrap()
		types.SetAllowLegacyKeyWrap(allowed)
		_, err := resolveWrapMechanism(string(types.WrapRSAOAEPSHA1), "unwrap")
		types.SetAllowLegacyKeyWrap(previous)

		require.Errorf(t, err, "RSA-OAEP-SHA1 with allow_legacy_key_wrap=%t", allowed)
		assert.ErrorIsf(t, err, ErrWeakOAEPHash,
			"RSA-OAEP-SHA1 must stay refused as weak with allow_legacy_key_wrap=%t", allowed)
		assert.NotErrorIsf(t, err, ErrLegacyWrapDisabled,
			"RSA-OAEP-SHA1 is not part of the legacy gate")
	}
}
