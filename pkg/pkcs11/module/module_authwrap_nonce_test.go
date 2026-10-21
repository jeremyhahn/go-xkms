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

package module

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authWrapKeyPair creates a wrapping key holding wrappingValue and an
// extractable target key holding targetValue, both AES secret keys, and
// returns their handles.
//
// The values are supplied by the caller rather than generated, because the
// nonce-reuse tests turn on which key material two wraps share: the guard is
// keyed by the wrapping key's bytes, so a test that needs two handles onto one
// key, or two keys that differ only in their material, has to say so.
func authWrapKeyPair(t *testing.T, m *Module, session SessionHandle, label string, wrappingValue, targetValue []byte) (ObjectHandle, ObjectHandle) {
	t.Helper()

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label+"-kek"),
		NewAttribute(CKA_VALUE, wrappingValue),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
	})
	require.Equal(t, CKR_OK, rv)

	targetKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label+"-target"),
		NewAttribute(CKA_VALUE, targetValue),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	return wrappingKey, targetKey
}

// uniqueTestIV returns a 12-byte IV no other test in this package has used,
// so a test that is not about nonce reuse never trips the guard by accident.
// The guard lives for the lifetime of the process and is keyed by key
// material, which is exactly why a test needing a fresh pair must either use
// fresh key material or a fresh IV.
func uniqueTestIV(t *testing.T) []byte {
	t.Helper()
	iv := make([]byte, GCMNonceSize)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	return iv
}

// gcmSealOracle encrypts with the standard library directly. It is the
// independent oracle these tests measure the module against: verifying the
// module's output by feeding it back through the module would pass just as
// well if both halves were wrong in the same way.
func gcmSealOracle(t *testing.T, key, nonce, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcm.Seal(nil, nonce, plaintext, aad)
}

// gcmOpenOracle decrypts with the standard library directly, for the same
// reason gcmSealOracle encrypts with it.
func gcmOpenOracle(t *testing.T, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	// The random-nonce construction opens any 96-bit nonce carried at the
	// head of its input, and is the one crypto/cipher allows under
	// fips140=only, so this oracle answers the same in both regimes.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	require.Len(t, nonce, GCMNonceSize)
	return gcm.Open(nil, nil, append(slices.Clone(nonce), ciphertext...), aad)
}

// xorBytes returns the byte-wise XOR of a and b, which must be the same
// length.
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// TestWrapKeyAuthenticatedRefusesAReusedIVUnderOneKey is the probe that
// demonstrated the flaw: one AES-128 KEK, one fixed IV, two different 16-byte
// target keys.
//
// AES-GCM is counter mode underneath, so both wraps would encrypt under the
// identical keystream and ct_a XOR ct_b XOR pt_a reproduces pt_b byte for
// byte. The plaintext of a key wrap is key material, so anyone holding the two
// blobs would recover both wrapped keys -- and the repeated GHASH subkey H
// makes tag forgery on further blobs feasible on top of that (NIST SP 800-38D
// section 8.2).
//
// The first half of this test proves the arithmetic against the standard
// library, so the assertion in the second half is measured against a
// demonstrated attack rather than an assumed one. The second half then
// requires the module to refuse the second wrap.
func TestWrapKeyAuthenticatedRefusesAReusedIVUnderOneKey(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kek := []byte("nonce-reuse-KEK1") // AES-128
	targetA := []byte("target-key-AAAA")
	targetA = append(targetA, 'A')
	targetB := []byte("target-key-BBBB")
	targetB = append(targetB, 'B')
	iv := uniqueTestIV(t)
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		wrappingKey, keyA := authWrapKeyPair(t, m, session, "reuse-a", kek, targetA)
		_, err := m.WrapKeyAuthenticated(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128)), wrappingKey, keyA, nil)
		return err
	}) {
		return
	}

	// The attack, performed outside the module, against the standard library.
	// This is what the module must not make possible.
	oracleA := gcmSealOracle(t, kek, iv, targetA, nil)
	oracleB := gcmSealOracle(t, kek, iv, targetB, nil)
	recovered := xorBytes(xorBytes(oracleA[:len(targetA)], oracleB[:len(targetB)]), targetA)
	require.Equal(t, targetB, recovered,
		"the premise of this test: two GCM seals under one (key, IV) leak the XOR of their plaintexts")

	wrappingKey, keyA := authWrapKeyPair(t, m, session, "reuse-a", kek, targetA)
	keyB, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "reuse-b-target"),
		NewAttribute(CKA_VALUE, targetB),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))

	blobA, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, keyA, nil)
	require.NoError(t, err, "the first use of an IV under a key is legitimate")
	require.Equal(t, oracleA, blobA,
		"the module's wrap must agree with the standard library for the same key, IV and plaintext")

	// The second wrap is the catastrophic one and must not happen.
	blobB, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, keyB, nil)
	require.Error(t, err, "a second wrap under the same (key, IV) recovers both wrapped keys and must be refused")
	assert.Nil(t, blobB, "a refused wrap must return no ciphertext")
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID),
		"the caller has to change the IV in the mechanism parameter, so the code names that parameter: got %v", err)
}

// TestWrapKeyAuthenticatedAcceptsAFreshIVUnderTheSameKey is the other half of
// the guard: it must refuse repeats, not refuse everything. A guard that
// answered CKR_MECHANISM_PARAM_INVALID to every wrap would satisfy the test
// above and make the verb useless.
func TestWrapKeyAuthenticatedAcceptsAFreshIVUnderTheSameKey(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kek := []byte("fresh-iv-KEK-256-bytes-long-abcd") // AES-256
	target := []byte("fresh-iv-target-")
	wrappingKey, targetKey := authWrapKeyPair(t, m, session, "fresh-iv", kek, target)

	first := uniqueTestIV(t)
	second := uniqueTestIV(t)
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticated(session,
			NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(first, 128)), wrappingKey, targetKey, nil)
		return err
	}) {
		return
	}

	blobFirst, err := m.WrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(first, 128)),
		wrappingKey, targetKey, nil)
	require.NoError(t, err)

	blobSecond, err := m.WrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(second, 128)),
		wrappingKey, targetKey, nil)
	require.NoError(t, err, "a different IV under the same key is exactly what the caller is told to do")
	assert.NotEqual(t, blobFirst, blobSecond, "different IVs must produce different ciphertext")

	// Both blobs must still be the real thing, checked outside the module.
	plainFirst, err := gcmOpenOracle(t, kek, first, blobFirst, nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainFirst)

	plainSecond, err := gcmOpenOracle(t, kek, second, blobSecond, nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainSecond)
}

// TestWrapKeyAuthenticatedAcceptsOneIVUnderTwoDifferentKeys proves the guard
// is keyed by the key as well as the nonce. SP 800-38D section 8.2 constrains
// the PAIR: the same IV under a different key is a different pair and is
// perfectly safe, so refusing it would make the guard a global ban on IVs and
// break every unrelated caller.
func TestWrapKeyAuthenticatedAcceptsOneIVUnderTwoDifferentKeys(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	iv := uniqueTestIV(t)
	target := []byte("two-kek-target--")

	kekOne, targetKey := authWrapKeyPair(t, m, session, "two-kek-one", []byte("two-kek-ONE-1234"), target)
	kekTwo, _ := authWrapKeyPair(t, m, session, "two-kek-two", []byte("two-kek-TWO-1234"), target)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticated(session, mech, kekOne, targetKey, nil)
		return err
	}) {
		return
	}

	_, err := m.WrapKeyAuthenticated(session, mech, kekOne, targetKey, nil)
	require.NoError(t, err)

	_, err = m.WrapKeyAuthenticated(session, mech, kekTwo, targetKey, nil)
	require.NoError(t, err, "one IV under two distinct keys is two distinct pairs and must be allowed")
}

// TestWrapKeyAuthenticatedRefusesAReusedIVAcrossHandlesAndSessions is why the
// guard is keyed by key material rather than by object handle, session or
// slot.
//
// The same AES key is created twice, as two objects with two handles, and the
// wraps are driven from two different sessions. GCM does not care how many
// names the token has for the material: the pair repeats and the keystream
// repeats with it. A guard keyed by handle, by session, or held per manager
// instance would see two unrelated operations here and let the second through.
func TestWrapKeyAuthenticatedRefusesAReusedIVAcrossHandlesAndSessions(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	sessionOne := loginAsNormalUser(t, m)

	kek := []byte("aliased-KEK-1234")
	target := []byte("aliased-target--")
	iv := uniqueTestIV(t)

	wrappingOne, targetOne := authWrapKeyPair(t, m, sessionOne, "alias-one", kek, target)

	sessionTwo, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	wrappingTwo, targetTwo := authWrapKeyPair(t, m, sessionTwo, "alias-two", kek, target)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticated(sessionOne, mech, wrappingOne, targetOne, nil)
		return err
	}) {
		return
	}

	_, err := m.WrapKeyAuthenticated(sessionOne, mech, wrappingOne, targetOne, nil)
	require.NoError(t, err)

	_, err = m.WrapKeyAuthenticated(sessionTwo, mech, wrappingTwo, targetTwo, nil)
	require.Error(t, err,
		"a second object holding the same key material is the same key to AES-GCM, so the pair still repeats")
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
}

// TestWrapKeyAuthenticatedSizeQueryDoesNotConsumeTheIV proves the size query
// stays a query. C_WrapKeyAuthenticated's own C ABI sizes the output before it
// wraps, so a probe that claimed the IV would make every well-behaved
// application's first real wrap fail as a reuse of its own probe.
func TestWrapKeyAuthenticatedSizeQueryDoesNotConsumeTheIV(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kek := []byte("probe-KEK-123456")
	target := []byte("probe-target----")
	iv := uniqueTestIV(t)
	wrappingKey, targetKey := authWrapKeyPair(t, m, session, "probe", kek, target)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticatedSize(session, mech, wrappingKey, targetKey)
		return err
	}) {
		return
	}

	size, err := m.WrapKeyAuthenticatedSize(session, mech, wrappingKey, targetKey)
	require.NoError(t, err)
	require.Equal(t, uint64(len(target)+GCMTagSize), size,
		"a caller-supplied IV is not prepended, so the size is ciphertext||tag")

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err, "the probe must not have claimed the IV the wrap is about to use")
	assert.Len(t, blob, int(size))
}

// TestWrapKeyAuthenticatedGuardsTheGeneratedIVToo proves the guard covers
// nonces the token produced as well as ones the caller supplied. A token that
// only checked caller-supplied IVs would not notice an RNG that had stopped
// producing fresh values, which is the failure mode that makes a generated IV
// unsafe.
func TestWrapKeyAuthenticatedGuardsTheGeneratedIVToo(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kek := []byte("generated-KEK-01")
	target := []byte("generated-target")
	wrappingKey, targetKey := authWrapKeyPair(t, m, session, "generated", kek, target)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128))

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err)
	require.Len(t, blob, GCMNonceSize+len(target)+GCMTagSize,
		"with no way to hand the IV back, the generated nonce is carried in the blob")

	// The generated nonce must have been recorded: presenting it back as a
	// caller-supplied IV is the same pair and must be refused.
	generated := blob[:GCMNonceSize]
	_, err = m.WrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(generated, 128)),
		wrappingKey, targetKey, nil)
	require.Error(t, err, "the IV the token generated is consumed, exactly like one the caller supplied")
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
}

// TestWrapKeyAuthenticatedDoesNotConsumeTheIVOfARefusedWrap pins where in the
// sequence the (key, IV) pair is claimed: after every policy check, not before.
//
// The guard is a one-way door -- a pair it has recorded can never be used again
// in this process -- so claiming it for a wrap the token was going to refuse
// anyway destroys an IV the caller never got to use. The caller's own retry,
// with the attribute corrected and the same IV it had prepared, would then be
// refused as a reuse of a wrap that never happened, and no attribute it could
// change would make that call succeed.
//
// The first wrap here is refused on CKA_EXTRACTABLE, which is a property of the
// target key and not of the mechanism, so the identical mechanism must still be
// good afterwards. A guard consulted before the attribute checks passes every
// other test in this file and fails only this one.
func TestWrapKeyAuthenticatedDoesNotConsumeTheIVOfARefusedWrap(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kek := []byte("refused-wrap-KEK")
	iv := uniqueTestIV(t)

	wrappingKey, _ := authWrapKeyPair(t, m, session, "refused", kek, []byte("unused-target---"))

	unextractable, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "refused-unextractable"),
		NewAttribute(CKA_VALUE, []byte("locked-in-target")),
		NewBoolAttribute(CKA_EXTRACTABLE, false),
	})
	require.Equal(t, CKR_OK, rv)

	extractable, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "refused-extractable"),
		NewAttribute(CKA_VALUE, []byte("free-to-go-targt")),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, extractable, nil)
		return err
	}) {
		return
	}

	_, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, unextractable, nil)
	require.Error(t, err)
	require.True(t, errorHasCode(err, CKR_KEY_UNEXTRACTABLE),
		"the premise of this test is a refusal on the key's attributes, not on the mechanism: got %v", err)

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, extractable, nil)
	require.NoError(t, err,
		"the refused wrap must not have claimed the IV: the caller's corrected retry has nothing else to change")

	plaintext, err := gcmOpenOracle(t, kek, iv, blob, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("free-to-go-targt"), plaintext)
}
