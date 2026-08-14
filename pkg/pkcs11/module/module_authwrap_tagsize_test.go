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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authWrapFixture is createAuthWrapTestObjects with the key VALUES returned as
// well, so a test can recompute the wrap with crypto/cipher rather than
// checking the module against its own inverse.
type authWrapFixture struct {
	module      *Module
	session     SessionHandle
	wrappingKey ObjectHandle
	targetKey   ObjectHandle

	// wrappingKeyValue is the AES KEK the module will seal under; it is what
	// the crypto/cipher oracle is keyed with.
	wrappingKeyValue []byte

	// targetKeyValue is the material being wrapped, i.e. the plaintext the
	// oracle must recover.
	targetKeyValue []byte
}

func newAuthWrapFixture(t *testing.T) *authWrapFixture {
	t.Helper()

	m := initializeTestModule(t)
	session := loginAsNormalUser(t, m)

	wrappingKeyValue := createAESKey(t)
	targetKeyValue := createAESKey(t)

	wrappingKeyHandle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "tagsize-wrapping-key"),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, wrappingKeyValue),
	})
	require.Equal(t, CKR_OK, rv)

	targetKeyHandle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "tagsize-target-key"),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, targetKeyValue),
	})
	require.Equal(t, CKR_OK, rv)

	return &authWrapFixture{
		module:           m,
		session:          session,
		wrappingKey:      wrappingKeyHandle,
		targetKey:        targetKeyHandle,
		wrappingKeyValue: wrappingKeyValue,
		targetKeyValue:   targetKeyValue,
	}
}

// openWithOracle decrypts nonce||ciphertext||tag with crypto/cipher at the
// given tag length, independently of the module's own unwrap path.
func openWithOracle(t *testing.T, key, blob, aad []byte, tagSize int) ([]byte, error) {
	t.Helper()

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
	require.NoError(t, err)

	require.Greater(t, len(blob), GCMNonceSize, "blob is too short to carry a nonce prefix")
	return gcm.Open(nil, blob[:GCMNonceSize], blob[GCMNonceSize:], aad)
}

// TestWrapKeyAuthenticated_HonoursTagBits proves C_WrapKeyAuthenticated seals
// at the tag length the caller named in CK_GCM_WRAP_PARAMS.ulTagBits (PKCS#11
// v3.2 §6.13.3) rather than at a hardcoded 128 bits.
//
// The oracle is crypto/cipher's own AES-GCM at the requested tag length, keyed
// with the KEK value the fixture chose: it must recover the exact target key
// material from the blob the module produced. The module's own unwrap is not
// consulted, because a wrap and an unwrap that are both wrong by the same
// 128-bit assumption agree with each other perfectly.
func TestWrapKeyAuthenticated_HonoursTagBits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tagBits uint32
		tagSize int
	}{
		{"96-bit tag", 96, 12},
		{"104-bit tag", 104, 13},
		{"112-bit tag", 112, 14},
		{"120-bit tag", 120, 15},
		{"128-bit tag", 128, 16},
		{"unspecified defaults to 128-bit", 0, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newAuthWrapFixture(t)
			mech := gcmMechanism(nil, nil, tc.tagBits)

			blob, err := fx.module.WrapKeyAuthenticated(
				fx.session, mech, fx.wrappingKey, fx.targetKey, nil)
			require.NoError(t, err)

			// nonce || ciphertext || tag, where ciphertext is the same length
			// as the plaintext. Any other length means the tag was not the one
			// requested.
			assert.Equal(t, GCMNonceSize+len(fx.targetKeyValue)+tc.tagSize, len(blob),
				"wrapped blob length does not match a %d-bit tag", tc.tagBits)

			recovered, err := openWithOracle(t, fx.wrappingKeyValue, blob, nil, tc.tagSize)
			require.NoError(t, err, "crypto/cipher could not authenticate the module's output at %d bits", tc.tagBits)
			assert.Equal(t, fx.targetKeyValue, recovered)
		})
	}
}

// TestWrapKeyAuthenticatedSize_HonoursTagBits proves the size query answers
// with the length the wrap actually produces. The two are compared directly:
// an application sizes its buffer from the query and then receives the wrap,
// so a query that overstates by four bytes at 96 bits is a defect even though
// nothing about the ciphertext is wrong.
func TestWrapKeyAuthenticatedSize_HonoursTagBits(t *testing.T) {
	for _, tagBits := range []uint32{96, 104, 112, 120, 128, 0} {
		fx := newAuthWrapFixture(t)
		mech := gcmMechanism(nil, nil, tagBits)

		size, err := fx.module.WrapKeyAuthenticatedSize(
			fx.session, mech, fx.wrappingKey, fx.targetKey)
		require.NoError(t, err)

		blob, err := fx.module.WrapKeyAuthenticated(
			fx.session, mech, fx.wrappingKey, fx.targetKey, nil)
		require.NoError(t, err)

		assert.Equal(t, uint64(len(blob)), size,
			"C_WrapKeyAuthenticated size query disagrees with the wrap at ulTagBits=%d", tagBits)
	}
}

// TestAuthWrapRoundTrip_HonoursTagBits proves wrap and unwrap agree on the tag
// length for every approved value, with and without a caller-supplied IV --
// the two output framings the file supports. A fix applied to the wrap alone
// would leave the unwrap rejecting its own peer's output as a forgery.
func TestAuthWrapRoundTrip_HonoursTagBits(t *testing.T) {
	callerIV := bytes.Repeat([]byte{0x2b}, GCMNonceSize)
	aad := []byte("authenticated-wrap-context")

	for _, tagBits := range []uint32{96, 104, 112, 120, 128, 0} {
		for _, ivCase := range []struct {
			name string
			iv   []byte
		}{
			{"token-generated IV", nil},
			{"caller-supplied IV", callerIV},
		} {
			fx := newAuthWrapFixture(t)
			mech := gcmMechanism(ivCase.iv, aad, tagBits)

			blob, err := fx.module.WrapKeyAuthenticated(
				fx.session, mech, fx.wrappingKey, fx.targetKey, nil)
			require.NoError(t, err, "wrap failed for ulTagBits=%d %s", tagBits, ivCase.name)

			handle, err := fx.module.UnwrapKeyAuthenticated(
				fx.session, mech, fx.wrappingKey, blob,
				[]Attribute{
					NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
					NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
				}, nil)
			require.NoError(t, err, "unwrap failed for ulTagBits=%d %s", tagBits, ivCase.name)

			// The recovered object must carry the original material, not merely
			// exist: an unwrap that authenticated the wrong number of bits and
			// then returned a truncated value would still produce a handle.
			attrs, rv := fx.module.GetAttributeValue(fx.session, handle,
				[]Attribute{{Type: CKA_VALUE}})
			require.Equal(t, CKR_OK, rv)
			require.Len(t, attrs, 1)
			assert.Equal(t, fx.targetKeyValue, attrs[0].Value,
				"unwrapped material differs for ulTagBits=%d %s", tagBits, ivCase.name)
		}
	}
}

// TestAuthWrap_ParamsAADAppliesWithoutCallerIV proves CK_GCM_PARAMS.pAAD is
// honoured on the unwrap side whether or not the caller also supplied an IV.
//
// The precedence used to be nested inside the caller-supplied-IV branch of the
// unwrap, while the wrap applied it unconditionally, so a caller that put its
// AAD in the mechanism and let the token generate the IV -- the framing this
// file documents as the default -- sealed under that AAD and verified under
// none. The oracle is crypto/cipher: it must authenticate the wrap under the
// AAD from the mechanism, and must NOT authenticate it under no AAD at all,
// which is what pins down which of the two inputs the tag actually covers.
func TestAuthWrap_ParamsAADAppliesWithoutCallerIV(t *testing.T) {
	fx := newAuthWrapFixture(t)
	aad := []byte("tenant=acme,purpose=key-transport")
	mech := gcmMechanism(nil, aad, 0)

	blob, err := fx.module.WrapKeyAuthenticated(
		fx.session, mech, fx.wrappingKey, fx.targetKey, nil)
	require.NoError(t, err)

	recovered, err := openWithOracle(t, fx.wrappingKeyValue, blob, aad, GCMTagSize)
	require.NoError(t, err, "the tag does not cover the AAD the mechanism carried")
	require.Equal(t, fx.targetKeyValue, recovered)

	if _, err := openWithOracle(t, fx.wrappingKeyValue, blob, nil, GCMTagSize); err == nil {
		t.Fatal("the wrap authenticated with no AAD, so CK_GCM_PARAMS.pAAD was never applied")
	}

	// The module's own unwrap must reach the same conclusion the oracle did.
	handle, err := fx.module.UnwrapKeyAuthenticated(
		fx.session, mech, fx.wrappingKey, blob,
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, nil)
	require.NoError(t, err)

	attrs, rv := fx.module.GetAttributeValue(fx.session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, attrs, 1)
	assert.Equal(t, fx.targetKeyValue, attrs[0].Value)
}

// TestUnwrapKeyAuthenticated_WrongAADFails is the bad-input counterpart: an
// unwrap whose mechanism carries different associated data from the wrap must
// fail authentication rather than return key material. Without this, the test
// above would pass on a module that ignored AAD entirely on both sides.
func TestUnwrapKeyAuthenticated_WrongAADFails(t *testing.T) {
	fx := newAuthWrapFixture(t)

	blob, err := fx.module.WrapKeyAuthenticated(
		fx.session, gcmMechanism(nil, []byte("tenant=acme"), 0),
		fx.wrappingKey, fx.targetKey, nil)
	require.NoError(t, err)

	_, err = fx.module.UnwrapKeyAuthenticated(
		fx.session, gcmMechanism(nil, []byte("tenant=evil"), 0), fx.wrappingKey, blob,
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, nil)
	require.Error(t, err, "an unwrap under different associated data returned key material")

	pkcsErr, ok := err.(*PKCS11Error)
	require.True(t, ok, "expected a PKCS11Error, got %T", err)
	assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
}

// TestUnwrapKeyAuthenticated_TagLengthComesFromRequest is the security case
// behind taking the tag length from CK_GCM_WRAP_PARAMS rather than from the
// bundle that arrived.
//
// A blob sealed at the full 128 bits is presented to an unwrap that asks for
// 96. SP 800-38D §5.2.2 authenticates by recomputing the tag at t bits and
// comparing, so the two disagree and the unwrap must fail. If the module
// inferred t from the blob instead, whoever produced the blob would be
// choosing how many bits of tag get checked.
func TestUnwrapKeyAuthenticated_TagLengthComesFromRequest(t *testing.T) {
	fx := newAuthWrapFixture(t)
	iv := bytes.Repeat([]byte{0x5c}, GCMNonceSize)

	blob, err := fx.module.WrapKeyAuthenticated(
		fx.session, gcmMechanism(iv, nil, 128), fx.wrappingKey, fx.targetKey, nil)
	require.NoError(t, err)

	_, err = fx.module.UnwrapKeyAuthenticated(
		fx.session, gcmMechanism(iv, nil, 96), fx.wrappingKey, blob,
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, nil)
	require.Error(t, err, "a 128-bit tag was accepted by an unwrap that asked for 96 bits")

	pkcsErr, ok := err.(*PKCS11Error)
	require.True(t, ok, "expected a PKCS11Error, got %T", err)
	assert.Equal(t, CKR_AEAD_DECRYPT_FAILED, pkcsErr.Code)
}

// TestUnwrapKeyAuthenticated_ShortTagBlobNotRejectedByLength proves the
// minimum-length check tracks the requested tag length, in BOTH output
// framings this file supports.
//
// The two framings have separate floors and so are separate defects. With a
// token-generated IV a one-byte payload sealed at 96 bits is 12+1+12 = 25
// bytes, under the 29-byte full-tag floor; with a caller-supplied IV the same
// payload is 1+12 = 13 bytes, under the 17-byte one. Either floor rejects a
// perfectly valid bundle with CKR_WRAPPED_KEY_INVALID before the tag is ever
// verified, so the unwrap can never succeed at a truncated length -- and
// covering only one of them leaves the other free to stay broken, which is
// exactly what a mutation of the caller-IV floor demonstrated.
func TestUnwrapKeyAuthenticated_ShortTagBlobNotRejectedByLength(t *testing.T) {
	callerIV := bytes.Repeat([]byte{0x71}, GCMNonceSize)

	for _, tc := range []struct {
		name string
		iv   []byte
		// floor is the minimum length the full-tag constant imposed on this
		// framing, which the blob must come in under for the test to bite.
		floor int
	}{
		{"token-generated IV", nil, GCMMinCiphertextSize + 1},
		{"caller-supplied IV", callerIV, GCMTagSize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newAuthWrapFixture(t)

			// A single-byte secret is the smallest payload that exercises the floor.
			oneByteKey, rv := fx.module.CreateObject(fx.session, []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
				NewStringAttribute(CKA_LABEL, "one-byte-secret"),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				NewAttribute(CKA_VALUE, []byte{0x9f}),
			})
			require.Equal(t, CKR_OK, rv)

			mech := gcmMechanism(tc.iv, nil, 96)
			blob, err := fx.module.WrapKeyAuthenticated(fx.session, mech, fx.wrappingKey, oneByteKey, nil)
			require.NoError(t, err)
			require.Less(t, len(blob), tc.floor,
				"this case is vacuous unless the blob is shorter than the full-tag floor")

			handle, err := fx.module.UnwrapKeyAuthenticated(
				fx.session, mech, fx.wrappingKey, blob,
				[]Attribute{
					NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
					NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
				}, nil)
			require.NoError(t, err)

			attrs, rv := fx.module.GetAttributeValue(fx.session, handle, []Attribute{{Type: CKA_VALUE}})
			require.Equal(t, CKR_OK, rv)
			require.Len(t, attrs, 1)
			assert.Equal(t, []byte{0x9f}, attrs[0].Value)
		})
	}
}

// TestAuthWrap_RejectsUnapprovedTagBits proves an unapproved
// CK_GCM_WRAP_PARAMS.ulTagBits is refused with CKR_MECHANISM_PARAM_INVALID by
// all three entry points, rather than silently rounded to a length the caller
// did not ask for. NIST SP 800-38D §5.2.1.2 approves t of 96, 104, 112, 120
// and 128 only.
func TestAuthWrap_RejectsUnapprovedTagBits(t *testing.T) {
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
	}

	for _, tagBits := range []uint32{1, 8, 64, 88, 100, 127, 129, 256} {
		fx := newAuthWrapFixture(t)
		mech := gcmMechanism(nil, nil, tagBits)

		_, err := fx.module.WrapKeyAuthenticated(fx.session, mech, fx.wrappingKey, fx.targetKey, nil)
		requireMechanismParamInvalid(t, err)

		_, err = fx.module.WrapKeyAuthenticatedSize(fx.session, mech, fx.wrappingKey, fx.targetKey)
		requireMechanismParamInvalid(t, err)

		_, err = fx.module.UnwrapKeyAuthenticated(fx.session, mech, fx.wrappingKey,
			bytes.Repeat([]byte{0x01}, 64), template, nil)
		requireMechanismParamInvalid(t, err)
	}
}
