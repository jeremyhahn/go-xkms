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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover the parameter structure PKCS#11 v3.2 §5.18.6
// actually defines for C_WrapKeyAuthenticated and C_UnwrapKeyAuthenticated:
// CK_GCM_MESSAGE_PARAMS, modelled here by AESGCMMessageParams. The older
// CK_GCM_PARAMS form is covered by TestAuthWrapWithGCMParams; both are
// accepted, and they frame their output differently because only one of them
// can hand a token-generated IV back to the caller.

// aesKeyTemplate is the template for an AES secret key holding value.
func aesKeyTemplate(label string, value []byte, extra ...Attribute) []Attribute {
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE, value),
	}
	return append(template, extra...)
}

// messageParamsFixture returns a module, an authenticated read-write session,
// a wrapping key and an extractable target key, together with the raw material
// of both so a test can check the module's output against an oracle that never
// goes through the module.
func messageParamsFixture(t *testing.T, label string) (m *Module, session SessionHandle, wrappingKey, targetKey ObjectHandle, kek, target []byte) {
	t.Helper()

	m = initializeTestModule(t)
	session = loginAsNormalUser(t, m)

	kek = createAESKey(t)
	target = createAESKey(t)

	var rv CK_RV
	wrappingKey, rv = m.CreateObject(session, aesKeyTemplate(label+"-kek", kek,
		NewBoolAttribute(CKA_WRAP, true), NewBoolAttribute(CKA_UNWRAP, true)))
	require.Equal(t, CKR_OK, rv)

	targetKey, rv = m.CreateObject(session, aesKeyTemplate(label+"-target", target,
		NewBoolAttribute(CKA_EXTRACTABLE, true)))
	require.Equal(t, CKR_OK, rv)

	return m, session, wrappingKey, targetKey, kek, target
}

// TestAuthWrapWithMessageParamsReturnsTheGeneratedIV proves the framing this
// module produces for the structure §5.18.6 defines.
//
// The blob is ciphertext||tag with no nonce prefix, and the IV the token
// generated comes back through the parameter -- §6.13.5 makes pIv an output
// whenever ivGenerator is not CKG_NO_GENERATE. That is what makes a
// token-generated IV usable, and a token-generated IV is the construction that
// cannot be replayed by a caller.
func TestAuthWrapWithMessageParamsReturnsTheGeneratedIV(t *testing.T) {
	m, session, wrappingKey, targetKey, kek, target := messageParamsFixture(t, "msg-generate")
	defer m.Finalize()

	// A caller-owned 12-byte buffer, which is what a C application's pIv is.
	params := &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     128,
	}
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, params)
	aad := []byte("message-params-aad")

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, aad)
	require.NoError(t, err)

	assert.Len(t, blob, len(target)+GCMTagSize,
		"CK_GCM_MESSAGE_PARAMS returns its IV through pIv, so the blob carries no nonce prefix")
	require.Len(t, params.IV, GCMNonceSize, "the token must write the IV it generated back to the caller")
	assert.NotEqual(t, make([]byte, GCMNonceSize), params.IV, "the generated IV must not be all zeroes")

	// The oracle is the standard library, driven with the IV the module handed
	// back. If the write-back were wrong, this could not open the blob.
	plaintext, err := gcmOpenOracle(t, kek, params.IV, blob, aad)
	require.NoError(t, err, "the IV written back must be the IV the wrap sealed under")
	assert.Equal(t, target, plaintext)
}

// TestAuthWrapMessageParamsRoundTrip closes the loop through the module: the
// IV the wrap generated, presented back with CKG_NO_GENERATE, must unwrap the
// blob to the original key material.
func TestAuthWrapMessageParamsRoundTrip(t *testing.T) {
	m, session, wrappingKey, targetKey, _, target := messageParamsFixture(t, "msg-roundtrip")
	defer m.Finalize()

	wrapParams := &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     128,
	}
	aad := []byte("round-trip-aad")

	blob, err := m.WrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, wrapParams), wrappingKey, targetKey, aad)
	require.NoError(t, err)

	unwrapParams := &AESGCMMessageParams{
		IV:          wrapParams.IV,
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     128,
	}
	handle, err := m.UnwrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, unwrapParams), wrappingKey, blob,
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, aad)
	require.NoError(t, err)
	require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

	got, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, got, 1)
	assert.Equal(t, target, got[0].Value, "the unwrapped object must hold the original key material")
}

// TestAuthWrapMessageParamsSizeQueryMatchesTheWrap proves the size query and
// the wrap agree on the framing. C_WrapKeyAuthenticated's C ABI sizes the
// output buffer with the query before it wraps, so a query that still assumed
// a 12-byte nonce prefix would over-report by exactly 12 bytes on this path.
func TestAuthWrapMessageParamsSizeQueryMatchesTheWrap(t *testing.T) {
	m, session, wrappingKey, targetKey, _, target := messageParamsFixture(t, "msg-size")
	defer m.Finalize()

	params := &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     128,
	}
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, params)

	size, err := m.WrapKeyAuthenticatedSize(session, mech, wrappingKey, targetKey)
	require.NoError(t, err)
	assert.Equal(t, uint64(len(target)+GCMTagSize), size)

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err)
	assert.Len(t, blob, int(size), "the query must predict exactly what the wrap produces")
}

// TestAuthWrapMessageParamsHonoursTruncatedTagBits proves ulTagBits is read
// from CK_GCM_MESSAGE_PARAMS as well as from CK_GCM_PARAMS. A tag length read
// as zero would silently produce a 128-bit tag for a caller who asked for 96.
func TestAuthWrapMessageParamsHonoursTruncatedTagBits(t *testing.T) {
	m, session, wrappingKey, targetKey, _, target := messageParamsFixture(t, "msg-tagbits")
	defer m.Finalize()

	params := &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     96,
	}
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, params)
	if authWrapRefusedUnderFIPS(t, 12, false, func() error {
		_, err := m.WrapKeyAuthenticatedSize(session, mech, wrappingKey, targetKey)
		return err
	}) {
		return
	}

	size, err := m.WrapKeyAuthenticatedSize(session, mech, wrappingKey, targetKey)
	require.NoError(t, err)
	assert.Equal(t, uint64(len(target)+12), size, "a 96-bit tag is 12 bytes")

	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err)
	assert.Len(t, blob, len(target)+12)
}

// TestAuthWrapMessageParamsGuardsAgainstIVReuse proves the nonce guard covers
// the spec-conforming parameter structure too, not only the CK_GCM_PARAMS form
// the Go callers use. A guard wired into one of the two would leave the path
// every C application takes unprotected.
func TestAuthWrapMessageParamsGuardsAgainstIVReuse(t *testing.T) {
	m, session, wrappingKey, targetKey, _, _ := messageParamsFixture(t, "msg-reuse")
	defer m.Finalize()

	iv := uniqueTestIV(t)
	params := &AESGCMMessageParams{
		IV:          iv,
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     128,
	}
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, params)
	if authWrapRefusedUnderFIPS(t, GCMTagSize, true, func() error {
		_, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
		return err
	}) {
		return
	}

	_, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err)

	_, err = m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.Error(t, err, "the same (key, IV) pair through CK_GCM_MESSAGE_PARAMS is the same catastrophe")
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
}

// TestAuthWrapMessageParamsRejectsUnusableParameters covers the parameter
// combinations that would otherwise produce a wrapped key nobody can unwrap,
// or report a request as honoured that this token does not implement.
func TestAuthWrapMessageParamsRejectsUnusableParameters(t *testing.T) {
	cases := []struct {
		name   string
		params *AESGCMMessageParams
		reason string
	}{
		{
			name: "generated IV with no buffer to return it in",
			params: &AESGCMMessageParams{
				IVGenerator: CKG_GENERATE_RANDOM,
				TagBits:     128,
			},
			reason: "the caller could never learn the IV, so the blob could never be unwrapped",
		},
		{
			name: "generated IV with a buffer too short to hold it",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize-1),
				IVGenerator: CKG_GENERATE_RANDOM,
				TagBits:     128,
			},
			reason: "an 11-byte pIv cannot carry the 12-byte IV back",
		},
		{
			name: "caller IV of the wrong length",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize-1),
				IVGenerator: CKG_NO_GENERATE,
				TagBits:     128,
			},
			reason: "AES-GCM here takes a 12-byte IV",
		},
		{
			name: "caller IV declared but absent",
			params: &AESGCMMessageParams{
				IVGenerator: CKG_NO_GENERATE,
				TagBits:     128,
			},
			reason: "CKG_NO_GENERATE means the caller supplies the IV, and none was supplied",
		},
		{
			name: "counter IV construction",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVGenerator: CKG_GENERATE_COUNTER,
				TagBits:     128,
			},
			reason: "this token keeps no durable counter, and a counter that restarts repeats",
		},
		{
			name: "caller-fixed IV bits",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVFixedBits: 32,
				IVGenerator: CKG_GENERATE,
				TagBits:     128,
			},
			reason: "the token cannot preserve fixed bits, and must not pretend it did",
		},
		{
			name: "tag length outside the approved set",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVGenerator: CKG_GENERATE_RANDOM,
				TagBits:     64,
			},
			reason: "NIST SP 800-38D section 5.2.1.2 approves 96 to 128 bits",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, session, wrappingKey, targetKey, _, _ := messageParamsFixture(t, "msg-bad")
			defer m.Finalize()

			blob, err := m.WrapKeyAuthenticated(session,
				NewMechanismWithTypedParams(CKM_AES_GCM, tc.params), wrappingKey, targetKey, nil)
			require.Error(t, err, tc.reason)
			assert.Nil(t, blob)
			assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
		})
	}
}

// TestAuthUnwrapMessageParamsRejectsUnusableParameters is the unwrap half.
// Decryption never generates an IV (v3.2 §6.13.5): the caller must present the
// exact nonce the wrap used, and a parameter that says otherwise describes an
// operation that cannot be performed.
func TestAuthUnwrapMessageParamsRejectsUnusableParameters(t *testing.T) {
	m, session, wrappingKey, targetKey, _, _ := messageParamsFixture(t, "msg-unwrap-bad")
	defer m.Finalize()

	wrapParams := &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     128,
	}
	blob, err := m.WrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, wrapParams), wrappingKey, targetKey, nil)
	require.NoError(t, err)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
	}

	cases := []struct {
		name   string
		params *AESGCMMessageParams
		reason string
	}{
		{
			name: "token asked to generate the IV",
			params: &AESGCMMessageParams{
				IV:          wrapParams.IV,
				IVGenerator: CKG_GENERATE_RANDOM,
				TagBits:     128,
			},
			reason: "an unwrap under an IV the token invents cannot authenticate anything",
		},
		{
			name: "no IV at all",
			params: &AESGCMMessageParams{
				IVGenerator: CKG_NO_GENERATE,
				TagBits:     128,
			},
			reason: "the blob carries no nonce prefix on this path, so the IV has to come from pIv",
		},
		{
			name: "IV of the wrong length",
			params: &AESGCMMessageParams{
				IV:          wrapParams.IV[:GCMNonceSize-1],
				IVGenerator: CKG_NO_GENERATE,
				TagBits:     128,
			},
			reason: "AES-GCM here takes a 12-byte IV",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := m.UnwrapKeyAuthenticated(session,
				NewMechanismWithTypedParams(CKM_AES_GCM, tc.params), wrappingKey, blob, template, nil)
			require.Error(t, err, tc.reason)
			assert.Equal(t, ObjectHandle(InvalidHandle), handle)
			assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
		})
	}

	// The same blob with correct parameters must still unwrap, so the cases
	// above are refusing the parameters rather than the blob.
	handle, err := m.UnwrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, &AESGCMMessageParams{
			IV:          wrapParams.IV,
			IVGenerator: CKG_NO_GENERATE,
			TagBits:     128,
		}), wrappingKey, blob, template, nil)
	require.NoError(t, err)
	assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
}

// TestAuthUnwrapMessageParamsRejectsATruncatedBlob proves the length gate on
// this path is the tag length the caller asked for. A blob shorter than a tag
// plus one byte of ciphertext cannot be a wrap of anything, and must be
// refused as a malformed blob rather than reaching cipher.AEAD.
func TestAuthUnwrapMessageParamsRejectsATruncatedBlob(t *testing.T) {
	m, session, wrappingKey, _, _, _ := messageParamsFixture(t, "msg-truncated")
	defer m.Finalize()

	params := &AESGCMMessageParams{
		IV:          uniqueTestIV(t),
		IVGenerator: CKG_NO_GENERATE,
		TagBits:     128,
	}

	handle, err := m.UnwrapKeyAuthenticated(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, params), wrappingKey, make([]byte, GCMTagSize),
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		}, nil)
	require.Error(t, err)
	assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	assert.True(t, errorHasCode(err, CKR_WRAPPED_KEY_INVALID), "got %v", err)
}
