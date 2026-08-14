// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package module

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mechanism-parameter accessors and the validators that guard them.
//
// Each accessor answers one question: "is the parameter attached to this
// mechanism the type this operation needs?" The comma-ok result is what every
// caller branches on, so both outcomes have to be right. An accessor that
// returned ok for the wrong parameter type would hand a caller a struct
// reinterpreted from unrelated memory; one that returned !ok for the right
// type would silently drop parameters the application supplied, which is the
// failure mode that hides a whole feature.

// TestMechanism_GetEdDSAParams_ReturnsAttachedParameters proves the accessor
// yields the CK_EDDSA_PARAMS an application attached to a CKM_EDDSA mechanism.
//
// PKCS#11 v3.2 §6.24 makes the parameter optional: its presence selects the
// context or pre-hash variant of RFC 8032, its absence selects pure
// Ed25519/Ed448. Dropping the parameter therefore does not fail — it produces
// a valid signature under the wrong variant, which verifies nowhere. That is
// the defect this test catches.
func TestMechanism_GetEdDSAParams_ReturnsAttachedParameters(t *testing.T) {
	context := []byte("rfc8032 context")
	mech := &Mechanism{
		Type:           CKM_EDDSA,
		TypedParameter: NewEdDSAParams(true, context),
	}

	params, ok := mech.GetEdDSAParams()
	require.True(t, ok, "CK_EDDSA_PARAMS attached to the mechanism must be readable")
	require.NotNil(t, params)
	assert.True(t, params.PreHash, "NewEdDSAParams must record the pre-hash selection")
	assert.Equal(t, context, params.Context, "NewEdDSAParams must record the context string")
}

// TestMechanism_GetEdDSAParams_RejectsAbsentAndMismatchedParameters proves the
// accessor reports !ok rather than misreading a parameter of another type.
//
// A mechanism's TypedParameter field holds whatever the caller attached. If
// the accessor answered ok for, say, an *AESGCMParams, the signing path would
// read an RFC 8032 context out of a GCM nonce.
func TestMechanism_GetEdDSAParams_RejectsAbsentAndMismatchedParameters(t *testing.T) {
	t.Run("no parameter attached", func(t *testing.T) {
		params, ok := (&Mechanism{Type: CKM_EDDSA}).GetEdDSAParams()
		assert.False(t, ok, "pure Ed25519 attaches no parameter, and that must read as absent")
		assert.Nil(t, params)
	})

	t.Run("parameter of another type", func(t *testing.T) {
		mech := &Mechanism{
			Type:           CKM_EDDSA,
			TypedParameter: &AESGCMParams{IV: make([]byte, 12)},
		}

		params, ok := mech.GetEdDSAParams()
		assert.False(t, ok, "a GCM parameter must not be read as CK_EDDSA_PARAMS")
		assert.Nil(t, params)
	})
}

// TestValidateEdDSAParams_AcceptsContextWithinBound proves the structural bound
// PKCS#11 v3.2 §6.24 places on CK_EDDSA_PARAMS.ulContextDataLen is 0..255
// inclusive, and that an absent parameter is valid.
//
// The boundary is the interesting part: rejecting a 255-byte context would
// refuse a signature RFC 8032 permits, and a validator written with the wrong
// comparison is invisible until an application uses the longest legal context.
func TestValidateEdDSAParams_AcceptsContextWithinBound(t *testing.T) {
	cases := []struct {
		name   string
		params *EdDSAParams
	}{
		{"absent parameter means pure Ed25519", nil},
		{"empty context", NewEdDSAParams(false, nil)},
		{"longest legal context", NewEdDSAParams(false, make([]byte, 255))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NoError(t, validateEdDSAParams(tc.params))
		})
	}
}

// TestValidateEdDSAParams_RejectsOversizedContext asserts
// CKR_MECHANISM_PARAM_INVALID for a context one byte past the §6.24 bound.
//
// CK_EDDSA_PARAMS.ulContextDataLen is one octet on the wire in RFC 8032's
// dom2/dom4 construction, so a 256-byte context cannot be encoded at all.
// Accepting it would produce a signature whose context silently truncated,
// verifying against a different message than the caller signed.
func TestValidateEdDSAParams_RejectsOversizedContext(t *testing.T) {
	err := validateEdDSAParams(NewEdDSAParams(false, make([]byte, 256)))
	require.Error(t, err)

	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, FromError(err),
		"a context longer than 255 bytes cannot be encoded (v3.2 §6.24)")
}

// TestCryptoManager_SignInit_RejectsOversizedEdDSAContext proves the validator
// is actually wired into C_SignInit rather than merely present.
//
// A validator no call site reaches is indistinguishable from no validator at
// all. This drives the same oversized context through the entry point an
// application uses and requires the operation to be refused before any signing
// state is created.
func TestCryptoManager_SignInit_RejectsOversizedEdDSAContext(t *testing.T) {
	cm := NewCryptoManager(newMockClient(), &CryptoManagerConfig{DefaultBackend: "software"})

	mech := &Mechanism{
		Type:           CKM_EDDSA,
		TypedParameter: NewEdDSAParams(false, make([]byte, 256)),
	}

	op, err := cm.SignInit(mech, ObjectHandle(1), "key-id", "software")
	require.Error(t, err, "C_SignInit must refuse a CK_EDDSA_PARAMS that violates v3.2 §6.24")
	assert.Nil(t, op, "a refused C_SignInit must not create a signing operation")
	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, FromError(err))
}

// TestMechanism_GetAESGCMMessageParams_DistinguishesMessageFromSessionParams
// proves the message-based accessor accepts only CK_GCM_MESSAGE_PARAMS.
//
// PKCS#11 v3.2 §6.13 defines two distinct GCM parameter structures: the
// session-based CK_GCM_PARAMS used by C_EncryptInit, and the message-based
// CK_GCM_MESSAGE_PARAMS used by C_EncryptMessage, which additionally carries
// the IV-generation policy. They are not interchangeable, and an accessor that
// conflated them would let the message path run with a caller-fixed IV where
// the token was supposed to generate one — nonce reuse, which forfeits GCM's
// authentication guarantee entirely.
func TestMechanism_GetAESGCMMessageParams_DistinguishesMessageFromSessionParams(t *testing.T) {
	t.Run("message parameters are returned", func(t *testing.T) {
		want := &AESGCMMessageParams{IV: make([]byte, 12), TagBits: 128}
		mech := &Mechanism{Type: CKM_AES_GCM, TypedParameter: want}

		got, ok := mech.GetAESGCMMessageParams()
		require.True(t, ok)
		assert.Same(t, want, got)
	})

	t.Run("session parameters are not message parameters", func(t *testing.T) {
		mech := &Mechanism{Type: CKM_AES_GCM, TypedParameter: &AESGCMParams{IV: make([]byte, 12)}}

		got, ok := mech.GetAESGCMMessageParams()
		assert.False(t, ok, "CK_GCM_PARAMS must not be read as CK_GCM_MESSAGE_PARAMS (v3.2 §6.13)")
		assert.Nil(t, got)
	})

	t.Run("no parameter attached", func(t *testing.T) {
		got, ok := (&Mechanism{Type: CKM_AES_GCM}).GetAESGCMMessageParams()
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}

// TestResolveMLDSASecurityLevel_FromMechanismAndKeySize proves both routes to
// an ML-DSA parameter set: the level named by a vendor mechanism, and the level
// inferred from a public key's length under the standard CKM_ML_DSA.
//
// FIPS 204 fixes the three public key sizes at 1312, 1952 and 2592 bytes and
// they never collide, so the inference is sound. Getting it wrong picks a
// different parameter set than the key was generated under, and every
// signature made with it fails verification.
func TestResolveMLDSASecurityLevel_FromMechanismAndKeySize(t *testing.T) {
	cases := []struct {
		name      string
		mech      MechanismType
		keyLength int
		want      int
	}{
		{"vendor mechanism names the level", CKM_VENDOR_ML_DSA_44, 0, 44},
		{"standard mechanism with ML-DSA-44 public key", CKM_ML_DSA, MLDSA44PublicKeySize, 44},
		{"standard mechanism with ML-DSA-65 public key", CKM_ML_DSA, MLDSA65PublicKeySize, 65},
		{"standard mechanism with ML-DSA-87 public key", CKM_ML_DSA, MLDSA87PublicKeySize, 87},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveMLDSASecurityLevel(tc.mech, tc.keyLength))
		})
	}
}

// TestResolveMLDSASecurityLevel_UnresolvableReturnsZero proves the resolver
// reports failure instead of guessing.
//
// This module stores every ML-DSA private key as a fixed 32-byte seed
// regardless of parameter set, so a seed length carries no level information.
// Returning a plausible default there would silently sign under the wrong
// parameter set; returning 0 forces the caller to consult the key object's
// CKA_PARAMETER_SET, which is the only authority in that case.
func TestResolveMLDSASecurityLevel_UnresolvableReturnsZero(t *testing.T) {
	cases := []struct {
		name      string
		mech      MechanismType
		keyLength int
	}{
		{"private key seed carries no level", CKM_ML_DSA, 32},
		{"length matches no ML-DSA public key size", CKM_ML_DSA, 999},
		{"mechanism is not ML-DSA at all", CKM_SHA256, MLDSA44PublicKeySize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, ResolveMLDSASecurityLevel(tc.mech, tc.keyLength),
				"an unresolvable level must be reported as 0, never guessed")
		})
	}
}

// TestResolveMLKEMSecurityLevel_FromMechanismAndKeySize is the ML-KEM analog:
// FIPS 203 fixes the public key sizes at 800, 1184 and 1568 bytes.
//
// A mis-resolved level produces a ciphertext the peer's decapsulation cannot
// consume, so the failure surfaces as an unexplained key-agreement mismatch
// rather than an error at the point of the mistake.
func TestResolveMLKEMSecurityLevel_FromMechanismAndKeySize(t *testing.T) {
	cases := []struct {
		name      string
		mech      MechanismType
		keyLength int
		want      int
	}{
		{"vendor mechanism names the level", CKM_VENDOR_ML_KEM_768_ENCAPSULATE, 0, 768},
		{"standard mechanism with ML-KEM-512 public key", CKM_ML_KEM, MLKEM512PublicKeySize, 512},
		{"standard mechanism with ML-KEM-768 public key", CKM_ML_KEM, MLKEM768PublicKeySize, 768},
		{"standard mechanism with ML-KEM-1024 public key", CKM_ML_KEM, MLKEM1024PublicKeySize, 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveMLKEMSecurityLevel(tc.mech, tc.keyLength))
		})
	}
}

// TestResolveMLKEMSecurityLevel_UnresolvableReturnsZero mirrors the ML-DSA
// case: this module stores every ML-KEM private key as a fixed 64-byte seed,
// which identifies no parameter set.
func TestResolveMLKEMSecurityLevel_UnresolvableReturnsZero(t *testing.T) {
	cases := []struct {
		name      string
		mech      MechanismType
		keyLength int
	}{
		{"private key seed carries no level", CKM_ML_KEM, 64},
		{"length matches no ML-KEM public key size", CKM_ML_KEM, 12345},
		{"mechanism is not ML-KEM at all", CKM_SHA256, MLKEM768PublicKeySize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, ResolveMLKEMSecurityLevel(tc.mech, tc.keyLength))
		})
	}
}

// TestGetStandardMechanism_MapsVendorToV32 proves the vendor-to-standard
// translation used to present one identity for a mechanism that predates its
// PKCS#11 v3.2 standard number.
//
// The pass-through for unmapped input is as important as the mapping: a
// translation that rewrote every mechanism it did not recognise would erase
// CKM_SHA256 on its way through.
func TestGetStandardMechanism_MapsVendorToV32(t *testing.T) {
	assert.Equal(t, CKM_ML_DSA, GetStandardMechanism(CKM_VENDOR_ML_DSA_44))
	assert.Equal(t, CKM_ML_KEM, GetStandardMechanism(CKM_VENDOR_ML_KEM_768_ENCAPSULATE))
}

// TestGetStandardMechanism_LeavesUnmappedMechanismsAlone asserts the identity
// behaviour documented for mechanisms with no vendor predecessor.
func TestGetStandardMechanism_LeavesUnmappedMechanismsAlone(t *testing.T) {
	assert.Equal(t, CKM_SHA256, GetStandardMechanism(CKM_SHA256))
	assert.Equal(t, MechanismType(0xDEADBEEF), GetStandardMechanism(MechanismType(0xDEADBEEF)),
		"an unrecognised mechanism must pass through unchanged, not collapse to a default")
}

// TestGetStandardKeyType_MapsVendorToV32 proves the key-type half of the same
// translation. A key object created under the vendor key type must report the
// v3.2 CKA_KEY_TYPE, or an application matching on the standard value finds
// nothing.
func TestGetStandardKeyType_MapsVendorToV32(t *testing.T) {
	assert.Equal(t, CKK_ML_DSA, GetStandardKeyType(CKK_VENDOR_ML_DSA))
	assert.Equal(t, CKK_ML_KEM, GetStandardKeyType(CKK_VENDOR_ML_KEM))
}

// TestGetStandardKeyType_LeavesUnmappedKeyTypesAlone asserts the identity
// behaviour for key types that were never vendor-defined.
func TestGetStandardKeyType_LeavesUnmappedKeyTypesAlone(t *testing.T) {
	assert.Equal(t, CKK_RSA, GetStandardKeyType(CKK_RSA))
	assert.Equal(t, KeyType(0xDEADBEEF), GetStandardKeyType(KeyType(0xDEADBEEF)))
}

// TestResolveMLKEMLevel_PrefersParameterSetAttribute proves CKA_PARAMETER_SET
// on the key object outranks any inference from a length.
//
// PKCS#11 v3.2 makes CKA_PARAMETER_SET the authoritative statement of an
// ML-KEM key's parameter set. Since this module stores private keys as a
// fixed-size seed, the attribute is the only thing that can identify the level
// for a private key at all; an implementation that consulted the length first
// would resolve every private key to the same wrong level.
func TestResolveMLKEMLevel_PrefersParameterSetAttribute(t *testing.T) {
	cases := []struct {
		name     string
		paramSet ParameterSetType
		want     int
	}{
		// CKP_ML_KEM_512 resolved to the baseline while the module had no
		// ML-KEM-512 generator; pkg/quantum/mlkem512 supplies one, so naming the
		// parameter set now selects it.
		{"ML-KEM-512", CKP_ML_KEM_512, 512},
		{"ML-KEM-768", CKP_ML_KEM_768, 768},
		{"ML-KEM-1024", CKP_ML_KEM_1024, 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := newParameterSetObject(tc.paramSet)

			// The fallback length names a different level, so a resolver that
			// ignored the attribute would return 768 for every case.
			assert.Equal(t, tc.want, resolveMLKEMLevel(obj, MLKEM768PublicKeySize))
		})
	}
}

// TestResolveMLKEMLevel_FallsBackToLengthThenBaseline proves the two remaining
// routes when the key object carries no CKA_PARAMETER_SET: inference from a
// real FIPS 203 size, and ML-KEM-768 as the mandatory baseline when the length
// matches nothing.
//
// Choosing the baseline rather than failing is deliberate — the crypto backend
// then rejects malformed key material on its own merits, instead of this
// function reporting a level error that masks the real one.
func TestResolveMLKEMLevel_FallsBackToLengthThenBaseline(t *testing.T) {
	empty := &Object{Attributes: map[AttributeType][]byte{}}

	cases := []struct {
		name        string
		fallbackLen int
		want        int
	}{
		{"ML-KEM-512 public key length", MLKEM512PublicKeySize, 512},
		{"ML-KEM-512 ciphertext length", MLKEM512CiphertextSize, 512},
		{"ML-KEM-768 public key length", MLKEM768PublicKeySize, 768},
		{"ML-KEM-1024 public key length", MLKEM1024PublicKeySize, 1024},
		{"unrecognised length falls back to the baseline", 7, 768},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveMLKEMLevel(empty, tc.fallbackLen))
		})
	}
}

// TestResolveMLKEMLevel_IgnoresTruncatedParameterSet proves a CKA_PARAMETER_SET
// too short to hold a CK_ULONG is not read.
//
// The attribute value is application-supplied through C_CreateObject, so a
// three-byte value is reachable input. Reading it would run off the end of the
// slice; ignoring it and falling back to the length is the safe answer.
func TestResolveMLKEMLevel_IgnoresTruncatedParameterSet(t *testing.T) {
	obj := &Object{Attributes: map[AttributeType][]byte{
		CKA_PARAMETER_SET: {0x01, 0x02, 0x03},
	}}

	// The length fallback is what answers once the truncated attribute is
	// ignored, so an 800-byte public key resolves to ML-KEM-512 -- the point
	// being that the three-byte attribute contributed nothing. Passing a length
	// no level claims would resolve to the 768 baseline instead, which would not
	// distinguish "ignored the attribute" from "decoded it as something".
	assert.Equal(t, 512, resolveMLKEMLevel(obj, MLKEM512PublicKeySize),
		"a truncated CKA_PARAMETER_SET must be ignored rather than partially decoded, "+
			"leaving the material length to resolve the level")

	assert.Equal(t, 768, resolveMLKEMLevel(obj, 7),
		"with neither a readable parameter set nor a recognisable length, the baseline stands")
}

// TestKemCiphertextSize_KnownMechanisms proves the ciphertext-length query used
// by the two-call convention returns the FIPS 203 size without performing an
// encapsulation.
//
// PKCS#11 v3.2 §5.2 lets an application ask for the output length first. If
// that query ran a real encapsulation it would consume entropy and produce a
// shared secret the caller never collects, so answering from a table is both
// correct and required.
func TestKemCiphertextSize_KnownMechanisms(t *testing.T) {
	cases := []struct {
		name string
		mech MechanismType
		want uint64
	}{
		{"vendor ML-KEM-768 encapsulate", CKM_VENDOR_ML_KEM_768_ENCAPSULATE, MLKEM768CiphertextSize},
		{"standard CKM_ML_KEM defaults to the baseline", CKM_ML_KEM, MLKEM768CiphertextSize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size, err := kemCiphertextSize(&Mechanism{Type: tc.mech})
			require.NoError(t, err)
			assert.Equal(t, tc.want, size)
		})
	}
}

// TestKemCiphertextSize_UnknownMechanism asserts CKR_MECHANISM_INVALID for a
// mechanism that is not a KEM.
//
// The length query must fail exactly where the encapsulation itself would.
// Returning a size for a non-KEM mechanism would have the application allocate
// a buffer for an operation that then refuses to run.
func TestKemCiphertextSize_UnknownMechanism(t *testing.T) {
	size, err := kemCiphertextSize(&Mechanism{Type: CKM_SHA256})
	require.Error(t, err)
	assert.Zero(t, size)
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))
}

// newParameterSetObject builds a key object carrying CKA_PARAMETER_SET, which
// PKCS#11 encodes as a little-endian CK_ULONG.
func newParameterSetObject(paramSet ParameterSetType) *Object {
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, uint32(paramSet))

	return &Object{Attributes: map[AttributeType][]byte{CKA_PARAMETER_SET: raw}}
}
