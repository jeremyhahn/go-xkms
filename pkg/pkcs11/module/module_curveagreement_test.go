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
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CKA_EC_PARAMS encodings these tests name. The Edwards and Montgomery
// OIDs are RFC 8410's; the last is an OID the module does not carry at all.
var (
	curveParamsP256         = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	curveParamsX25519       = []byte{0x06, 0x03, 0x2b, 0x65, 0x6e}
	curveParamsEd25519      = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
	curveParamsUnrecognised = []byte{0x06, 0x03, 0x2a, 0x03, 0x04}
)

// TestTemplateCurveNameSeparatesAbsentFromUnusable is the defect #161 reports.
//
// templateCurveName reported "absent" and "present but unrecognised" with the
// same string, so a caller that gated on the name alone refused the omitted
// attribute too -- a case PKCS#11 v3.2 Table 13 footnote 6 requires be served.
// The presence flag is what makes the two distinguishable, so the assertion
// that matters is not any single row: it is that the two rows returning name
// "" differ in `present`.
func TestTemplateCurveNameSeparatesAbsentFromUnusable(t *testing.T) {
	cases := []struct {
		name        string
		ecParams    []byte
		wantName    string
		wantPresent bool
		wantRV      CK_RV
	}{
		{"absent", nil, "", false, CKR_OK},
		{"recognised", curveParamsP256, "P-256", true, CKR_OK},
		{"recognised but not an ECDSA curve", curveParamsX25519, "X25519", true, CKR_OK},
		{"unrecognised", curveParamsUnrecognised, "", true, CKR_CURVE_NOT_SUPPORTED},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, present, rv := templateCurveName(ecPrivateKeyUnwrapTemplate(tc.ecParams))
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantPresent, present)
			assert.Equal(t, tc.wantRV, rv)
		})
	}

	// The control: absent and unrecognised agree on the name and disagree on
	// presence. If these ever return the same pair again, the signature has
	// stopped carrying the distinction and the gate below is unsound.
	absentName, absentPresent, _ := templateCurveName(ecPrivateKeyUnwrapTemplate(nil))
	badName, badPresent, _ := templateCurveName(ecPrivateKeyUnwrapTemplate(curveParamsUnrecognised))
	require.Equal(t, absentName, badName, "both still answer the name question with \"\"")
	require.NotEqual(t, absentPresent, badPresent,
		"absent and unrecognised must be distinguishable, which is the whole point of the flag")
}

// TestCurveUsableForECDSA pins the predicate both verbs share. Recognising a
// curve and being able to put an ECDSA key on it are different questions: the
// module recognises the Edwards and Montgomery OIDs so CKA_EC_PARAMS can
// identify their own key types, while types.ParseCurve -- which every backend
// resolves an ECDSA curve through -- names only the NIST prime curves.
func TestCurveUsableForECDSA(t *testing.T) {
	for _, name := range []string{"P-256", "P-384", "P-521"} {
		assert.True(t, curveUsableForECDSA(name), "%s carries ECDSA keys", name)
	}
	for _, name := range []string{"Ed25519", "Ed448", "X25519", "X448"} {
		assert.False(t, curveUsableForECDSA(name), "%s is recognised but cannot carry an ECDSA key", name)
	}
	assert.False(t, curveUsableForECDSA("P-192"), "a name the table does not carry is not usable")
	assert.False(t, curveUsableForECDSA(""), "the empty name is not a curve")
}

// TestUnwrapKeyRefusesRecognisedNonECDSACurve is the inconsistency #161 names.
//
// The X25519 OID is the shape older implementations such as NSS emit for
// Curve25519. It is in the module's table, so before this change it resolved as
// recognised, was passed through, and came back from the service as a generic
// "invalid curve: X25519" several layers down -- while an OID the table does
// not carry got CKR_CURVE_NOT_SUPPORTED at the module. One condition, two
// answers, and only the second is one a PKCS#11 caller can act on.
func TestUnwrapKeyRefusesRecognisedNonECDSACurve(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ecParams []byte
	}{
		{"X25519", curveParamsX25519},
		{"Ed25519", curveParamsEd25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
			defer m.Finalize()

			blob := wrappedECKey(t, elliptic.P256(), oracle.symmetricKEK(requireBoundToBackend(t, m, wrappingKey)))

			_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP_PAD}, wrappingKey,
				blob, ecPrivateKeyUnwrapTemplate(tc.ecParams))

			assert.Equal(t, CKR_CURVE_NOT_SUPPORTED, rv,
				"a curve no ECDSA key can live on must be refused with the code PKCS#11 defines for it")
			assert.Nil(t, oracle.lastUnwrapReq,
				"the backend must never be asked to unwrap onto a curve it cannot produce")
		})
	}
}

// TestUnwrapKeyAbsentECParamsStillReachesTheBackend is the trap #161 warns
// about, kept as a control beside the refusal above: the first implementation
// of this gate keyed on the name alone, so it also refused templates that
// simply omit CKA_EC_PARAMS -- which is the shape Table 13 footnote 6 requires
// for an unwrapped EC private key. The refusal must key on name AND presence.
func TestUnwrapKeyAbsentECParamsStillReachesTheBackend(t *testing.T) {
	m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	blob := wrappedECKey(t, elliptic.P384(), oracle.symmetricKEK(requireBoundToBackend(t, m, wrappingKey)))

	_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP_PAD}, wrappingKey,
		blob, ecPrivateKeyUnwrapTemplate(nil))

	require.Equal(t, CKR_OK, rv, "an omitted CKA_EC_PARAMS is spec-conformant and must be served")
	require.NotNil(t, oracle.lastUnwrapReq, "the backend must be reached")
	assert.Empty(t, oracle.lastUnwrapReq.TargetCurve, "naming no curve leaves the service default in place")
}

// TestGenerateKeyPairAgreesWithUnwrapOnCurves is the agreement #161 asks for:
// whichever way the decision goes, C_GenerateKeyPair and C_UnwrapKey must give
// the same answer about the same curve. Both now resolve it through
// curveUsableForECDSA.
//
// The Edwards row is the regression guard. The gate is on the MECHANISM, not on
// the curve alone -- applying it to every CKA_EC_PARAMS would refuse
// CKM_EC_EDWARDS_KEY_PAIR_GEN over the very curve it is supposed to name.
func TestGenerateKeyPairAgreesWithUnwrapOnCurves(t *testing.T) {
	ecPublicTemplate := func(ecParams []byte) []Attribute {
		return []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
			NewStringAttribute(CKA_LABEL, "curve-agreement"),
			NewAttribute(CKA_EC_PARAMS, ecParams),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_TOKEN, false),
		}
	}
	privTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
		NewStringAttribute(CKA_LABEL, "curve-agreement"),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	t.Run("ECDSA generation refuses a curve unwrap also refuses", func(t *testing.T) {
		m, _, session, _, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(session, &Mechanism{Type: CKM_EC_KEY_PAIR_GEN},
			ecPublicTemplate(curveParamsX25519), privTemplate)

		assert.Equal(t, CKR_CURVE_NOT_SUPPORTED, rv,
			"C_GenerateKeyPair must answer the same curve the same way C_UnwrapKey does")
	})

	t.Run("Edwards generation is not refused over its own curve", func(t *testing.T) {
		m, _, session, _, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(session, &Mechanism{Type: CKM_EC_EDWARDS_KEY_PAIR_GEN},
			ecPublicTemplate(curveParamsEd25519), privTemplate)

		assert.NotEqual(t, CKR_CURVE_NOT_SUPPORTED, rv,
			"the ECDSA curve rule must not reach a mechanism whose keys live on Edwards curves")
	})
}
