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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ecPrivateKeyUnwrapTemplate is a C_UnwrapKey template for an EC private key,
// carrying the CKA_EC_PARAMS value that names its curve.
func ecPrivateKeyUnwrapTemplate(ecParams []byte) []Attribute {
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
	if ecParams != nil {
		template = append(template, NewAttribute(CKA_EC_PARAMS, ecParams))
	}
	return template
}

// wrappedECKey returns a blob the oracle can unwrap back into the PKCS#8
// encoding of a private key on the named curve, wrapped under the module's
// wrapping key with CKM_AES_KEY_WRAP_PAD.
func wrappedECKey(t *testing.T, curve elliptic.Curve, kek []byte) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	wrapped, err := wrapping.WrapAESKWP(der, kek)
	require.NoError(t, err)

	return wrapped
}

// TestUnwrapKeyCarriesTheTemplateCurve is the fix for the regression a
// tightened import validator exposed: C_UnwrapKey never set TargetCurve, so
// every EC key it unwrapped arrived at the backend described as P-256.
//
// applyAsymmetricAlgorithm substitutes P-256 for an empty curve, which is
// correct as a default for a caller that named none and wrong as a description
// of a P-384 key. The attributes an unwrapped key is stored under must describe
// the key, and the curve is the caller's to name: the template names it in
// CKA_EC_PARAMS and this is where that value reaches the request.
func TestUnwrapKeyCarriesTheTemplateCurve(t *testing.T) {
	cases := []struct {
		name     string
		curve    elliptic.Curve
		ecParams []byte
		want     string
	}{
		{"P-256", elliptic.P256(), []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, "P-256"},
		{"P-384", elliptic.P384(), []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, "P-384"},
		{"P-521", elliptic.P521(), []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}, "P-521"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
			defer m.Finalize()

			blob := wrappedECKey(t, tc.curve, oracle.symmetricKEK(requireBoundToBackend(t, m, wrappingKey)))

			_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP_PAD}, wrappingKey,
				blob, ecPrivateKeyUnwrapTemplate(tc.ecParams))
			require.Equal(t, CKR_OK, rv)

			require.NotNil(t, oracle.lastUnwrapReq)
			assert.Equal(t, "ecdsa", oracle.lastUnwrapReq.TargetKeyType)
			assert.Equal(t, tc.want, oracle.lastUnwrapReq.TargetCurve,
				"the unwrap request must name the curve the template named, not the service's P-256 default")
		})
	}
}

// TestUnwrapKeyWithoutECParamsNamesNoCurve keeps the addition from becoming a
// new requirement. PKCS#11 v3.2 Table 13 footnote 6 says CKA_EC_PARAMS must
// NOT be specified when an EC private key is unwrapped -- the wrapped PKCS#8
// blob carries the curve -- so a spec-conformant caller sends no such
// attribute and must still be served. An empty TargetCurve leaves the service's
// existing default in place, which is exactly the behaviour before this change.
func TestUnwrapKeyWithoutECParamsNamesNoCurve(t *testing.T) {
	m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	blob := wrappedECKey(t, elliptic.P384(), oracle.symmetricKEK(requireBoundToBackend(t, m, wrappingKey)))

	_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP_PAD}, wrappingKey,
		blob, ecPrivateKeyUnwrapTemplate(nil))
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastUnwrapReq)
	assert.Empty(t, oracle.lastUnwrapReq.TargetCurve)
}

// TestUnwrapKeyRefusesUnrecognisedECParams matches what C_GenerateKeyPair
// already does with a CKA_EC_PARAMS value it does not recognise: naming a curve
// the module does not implement fails rather than quietly producing a key on a
// different one. Reporting the value as absent would let the service substitute
// P-256 for it, which is the silent substitution this change exists to close.
func TestUnwrapKeyRefusesUnrecognisedECParams(t *testing.T) {
	m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	blob := wrappedECKey(t, elliptic.P256(), oracle.symmetricKEK(requireBoundToBackend(t, m, wrappingKey)))

	_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP_PAD}, wrappingKey,
		blob, ecPrivateKeyUnwrapTemplate([]byte{0x06, 0x03, 0x2a, 0x03, 0x04}))

	assert.Equal(t, CKR_CURVE_NOT_SUPPORTED, rv)
	assert.Nil(t, oracle.lastUnwrapReq, "an unsupported curve must be refused before the backend is asked to unwrap")
}

// TestUnwrapKeySecretKeyIgnoresECParams keeps the curve lookup off the paths it
// cannot describe. backendKeyTypeName maps every key type it does not name to
// "symmetric", so refusing an unrecognised CKA_EC_PARAMS on a secret-key
// template would reject a request over an attribute that cannot affect its
// result -- the service consumes a curve for ECDSA and for nothing else.
func TestUnwrapKeySecretKeyIgnoresECParams(t *testing.T) {
	m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	wrapped, rv := m.WrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)

	template := append(unwrapTemplate(), NewAttribute(CKA_EC_PARAMS, []byte{0x06, 0x03, 0x2a, 0x03, 0x04}))

	_, rv = m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, wrappingKey, wrapped, template)
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastUnwrapReq)
	assert.Equal(t, "symmetric", oracle.lastUnwrapReq.TargetKeyType)
	assert.Empty(t, oracle.lastUnwrapReq.TargetCurve)
}
