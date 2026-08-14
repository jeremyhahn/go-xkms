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

	"github.com/jeremyhahn/go-xkms/pkg/quantum/mlkem512"
)

// mlkemKeyGenTemplate builds one half of a C_GenerateKeyPair template for the
// named ML-KEM parameter set.
func mlkemKeyGenTemplate(parameterSet ParameterSetType, class ObjectClass, label string) []Attribute {
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(class)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewUint32Attribute(CKA_PARAMETER_SET, uint32(parameterSet)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
	}
	if class == CKO_PUBLIC_KEY {
		return append(template, NewBoolAttribute(CKA_ENCAPSULATE, true))
	}
	return append(template,
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	)
}

// TestMLKEMGeneratesEveryFIPS203ParameterSet proves the token performs all three
// parameter sets FIPS 203 defines, and that each produces the published key size.
//
// ML-KEM-512 was unavailable for a period: crypto/mlkem, which the 768 and 1024
// paths wrap, implements only those two sets, so the token registered no
// descriptors for 512 and a C_GenerateKeyPair naming CKP_ML_KEM_512 resolved
// through the parameter-set table and then failed several layers down with
// CKR_MECHANISM_INVALID -- a code naming the mechanism when the mechanism was
// fine and had just produced an ML-KEM-768 key. It is now supplied by
// pkg/quantum/mlkem512, wrapping CIRCL's FIPS 203 implementation.
//
// The public key length is asserted per set because it is the one value that
// distinguishes them on the wire, and because a dispatch bug that silently
// generated 768 for a 512 request would otherwise pass every other assertion
// here.
func TestMLKEMGeneratesEveryFIPS203ParameterSet(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	for _, tc := range []struct {
		name            string
		parameterSet    ParameterSetType
		publicKeyLength int
	}{
		{"ML-KEM-512", CKP_ML_KEM_512, MLKEM512PublicKeySize},
		{"ML-KEM-768", CKP_ML_KEM_768, MLKEM768PublicKeySize},
		{"ML-KEM-1024", CKP_ML_KEM_1024, MLKEM1024PublicKeySize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicHandle, privateHandle, rv := m.GenerateKeyPair(session,
				NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN),
				mlkemKeyGenTemplate(tc.parameterSet, CKO_PUBLIC_KEY, tc.name+"-pub"),
				mlkemKeyGenTemplate(tc.parameterSet, CKO_PRIVATE_KEY, tc.name+"-priv"))
			require.Equal(t, CKR_OK, rv, "%s must generate", tc.name)
			require.NotEqual(t, ObjectHandle(InvalidHandle), publicHandle)
			require.NotEqual(t, ObjectHandle(InvalidHandle), privateHandle)

			attrs, rv := m.GetAttributeValue(session, publicHandle, []Attribute{
				{Type: CKA_VALUE},
				{Type: CKA_PARAMETER_SET},
			})
			require.Equal(t, CKR_OK, rv)

			value := findAttr(attrs, CKA_VALUE)
			require.NotNil(t, value)
			assert.Len(t, value.Value, tc.publicKeyLength,
				"%s encapsulation key must be %d bytes; a different length means the request "+
					"was dispatched to another parameter set", tc.name, tc.publicKeyLength)

			parameterSet := findAttr(attrs, CKA_PARAMETER_SET)
			require.NotNil(t, parameterSet, "CKA_PARAMETER_SET must be recorded on the key, "+
				"or C_EncapsulateKey has to guess the level from a key length")
		})
	}
}

// TestMLKEM512EncapsulateDecapsulateRoundTrip is the end-to-end proof that
// ML-KEM-512 is implemented rather than merely advertised.
//
// It drives the module's own C_GenerateKeyPair, C_EncapsulateKey and
// C_DecapsulateKey rather than pkg/quantum/mlkem512 directly, so it covers the
// dispatch that decides which parameter set each operation runs at -- the layer
// where a level that is registered but not wired shows up. The shared secrets
// must match: that is the property the KEM exists to provide, and the one a
// mis-dispatched level would break.
func TestMLKEM512EncapsulateDecapsulateRoundTrip(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	publicHandle, privateHandle, rv := m.GenerateKeyPair(session,
		NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN),
		mlkemKeyGenTemplate(CKP_ML_KEM_512, CKO_PUBLIC_KEY, "mlkem512-roundtrip-pub"),
		mlkemKeyGenTemplate(CKP_ML_KEM_512, CKO_PRIVATE_KEY, "mlkem512-roundtrip-priv"))
	require.Equal(t, CKR_OK, rv)

	sharedTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}

	encapsulatedHandle, ciphertext, err := m.EncapsulateKey(session,
		NewMechanism(CKM_ML_KEM), publicHandle, sharedTemplate)
	require.NoError(t, err, "C_EncapsulateKey must succeed for an ML-KEM-512 key")
	require.Len(t, ciphertext, MLKEM512CiphertextSize,
		"an ML-KEM-512 ciphertext is %d bytes", MLKEM512CiphertextSize)

	decapsulatedHandle, err := m.DecapsulateKey(session,
		NewMechanism(CKM_ML_KEM), privateHandle, sharedTemplate, ciphertext)
	require.NoError(t, err, "C_DecapsulateKey must succeed for an ML-KEM-512 key")

	encapsulatedSecret := secretValueOf(t, m, session, encapsulatedHandle)
	decapsulatedSecret := secretValueOf(t, m, session, decapsulatedHandle)

	require.Len(t, encapsulatedSecret, MLKEM512SharedSecretSize)
	assert.Equal(t, encapsulatedSecret, decapsulatedSecret,
		"encapsulation and decapsulation must agree on the shared secret")

	zero := make([]byte, MLKEM512SharedSecretSize)
	assert.NotEqual(t, zero, decapsulatedSecret,
		"an all-zero shared secret would mean no key material was derived at all")
}

// secretValueOf reads a secret key object's CKA_VALUE, failing the test if the
// token withheld it.
func secretValueOf(t *testing.T, m *Module, session SessionHandle, handle ObjectHandle) []byte {
	t.Helper()

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv, "the shared secret objects are created unprotected on purpose")

	value := findAttr(attrs, CKA_VALUE)
	require.NotNil(t, value)
	require.False(t, value.Unavailable)
	return value.Value
}

// TestMLKEM512IsNotKyber512 guards the one substitution that would be silently
// wrong.
//
// CIRCL ships both kem/kyber/kyber512 and kem/mlkem/mlkem512. Kyber512 is the
// NIST round-3 submission; ML-KEM-512 is the standardised FIPS 203 version, and
// the two differ in the key-derivation step -- so a key generated by one cannot
// be decapsulated by the other, and an implementation that reached for the wrong
// import would pass every round-trip test in this file while being unable to
// interoperate with any other FIPS 203 token.
//
// The lengths are identical between the two, so length assertions cannot catch
// it. What can is the cross-check below: the module's own decapsulation must
// agree with the pkg/quantum/mlkem512 wrapper operating on the same seed, which
// only holds if both sides run the same algorithm.
func TestMLKEM512IsNotKyber512(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	publicHandle, privateHandle, rv := m.GenerateKeyPair(session,
		NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN),
		mlkemKeyGenTemplate(CKP_ML_KEM_512, CKO_PUBLIC_KEY, "mlkem512-crosscheck-pub"),
		mlkemKeyGenTemplate(CKP_ML_KEM_512, CKO_PRIVATE_KEY, "mlkem512-crosscheck-priv"))
	require.Equal(t, CKR_OK, rv)

	publicKey := secretValueOf(t, m, session, publicHandle)
	require.Len(t, publicKey, MLKEM512PublicKeySize)

	// Encapsulate outside the module, to this key, using the wrapper directly.
	external, err := newMLKEM512ForTest()
	require.NoError(t, err)
	defer external.Clean()

	ciphertext, externalSecret, err := external.Encapsulate(publicKey)
	require.NoError(t, err)

	// The module must recover the same secret from that ciphertext.
	sharedTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
	decapsulatedHandle, err := m.DecapsulateKey(session,
		NewMechanism(CKM_ML_KEM), privateHandle, sharedTemplate, ciphertext)
	require.NoError(t, err)

	assert.Equal(t, externalSecret, secretValueOf(t, m, session, decapsulatedHandle),
		"the module and pkg/quantum/mlkem512 must agree on the shared secret; a mismatch "+
			"means one of them is running Kyber round-3 rather than FIPS 203 ML-KEM")
}

// newMLKEM512ForTest builds a wrapper instance for the cross-check above. It
// exists so the test file names the package once, making the FIPS 203 import
// obvious to a reader checking it is not the Kyber round-3 one.
func newMLKEM512ForTest() (*mlkem512.MLKEM512, error) {
	return mlkem512.New()
}
