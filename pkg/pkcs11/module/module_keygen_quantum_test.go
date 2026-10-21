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

	"github.com/jeremyhahn/go-xkms/pkg/quantum/dilithium2"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/mldsa65"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/mlkem1024"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parameterSetAttribute builds the CKA_PARAMETER_SET a caller states alongside
// a v3.2 standard key-pair generation mechanism.
func parameterSetAttribute(parameterSet ParameterSetType) Attribute {
	return NewUint32Attribute(CKA_PARAMETER_SET, uint32(parameterSet))
}

// objectAttribute reads an attribute straight out of the object store. It
// bypasses C_GetAttributeValue deliberately: a generated private key is
// CKA_SENSITIVE, so its CKA_VALUE is unreadable through the application-facing
// call, and the point of these tests is to check what the token actually
// stored.
func objectAttribute(t *testing.T, m *Module, handle ObjectHandle, attrType AttributeType) []byte {
	t.Helper()
	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	return obj.GetAttribute(attrType)
}

// generatePQCKeyPair drives C_GenerateKeyPair for a post-quantum mechanism with
// the attributes the KEM and verification paths require, and returns the two
// handles.
func generatePQCKeyPair(t *testing.T, m *Module, session SessionHandle, mechType MechanismType, label string, extra ...Attribute) (ObjectHandle, ObjectHandle) {
	t.Helper()

	publicTemplate := append([]Attribute{
		NewStringAttribute(CKA_LABEL, label+"-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
	}, extra...)
	privateTemplate := append([]Attribute{
		NewStringAttribute(CKA_LABEL, label+"-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_DECAPSULATE, true),
	}, extra...)

	pub, priv, rv := m.GenerateKeyPair(session, &Mechanism{Type: mechType}, publicTemplate, privateTemplate)
	require.Equal(t, CKR_OK, rv, "C_GenerateKeyPair(%s) must succeed", GetMechanismName(mechType))
	return pub, priv
}

// --- parameter set resolution ---

// TestQuantumKeyGenSpecResolvesBothAddressingForms proves the two ways an
// application can name a post-quantum key pair resolve to one answer.
//
// PKCS#11 v3.2 §6.67.2 and §6.68.2 give CKM_ML_DSA_KEY_PAIR_GEN and
// CKM_ML_KEM_KEY_PAIR_GEN no mechanism parameter, so CKA_PARAMETER_SET is the
// only thing that says which key to generate; the per-level vendor mechanisms
// say it in the mechanism instead. If the two forms disagreed, the same
// application request would produce keys of different strengths depending on
// which spelling it used.
func TestQuantumKeyGenSpecResolvesBothAddressingForms(t *testing.T) {
	cases := []struct {
		name         string
		vendor       MechanismType
		standard     MechanismType
		parameterSet ParameterSetType
		level        int
		keyType      KeyType
	}{
		{"ML-DSA-44", CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, CKM_ML_DSA_KEY_PAIR_GEN, CKP_ML_DSA_44, 44, CKK_ML_DSA},
		{"ML-DSA-65", CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, CKM_ML_DSA_KEY_PAIR_GEN, CKP_ML_DSA_65, 65, CKK_ML_DSA},
		{"ML-DSA-87", CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN, CKM_ML_DSA_KEY_PAIR_GEN, CKP_ML_DSA_87, 87, CKK_ML_DSA},
		{"ML-KEM-512", CKM_VENDOR_ML_KEM_512_KEY_GEN, CKM_ML_KEM_KEY_PAIR_GEN, CKP_ML_KEM_512, 512, CKK_ML_KEM},
		{"ML-KEM-768", CKM_VENDOR_ML_KEM_768_KEY_GEN, CKM_ML_KEM_KEY_PAIR_GEN, CKP_ML_KEM_768, 768, CKK_ML_KEM},
		{"ML-KEM-1024", CKM_VENDOR_ML_KEM_1024_KEY_GEN, CKM_ML_KEM_KEY_PAIR_GEN, CKP_ML_KEM_1024, 1024, CKK_ML_KEM},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vendorSpec, isQuantum, err := resolveQuantumKeyGenSpec(tc.vendor, nil, nil)
			require.True(t, isQuantum, "the vendor mechanism must be recognized as post-quantum")
			require.NoError(t, err)

			// The parameter set stated on the public half, and on the private
			// half, must both be honoured: v3.2 puts CKA_PARAMETER_SET on both
			// objects of the pair.
			onPublic, isQuantum, err := resolveQuantumKeyGenSpec(tc.standard,
				[]Attribute{parameterSetAttribute(tc.parameterSet)}, nil)
			require.True(t, isQuantum)
			require.NoError(t, err)

			onPrivate, isQuantum, err := resolveQuantumKeyGenSpec(tc.standard,
				nil, []Attribute{parameterSetAttribute(tc.parameterSet)})
			require.True(t, isQuantum)
			require.NoError(t, err)

			assert.Equal(t, tc.level, vendorSpec.level)
			assert.Equal(t, tc.keyType, vendorSpec.keyType)
			assert.Equal(t, tc.parameterSet, vendorSpec.parameterSet)
			assert.Equal(t, vendorSpec, onPublic,
				"naming the level in the mechanism must resolve exactly as stating it in the public template")
			assert.Equal(t, vendorSpec, onPrivate,
				"naming the level in the mechanism must resolve exactly as stating it in the private template")
		})
	}
}

// TestQuantumKeyGenSpecScopesParameterSetsPerAlgorithm proves the numerically
// identical parameter set values are not confused across families.
//
// CKP_ML_DSA_44 and CKP_ML_KEM_512 are both 0x00000001; v3.2 §2.3 scopes
// parameter set values per algorithm. A single shared lookup would have
// CKM_ML_KEM_KEY_PAIR_GEN with CKP_ML_DSA_44 generate an ML-DSA key.
func TestQuantumKeyGenSpecScopesParameterSetsPerAlgorithm(t *testing.T) {
	require.Equal(t, uint32(CKP_ML_DSA_44), uint32(CKP_ML_KEM_512),
		"this test is only meaningful while the two values collide")

	kemSpec, _, err := resolveQuantumKeyGenSpec(CKM_ML_KEM_KEY_PAIR_GEN,
		[]Attribute{parameterSetAttribute(CKP_ML_KEM_512)}, nil)
	require.NoError(t, err)
	assert.Equal(t, quantumFamilyMLKEM, kemSpec.family)
	assert.Equal(t, 512, kemSpec.level)

	dsaSpec, _, err := resolveQuantumKeyGenSpec(CKM_ML_DSA_KEY_PAIR_GEN,
		[]Attribute{parameterSetAttribute(CKP_ML_DSA_44)}, nil)
	require.NoError(t, err)
	assert.Equal(t, quantumFamilyMLDSA, dsaSpec.family)
	assert.Equal(t, 44, dsaSpec.level)
}

// TestQuantumKeyGenSpecRejectsAnUnusableRequest proves the refusals are
// determinate rather than a guess.
func TestQuantumKeyGenSpecRejectsAnUnusableRequest(t *testing.T) {
	t.Run("no parameter set at all", func(t *testing.T) {
		// The mechanism carries no parameter and the templates name no level,
		// so nothing in the request says which key to generate.
		// CKR_TEMPLATE_INCOMPLETE is in C_GenerateKeyPair's return table
		// (§5.18.2); defaulting to a level would hand back a strength the
		// application never asked for.
		_, isQuantum, err := resolveQuantumKeyGenSpec(CKM_ML_DSA_KEY_PAIR_GEN, nil, nil)
		require.True(t, isQuantum)
		require.Error(t, err)
		assert.Equal(t, CKR_TEMPLATE_INCOMPLETE, FromError(err))
	})

	t.Run("parameter set of another algorithm", func(t *testing.T) {
		// CKP_SLH_DSA_SHAKE_256F is 0x0C, which no ML-DSA parameter set uses.
		_, isQuantum, err := resolveQuantumKeyGenSpec(CKM_ML_DSA_KEY_PAIR_GEN,
			[]Attribute{parameterSetAttribute(CKP_SLH_DSA_SHAKE_256F)}, nil)
		require.True(t, isQuantum)
		require.Error(t, err)
		assert.Equal(t, CKR_PARAMETER_SET_NOT_SUPPORTED, FromError(err))
	})

	t.Run("parameter set value too short to read", func(t *testing.T) {
		_, isQuantum, err := resolveQuantumKeyGenSpec(CKM_ML_KEM_KEY_PAIR_GEN,
			[]Attribute{NewAttribute(CKA_PARAMETER_SET, []byte{0x01, 0x00})}, nil)
		require.True(t, isQuantum)
		require.Error(t, err)
		assert.Equal(t, CKR_TEMPLATE_INCOMPLETE, FromError(err))
	})

	t.Run("classical mechanism is not claimed", func(t *testing.T) {
		spec, isQuantum, err := resolveQuantumKeyGenSpec(CKM_RSA_PKCS_KEY_PAIR_GEN, nil, nil)
		require.NoError(t, err)
		assert.False(t, isQuantum, "a classical mechanism must fall through to the backend path")
		assert.Equal(t, quantumFamilyNone, spec.family)
	})
}

// --- end-to-end generation ---

// TestGenerateKeyPairMLKEMRoundTripsUnderTheReferenceImplementation drives
// ML-KEM from generation to decapsulation and back, for both addressing forms.
//
// The oracle is pkg/quantum's own kyber768/mlkem1024 encapsulating against the
// public key the token generated: if the token's C_DecapsulateKey recovers the
// same shared secret the reference implementation produced, the generated pair
// is a real FIPS 203 key pair and not merely something the module's own inverse
// accepts. Before CKA_PARAMETER_SET was read and the vendor mechanisms
// resolved, C_GenerateKeyPair produced no ML-KEM key at all.
func TestGenerateKeyPairMLKEMRoundTripsUnderTheReferenceImplementation(t *testing.T) {
	cases := []struct {
		name          string
		mechanism     MechanismType
		extra         []Attribute
		publicKeySize int
		encapsulate   func(publicKey []byte) (ciphertext, sharedSecret []byte, err error)
	}{
		{
			name:          "ML-KEM-768 vendor mechanism",
			mechanism:     CKM_VENDOR_ML_KEM_768_KEY_GEN,
			publicKeySize: MLKEM768PublicKeySize,
			encapsulate:   referenceEncapsulateMLKEM768,
		},
		{
			name:          "ML-KEM-768 standard mechanism with CKA_PARAMETER_SET",
			mechanism:     CKM_ML_KEM_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_KEM_768)},
			publicKeySize: MLKEM768PublicKeySize,
			encapsulate:   referenceEncapsulateMLKEM768,
		},
		{
			name:          "ML-KEM-1024 vendor mechanism",
			mechanism:     CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			publicKeySize: MLKEM1024PublicKeySize,
			encapsulate:   referenceEncapsulateMLKEM1024,
		},
		{
			name:          "ML-KEM-1024 standard mechanism with CKA_PARAMETER_SET",
			mechanism:     CKM_ML_KEM_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_KEM_1024)},
			publicKeySize: MLKEM1024PublicKeySize,
			encapsulate:   referenceEncapsulateMLKEM1024,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()
			session := loginAsNormalUser(t, m)

			pub, priv := generatePQCKeyPair(t, m, session, tc.mechanism, "mlkem", tc.extra...)

			publicKey := objectAttribute(t, m, pub, CKA_VALUE)
			require.Len(t, publicKey, tc.publicKeySize,
				"the public key must be the FIPS 203 size for this parameter set")

			// Both halves must describe the parameter set, or C_DecapsulateKey
			// would have to infer the level from a ciphertext length.
			assert.Equal(t, objectAttribute(t, m, pub, CKA_PARAMETER_SET),
				objectAttribute(t, m, priv, CKA_PARAMETER_SET),
				"both halves of the pair must carry the same CKA_PARAMETER_SET")

			secretTemplate := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
				NewBoolAttribute(CKA_TOKEN, false),
			}

			// Direction one: the reference implementation encapsulates, the
			// token decapsulates. The token must arrive at the secret the
			// reference produced.
			ciphertext, expectedSecret, err := tc.encapsulate(publicKey)
			require.NoError(t, err, "the reference implementation must accept the generated public key")

			secretHandle, err := m.DecapsulateKey(session, &Mechanism{Type: CKM_ML_KEM}, priv, secretTemplate, ciphertext)
			require.NoError(t, err, "C_DecapsulateKey must accept the generated private key")

			assert.Equal(t, expectedSecret, objectAttribute(t, m, secretHandle, CKA_VALUE),
				"the token must recover the shared secret the reference implementation encapsulated")

			// NOT YET COVERED: the reverse direction, where the token
			// encapsulates and the reference implementation decapsulates. That
			// is what would make C_EncapsulateKey a proven operation rather
			// than one whose output only the token's own C_DecapsulateKey
			// accepts, and it needs a reference decapsulate helper taking the
			// stored seed. Direction one below is genuine interop and is not
			// weakened by the gap, but do not read this test as covering
			// C_EncapsulateKey.

			// The pair must be destroyable, closing the generate/use/delete
			// lifecycle rather than leaving objects the token cannot release.
			access := NewAccessContext(session, mustSession(t, m, session))
			require.NoError(t, m.objectManager.DestroyObject(access, pub))
			require.NoError(t, m.objectManager.DestroyObject(access, priv))
			_, err = m.objectManager.getObjectUnchecked(pub)
			assert.Error(t, err, "a destroyed public key must no longer resolve")
		})
	}
}

// TestGenerateKeyPairMLDSAProducesARealSigningKey proves the generated ML-DSA
// pair is a genuine FIPS 204 pair, for both addressing forms.
//
// The oracle is pkg/quantum's reference signer, constructed from the seed the
// token stored: a signature it produces must verify under the token's
// C_VerifySignature against the token's own public key object. The two halves
// therefore have to belong together and be the parameter set that was asked
// for -- a mismatched pair, or a key generated at the wrong level, fails.
func TestGenerateKeyPairMLDSAProducesARealSigningKey(t *testing.T) {
	message := []byte("post-quantum key generation, end to end")

	cases := []struct {
		name          string
		mechanism     MechanismType
		extra         []Attribute
		publicKeySize int
		verifyWith    MechanismType
		sign          func(seed, message []byte) ([]byte, error)
	}{
		{
			name:          "ML-DSA-44 vendor mechanism",
			mechanism:     CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			publicKeySize: MLDSA44PublicKeySize,
			verifyWith:    CKM_VENDOR_ML_DSA_44,
			sign:          referenceSignMLDSA44,
		},
		{
			name:          "ML-DSA-44 standard mechanism with CKA_PARAMETER_SET",
			mechanism:     CKM_ML_DSA_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_DSA_44)},
			publicKeySize: MLDSA44PublicKeySize,
			verifyWith:    CKM_VENDOR_ML_DSA_44,
			sign:          referenceSignMLDSA44,
		},
		{
			name:          "ML-DSA-65 vendor mechanism",
			mechanism:     CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			publicKeySize: MLDSA65PublicKeySize,
			verifyWith:    CKM_VENDOR_ML_DSA_65,
			sign:          referenceSignMLDSA65,
		},
		{
			name:          "ML-DSA-65 standard mechanism with CKA_PARAMETER_SET",
			mechanism:     CKM_ML_DSA_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_DSA_65)},
			publicKeySize: MLDSA65PublicKeySize,
			verifyWith:    CKM_VENDOR_ML_DSA_65,
			sign:          referenceSignMLDSA65,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()
			session := loginAsNormalUser(t, m)

			pub, priv := generatePQCKeyPair(t, m, session, tc.mechanism, "mldsa", tc.extra...)

			publicKey := objectAttribute(t, m, pub, CKA_VALUE)
			require.Len(t, publicKey, tc.publicKeySize,
				"the public key must be the FIPS 204 size for this parameter set")

			seed := objectAttribute(t, m, priv, CKA_VALUE)
			require.NotEmpty(t, seed, "the private half must carry key material")

			signature, err := tc.sign(seed, message)
			require.NoError(t, err, "the reference signer must accept the stored seed")

			require.NoError(t, m.VerifySignatureInit(session, &Mechanism{Type: tc.verifyWith}, pub, signature))
			require.NoError(t, m.VerifySignature(session, message),
				"a signature made with the generated private key must verify under the generated public key")

			// A signature over different data must not verify, so the check
			// above is shown to be a verification and not an acceptance.
			require.NoError(t, m.VerifySignatureInit(session, &Mechanism{Type: tc.verifyWith}, pub, signature))
			// A failed C_VerifySignature terminates the operation itself, so
			// there is nothing left to finish.
			assert.Error(t, m.VerifySignature(session, append(message, '!')),
				"the token must reject a signature over different data")
			assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, m.FinishOperation(session, OperationVerifySignature),
				"the failed verification must have left no active operation behind")
		})
	}
}

// TestGenerateKeyPairGeneratesEveryMLKEMParameterSet proves each FIPS 203
// parameter set is reachable by both addressing forms and produces a key of that
// set's own size.
//
// This test replaced one asserting the opposite for ML-KEM-512. That set had no
// generator while pkg/quantum wrapped only crypto/mlkem, so C_GenerateKeyPair
// refused it; pkg/quantum/mlkem512 supplies it now. The size assertion is what
// makes the test meaningful -- a dispatch that quietly fell through to
// ML-KEM-768, which is what resolveMLKEMLevel's default did before the routing
// tables learned 512, would still return CKR_OK and hand back a key of the
// wrong strength.
func TestGenerateKeyPairGeneratesEveryMLKEMParameterSet(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	for _, tc := range []struct {
		name            string
		parameterSet    ParameterSetType
		vendorMechanism MechanismType
		publicKeyLength int
	}{
		{"ML-KEM-512", CKP_ML_KEM_512, CKM_VENDOR_ML_KEM_512_KEY_GEN, MLKEM512PublicKeySize},
		{"ML-KEM-768", CKP_ML_KEM_768, CKM_VENDOR_ML_KEM_768_KEY_GEN, MLKEM768PublicKeySize},
		{"ML-KEM-1024", CKP_ML_KEM_1024, CKM_VENDOR_ML_KEM_1024_KEY_GEN, MLKEM1024PublicKeySize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := []Attribute{
				NewStringAttribute(CKA_LABEL, tc.name),
				NewBoolAttribute(CKA_TOKEN, false),
			}

			// The vendor mechanism names the parameter set by itself.
			publicHandle, _, rv := m.GenerateKeyPair(session,
				&Mechanism{Type: tc.vendorMechanism}, base, base)
			if tc.parameterSet == CKP_ML_KEM_512 && mlkem512RefusedUnderFIPS(t, rv) {
				return
			}
			require.Equal(t, CKR_OK, rv, "the vendor mechanism must generate %s", tc.name)
			assertMLKEMPublicKeyLength(t, m, session, publicHandle, tc.publicKeyLength, tc.name)

			// The standard mechanism takes it from CKA_PARAMETER_SET.
			withParameterSet := append([]Attribute{parameterSetAttribute(tc.parameterSet)}, base...)
			publicHandle, _, rv = m.GenerateKeyPair(session,
				&Mechanism{Type: CKM_ML_KEM_KEY_PAIR_GEN}, withParameterSet, withParameterSet)
			require.Equal(t, CKR_OK, rv, "the standard addressing form must generate %s", tc.name)
			assertMLKEMPublicKeyLength(t, m, session, publicHandle, tc.publicKeyLength, tc.name)
		})
	}
}

// assertMLKEMPublicKeyLength checks a generated encapsulation key is the size
// its parameter set defines, which is what distinguishes the levels.
func assertMLKEMPublicKeyLength(t *testing.T, m *Module, session SessionHandle,
	handle ObjectHandle, want int, name string) {
	t.Helper()

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	value := findAttr(attrs, CKA_VALUE)
	require.NotNil(t, value)
	assert.Len(t, value.Value, want,
		"%s must produce a %d-byte encapsulation key; another length means the request "+
			"was dispatched to a different parameter set", name, want)
}

// TestGenerateKeyPairRejectsAMissingParameterSet proves the refusal reaches
// C_GenerateKeyPair and not only the resolver.
func TestGenerateKeyPairRejectsAMissingParameterSet(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	template := []Attribute{
		NewStringAttribute(CKA_LABEL, "no-parameter-set"),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	_, _, rv := m.GenerateKeyPair(session, &Mechanism{Type: CKM_ML_DSA_KEY_PAIR_GEN}, template, template)
	assert.Equal(t, CKR_TEMPLATE_INCOMPLETE, rv,
		"CKM_ML_DSA_KEY_PAIR_GEN carries no parameter, so the template must state the level")
}

// --- token residency and persistence ---

// TestQuantumPrivateKeyPersistenceErrorAnswersEachTemplate proves the rule that
// decides whether a post-quantum private key can be given back after a restart.
//
// The token store is a plaintext file and ModuleStorage.SaveObject withholds
// CKA_VALUE from any key object that protects its material. A post-quantum
// private key's CKA_VALUE is its only copy, so the combination CKA_TOKEN=CK_TRUE
// with protected material describes a key that cannot survive; the one storable
// shape is a key the application itself declared readable and extractable.
func TestQuantumPrivateKeyPersistenceErrorAnswersEachTemplate(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
		refused  bool
	}{
		{
			name:     "session key needs no store at all",
			template: []Attribute{NewBoolAttribute(CKA_TOKEN, false)},
		},
		{
			name:     "no CKA_TOKEN defaults to a session key",
			template: nil,
		},
		{
			name: "token key with the class defaults is refused",
			// applyClassDefaults makes a CKO_PRIVATE_KEY sensitive, so a
			// template stating nothing inherits protected material.
			template: []Attribute{NewBoolAttribute(CKA_TOKEN, true)},
			refused:  true,
		},
		{
			name: "token key explicitly sensitive is refused",
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, true),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			},
			refused: true,
		},
		{
			name: "token key that is not extractable is refused",
			// protectsSensitiveAttributes withholds the material for a
			// non-extractable key even when it is not sensitive, so
			// CKA_SENSITIVE=CK_FALSE alone is not enough.
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, false),
			},
			refused: true,
		},
		{
			name: "token key the application declared readable and extractable is allowed",
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := quantumPrivateKeyPersistenceError(tc.template)
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, FromError(err),
				"§5.1 defines CKR_TEMPLATE_INCONSISTENT as conflicting attributes, which is what asking the token both to keep the key and to protect its only copy is")
		})
	}
}

// TestGenerateKeyPairRefusesATokenPQCKeyItCannotPersist proves the refusal
// reaches C_GenerateKeyPair, and that nothing is created on the way out.
//
// Before this, the call returned CKR_OK, the key worked all session, and the
// restored object came back with no CKA_VALUE at all: C_Sign and
// C_DecapsulateKey then failed on a handle the application had every reason to
// believe was a key, with nothing having warned at generation time.
func TestGenerateKeyPairRefusesATokenPQCKeyItCannotPersist(t *testing.T) {
	cases := []struct {
		name      string
		mechanism MechanismType
	}{
		{"ML-DSA-65", CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN},
		{"ML-KEM-768", CKM_VENDOR_ML_KEM_768_KEY_GEN},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()
			session := loginAsNormalUser(t, m)

			const label = "unpersistable-token-key"
			publicTemplate := []Attribute{
				NewStringAttribute(CKA_LABEL, label+"-pub"),
				NewBoolAttribute(CKA_TOKEN, true),
			}
			privateTemplate := []Attribute{
				NewStringAttribute(CKA_LABEL, label+"-priv"),
				NewBoolAttribute(CKA_TOKEN, true),
			}

			_, _, rv := m.GenerateKeyPair(session, &Mechanism{Type: tc.mechanism}, publicTemplate, privateTemplate)
			assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv,
				"a token key whose only copy of its material this token may not write out must be refused at generation")

			// The refusal precedes generation, so neither half may exist.
			require.Equal(t, CKR_OK, m.FindObjectsInit(session, []Attribute{
				NewStringAttribute(CKA_LABEL, label+"-pub"),
			}))
			handles, findRV := m.FindObjects(session, 16)
			require.Equal(t, CKR_OK, findRV)
			require.Equal(t, CKR_OK, m.FindObjectsFinal(session))
			assert.Empty(t, handles, "a refused C_GenerateKeyPair must leave no half-built pair behind")
		})
	}
}

// TestTokenPQCKeyPairSurvivesFinalizeAndStaysUsable is the generate → persist →
// restore → USE proof for the shape of post-quantum token key this module can
// store.
//
// Restoring the object is not the claim being tested; using it is. A restored
// key whose CKA_VALUE had been withheld looks entirely healthy — it is found by
// label, it reports its class, its key type and its parameter set — and fails
// only at the moment an application tries to sign or decapsulate with it. So
// the test does both, against oracles outside the module: cloudflare/circl
// verifies what the restored ML-DSA key signs, and pkg/quantum's reference KEM
// encapsulates the ciphertext the restored ML-KEM key must decapsulate.
func TestTokenPQCKeyPairSurvivesFinalizeAndStaysUsable(t *testing.T) {
	const (
		soPIN   = "so-pin-pqc-token"
		userPIN = "user-pin-pqc-token"
	)

	// storableTemplates builds the one shape of token post-quantum private key
	// this store can hold: one the application declared readable and
	// extractable, so nothing SaveObject withholds is load-bearing.
	storableTemplates := func(label string) ([]Attribute, []Attribute) {
		pub := []Attribute{
			NewStringAttribute(CKA_LABEL, label+"-pub"),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_PRIVATE, false),
			NewBoolAttribute(CKA_VERIFY, true),
			NewBoolAttribute(CKA_ENCAPSULATE, true),
		}
		priv := []Attribute{
			NewStringAttribute(CKA_LABEL, label+"-priv"),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_SENSITIVE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewBoolAttribute(CKA_SIGN, true),
			NewBoolAttribute(CKA_DECAPSULATE, true),
		}
		return pub, priv
	}

	// findOne resolves a restored object by the label it was created with.
	// Handles are not the point of the test: an application finds its key
	// again by attribute, and the found handle is the one that must work.
	findOne := func(t *testing.T, m *Module, session SessionHandle, label string) ObjectHandle {
		t.Helper()
		require.Equal(t, CKR_OK, m.FindObjectsInit(session, []Attribute{
			NewStringAttribute(CKA_LABEL, label),
		}))
		handles, rv := m.FindObjects(session, 16)
		require.Equal(t, CKR_OK, rv)
		require.Equal(t, CKR_OK, m.FindObjectsFinal(session))
		require.Len(t, handles, 1, "the token object created before the restart must be found after it")
		return handles[0]
	}

	dir := t.TempDir()

	// --- before the restart ---

	first := newPersistentModule(t, dir)
	require.Equal(t, CKR_OK, first.InitToken(0, []byte(soPIN), "PQC Token"))

	session, rv := first.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.Login(session, CKU_SO, []byte(soPIN)))
	require.Equal(t, CKR_OK, first.InitPIN(session, []byte(userPIN)))
	require.Equal(t, CKR_OK, first.Logout(session))
	require.Equal(t, CKR_OK, first.Login(session, CKU_USER, []byte(userPIN)))

	dsaPubTemplate, dsaPrivTemplate := storableTemplates("pqc-mldsa")
	_, _, rv = first.GenerateKeyPair(session,
		&Mechanism{Type: CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN}, dsaPubTemplate, dsaPrivTemplate)
	require.Equal(t, CKR_OK, rv, "a storable token ML-DSA pair must be accepted")

	kemPubTemplate, kemPrivTemplate := storableTemplates("pqc-mlkem")
	_, _, rv = first.GenerateKeyPair(session,
		&Mechanism{Type: CKM_VENDOR_ML_KEM_768_KEY_GEN}, kemPubTemplate, kemPrivTemplate)
	require.Equal(t, CKR_OK, rv, "a storable token ML-KEM pair must be accepted")

	require.Equal(t, CKR_OK, first.CloseSession(session))
	require.Equal(t, CKR_OK, first.Finalize())

	// --- after the restart ---

	second := newPersistentModule(t, dir)
	defer second.Finalize()

	restored, rv := second.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.Login(restored, CKU_USER, []byte(userPIN)))

	t.Run("ML-DSA signs after the restart", func(t *testing.T) {
		pub := findOne(t, second, restored, "pqc-mldsa-pub")
		priv := findOne(t, second, restored, "pqc-mldsa-priv")

		seed := objectAttribute(t, second, priv, CKA_VALUE)
		require.Len(t, seed, mldsaSeedSize,
			"the restored private key must still carry the seed it was generated with")

		publicKey := objectAttribute(t, second, pub, CKA_VALUE)
		require.Len(t, publicKey, MLDSA65PublicKeySize)

		message := []byte("signed by a key that outlived the module")
		signature, signRV := signThroughQuantumDispatch(t, second, restored,
			&Mechanism{Type: CKM_VENDOR_ML_DSA_65}, priv, message)
		require.Equal(t, CKR_OK, signRV, "the restored private key must still sign")

		assert.True(t, circlVerifyMLDSA65(publicKey, message, signature),
			"an independent ML-DSA implementation must accept a signature made after the restart")
	})

	t.Run("ML-KEM decapsulates after the restart", func(t *testing.T) {
		pub := findOne(t, second, restored, "pqc-mlkem-pub")
		priv := findOne(t, second, restored, "pqc-mlkem-priv")

		publicKey := objectAttribute(t, second, pub, CKA_VALUE)
		require.Len(t, publicKey, MLKEM768PublicKeySize)

		ciphertext, expectedSecret, err := referenceEncapsulateMLKEM768(publicKey)
		require.NoError(t, err, "the reference implementation must accept the restored public key")

		secretHandle, err := second.DecapsulateKey(restored, &Mechanism{Type: CKM_ML_KEM}, priv, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
			NewBoolAttribute(CKA_TOKEN, false),
		}, ciphertext)
		require.NoError(t, err,
			"C_DecapsulateKey must work on the restored private key; before the fix it returned CKR_UNWRAPPING_KEY_HANDLE_INVALID because CKA_VALUE was never written out")

		assert.Equal(t, expectedSecret, objectAttribute(t, second, secretHandle, CKA_VALUE),
			"the restored key must recover the shared secret the reference implementation encapsulated")
	})
}

// --- reference implementations used as oracles ---

func referenceEncapsulateMLKEM768(publicKey []byte) ([]byte, []byte, error) {
	kem, err := kyber768.New()
	if err != nil {
		return nil, nil, err
	}
	defer kem.Clean()
	return kem.Encapsulate(publicKey)
}

func referenceEncapsulateMLKEM1024(publicKey []byte) ([]byte, []byte, error) {
	kem, err := mlkem1024.New()
	if err != nil {
		return nil, nil, err
	}
	defer kem.Clean()
	return kem.Encapsulate(publicKey)
}

func referenceSignMLDSA44(seed, message []byte) ([]byte, error) {
	signer, err := dilithium2.Create(seed)
	if err != nil {
		return nil, err
	}
	defer signer.Clean()
	return signer.Sign(message)
}

func referenceSignMLDSA65(seed, message []byte) ([]byte, error) {
	signer, err := mldsa65.Create(seed)
	if err != nil {
		return nil, err
	}
	defer signer.Clean()
	return signer.Sign(message)
}

// mustSession resolves a session for building an access context in tests.
func mustSession(t *testing.T, m *Module, handle SessionHandle) *Session {
	t.Helper()
	_, session, rv := m.findSession(handle)
	require.Equal(t, CKR_OK, rv)
	return session
}
