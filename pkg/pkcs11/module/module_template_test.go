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
	"context"
	"encoding/binary"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Template decoding, and the CKA_VALUE path that reaches into the backend.
//
// The helpers here turn an application's CK_ATTRIBUTE array into the shape the
// transport layer needs. They are small, they are not on any error path, and
// every one of them fails silently when it is wrong: a mis-decoded
// CKA_VALUE_LEN generates a key of the wrong size, a mis-mapped key type sends
// an RSA key to the symmetric code path, and a wrapping mechanism that falls
// through to its display name reaches the backend as an algorithm it does not
// implement.

// TestTemplateValueLenBits_ConvertsBytesToBits proves the unit conversion
// PKCS#11 requires: CKA_VALUE_LEN is a CK_ULONG count of bytes, while the
// backend's key-generation request is expressed in bits.
//
// The width cases exist because CK_ULONG is 8 bytes on the platforms this
// module supports but applications marshal the attribute at whatever width
// their own headers use. Reading only the first four bytes of an 8-byte value,
// or refusing the 4-byte form, would generate a key of the wrong size — which
// succeeds, and is discovered later by whoever cannot decrypt with it.
func TestTemplateValueLenBits_ConvertsBytesToBits(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		want  int
	}{
		{"32 bytes as a 4-byte CK_ULONG", valueLenAttribute(32, 4), 256},
		{"32 bytes as an 8-byte CK_ULONG", valueLenAttribute(32, 8), 256},
		{"16 bytes as an 8-byte CK_ULONG", valueLenAttribute(16, 8), 128},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			template := []Attribute{NewAttribute(CKA_VALUE_LEN, tc.value)}
			assert.Equal(t, tc.want, templateValueLenBits(template))
		})
	}
}

// TestTemplateValueLenBits_RejectsAbsentAndImplausibleLengths proves the
// helper reports "no length specified" as 0 rather than inventing one.
//
// 0 is the caller's signal to fall back to a mechanism default. A zero-valued
// or absurd CKA_VALUE_LEN is application input — a template built from
// uninitialized memory produces exactly that — and passing it through would
// ask the backend for a zero-length or 16-megabyte key.
func TestTemplateValueLenBits_RejectsAbsentAndImplausibleLengths(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
	}{
		{"attribute absent", []Attribute{NewStringAttribute(CKA_LABEL, "no length here")}},
		{"explicit zero", []Attribute{NewAttribute(CKA_VALUE_LEN, valueLenAttribute(0, 8))}},
		{"absurdly large", []Attribute{NewAttribute(CKA_VALUE_LEN, valueLenAttribute(1<<25, 8))}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, templateValueLenBits(tc.template),
				"an unusable CKA_VALUE_LEN must read as unspecified, not be passed to the backend")
		})
	}
}

// TestUnwrapTargetClass_ReadsTemplateClassOrDefaults proves C_UnwrapKey reads
// CKA_CLASS from the template it was given.
//
// PKCS#11 v3.2 §5.15.6 has the application state the class of the key it
// expects to recover. Defaulting to CKO_SECRET_KEY is right for the common
// case, but only when the template is silent: ignoring a stated
// CKO_PRIVATE_KEY would build a secret-key object around unwrapped private key
// material, and CKA_PRIVATE and CKA_SENSITIVE would then be applied under the
// wrong class's rules.
func TestUnwrapTargetClass_ReadsTemplateClassOrDefaults(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
		want     ObjectClass
	}{
		{
			name:     "class stated as private key",
			template: []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY))},
			want:     CKO_PRIVATE_KEY,
		},
		{
			name:     "class stated as secret key",
			template: []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY))},
			want:     CKO_SECRET_KEY,
		},
		{
			name:     "template silent, defaults to secret key",
			template: []Attribute{NewStringAttribute(CKA_LABEL, "unwrapped")},
			want:     CKO_SECRET_KEY,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unwrapTargetClass(tc.template))
		})
	}
}

// TestUnwrapTargetKeyType_MapsToBackendName proves the CKA_KEY_TYPE decode and
// the backend name it produces are consistent.
//
// The backend dispatches on the name, so a key type that mapped to the wrong
// one would have an RSA key unwrapped by the symmetric code path. The
// "symmetric" default is correct for the generic-secret and AES cases and is
// the only safe fallback for a key type this module does not name.
func TestUnwrapTargetKeyType_MapsToBackendName(t *testing.T) {
	cases := []struct {
		name     string
		keyType  KeyType
		wantName string
	}{
		{"RSA", CKK_RSA, "rsa"},
		{"EC", CKK_EC, "ecdsa"},
		{"Edwards", CKK_EC_EDWARDS, "ed25519"},
		{"AES falls under symmetric", CKK_AES, "symmetric"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			template := []Attribute{NewUint32Attribute(CKA_KEY_TYPE, uint32(tc.keyType))}

			gotType, gotName := unwrapTargetKeyType(template)
			assert.Equal(t, tc.keyType, gotType)
			assert.Equal(t, tc.wantName, gotName)
		})
	}
}

// TestUnwrapTargetKeyType_DefaultsToGenericSecret proves an absent or
// truncated CKA_KEY_TYPE resolves to CKK_GENERIC_SECRET rather than to
// whatever the first bytes of another attribute happen to be.
//
// A CKA_KEY_TYPE shorter than a CK_ULONG is reachable application input, and
// decoding it partially would produce a key type from three bytes of the
// caller's value plus one byte of nothing.
func TestUnwrapTargetKeyType_DefaultsToGenericSecret(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
	}{
		{"attribute absent", []Attribute{NewStringAttribute(CKA_LABEL, "unwrapped")}},
		{"attribute truncated", []Attribute{NewAttribute(CKA_KEY_TYPE, []byte{0x00, 0x00, 0x00})}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotName := unwrapTargetKeyType(tc.template)
			assert.Equal(t, CKK_GENERIC_SECRET, gotType)
			assert.Equal(t, "symmetric", gotName)
		})
	}
}

// TestMechanismToAlgorithm_NamesWrappingMechanisms proves each supported
// key-wrapping mechanism reaches the transport layer under the name that layer
// implements.
//
// The distinctions are not cosmetic. CKM_AES_KEY_WRAP (RFC 3394) and
// CKM_AES_KEY_WRAP_PAD (RFC 5649) produce different ciphertext for the same
// key, and CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP are different padding schemes
// entirely. A wrong name here yields a wrapped key nothing can unwrap.
func TestMechanismToAlgorithm_NamesWrappingMechanisms(t *testing.T) {
	cases := []struct {
		mech MechanismType
		want types.KeyWrapAlgorithm
	}{
		{CKM_AES_KEY_WRAP, types.WrapAESKW},
		{CKM_AES_KEY_WRAP_PAD, types.WrapAESKWP},
		{CKM_AES_GCM, types.WrapAESGCM},
		{CKM_AES_CBC, types.WrapAESCBC},
		{CKM_AES_CBC_PAD, types.WrapAESCBCPad},
		{CKM_RSA_PKCS, types.WrapRSAPKCS1v15},
	}

	for _, tc := range cases {
		t.Run(string(tc.want), func(t *testing.T) {
			assert.Equal(t, string(tc.want), mechanismToAlgorithm(&Mechanism{Type: tc.mech}),
				"the module must emit the canonical algorithm the service accepts")
		})
	}
}

// TestMechanismToAlgorithm_OAEPCarriesTheCallersDigest proves the digest a
// caller selected in CK_RSA_PKCS_OAEP_PARAMS reaches the service inside the
// algorithm name.
//
// The mechanism alone cannot say which digest was chosen, so naming only the
// mechanism forced the service to default one — silently returning SHA-256
// output to a caller who asked for SHA-384.
func TestMechanismToAlgorithm_OAEPCarriesTheCallersDigest(t *testing.T) {
	cases := map[MechanismType]types.KeyWrapAlgorithm{
		CKM_SHA_1:  types.WrapRSAOAEPSHA1,
		CKM_SHA256: types.WrapRSAOAEPSHA256,
		CKM_SHA384: types.WrapRSAOAEPSHA384,
		CKM_SHA512: types.WrapRSAOAEPSHA512,
	}

	for hashMech, want := range cases {
		t.Run(string(want), func(t *testing.T) {
			mech := &Mechanism{
				Type:           CKM_RSA_PKCS_OAEP,
				TypedParameter: &RSAOAEPParams{HashAlg: hashMech},
			}
			assert.Equal(t, string(want), mechanismToAlgorithm(mech))
		})
	}
}

// TestMechanismToAlgorithm_OAEPWithoutParamsKeepsProjectDefault pins the
// deliberate deviation from PKCS#11: the spec's default digest for an absent
// CK_RSA_PKCS_OAEP_PARAMS is SHA-1, but SHA-1 OAEP is refused project-wide, so
// emitting it would turn every parameterless wrap into a rejection.
func TestMechanismToAlgorithm_OAEPWithoutParamsKeepsProjectDefault(t *testing.T) {
	assert.Equal(t, string(types.WrapRSAOAEPSHA256),
		mechanismToAlgorithm(&Mechanism{Type: CKM_RSA_PKCS_OAEP}))
}

// TestMechanismToAlgorithm_UnknownOAEPDigestIsNotSubstituted proves an
// unrecognized digest is NOT quietly replaced with SHA-256. Substituting one
// would hand back a blob the caller cannot unwrap while reporting success; the
// mechanism name it returns instead is refused by the service as unsupported.
func TestMechanismToAlgorithm_UnknownOAEPDigestIsNotSubstituted(t *testing.T) {
	got := mechanismToAlgorithm(&Mechanism{
		Type:           CKM_RSA_PKCS_OAEP,
		TypedParameter: &RSAOAEPParams{HashAlg: CKM_SHA224},
	})
	assert.NotEqual(t, string(types.WrapRSAOAEPSHA256), got)
	assert.Equal(t, GetMechanismName(CKM_RSA_PKCS_OAEP), got)
}

// TestMechanismToAlgorithm_FallsBackToMechanismName proves a mechanism with no
// wrapping-specific name still produces its PKCS#11 name rather than an empty
// string.
//
// An empty algorithm would reach the backend as a request with no algorithm at
// all, which is far harder to diagnose than a request naming a mechanism the
// backend declines to wrap with.
func TestMechanismToAlgorithm_FallsBackToMechanismName(t *testing.T) {
	assert.Equal(t, GetMechanismName(CKM_SHA256), mechanismToAlgorithm(&Mechanism{Type: CKM_SHA256}))
	assert.NotEmpty(t, mechanismToAlgorithm(&Mechanism{Type: CKM_SHA256}))
}

// TestAnyAttributeUnavailable_DetectsWithheldAttributes proves the predicate
// that decides whether a partially-filled C_GetAttributeValue result may be
// reported as CKR_OK.
//
// PKCS#11 v3.2 §5.7.5 requires the library to mark each unavailable attribute
// with a length of -1 and return an error for the call as a whole. Reporting
// CKR_OK while one entry is still withheld would have the application read a
// zero-length value as the attribute's real content.
func TestAnyAttributeUnavailable_DetectsWithheldAttributes(t *testing.T) {
	t.Run("all available", func(t *testing.T) {
		attrs := []Attribute{
			{Type: CKA_LABEL, Value: []byte("label")},
			{Type: CKA_CLASS, Value: []byte{0x02}},
		}
		assert.False(t, anyAttributeUnavailable(attrs))
	})

	t.Run("one withheld", func(t *testing.T) {
		attrs := []Attribute{
			{Type: CKA_LABEL, Value: []byte("label")},
			{Type: CKA_VALUE, Unavailable: true},
		}
		assert.True(t, anyAttributeUnavailable(attrs),
			"a single withheld attribute must fail the whole call (v3.2 §5.7.5)")
	})

	t.Run("empty result", func(t *testing.T) {
		assert.False(t, anyAttributeUnavailable(nil))
	})
}

// TestModule_GetAttributeValue_FetchesBackendKeyMaterial proves CKA_VALUE is
// readable on a backend-generated secret key that permits it.
//
// C_GenerateKey creates the material inside the backend and keeps only a key
// identifier on the object, so the attribute map holds no CKA_VALUE at all.
// Reading the map alone cannot tell "this key has no value" apart from "this
// key's value lives elsewhere", and treating the second as the first reports a
// perfectly readable key as unavailable — a wrapping or export operation that
// should work simply stops working.
func TestModule_GetAttributeValue_FetchesBackendKeyMaterial(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)
	keyHandle := generateExtractableSecretKey(t, m, session, "backend-value-key")

	attrs, rv := m.GetAttributeValue(session, keyHandle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv, "an extractable, non-sensitive secret key must expose CKA_VALUE")
	defer ReleaseAttributes(attrs)

	assert.Empty(t, attrs[0].Value, "the backend's material must stay sealed, not sit in Value")
	require.NotNil(t, attrs[0].Secret)
	assert.Equal(t, len(mockKeyMaterial), attrs[0].ValueLen())

	var got []byte
	require.NoError(t, attrs[0].WithValue(func(v []byte) error {
		got = append([]byte(nil), v...)
		return nil
	}))
	assert.Equal(t, []byte(mockKeyMaterial), got,
		"CKA_VALUE must come back as the material the backend holds")
	assert.False(t, attrs[0].Unavailable)
}

// TestModule_GetAttributeValue_WithholdsProtectedKeyMaterial asserts
// CKR_ATTRIBUTE_SENSITIVE for the two ways a secret key's value is protected.
//
// PKCS#11 v3.2 §4.9 footnote 7 withholds CKA_VALUE whenever CKA_SENSITIVE is
// CK_TRUE or CKA_EXTRACTABLE is CK_FALSE. Both must be checked on the object
// before the backend is asked: a module that consulted only CKA_SENSITIVE
// would export an unextractable key's material the moment its owner forgot to
// also mark it sensitive, and the two attributes exist precisely so that
// either one alone is sufficient protection.
func TestModule_GetAttributeValue_WithholdsProtectedKeyMaterial(t *testing.T) {
	cases := []struct {
		name        string
		sensitive   bool
		extractable bool
	}{
		{"CKA_SENSITIVE is true", true, true},
		{"CKA_EXTRACTABLE is false", false, false},
		{"both protections set", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()

			session := loginAsNormalUser(t, m)

			keyHandle, rv := m.GenerateKey(session, &Mechanism{Type: CKM_AES_KEY_GEN}, []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
				NewStringAttribute(CKA_LABEL, "protected-key"),
				NewAttribute(CKA_VALUE_LEN, valueLenAttribute(32, 8)),
				NewBoolAttribute(CKA_TOKEN, false),
				NewBoolAttribute(CKA_SENSITIVE, tc.sensitive),
				NewBoolAttribute(CKA_EXTRACTABLE, tc.extractable),
			})
			require.Equal(t, CKR_OK, rv)

			_, rv = m.GetAttributeValue(session, keyHandle, []Attribute{{Type: CKA_VALUE}})
			assert.Equal(t, CKR_ATTRIBUTE_SENSITIVE, rv,
				"a protected secret key must never yield CKA_VALUE (v3.2 §4.9 footnote 7)")
		})
	}
}

// TestModule_GetAttributeValue_ReportsBackendRefusalAsSensitive asserts
// CKR_ATTRIBUTE_SENSITIVE when the object's own attributes permit the read but
// the backend declines to release the material.
//
// The two sides apply the same rule independently, and the backend is the
// authority over material it holds. Reporting its refusal as CKR_OK with an
// empty value would hand the application a zero-length key; reporting it as
// CKR_FUNCTION_FAILED would suggest a transient fault worth retrying. The
// honest answer is that the value is not available to be read, which is what
// CKR_ATTRIBUTE_SENSITIVE means.
func TestModule_GetAttributeValue_ReportsBackendRefusalAsSensitive(t *testing.T) {
	client := &exportRefusingClient{mockClient: newMockClient()}

	m, err := New(WithClient(client), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))
	defer m.Finalize()

	session := loginAsNormalUser(t, m)
	keyHandle := generateExtractableSecretKey(t, m, session, "backend-refuses-export")

	_, rv := m.GetAttributeValue(session, keyHandle, []Attribute{{Type: CKA_VALUE}})
	assert.Equal(t, CKR_ATTRIBUTE_SENSITIVE, rv,
		"a backend that refuses to release key material must not read as an empty value")
}

// mockKeyMaterial is the key material the shared mock transport returns from
// ExportKeyMaterial.
const mockKeyMaterial = "mock-key-material-32bytes-------"

// exportRefusingClient is the shared mock transport with one behaviour
// changed: it refuses to release key material, as a backend does for a key it
// considers non-exportable on its own side.
type exportRefusingClient struct {
	*mockClient
}

func (c *exportRefusingClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, &errs.Message{Msg: "backend refuses to export this key"}
}

// generateExtractableSecretKey creates a backend-generated AES key whose
// material the object itself permits reading, so CKA_VALUE has to be fetched
// from the backend rather than read out of the attribute map.
func generateExtractableSecretKey(t *testing.T, m *Module, session SessionHandle, label string) ObjectHandle {
	t.Helper()

	handle, rv := m.GenerateKey(session, &Mechanism{Type: CKM_AES_KEY_GEN}, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE_LEN, valueLenAttribute(32, 8)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	return handle
}

// valueLenAttribute marshals a CKA_VALUE_LEN at the given CK_ULONG width,
// little-endian, as an application's own headers would.
func valueLenAttribute(bytes uint64, width int) []byte {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, bytes)

	return raw[:width]
}
