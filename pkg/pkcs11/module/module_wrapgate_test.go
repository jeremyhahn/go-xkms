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

// wrapGateSecretKey creates a session secret key carrying its own value, so
// C_WrapKey takes the local path and no backend is involved in deciding whether
// the mechanism is acceptable.
func wrapGateSecretKey(t *testing.T, m *Module, session SessionHandle, label string, extra ...Attribute) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
	}
	handle, rv := m.CreateObject(session, append(template, extra...))
	require.Equal(t, CKR_OK, rv, "creating %s must succeed", label)

	// C_WrapKey names its wrapping key to the service by backend key id, so a
	// key that is resident in no backend cannot wrap. The gate tests are about
	// the mechanism flags, not about key residency, so the keys are bound to a
	// backend here rather than each test asserting the residency error instead
	// of the flag it means to exercise.
	bindObjectToBackend(t, m, handle, label)
	return handle
}

// --- CanWrap / CanUnwrap gates ---

// TestWrapKeyRefusesAMechanismWithoutCKF_WRAP proves C_WrapKey asks whether the
// mechanism is one this token wraps with, not merely whether it is a mechanism
// the token has heard of.
//
// CKM_AES_ECB is advertised and carries CKF_ENCRYPT, so it passes
// validateInitMechanism and the local wrap path could encrypt with it perfectly
// well. PKCS#11 v3.2 §5.5 makes CKF_WRAP the flag C_GetMechanismInfo publishes
// for "may be used to wrap keys", and §6.10.4 gives CKM_AES_ECB no such flag.
// Without this gate the token performed a wrap it never advertised, and the
// only thing standing between a caller and an ECB-wrapped key was whichever
// error the encryption path happened to raise later.
func TestWrapKeyRefusesAMechanismWithoutCKF_WRAP(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	// The premise the gate rests on: the mechanism is registered and advertised,
	// so nothing before the gate refuses it.
	desc := GetMechanismDescriptor(CKM_AES_ECB)
	require.NotNil(t, desc)
	require.True(t, desc.Advertised, "CKM_AES_ECB must be advertised for this test to mean anything")
	require.Zero(t, desc.Flags&CKF_WRAP, "CKM_AES_ECB must not carry CKF_WRAP")
	require.NotZero(t, desc.Flags&CKF_ENCRYPT, "CKM_AES_ECB must be able to encrypt, or the gate is untested")

	wrappingKey := wrapGateSecretKey(t, m, session, "ecb-wrapping-key", NewBoolAttribute(CKA_WRAP, true))
	targetKey := wrapGateSecretKey(t, m, session, "ecb-target-key", NewBoolAttribute(CKA_EXTRACTABLE, true))

	_, rv := m.WrapKey(session, &Mechanism{Type: CKM_AES_ECB}, wrappingKey, targetKey)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv,
		"a mechanism without CKF_WRAP must not wrap, however well it encrypts")

	// A mechanism that does carry CKF_WRAP must still work, so the gate is shown
	// to reject on the flag rather than on everything. CKM_AES_GCM is the
	// comparison because, like CKM_AES_ECB, it can encrypt -- the two differ
	// only in CKF_WRAP, which is the whole point.
	require.NotZero(t, GetMechanismDescriptor(CKM_AES_GCM).Flags&CKF_WRAP)
	_, rv = m.WrapKey(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
		wrappingKey, targetKey)
	assert.Equal(t, CKR_OK, rv, "CKM_AES_GCM carries CKF_WRAP and must wrap")
}

// TestUnwrapKeyRefusesAMechanismWithoutCKF_UNWRAP is the C_UnwrapKey half of
// the gate above. CKF_UNWRAP is the flag §5.5 publishes for the reverse
// direction, and CKM_AES_ECB carries it no more than it carries CKF_WRAP.
func TestUnwrapKeyRefusesAMechanismWithoutCKF_UNWRAP(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	require.Zero(t, GetMechanismDescriptor(CKM_AES_ECB).Flags&CKF_UNWRAP,
		"CKM_AES_ECB must not carry CKF_UNWRAP")

	unwrappingKey := wrapGateSecretKey(t, m, session, "ecb-unwrapping-key", NewBoolAttribute(CKA_UNWRAP, true))

	_, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_ECB}, unwrappingKey,
		[]byte("0123456789ABCDEF"), nil)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv,
		"a mechanism without CKF_UNWRAP must not unwrap")
}

// TestEveryRoutedWrapMechanismCarriesItsFlags proves the gate above cannot
// refuse a mechanism the module still routes.
//
// wrapAlgorithmNames is the table that translates a wrapping mechanism into the
// algorithm the service performs. If a mechanism appears there without
// CKF_WRAP, C_WrapKey now rejects a request the routing table was written to
// serve; if the flags were added without the routing, the request reaches
// mechanismToAlgorithm's fallback and the service refuses a name it does not
// know. Both halves have to move together, which is what this asserts.
func TestEveryRoutedWrapMechanismCarriesItsFlags(t *testing.T) {
	// CKM_RSA_PKCS_OAEP is routed by oaepWrapAlgorithm rather than by the table,
	// because its algorithm name depends on CK_RSA_PKCS_OAEP_PARAMS.hashAlg.
	routed := []MechanismType{CKM_RSA_PKCS_OAEP}
	for mechType := range wrapAlgorithmNames {
		routed = append(routed, mechType)
	}

	for _, mechType := range routed {
		name := GetMechanismName(mechType)
		desc := GetMechanismDescriptor(mechType)
		require.NotNil(t, desc, "%s is routed for wrapping but has no descriptor", name)

		assert.True(t, CanWrap(mechType),
			"%s is routed by the wrap tables but lacks CKF_WRAP, so C_WrapKey now refuses it", name)
		assert.True(t, CanUnwrap(mechType),
			"%s is routed by the wrap tables but lacks CKF_UNWRAP, so C_UnwrapKey now refuses it", name)
	}
}

// --- the empty *_TEMPLATE value ---

// TestWrapKeyTreatsAnEmptyWrapTemplateAsUnconstrained proves a wrapping key
// whose CKA_WRAP_TEMPLATE is the empty template can still wrap.
//
// PKCS#11 v3.2 §6.43 makes the empty template CKA_WRAP_TEMPLATE's default and
// it constrains nothing, which is exactly what the attribute validator already
// accepted. The enforcement path disagreed: it decoded the stored value with a
// parser that requires at least a four-byte element count, so a Go caller
// passing NewAttribute(CKA_WRAP_TEMPLATE, nil) got a key that wrapped nothing
// at all -- every C_WrapKey failed with CKR_ATTRIBUTE_VALUE_INVALID rather than
// being unrestricted. A C application never saw it, because the cgo boundary
// emits the canonical zero-count encoding for an empty array.
func TestWrapKeyTreatsAnEmptyWrapTemplateAsUnconstrained(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	target := wrapGateSecretKey(t, m, session, "empty-template-target",
		NewBoolAttribute(CKA_EXTRACTABLE, true))

	// The two spellings of "no constraint": the zero-length value only a Go
	// caller can produce, and the canonical zero-count encoding the C boundary
	// produces. They must behave identically.
	// Each subtest carries its own GCM nonce because both wrapping keys hold
	// the same value, and sealing twice under one (key, IV) pair leaks the XOR
	// of the two plaintexts (NIST SP 800-38D section 8.2).
	//
	// This is hygiene here, not an assertion: C_WrapKey delegates to
	// CryptoManager.WrapKeyByID, which forwards the caller's IV to the backend
	// without consulting any reuse guard, so the pair would in fact be accepted
	// twice on this path. The authenticated wrap verbs do refuse it -- see
	// TestWrapKeyAuthenticatedRefusesAReusedIVUnderOneKey -- and extending the
	// same guard to WrapKeyByID is tracked as a required follow-up on
	// crypto.go.
	for _, spelling := range []struct {
		name  string
		value Attribute
		iv    []byte
	}{
		{"zero-length value", NewAttribute(CKA_WRAP_TEMPLATE, nil), []byte("empty-tmpl-a")},
		{"canonical empty encoding", nestedTemplateAttribute(CKA_WRAP_TEMPLATE), []byte("empty-tmpl-b")},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			wrappingKey := wrapGateSecretKey(t, m, session, "empty-template-"+spelling.name,
				NewBoolAttribute(CKA_WRAP, true), spelling.value)

			_, rv := m.WrapKey(session,
				NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(spelling.iv, 128)),
				wrappingKey, target)
			assert.Equal(t, CKR_OK, rv,
				"an empty CKA_WRAP_TEMPLATE constrains nothing, so the wrap must proceed")
		})
	}
}

// TestWrapKeyStillEnforcesANonEmptyWrapTemplate is the other half: treating the
// empty template as unconstrained must not have made every template
// unconstrained. A key that contradicts a real constraint must still be
// refused with the CKR_KEY_HANDLE_INVALID §5.14.3 requires.
func TestWrapKeyStillEnforcesANonEmptyWrapTemplate(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	wrappingKey := wrapGateSecretKey(t, m, session, "nonempty-template-wrapping",
		NewBoolAttribute(CKA_WRAP, true),
		nestedTemplateAttribute(CKA_WRAP_TEMPLATE, NewBoolAttribute(CKA_SENSITIVE, true)))

	mismatching := wrapGateSecretKey(t, m, session, "nonempty-template-mismatching",
		NewBoolAttribute(CKA_EXTRACTABLE, true), NewBoolAttribute(CKA_SENSITIVE, false))

	_, rv := m.WrapKey(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
		wrappingKey, mismatching)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv,
		"a non-empty CKA_WRAP_TEMPLATE must still partition the wrapping key")
}

// TestUnwrapTemplateEmptyValueAddsNothing proves the same agreement for
// ApplyAttributeTemplate, which serves CKA_UNWRAP_TEMPLATE,
// CKA_DERIVE_TEMPLATE and the two KEM templates. §5.14.4 says a key without the
// attribute adds nothing to the caller's template; a key carrying the empty
// template has nothing to add either, and must not fail instead.
func TestUnwrapTemplateEmptyValueAddsNothing(t *testing.T) {
	caller := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}

	for _, spelling := range []struct {
		name  string
		value []byte
	}{
		{"zero-length value", nil},
		{"canonical empty encoding", EncodeAttributeArray(nil)},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			key := &Object{Attributes: map[AttributeType][]byte{
				CKA_UNWRAP_TEMPLATE: spelling.value,
			}}

			merged, err := key.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE, caller)
			require.NoError(t, err, "an empty constraint template must not fail the merge")
			assert.Equal(t, caller, merged, "an empty constraint template adds no attribute")
		})
	}
}

// TestConstraintTemplateStillRefusesAMalformedValue proves the leniency is
// confined to the empty value. A value that is present but cannot be parsed is
// a constraint the token cannot apply, and storing it unread is the silent
// acceptance the encoding exists to prevent.
func TestConstraintTemplateStillRefusesAMalformedValue(t *testing.T) {
	malformed := map[string][]byte{
		"truncated element count":  {0x01, 0x00},
		"count larger than buffer": {0x09, 0x00, 0x00, 0x00},
		"trailing bytes":           append(EncodeAttributeArray(nil), 0xFF),
	}

	for name, value := range malformed {
		t.Run(name, func(t *testing.T) {
			_, err := decodeConstraintTemplate(value)
			require.Error(t, err)
			assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, FromError(err))

			// The same value must be refused on the way in, so it can never
			// reach an object in the first place.
			assert.Error(t, validateAttributeArrayValue(value))
		})
	}
}

// TestCreateObjectRefusesAMalformedWrapTemplate proves the refusal reaches the
// application-facing entry point and not only the helper.
func TestCreateObjectRefusesAMalformedWrapTemplate(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	_, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "malformed-wrap-template"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		NewAttribute(CKA_WRAP_TEMPLATE, []byte{0x01, 0x00}),
	})
	assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv,
		"a CKA_WRAP_TEMPLATE the token cannot parse must be refused at creation")
}
