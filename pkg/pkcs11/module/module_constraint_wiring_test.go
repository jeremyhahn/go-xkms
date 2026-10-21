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

	"github.com/jeremyhahn/go-xkms/pkg/quantum/dilithium2"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
)

// Enforcement wiring for the per-key constraint attributes.
//
// Object.CheckAllowedMechanism, Object.CheckWrapTemplate and
// Object.ApplyAttributeTemplate are unit-tested in object_enforcement_test.go
// against an Object built by hand. That proves the rules; it does not prove any
// operation consults them. These tests drive the module's own entry points, so
// a call site that stops calling a check fails here even though every check
// still passes its own test.
//
// Each entry point is exercised twice: once with a constraint the request
// satisfies, which must succeed, and once with a constraint it violates, which
// must be refused with the code the specification names for that function.

// allowedMechanismsAttribute builds a CKA_ALLOWED_MECHANISMS value
// (PKCS#11 v3.2 §4.8.2) listing exactly the mechanisms named.
func allowedMechanismsAttribute(mechanisms ...MechanismType) Attribute {
	return NewAttribute(CKA_ALLOWED_MECHANISMS, EncodeMechanismList(mechanisms))
}

// nestedTemplateAttribute builds one of the *_TEMPLATE attributes from the
// attributes it constrains.
func nestedTemplateAttribute(attrType AttributeType, constraint ...Attribute) Attribute {
	return NewAttribute(attrType, EncodeAttributeArray(constraint))
}

// createRSAOperationKey creates a private key marked for every operation
// category resolveOperationKey gates, restricted to the mechanisms named.
func createRSAOperationKey(t *testing.T, m *Module, session SessionHandle, label string, extra ...Attribute) ObjectHandle {
	t.Helper()

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_SIGN_RECOVER, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_VERIFY_RECOVER, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
	}
	template = append(template, extra...)

	handle, rv := m.CreateObject(session, template)
	require.Equal(t, CKR_OK, rv)

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	obj.KeyID = label + "-id"
	obj.BackendName = "default"

	return handle
}

// operationInitializer pairs a C_*Init with a second RSA mechanism that
// initializer accepts, for the tests that need a mechanism outside a key's
// CKA_ALLOWED_MECHANISMS but still usable with the key.
//
// The pair is per-initializer rather than one pair for all of them because no
// single registered mechanism carries CKF_SIGN, CKF_VERIFY, CKF_ENCRYPT and
// CKF_DECRYPT at once except CKM_RSA_PKCS, and the sign-recover and
// verify-recover initializers accept CKM_RSA_PKCS alone. CKM_RSA_X_509 used to
// serve the role for every initializer, on the assumption that it was "a
// mechanism the token itself supports"; it is not. Its descriptor claimed all
// four capabilities while the module signed with PKCS#1 v1.5 type-1 block
// padding instead of the raw RSA the mechanism names, so the entry has been
// removed from the registry and the assumption with it. The recover
// initializers therefore invert the pair: they probe with CKM_RSA_PKCS and put
// CKM_SHA256_RSA_PKCS in the allowed list.
type operationInitializer struct {
	initialize func(SessionHandle, *Mechanism, ObjectHandle) CK_RV

	// probe is a mechanism this initializer accepts for an RSA key. It is the
	// mechanism the refusal test passes in.
	probe MechanismType

	// allowed is a different mechanism, the one the refusal test puts in the
	// key's CKA_ALLOWED_MECHANISMS so that probe is outside the list.
	allowed MechanismType
}

// operationInitializers names every C_*Init that resolves its key through
// resolveOperationKey. The Message* initializers delegate to these, so wiring
// the choke point covers them too.
func operationInitializers(m *Module) map[string]operationInitializer {
	return map[string]operationInitializer{
		"C_SignInit":          {m.SignInit, CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS},
		"C_VerifyInit":        {m.VerifyInit, CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS},
		"C_SignRecoverInit":   {m.SignRecoverInit, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS},
		"C_VerifyRecoverInit": {m.VerifyRecoverInit, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS},
		"C_EncryptInit":       {m.EncryptInit, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS},
		"C_DecryptInit":       {m.DecryptInit, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS},
		"C_MessageEncryptInit": {func(s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
			return m.MessageEncryptInit(s, mech, k)
		}, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS},
		"C_MessageDecryptInit": {func(s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
			return m.MessageDecryptInit(s, mech, k)
		}, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS},
	}
}

// TestOperationInitAcceptsAnAllowedMechanism proves the wiring does not refuse
// what CKA_ALLOWED_MECHANISMS permits. Without this half, a check wired to
// reject unconditionally would still pass the rejection test.
func TestOperationInitAcceptsAnAllowedMechanism(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	key := createRSAOperationKey(t, m, session, "allowed-mech-permits",
		allowedMechanismsAttribute(CKM_RSA_PKCS))

	for name, op := range operationInitializers(m) {
		t.Run(name, func(t *testing.T) {
			rv := op.initialize(session, &Mechanism{Type: CKM_RSA_PKCS}, key)
			assert.Equal(t, CKR_OK, rv,
				"CKM_RSA_PKCS is in the key's CKA_ALLOWED_MECHANISMS and must be accepted")
			require.Equal(t, CKR_OK, m.SessionCancel(session, uint64(
				CKF_SIGN|CKF_VERIFY|CKF_ENCRYPT|CKF_DECRYPT|CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT)))
		})
	}
}

// TestOperationInitRefusesAMechanismOutsideTheAllowedList proves every
// initializer that resolves a key through resolveOperationKey consults
// CKA_ALLOWED_MECHANISMS.
//
// Each initializer probes with a mechanism it otherwise accepts for this key
// (operationInitializer.probe) against a key whose list names only a different
// one (operationInitializer.allowed), so the only thing that can refuse it is
// the key's own list. PKCS#11 v3.2 names the refusal CKR_MECHANISM_INVALID:
// "specified mechanism is invalid for this operation".
func TestOperationInitRefusesAMechanismOutsideTheAllowedList(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	unrestricted := createRSAOperationKey(t, m, session, "allowed-mech-absent")

	for name, op := range operationInitializers(m) {
		t.Run(name, func(t *testing.T) {
			restricted := createRSAOperationKey(t, m, session, "allowed-mech-refuses-"+name,
				allowedMechanismsAttribute(op.allowed))

			rv := op.initialize(session, &Mechanism{Type: op.probe}, restricted)
			assert.Equal(t, CKR_MECHANISM_INVALID, rv,
				"%s is absent from the key's CKA_ALLOWED_MECHANISMS",
				GetMechanismName(op.probe))

			// The same call on a key without the attribute must succeed, which
			// is what proves the refusal came from the list and not from the
			// mechanism being unusable here.
			rv = op.initialize(session, &Mechanism{Type: op.probe}, unrestricted)
			assert.Equal(t, CKR_OK, rv,
				"a key without CKA_ALLOWED_MECHANISMS is unrestricted")
			require.Equal(t, CKR_OK, m.SessionCancel(session, uint64(
				CKF_SIGN|CKF_VERIFY|CKF_ENCRYPT|CKF_DECRYPT|CKF_MESSAGE_ENCRYPT|CKF_MESSAGE_DECRYPT)))
		})
	}
}

// TestOperationInitRefusesEveryMechanismWhenTheAllowedListIsEmpty proves the
// absent/empty distinction survives the wiring: an empty CKA_ALLOWED_MECHANISMS
// is a list that permits nothing, not a key without restrictions.
func TestOperationInitRefusesEveryMechanismWhenTheAllowedListIsEmpty(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	key := createRSAOperationKey(t, m, session, "allowed-mech-empty",
		allowedMechanismsAttribute())

	for name, op := range operationInitializers(m) {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, CKR_MECHANISM_INVALID,
				op.initialize(session, &Mechanism{Type: CKM_RSA_PKCS}, key))
		})
	}
}

// TestVerifySignatureInitEnforcesAllowedMechanisms covers C_VerifySignatureInit,
// which resolves its own key rather than going through resolveOperationKey and
// so needs the rule applied at its own call site.
//
// The key carries real ML-DSA-44 material and the request is
// CKM_VENDOR_ML_DSA_44, which this initializer accepts: the unrestricted half
// of the test initializes successfully. Nothing but the key's list can account
// for the restricted half failing, and a synthetic key would not have shown
// that — the initializer refuses malformed key material with the same
// CKR_MECHANISM_INVALID the list produces, so a test built on one cannot tell
// an enforced list from an absent one.
func TestVerifySignatureInitEnforcesAllowedMechanisms(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	signer, err := dilithium2.New()
	require.NoError(t, err)
	publicKey, err := signer.GenerateKeyPair()
	require.NoError(t, err)
	t.Cleanup(signer.Clean)

	verifyKey := func(label string, extra ...Attribute) ObjectHandle {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_DSA)),
			NewStringAttribute(CKA_LABEL, label),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_VERIFY, true),
			NewAttribute(CKA_VALUE, publicKey),
		}
		handle, rv := m.CreateObject(session, append(template, extra...))
		require.Equal(t, CKR_OK, rv)
		return handle
	}

	restricted := verifyKey("verifysig-restricted", allowedMechanismsAttribute(CKM_ML_DSA))
	unrestricted := verifyKey("verifysig-unrestricted")

	signature, err := signer.Sign([]byte("verifysig allowed-mechanisms payload"))
	require.NoError(t, err)

	mechanism := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}

	err = m.VerifySignatureInit(session, mechanism, restricted, signature)
	require.Error(t, err, "CKM_VENDOR_ML_DSA_44 is absent from the key's CKA_ALLOWED_MECHANISMS")
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))

	require.NoError(t, m.VerifySignatureInit(session, mechanism, unrestricted, signature),
		"a key without CKA_ALLOWED_MECHANISMS is unrestricted")
	require.Equal(t, CKR_OK, m.FinishOperation(session, OperationVerifySignature))
}

// TestWrapKeyEnforcesAllowedMechanisms proves C_WrapKey consults the wrapping
// key's CKA_ALLOWED_MECHANISMS.
func TestWrapKeyEnforcesAllowedMechanisms(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-mech-restricted"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		allowedMechanismsAttribute(CKM_AES_GCM),
	})
	require.Equal(t, CKR_OK, rv)
	// C_WrapKey names its wrapping key to the service by backend key id; this
	// test is about CKA_ALLOWED_MECHANISMS, not key residency.
	bindObjectToBackend(t, m, wrappingKey, "wrap-mech-restricted")

	targetKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-mech-target"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
	})
	require.Equal(t, CKR_OK, rv)

	_, rv = m.WrapKey(session, &Mechanism{Type: CKM_AES_CBC}, wrappingKey, targetKey)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv,
		"CKM_AES_CBC is absent from the wrapping key's CKA_ALLOWED_MECHANISMS")

	_, rv = m.WrapKey(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
		wrappingKey, targetKey)
	assert.Equal(t, CKR_OK, rv, "the listed mechanism must still wrap")
}

// TestWrapKeyEnforcesWrapTemplate proves C_WrapKey compares the key it was
// asked to wrap against the wrapping key's CKA_WRAP_TEMPLATE.
//
// PKCS#11 v3.2 §5.14.3: "If any attribute mismatch occurs on an attempt to wrap
// a key then the function SHALL return CKR_KEY_HANDLE_INVALID."
func TestWrapKeyEnforcesWrapTemplate(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-template-partitioned"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		nestedTemplateAttribute(CKA_WRAP_TEMPLATE, NewBoolAttribute(CKA_SENSITIVE, true)),
	})
	require.Equal(t, CKR_OK, rv)
	// C_WrapKey names its wrapping key to the service by backend key id; this
	// test is about CKA_WRAP_TEMPLATE, not key residency.
	bindObjectToBackend(t, m, wrappingKey, "wrap-template-partitioned")

	matching, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-template-matching"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
	})
	require.Equal(t, CKR_OK, rv)

	mismatching, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-template-mismatching"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
	})
	require.Equal(t, CKR_OK, rv)

	gcm := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	_, rv = m.WrapKey(session, gcm, wrappingKey, matching)
	assert.Equal(t, CKR_OK, rv, "a key satisfying CKA_WRAP_TEMPLATE must wrap")

	_, rv = m.WrapKey(session, gcm, wrappingKey, mismatching)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv,
		"a key contradicting CKA_WRAP_TEMPLATE must not wrap")
}

// TestUnwrapKeyAppliesUnwrapTemplate proves C_UnwrapKey merges the unwrapping
// key's CKA_UNWRAP_TEMPLATE into the caller's template, and refuses a template
// that contradicts it (PKCS#11 v3.2 §5.14.4).
func TestUnwrapKeyAppliesUnwrapTemplate(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	unwrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrap-template-key"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		nestedTemplateAttribute(CKA_UNWRAP_TEMPLATE, NewBoolAttribute(CKA_EXTRACTABLE, false)),
	})
	require.Equal(t, CKR_OK, rv)

	unwrapObj, err := m.objectManager.getObjectUnchecked(unwrappingKey)
	require.NoError(t, err)
	unwrapObj.KeyID = "unwrap-template-key-id"
	unwrapObj.BackendName = "default"

	gcm := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128))

	baseTemplate := func() []Attribute {
		return []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewBoolAttribute(CKA_TOKEN, false),
		}
	}

	// The constraint is added to a template that says nothing about
	// CKA_EXTRACTABLE, so the unwrapped key must come out non-extractable even
	// though §5.18.4's own default for C_UnwrapKey is CK_TRUE.
	handle, rv := m.UnwrapKey(session, gcm, unwrappingKey, make([]byte, 32), baseTemplate())
	require.Equal(t, CKR_OK, rv)

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_EXTRACTABLE}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, attrs, 1)
	assert.Equal(t, []byte{0}, attrs[0].Value,
		"CKA_UNWRAP_TEMPLATE must have added CKA_EXTRACTABLE=CK_FALSE")

	// A template that contradicts the constraint is a conflict, not a merge.
	conflicting := append(baseTemplate(), NewBoolAttribute(CKA_EXTRACTABLE, true))
	_, rv = m.UnwrapKey(session, gcm, unwrappingKey, make([]byte, 32), conflicting)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv)

	// Agreeing with the constraint is not a conflict.
	agreeing := append(baseTemplate(), NewBoolAttribute(CKA_EXTRACTABLE, false))
	_, rv = m.UnwrapKey(session, gcm, unwrappingKey, make([]byte, 32), agreeing)
	assert.Equal(t, CKR_OK, rv)
}

// TestUnwrapKeyEnforcesAllowedMechanisms proves C_UnwrapKey consults the
// unwrapping key's CKA_ALLOWED_MECHANISMS.
func TestUnwrapKeyEnforcesAllowedMechanisms(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	unwrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrap-mech-restricted"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
		allowedMechanismsAttribute(CKM_AES_GCM),
	})
	require.Equal(t, CKR_OK, rv)

	unwrapObj, err := m.objectManager.getObjectUnchecked(unwrappingKey)
	require.NoError(t, err)
	unwrapObj.KeyID = "unwrap-mech-restricted-id"
	unwrapObj.BackendName = "default"

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	_, rv = m.UnwrapKey(session, &Mechanism{Type: CKM_AES_CBC}, unwrappingKey, make([]byte, 32), template)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv)

	_, rv = m.UnwrapKey(session,
		NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(testGCMIV(), 128)),
		unwrappingKey, make([]byte, 32), template)
	assert.Equal(t, CKR_OK, rv)
}

// TestDeriveKeyEnforcesAllowedMechanisms proves C_DeriveKey consults the base
// key's CKA_ALLOWED_MECHANISMS.
func TestDeriveKeyEnforcesAllowedMechanisms(t *testing.T) {
	m, _, session := deriveFixture(t)
	listed := availableDeriveMechanism()

	base, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, "derive-mech-restricted"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
		allowedMechanismsAttribute(listed.Type),
	})
	require.Equal(t, CKR_OK, rv)

	_, rv = m.DeriveKey(session, &Mechanism{Type: CKM_SP800_108_FEEDBACK_KDF}, base, derivedKeyTemplate(32))
	assert.Equal(t, CKR_MECHANISM_INVALID, rv,
		"CKM_SP800_108_FEEDBACK_KDF is absent from the base key's CKA_ALLOWED_MECHANISMS")

	_, rv = m.DeriveKey(session, listed, base, derivedKeyTemplate(32))
	assert.Equal(t, CKR_OK, rv, "the listed mechanism must still derive")
}

// TestDeriveKeyAppliesDeriveTemplate proves C_DeriveKey merges the base key's
// CKA_DERIVE_TEMPLATE into the caller's template on the KDF path, and refuses a
// template that contradicts it (PKCS#11 v3.2 §5.15.1).
func TestDeriveKeyAppliesDeriveTemplate(t *testing.T) {
	m, _, session := deriveFixture(t)

	base, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, "derive-template-base"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
		nestedTemplateAttribute(CKA_DERIVE_TEMPLATE, NewStringAttribute(CKA_LABEL, "constrained")),
	})
	require.Equal(t, CKR_OK, rv)

	handle, rv := m.DeriveKey(session, availableDeriveMechanism(), base, derivedKeyTemplate(32))
	require.Equal(t, CKR_OK, rv)

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_LABEL}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, attrs, 1)
	assert.Equal(t, "constrained", string(attrs[0].Value),
		"CKA_DERIVE_TEMPLATE must have added its CKA_LABEL to the derived key")

	conflicting := append(derivedKeyTemplate(32), NewStringAttribute(CKA_LABEL, "caller-chosen"))
	_, rv = m.DeriveKey(session, availableDeriveMechanism(), base, conflicting)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv,
		"a caller label contradicting CKA_DERIVE_TEMPLATE is a conflict")
}

// TestDeriveKeyAppliesDeriveTemplateOnTheECDHPath proves the merge reaches the
// second CreateDerivedObject call as well. C_DeriveKey returns from inside its
// mechanism switch for CKM_ECDH1_DERIVE, so a merge placed after the switch
// would silently skip every ECDH derivation.
func TestDeriveKeyAppliesDeriveTemplateOnTheECDHPath(t *testing.T) {
	m, _, session := deriveFixture(t)

	base, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
		NewStringAttribute(CKA_LABEL, "derive-template-ecdh-base"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DERIVE, true),
		nestedTemplateAttribute(CKA_DERIVE_TEMPLATE, NewStringAttribute(CKA_LABEL, "ecdh-constrained")),
	})
	require.Equal(t, CKR_OK, rv)

	obj, err := m.objectManager.getObjectUnchecked(base)
	require.NoError(t, err)
	obj.KeyID = "derive-template-ecdh-base-id"
	obj.BackendName = "default"

	mechanism := &Mechanism{
		Type: CKM_ECDH1_DERIVE,
		TypedParameter: &ECDHParams{
			KDF:        CKD_SHA256_KDF,
			PublicData: validECDHPeerPoint(t),
		},
	}

	handle, rv := m.DeriveKey(session, mechanism, base, derivedKeyTemplate(32))
	require.Equal(t, CKR_OK, rv)

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_LABEL}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, attrs, 1)
	assert.Equal(t, "ecdh-constrained", string(attrs[0].Value),
		"CKA_DERIVE_TEMPLATE must reach the ECDH derivation too")

	conflicting := append(derivedKeyTemplate(32), NewStringAttribute(CKA_LABEL, "caller-chosen"))
	_, rv = m.DeriveKey(session, mechanism, base, conflicting)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv)
}

// TestAuthenticatedWrapEnforcesWrapTemplateAndAllowedMechanisms covers
// C_WrapKeyAuthenticated and its size query. The size query is checked because
// an application sizes its buffer from it: if it answers CKR_OK for a wrap the
// token will refuse, the application allocates for a call that can only fail.
func TestAuthenticatedWrapEnforcesWrapTemplateAndAllowedMechanisms(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authwrap-constrained"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
		allowedMechanismsAttribute(CKM_AES_GCM),
		nestedTemplateAttribute(CKA_WRAP_TEMPLATE, NewBoolAttribute(CKA_SENSITIVE, true)),
	})
	require.Equal(t, CKR_OK, rv)

	matching, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authwrap-matching"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	})
	require.Equal(t, CKR_OK, rv)

	mismatching, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authwrap-mismatching"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	})
	require.Equal(t, CKR_OK, rv)

	gcm := &Mechanism{Type: CKM_AES_GCM}

	wrapped, err := m.WrapKeyAuthenticated(session, gcm, wrappingKey, matching, nil)
	require.NoError(t, err, "a key satisfying CKA_WRAP_TEMPLATE must wrap")
	assert.NotEmpty(t, wrapped)

	size, err := m.WrapKeyAuthenticatedSize(session, gcm, wrappingKey, matching)
	require.NoError(t, err)
	assert.Positive(t, size)

	_, err = m.WrapKeyAuthenticated(session, gcm, wrappingKey, mismatching, nil)
	require.Error(t, err)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, FromError(err))

	_, err = m.WrapKeyAuthenticatedSize(session, gcm, wrappingKey, mismatching)
	require.Error(t, err, "the size query must refuse what the wrap would refuse")
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, FromError(err))
}

// TestAuthenticatedWrapRefusesAMechanismOutsideTheAllowedList proves the
// CKA_ALLOWED_MECHANISMS check reaches both authenticated-wrap entry points.
//
// CKM_AES_GCM is the only mechanism C_WrapKeyAuthenticated accepts at all, so
// the constraint is written to permit something else; the refusal must then
// come from the key's list rather than from the mechanism check that precedes
// it.
func TestAuthenticatedWrapRefusesAMechanismOutsideTheAllowedList(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authwrap-mech-refused"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
		allowedMechanismsAttribute(CKM_AES_KEY_WRAP),
	})
	require.Equal(t, CKR_OK, rv)

	target, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authwrap-mech-target"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	})
	require.Equal(t, CKR_OK, rv)

	gcm := &Mechanism{Type: CKM_AES_GCM}

	_, err := m.WrapKeyAuthenticated(session, gcm, wrappingKey, target, nil)
	require.Error(t, err)
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))

	_, err = m.WrapKeyAuthenticatedSize(session, gcm, wrappingKey, target)
	require.Error(t, err)
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))

	_, err = m.UnwrapKeyAuthenticated(session, gcm, wrappingKey, make([]byte, 64), []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
	}, nil)
	require.Error(t, err)
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))
}

// TestUnwrapKeyAuthenticatedAppliesUnwrapTemplate proves
// C_UnwrapKeyAuthenticated merges the unwrapping key's CKA_UNWRAP_TEMPLATE and
// refuses a template that contradicts it.
func TestUnwrapKeyAuthenticatedAppliesUnwrapTemplate(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyValue := createAESKey(t)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authunwrap-template-key"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, keyValue),
		nestedTemplateAttribute(CKA_UNWRAP_TEMPLATE, NewStringAttribute(CKA_LABEL, "constrained")),
	})
	require.Equal(t, CKR_OK, rv)

	target, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "authunwrap-template-target"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, createAESKey(t)),
	})
	require.Equal(t, CKR_OK, rv)

	gcm := &Mechanism{Type: CKM_AES_GCM}
	wrapped, err := m.WrapKeyAuthenticated(session, gcm, wrappingKey, target, nil)
	require.NoError(t, err)

	unwrapped, err := m.UnwrapKeyAuthenticated(session, gcm, wrappingKey, wrapped, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, false),
	}, nil)
	require.NoError(t, err)

	attrs, rv := m.GetAttributeValue(session, unwrapped, []Attribute{{Type: CKA_LABEL}})
	require.Equal(t, CKR_OK, rv)
	require.Len(t, attrs, 1)
	assert.Equal(t, "constrained", string(attrs[0].Value))

	_, err = m.UnwrapKeyAuthenticated(session, gcm, wrappingKey, wrapped, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewStringAttribute(CKA_LABEL, "caller-chosen"),
	}, nil)
	require.Error(t, err)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, FromError(err))
}

// TestKEMEnforcesAllowedMechanisms proves C_EncapsulateKey, C_DecapsulateKey
// and the ciphertext-size query all consult CKA_ALLOWED_MECHANISMS.
func TestKEMEnforcesAllowedMechanisms(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	publicKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-mech-public"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
		allowedMechanismsAttribute(CKM_VENDOR_ML_KEM_768_ENCAPSULATE),
	})
	require.Equal(t, CKR_OK, rv)

	privateKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-mech-private"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
		allowedMechanismsAttribute(CKM_VENDOR_ML_KEM_768_DECAPSULATE),
	})
	require.Equal(t, CKR_OK, rv)

	mlkem := &Mechanism{Type: CKM_ML_KEM}

	_, _, err := m.EncapsulateKey(session, mlkem, publicKey, nil)
	require.Error(t, err, "CKM_ML_KEM is absent from the public key's CKA_ALLOWED_MECHANISMS")
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))

	_, err = m.KEMCiphertextSize(session, mlkem, publicKey)
	require.Error(t, err, "the size query must refuse what the encapsulation would refuse")
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))

	_, err = m.DecapsulateKey(session, mlkem, privateKey, nil, make([]byte, MLKEM768CiphertextSize))
	require.Error(t, err, "CKM_ML_KEM is absent from the private key's CKA_ALLOWED_MECHANISMS")
	assert.Equal(t, CKR_MECHANISM_INVALID, FromError(err))
}

// TestKEMAcceptsAnAllowedMechanism proves the KEM checks do not refuse what the
// list permits: a size query for a key whose list names CKM_ML_KEM succeeds.
func TestKEMAcceptsAnAllowedMechanism(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	publicKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-mech-permitted"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, make([]byte, MLKEM768PublicKeySize)),
		allowedMechanismsAttribute(CKM_ML_KEM),
	})
	require.Equal(t, CKR_OK, rv)

	size, err := m.KEMCiphertextSize(session, &Mechanism{Type: CKM_ML_KEM}, publicKey)
	require.NoError(t, err)
	assert.Equal(t, uint64(MLKEM768CiphertextSize), size)
}

// TestKEMAppliesEncapsulateAndDecapsulateTemplates proves C_EncapsulateKey and
// C_DecapsulateKey merge the KEM key's CKA_ENCAPSULATE_TEMPLATE and
// CKA_DECAPSULATE_TEMPLATE into the caller's template for the shared secret,
// and refuse a template that contradicts either.
//
// Real ML-KEM-768 material is used because both functions create their output
// object only after the KEM itself succeeds: synthetic key bytes fail inside
// the crypto backend, and a test built on them would never reach the merge it
// claims to cover.
func TestKEMAppliesEncapsulateAndDecapsulateTemplates(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	kem, err := kyber768.New()
	require.NoError(t, err)
	publicKey, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	seed := kem.ExportSecretKey()
	t.Cleanup(kem.Clean)

	pubHandle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-template-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, publicKey),
		nestedTemplateAttribute(CKA_ENCAPSULATE_TEMPLATE, NewStringAttribute(CKA_LABEL, "encap-constrained")),
	})
	require.Equal(t, CKR_OK, rv)

	privHandle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "kem-template-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, seed),
		nestedTemplateAttribute(CKA_DECAPSULATE_TEMPLATE, NewStringAttribute(CKA_LABEL, "decap-constrained")),
	})
	require.Equal(t, CKR_OK, rv)

	secretTemplate := func(extra ...Attribute) []Attribute {
		return append([]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewBoolAttribute(CKA_SENSITIVE, false),
		}, extra...)
	}

	encMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	encHandle, ciphertext, err := m.EncapsulateKey(session, encMech, pubHandle, secretTemplate())
	require.NoError(t, err)

	encAttrs, encRV := m.GetAttributeValue(session, encHandle, []Attribute{{Type: CKA_LABEL}})
	require.Equal(t, CKR_OK, encRV)
	require.Len(t, encAttrs, 1)
	assert.Equal(t, "encap-constrained", string(encAttrs[0].Value),
		"CKA_ENCAPSULATE_TEMPLATE must have added its CKA_LABEL to the shared secret")

	_, _, err = m.EncapsulateKey(session, encMech, pubHandle,
		secretTemplate(NewStringAttribute(CKA_LABEL, "caller-chosen")))
	require.Error(t, err)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, FromError(err))

	decMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}
	decHandle, err := m.DecapsulateKey(session, decMech, privHandle, secretTemplate(), ciphertext)
	require.NoError(t, err)

	decAttrs, decRV := m.GetAttributeValue(session, decHandle, []Attribute{{Type: CKA_LABEL}})
	require.Equal(t, CKR_OK, decRV)
	require.Len(t, decAttrs, 1)
	assert.Equal(t, "decap-constrained", string(decAttrs[0].Value),
		"CKA_DECAPSULATE_TEMPLATE must have added its CKA_LABEL to the shared secret")

	_, err = m.DecapsulateKey(session, decMech, privHandle,
		secretTemplate(NewStringAttribute(CKA_LABEL, "caller-chosen")), ciphertext)
	require.Error(t, err)
	assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, FromError(err))
}
