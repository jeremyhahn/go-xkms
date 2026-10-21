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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Durability of the C_UnwrapKeyAuthenticated result.
//
// PKCS#11 v3.2 section 4.4 defines a token object as one that "remains on the
// token until specifically destroyed". This verb decrypts in process and puts
// the recovered material straight into CKA_VALUE, naming no backend copy, so
// the object it creates is the only place that key exists -- which makes both
// halves of storing it load-bearing:
//
//   - a CKA_TOKEN result has to be written to the store, or the application is
//     told it holds a key that is gone at the next C_Initialize;
//   - a CKA_TOKEN result the store would only accept as a shell has to be
//     refused, because ModuleStorage.SaveObject withholds CKA_VALUE from a key
//     that protects its material, and persisting one is how the protection
//     takes effect by erasing the key.
//
// The first is unobservable in a single process -- the object is in memory and
// answers every query correctly right up to C_Finalize -- so the test for it
// has to bring a second module up over the same files.

// authWrapPersistenceFixture provisions a module over dir, creates an AES KEK
// and an extractable target key holding material, and returns the session, the
// KEK handle and a wrapped blob together with the mechanism that produced it.
//
// The IV is freshly random on every call because the AES-GCM reuse guard is
// process-wide and keyed by key material: two fixtures sharing a KEK value
// would otherwise have the second wrap refused as a repeat, which is the guard
// working rather than the test failing.
func authWrapPersistenceFixture(t *testing.T, m *Module, kek, material []byte, label string) (SessionHandle, ObjectHandle, *Mechanism, []byte) {
	t.Helper()

	require.True(t, validAESKeySize(len(kek)),
		"the fixture's KEK must be a legal AES key length, or every wrap below fails for that reason instead")

	session := loginAsNormalUser(t, m)
	wrappingKey, targetKey := authWrapKeyPair(t, m, session, label, kek, material)

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(callerIVOutsideFIPS(uniqueTestIV(t)), 128))
	blob, err := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
	require.NoError(t, err)

	return session, wrappingKey, mech, blob
}

// TestUnwrapKeyAuthenticatedTokenKeySurvivesFinalize is the restart test: a key
// unwrapped with CKA_TOKEN=CK_TRUE must still be on the token, with its
// material, after C_Finalize and a fresh C_Initialize over the same store.
//
// Before the store call was wired in, the key reported CKA_TOKEN=CK_TRUE for
// the life of the process and C_FindObjects returned nothing for it after the
// restart. Reading the attribute back inside the first process cannot catch
// that, so the assertion is made against a second module reading the same
// files, and it is made on CKA_VALUE rather than on the handle count: an object
// restored as a shell would satisfy C_FindObjects and then fail every use.
//
// The session-object half is the control that keeps this from passing for the
// wrong reason. A module that persisted every unwrapped key regardless of
// CKA_TOKEN would satisfy the survival assertion and violate section 4.4 in the
// other direction, so a second key unwrapped without CKA_TOKEN must be absent
// after the same restart.
func TestUnwrapKeyAuthenticatedTokenKeySurvivesFinalize(t *testing.T) {
	const (
		tokenLabel   = "authwrap-unwrapped-token-key"
		sessionLabel = "authwrap-unwrapped-session-key"
	)

	dir := t.TempDir()
	kek := []byte("authwrap-persist-KEK-32-bytes!!!") // AES-256
	material := []byte("unwrapped-secret")            // AES-128 payload

	first := newPersistentModule(t, dir)
	session, wrappingKey, mech, blob := authWrapPersistenceFixture(t, first, kek, material, "persist")

	tokenHandle, err := first.UnwrapKeyAuthenticated(session, mech, wrappingKey, blob, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, tokenLabel),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
	}, nil)
	require.NoError(t, err)

	attrs, rv := first.GetAttributeValue(session, tokenHandle, []Attribute{{Type: CKA_TOKEN}})
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, byte(1), attrs[0].Value[0], "the fixture must actually have asked for a token object")

	sessionKeyHandle, err := first.UnwrapKeyAuthenticated(session, mech, wrappingKey, blob, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, sessionLabel),
		NewBoolAttribute(CKA_PRIVATE, false),
	}, nil)
	require.NoError(t, err)
	assert.NotEqual(t, tokenHandle, sessionKeyHandle)

	require.Equal(t, CKR_OK, first.CloseSession(session))
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()
	restoredSession := loginAsNormalUser(t, second)

	restored := findObjectByLabel(t, second, restoredSession, tokenLabel)
	require.Len(t, restored, 1,
		"a CKA_TOKEN key unwrapped before the restart must be on the token after it")

	restoredAttrs, rv := second.GetAttributeValue(restoredSession, restored[0], []Attribute{
		{Type: CKA_VALUE},
		{Type: CKA_KEY_TYPE},
	})
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, material, restoredAttrs[0].Value,
		"the restored key must carry the unwrapped material, not an empty shell")
	assert.Equal(t, uint32(CKK_AES), uint32(restoredAttrs[1].Value[0]),
		"CKA_KEY_TYPE must survive the restart with the value")

	assert.Empty(t, findObjectByLabel(t, second, restoredSession, sessionLabel),
		"a key unwrapped without CKA_TOKEN is a session object and must not outlive the module")
}

// TestUnwrapKeyAuthenticatedRefusesAKeyItCouldNotGiveBack covers the gate in
// front of the object creation.
//
// SaveObject withholds every attribute IsSensitiveAttribute names -- CKA_VALUE
// among them -- from a key object that protects its material, and this verb's
// result holds its material nowhere else. Asking for a key that is both kept
// and protected therefore stores a key-shaped shell, so the combination is
// refused with CKR_TEMPLATE_INCONSISTENT (v3.2 section 5.1: a template carrying
// conflicting attributes) instead of being written.
//
// The two accepted cases are the controls. A gate that refused every CKA_TOKEN
// unwrap, or every protected one, would satisfy the refusals alone and make the
// verb useless for the storable combination that is also its default.
func TestUnwrapKeyAuthenticatedRefusesAKeyItCouldNotGiveBack(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	kek := []byte("authwrap-gate-KEK-aes256-32bytes")
	material := []byte("gate-secret-mat!")
	session, wrappingKey, mech, blob := authWrapPersistenceFixture(t, m, kek, material, "gate")

	// One wrap serves every case below: unwrapping does not consume an IV, so
	// the reuse guard is not involved on this side.
	base := func(label string, extra ...Attribute) []Attribute {
		tmpl := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, label),
			NewBoolAttribute(CKA_PRIVATE, false),
		}
		return append(tmpl, extra...)
	}

	for _, tc := range []struct {
		name     string
		template []Attribute
		refused  bool
	}{
		{
			name: "token key asked to be sensitive",
			template: base("gate-token-sensitive",
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, true)),
			refused: true,
		},
		{
			name: "token key asked to be unextractable",
			template: base("gate-token-unextractable",
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_EXTRACTABLE, false)),
			refused: true,
		},
		{
			name: "token key stating neither attribute is storable whole",
			template: base("gate-token-plain",
				NewBoolAttribute(CKA_TOKEN, true)),
			refused: false,
		},
		{
			name: "session key may be protected because it is never written out",
			template: base("gate-session-sensitive",
				NewBoolAttribute(CKA_SENSITIVE, true),
				NewBoolAttribute(CKA_EXTRACTABLE, false)),
			refused: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := m.UnwrapKeyAuthenticated(session, mech, wrappingKey, blob, tc.template, nil)

			if !tc.refused {
				require.NoError(t, err)
				assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
				return
			}

			require.Error(t, err)
			assert.Equal(t, ObjectHandle(InvalidHandle), handle,
				"a refused unwrap must hand back no handle")
			assert.True(t, errorHasCode(err, CKR_TEMPLATE_INCONSISTENT),
				"the caller has to change the template, so the code names the template: got %v", err)
		})
	}
}

// TestUnwrappedKeyPersistenceErrorResolvesSensitiveByClass pins the fallback
// this gate uses for a template that states no CKA_SENSITIVE at all.
//
// The value cannot be a fixed CK_FALSE the way it is on the KEM path, because
// the class there is always the one buildSecretKeyTemplate produced, while this
// verb resolves its class through unwrapTargetClass and it may be
// CKO_PRIVATE_KEY. applyClassDefaults makes a private key CKA_SENSITIVE by
// default (v3.2 section 4.9: a token that protects key material chooses the
// protective value), so a private-key unwrap that states neither attribute
// becomes sensitive after the gate has run -- and a gate that assumed CK_FALSE
// would wave through exactly the token private key whose stored form is a
// shell.
//
// The function is exercised directly because the distinction is in the class
// fallback rather than in anything the object store does, and because the
// private-key case has to be stated both ways: refused when the template is
// silent, allowed when the template says CK_FALSE. A gate that simply refused
// every private key would pass the first and fail the second.
func TestUnwrappedKeyPersistenceErrorResolvesSensitiveByClass(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template []Attribute
		refused  bool
	}{
		{
			name: "session object is never written out",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			},
			refused: false,
		},
		{
			name: "token private key silent on CKA_SENSITIVE defaults to protected",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
			},
			refused: true,
		},
		{
			name: "token private key that opts out of protection is storable",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
			},
			refused: false,
		},
		{
			name: "token secret key silent on CKA_SENSITIVE defaults to storable",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
			},
			refused: false,
		},
		{
			name: "token secret key that opts in to protection is refused",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, true),
			},
			refused: true,
		},
		{
			name: "token key that opts out of extraction is refused whatever its class",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_EXTRACTABLE, false),
			},
			refused: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := unwrappedKeyPersistenceError(tc.template)

			if !tc.refused {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.True(t, errorHasCode(err, CKR_TEMPLATE_INCONSISTENT), "got %v", err)
		})
	}
}

// TestUnwrapKeyAuthenticatedReportsAStoreThatRefusesTheKey covers the other
// half of the durability fix: when the store refuses the write, the call must
// fail rather than return a handle to an object that is not on the token.
//
// CKR_DEVICE_ERROR is the code, because the template was valid and the token
// itself could not carry out the request. The object must also be gone: one
// left behind in memory would be findable for the life of the process and
// absent from the next one, which is the divergence between what the token
// reports and what it holds that failing the call exists to prevent.
//
// The accepting-store case in the same test is the control. A verb that
// answered CKR_DEVICE_ERROR to every CKA_TOKEN unwrap would satisfy the
// assertion above while making the durable case unreachable.
func TestUnwrapKeyAuthenticatedReportsAStoreThatRefusesTheKey(t *testing.T) {
	const label = "authwrap-rejected-token-key"

	unwrapTokenKey := func(t *testing.T, m *Module) (ObjectHandle, SessionHandle, error) {
		t.Helper()

		kek := []byte("authwrap-store-KEK-aes256-32byte")
		material := []byte("store-secret-mat")
		session, wrappingKey, mech, blob := authWrapPersistenceFixture(t, m, kek, material, "store")

		handle, err := m.UnwrapKeyAuthenticated(session, mech, wrappingKey, blob, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, label),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_PRIVATE, false),
		}, nil)

		return handle, session, err
	}

	t.Run("a store that refuses the write fails the call", func(t *testing.T) {
		// Zero object writes are honoured. The fixture's own keys are session
		// objects, which are never written out, so the unwrapped token key is
		// the first write the store sees.
		m := newRejectingStoreModule(t, 0)
		defer m.Finalize()

		handle, _, err := unwrapTokenKey(t, m)
		require.Error(t, err, "an unwrapped token key the store would not take must not be reported as created")
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.True(t, errorHasCode(err, CKR_DEVICE_ERROR),
			"the template was valid and the token could not carry out the request: got %v", err)
		assert.ErrorIs(t, err, errObjectWriteRejected, "the failure must unwrap to the store's own refusal")
	})

	t.Run("the object is rolled back rather than left behind", func(t *testing.T) {
		m := newRejectingStoreModule(t, 0)
		defer m.Finalize()

		_, session, err := unwrapTokenKey(t, m)
		require.Error(t, err)

		assert.Empty(t, findObjectByLabel(t, m, session, label),
			"an object the store refused must not remain findable in this process")
	})

	t.Run("a store that accepts the write returns the key", func(t *testing.T) {
		m := newRejectingStoreModule(t, 1)
		defer m.Finalize()

		handle, session, err := unwrapTokenKey(t, m)
		require.NoError(t, err)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
		assert.Len(t, findObjectByLabel(t, m, session, label), 1)
	})
}
