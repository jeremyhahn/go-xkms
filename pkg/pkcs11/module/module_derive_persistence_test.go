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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C_DeriveKey and the token store, PKCS#11 v3.2 §5.18.5.
//
// A derived key holds its material in CKA_VALUE and nowhere else: unlike a
// C_UnwrapKey result it names no backend key, so the store has nothing to fall
// back on when it withholds the sensitive attributes of a protected key. A
// CKA_TOKEN derived key that is also CKA_SENSITIVE or non-extractable therefore
// persists as a key-shaped record with no key in it, and comes back after the
// restart as a handle every operation fails on.
//
// The module used to answer CKR_OK and create exactly that. It now refuses the
// combination before deriving, which §5.18.5 requires of a template it cannot
// support: "it will fail and return without creating any key object."

// derivedMaterial is what deriveRecordingClient derives, and what a surviving
// CKA_VALUE must contain after the restart.
var derivedMaterial = bytes.Repeat([]byte{0xA5}, 32)

// storableTokenDerivedTemplate asks for a CKA_TOKEN derived key in the one
// protection state this token can keep: derivedKeyAttributes would otherwise
// inject CKA_SENSITIVE=CK_TRUE and CKA_EXTRACTABLE=CK_FALSE.
func storableTokenDerivedTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_DERIVE, true),
		NewUint32Attribute(CKA_VALUE_LEN, 32),
	}
}

// protectedTokenDerivedTemplate is the same request without the two protection
// attributes, so the defaults derivedKeyAttributes injects apply. This is the
// template that used to persist a shell.
func protectedTokenDerivedTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewUint32Attribute(CKA_VALUE_LEN, 32),
	}
}

// derivableBaseKeyTemplate is a base key the module holds the material for, so a
// derivation needs no backend key of its own.
func derivableBaseKeyTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_VALUE, bytes.Repeat([]byte{0x2B}, 32)),
	}
}

// newPersistentDeriveModule builds a module whose store is the file backend
// rooted at dir and whose transport records what the derivation asked for.
//
// Each call opens the directory for itself, exactly as two runs of a host
// process do; see newPersistentModule for why sharing one open backend would
// not model a restart.
func newPersistentDeriveModule(t *testing.T, dir string) (*Module, *deriveRecordingClient) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.StorageType = StorageTypeFile
	cfg.StoragePath = dir

	client := newDeriveRecordingClient()
	m, err := New(WithClient(client), WithConfig(cfg))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))

	return m, client
}

// TestDeriveKeyTokenKeySurvivesFinalize is the decisive test for the defect.
//
// It cannot be made in memory. Before the fix the module answered every
// C_GetAttributeValue with the derived material right up to C_Finalize, and the
// loss appeared only in what ModuleStorage.SaveObject chose to write. So the
// assertion is made from a second module reading the same files: the key must
// come back with its CKA_VALUE, and it must still work as a key — a record that
// merely satisfies C_FindObjects is the shell this test exists to catch.
func TestDeriveKeyTokenKeySurvivesFinalize(t *testing.T) {
	const (
		soPIN   = "so-pin-derive"
		userPIN = "user-pin-derive"
		label   = "derived-token-key"
	)

	dir := t.TempDir()

	first, _ := newPersistentDeriveModule(t, dir)
	require.Equal(t, CKR_OK, first.InitToken(0, []byte(soPIN), "Derive Token"))

	session, rv := first.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.Login(session, CKU_SO, []byte(soPIN)))
	require.Equal(t, CKR_OK, first.InitPIN(session, []byte(userPIN)))
	require.Equal(t, CKR_OK, first.Logout(session))
	require.Equal(t, CKR_OK, first.Login(session, CKU_USER, []byte(userPIN)))

	base, rv := first.CreateObject(session, derivableBaseKeyTemplate("survives-base"))
	require.Equal(t, CKR_OK, rv)

	derived, rv := first.DeriveKey(session,
		availableDeriveMechanism(), base, storableTokenDerivedTemplate(label))
	require.Equal(t, CKR_OK, rv)

	// The control that makes the point of the restart: in memory the material is
	// present either way, so this assertion would hold even with the defect.
	attrs, rv := first.GetAttributeValue(session, derived, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, derivedMaterial, attrs[0].Value)

	require.Equal(t, CKR_OK, first.CloseSession(session))
	require.Equal(t, CKR_OK, first.Finalize())

	second, client := newPersistentDeriveModule(t, dir)
	defer second.Finalize()

	restored, rv := second.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.Login(restored, CKU_USER, []byte(userPIN)))

	require.Equal(t, CKR_OK, second.FindObjectsInit(restored, []Attribute{
		NewStringAttribute(CKA_LABEL, label),
	}))
	handles, rv := second.FindObjects(restored, 16)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.FindObjectsFinal(restored))
	require.Len(t, handles, 1, "the CKA_TOKEN derived key must be on the token after the restart")

	attrs, rv = second.GetAttributeValue(restored, handles[0], []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, derivedMaterial, attrs[0].Value,
		"a restored derived key must carry the material it was derived with; an empty CKA_VALUE is the shell")

	// Survival is not enough: the restored object has to be a key. Deriving from
	// it sends its material to the backend, which is something only a key with
	// real CKA_VALUE can do.
	_, rv = second.DeriveKey(restored,
		availableDeriveMechanism(), handles[0], derivedKeyTemplate(32))
	require.Equal(t, CKR_OK, rv)
	require.NotNil(t, client.lastDerive)
	assert.Equal(t, derivedMaterial, client.lastDerive.InputKeyMaterial,
		"the restored key must still be usable as key material, not merely findable")
}

// TestDeriveKeyRefusesATokenKeyItCannotPersist is the bad-input half, on both
// derivation paths.
//
// C_DeriveKey returns from inside its mechanism switch for CKM_ECDH1_DERIVE, so
// a guard placed after the switch would cover only the KDF path and the ECDH
// path would keep creating shells. Each case also requires that nothing reached
// the backend: §5.18.5 makes the refusal precede the derivation, and a token
// that derives first has already spent the operation on a key it will discard.
func TestDeriveKeyRefusesATokenKeyItCannotPersist(t *testing.T) {
	t.Run("KDF path", func(t *testing.T) {
		m, client, session := deriveFixture(t)

		base, rv := m.CreateObject(session, derivableBaseKeyTemplate("kdf-refusal-base"))
		require.Equal(t, CKR_OK, rv)

		handle, rv := m.DeriveKey(session,
			availableDeriveMechanism(), base, protectedTokenDerivedTemplate("kdf-refused"))
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, client.lastDerive,
			"the template is refused before the derivation, so nothing may reach the backend")
	})

	t.Run("ECDH path", func(t *testing.T) {
		m, client, session := deriveFixture(t)

		base, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
			NewStringAttribute(CKA_LABEL, "ecdh-refusal-base"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_DERIVE, true),
		})
		require.Equal(t, CKR_OK, rv)

		obj, err := m.objectManager.getObjectUnchecked(base)
		require.NoError(t, err)
		obj.KeyID = "ecdh-refusal-base-id"
		obj.BackendName = "default"

		mechanism := &Mechanism{
			Type:           CKM_ECDH1_DERIVE,
			TypedParameter: &ECDHParams{KDF: CKD_SHA256_KDF, PublicData: validECDHPeerPoint(t)},
		}

		handle, rv := m.DeriveKey(session, mechanism, base, protectedTokenDerivedTemplate("ecdh-refused"))
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, rv)
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
		assert.Nil(t, client.lastDeriveECDHReq,
			"the ECDH derivation must not run for a key the token is about to discard")

		// The positive control on the same path: the storable combination still
		// derives, so the guard is a filter and not a wall.
		handle, rv = m.DeriveKey(session, mechanism, base, storableTokenDerivedTemplate("ecdh-kept"))
		require.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
		assert.NotNil(t, client.lastDeriveECDHReq)
	})
}

// TestDerivedKeyPersistenceErrorNarrowings pins each condition the refusal is
// narrowed by, one case per condition, so that widening any of them turns a
// legal derivation into CKR_TEMPLATE_INCONSISTENT and narrowing any of them
// lets a shell through.
//
// The fallbacks are the subtle part. They are what derivedKeyAttributes injects
// into a template that states neither attribute — CKA_SENSITIVE=CK_TRUE and
// CKA_EXTRACTABLE=CK_FALSE — and not the class defaults applyClassDefaults would
// supply. Reading the class defaults here would make a bare CKA_TOKEN template
// look storable, which is exactly the template that produced the shell.
func TestDerivedKeyPersistenceErrorNarrowings(t *testing.T) {
	valueLen := NewUint32Attribute(CKA_VALUE_LEN, 32)

	cases := []struct {
		name     string
		template []Attribute
		refused  bool
	}{
		{
			name:     "a session key is never written out",
			template: []Attribute{NewBoolAttribute(CKA_TOKEN, false), valueLen},
			refused:  false,
		},
		{
			name:     "an absent CKA_TOKEN is CK_FALSE",
			template: []Attribute{valueLen},
			refused:  false,
		},
		{
			name: "a data object's CKA_VALUE is public content that always persists",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
				NewBoolAttribute(CKA_TOKEN, true),
				valueLen,
			},
			refused: false,
		},
		{
			name:     "a token key defaults to sensitive and unextractable, which is unstorable",
			template: []Attribute{NewBoolAttribute(CKA_TOKEN, true), valueLen},
			refused:  true,
		},
		{
			name: "CKA_SENSITIVE=CK_FALSE alone leaves CKA_EXTRACTABLE at its CK_FALSE default",
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
				valueLen,
			},
			refused: true,
		},
		{
			name: "CKA_EXTRACTABLE=CK_TRUE alone leaves CKA_SENSITIVE at its CK_TRUE default",
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				valueLen,
			},
			refused: true,
		},
		{
			name: "the one storable combination is kept",
			template: []Attribute{
				NewBoolAttribute(CKA_TOKEN, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				valueLen,
			},
			refused: false,
		},
		{
			name: "a private key class is protected the same way",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
				NewBoolAttribute(CKA_TOKEN, true),
				valueLen,
			},
			refused: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := derivedKeyPersistenceError(tc.template)
			if !tc.refused {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, pkcsErr.Code,
				"CKR_TEMPLATE_INCONSISTENT is in C_DeriveKey's return table (v3.2 §5.18.5)")
		})
	}
}
