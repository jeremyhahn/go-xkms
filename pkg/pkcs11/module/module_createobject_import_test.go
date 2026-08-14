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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C_CreateObject's key import, PKCS#11 v3.2 §5.7.1.
//
// A secret key an application supplies with CKA_VALUE is imported into the
// backend and given a key id, which is what makes it a key the token holds
// rather than an attribute map in this process. Everything the service resolves
// by (backend, key id) depends on it: C_WrapKey and C_UnwrapKey refuse a KEK
// without one outright, and C_Encrypt, C_Decrypt and C_Sign fail their own key
// lookups.
//
// The rules are asserted here one at a time, because each is a decision that
// could plausibly have gone the other way and none of them is visible from a
// call's return code alone -- C_CreateObject answers CKR_OK either way.

// errImportRefused stands for a backend that will not run the import ceremony.
var errImportRefused = errors.New("module: test backend refuses key import")

// importFixture returns a logged-in module whose transport is a mockClient
// running the real import ceremony, and the client itself.
func importFixture(t *testing.T) (*Module, *mockClient, SessionHandle) {
	t.Helper()

	client := newMockClient()
	m := initializeTestModule(t)
	m.cryptoManager.client = client
	session := loginAsNormalUser(t, m)

	return m, client, session
}

// importedSecretKeyTemplate is an extractable AES secret key carrying material.
func importedSecretKeyTemplate(label string, value []byte) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, value),
	}
}

// TestCreateObjectImportsSecretKeyMaterial is the success case: the key reaches
// the backend, wrapped, and the object records where it went.
func TestCreateObjectImportsSecretKeyMaterial(t *testing.T) {
	value := []byte("0123456789ABCDEF0123456789ABCDEF")

	m, client, session := importFixture(t)
	defer m.Finalize()

	handle, rv := m.CreateObject(session, importedSecretKeyTemplate("imported-secret", value))
	require.Equal(t, CKR_OK, rv)

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	assert.NotEmpty(t, obj.KeyID, "an imported key must record the id the backend gave it")
	assert.Equal(t, m.cryptoManager.config.DefaultBackend, obj.BackendName,
		"an imported key must record which backend holds it, or nothing can resolve the id")

	require.True(t, client.importParamsCalled,
		"the module must obtain the backend's wrapping key rather than invent one")
	require.True(t, client.importKeyCalled)

	// The ceremony is the reason this is acceptable for a TPM, an HSM or a
	// cloud KMS: what crosses the transport is ciphertext.
	require.NotNil(t, client.lastImportKeyReq)
	assert.NotEqual(t, value, client.lastImportKeyReq.WrappedKeyMaterial,
		"key material must never cross the transport in plaintext")
	assert.Equal(t, value, client.importedMaterial[obj.KeyID],
		"the backend must end up holding exactly the bytes the template supplied")

	// KeySize, not AESKeySize: only KeySize survives the gRPC transport, so
	// sending the size in the other field would make the same call behave
	// differently over gRPC than over the unix socket.
	assert.Equal(t, 256, client.lastImportKeyReq.KeySize)
	assert.Equal(t, string(types.AlgorithmSymmetric), client.lastImportKeyReq.KeyType,
		"the service routes a symmetric import on this key type, and matches it case-insensitively")
}

// TestCreateObjectImportsEveryAESKeyLength proves the material's length decides
// the key size, rather than one size being assumed for all of them.
//
// The service resolves a symmetric import through a table keyed by size, so a
// size that did not match the material would either be refused there or, worse,
// import the key as a different algorithm than the one it is.
func TestCreateObjectImportsEveryAESKeyLength(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
		bits  int
	}{
		{"AES-128", []byte("0123456789ABCDEF"), 128},
		{"AES-192", []byte("0123456789ABCDEF01234567"), 192},
		{"AES-256", []byte("0123456789ABCDEF0123456789ABCDEF"), 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, client, session := importFixture(t)
			defer m.Finalize()

			require.Len(t, tc.value, tc.bits/8)

			handle, rv := m.CreateObject(session, importedSecretKeyTemplate("sized-"+tc.name, tc.value))
			require.Equal(t, CKR_OK, rv)

			obj, err := m.objectManager.getObjectUnchecked(handle)
			require.NoError(t, err)
			require.NotEmpty(t, obj.KeyID)

			require.NotNil(t, client.lastImportKeyReq)
			assert.Equal(t, tc.bits, client.lastImportKeyReq.KeySize,
				"the size sent must be the size of the material, not a fixed default")
			assert.Equal(t, tc.value, client.importedMaterial[obj.KeyID])
		})
	}
}

// TestCreateObjectDoesNotImportWhatItCannotProtect collects the objects that
// deliberately stay local, each for its own reason.
func TestCreateObjectDoesNotImportWhatItCannotProtect(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
		why      string
	}{
		{
			name: "CKA_EXTRACTABLE=CK_FALSE",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
				NewStringAttribute(CKA_LABEL, "unextractable"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewBoolAttribute(CKA_EXTRACTABLE, false),
				NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
			},
			why: "the import ceremony carries no exportability field, so a backend copy would silently widen the protection the caller asked for",
		},
		{
			name: "a public key",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
				NewAttribute(CKA_MODULUS, make([]byte, 256)),
				NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
				NewStringAttribute(CKA_LABEL, "public"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
			},
			why: "a public key holds no secret, so a backend copy would make nothing possible",
		},
		{
			name: "a certificate",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
				NewUint32Attribute(CKA_CERTIFICATE_TYPE, uint32(CKC_X_509)),
				// Required at creation for an X.509 certificate
				// (v3.2 §4.6.3 footnote 1).
				NewAttribute(CKA_SUBJECT, []byte{0x30, 0x00}),
				NewStringAttribute(CKA_LABEL, "cert"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
			},
			why: "a certificate is public object content",
		},
		{
			name: "a data object",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
				NewStringAttribute(CKA_LABEL, "data"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
			},
			why: "a data object is public object content",
		},
		{
			name: "a private key",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
				NewStringAttribute(CKA_LABEL, "private"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewBoolAttribute(CKA_PRIVATE, true),
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
			},
			why: "CKA_VALUE on a private key may be PKCS#8 or a bare seed, and post-quantum private keys are local by design",
		},
		{
			name: "a secret of a length no AES algorithm names",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
				NewStringAttribute(CKA_LABEL, "twenty-bytes"),
				NewBoolAttribute(CKA_TOKEN, false),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
				NewAttribute(CKA_VALUE, []byte("TWENTY-BYTE-SECRET!!")),
			},
			why: "the import ceremony has no algorithm to name for a 20-byte secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, client, session := importFixture(t)
			defer m.Finalize()

			handle, rv := m.CreateObject(session, tc.template)
			require.Equal(t, CKR_OK, rv, "the object must still be created: %s", tc.why)

			obj, err := m.objectManager.getObjectUnchecked(handle)
			require.NoError(t, err)
			assert.Empty(t, obj.KeyID, tc.why)
			assert.False(t, client.importKeyCalled,
				"no material may be sent to the backend for this object: %s", tc.why)
		})
	}
}

// TestCreateObjectRefusesASecretKeyWithNoMaterial proves the template itself is
// refused, rather than yielding an object with nothing to import.
//
// This case used to sit in the table above, asserting that such an object was
// created and simply not sent to the backend. C_CreateObject now requires
// CKA_VALUE for an AES secret key (v3.2 §6.10.1, Table 13 footnote 1), so the
// refusal comes first and the application learns at the call it made rather than
// at some later operation on a key that was never usable.
func TestCreateObjectRefusesASecretKeyWithNoMaterial(t *testing.T) {
	m, client, session := importFixture(t)
	defer m.Finalize()

	_, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "no-value"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})

	assert.Equal(t, CKR_TEMPLATE_INCOMPLETE, rv)
	assert.False(t, client.importKeyCalled,
		"a refused template must not reach the backend")
}

// TestCreateObjectFallsBackWhenTheBackendCannotImport proves a backend with no
// import support yields a local object rather than a failed call.
//
// Refusing would withdraw a capability such backends have today, and §5.7.1's
// return table offers no code meaning "this token cannot hold this kind of
// key". The cost is stated in Module.CreateObject's doc comment and asserted
// here: the key keeps its material in CKA_VALUE and cannot be a KEK.
func TestCreateObjectFallsBackWhenTheBackendCannotImport(t *testing.T) {
	m, client, session := importFixture(t)
	defer m.Finalize()

	client.importParamsError = NewPKCS11ErrorWithMessage(CKR_FUNCTION_NOT_SUPPORTED,
		"this backend does not implement key import")

	value := []byte("0123456789ABCDEF")
	handle, rv := m.CreateObject(session, importedSecretKeyTemplate("no-import-backend", value))
	require.Equal(t, CKR_OK, rv,
		"a backend that cannot import must not make C_CreateObject fail")

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	assert.Empty(t, obj.KeyID, "the object stays local when the backend cannot take the key")
	assert.Equal(t, value, obj.GetAttribute(CKA_VALUE),
		"a local object must keep the material the template supplied")
}

// TestCreateObjectReportsAnImportThatShouldHaveWorked is the bad-input half of
// the fallback: a backend that CAN import and failed anyway is a real error.
//
// Falling back here would answer CKR_OK for a key that is not on the token,
// which is the silent divergence between what the token reports and what it
// holds that this whole area exists to prevent. CKR_DEVICE_ERROR is in
// C_CreateObject's return table (v3.2 §5.7.1).
func TestCreateObjectReportsAnImportThatShouldHaveWorked(t *testing.T) {
	m, client, session := importFixture(t)
	defer m.Finalize()

	client.importKeyError = errImportRefused

	handle, rv := m.CreateObject(session,
		importedSecretKeyTemplate("import-fails", []byte("0123456789ABCDEF")))
	assert.Equal(t, CKR_DEVICE_ERROR, rv,
		"an import that failed for any reason other than 'unsupported' is a device error")
	assert.Equal(t, ObjectHandle(InvalidHandle), handle,
		"a failed call must hand back no handle")

	// A failed creation must leave nothing behind. An object findable for the
	// life of the process and absent from the next one is exactly the
	// divergence the rollback exists to prevent.
	require.Equal(t, CKR_OK, m.FindObjectsInit(session, []Attribute{
		NewStringAttribute(CKA_LABEL, "import-fails"),
	}))
	handles, rv := m.FindObjects(session, 16)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.FindObjectsFinal(session))
	assert.Empty(t, handles, "a refused C_CreateObject must leave no object behind")
}

// TestCreateObjectRefusesATokenKeyItCouldNotImport closes the gap that made
// C_CreateObject the one creation verb without a persistence rule.
//
// A CKA_TOKEN secret key marked CKA_SENSITIVE used to be accepted with CKR_OK
// and come back from the next C_Initialize with a zero-length CKA_VALUE,
// because ModuleStorage.SaveObject withholds the material from a key object
// that protects it and the object had no backend copy to fall back on. Every
// use of that handle then failed on an object the application had every reason
// to believe was a key, and nothing at creation time had warned.
func TestCreateObjectRefusesATokenKeyItCouldNotImport(t *testing.T) {
	protectedTemplate := func(label string, extra ...Attribute) []Attribute {
		return append([]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
			NewStringAttribute(CKA_LABEL, label),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_PRIVATE, false),
			NewAttribute(CKA_VALUE, unimportableSecretKeyValue),
		}, extra...)
	}

	cases := []struct {
		name  string
		extra []Attribute
		want  CK_RV
	}{
		{
			name:  "CKA_SENSITIVE=CK_TRUE",
			extra: []Attribute{NewBoolAttribute(CKA_SENSITIVE, true), NewBoolAttribute(CKA_EXTRACTABLE, true)},
			want:  CKR_TEMPLATE_INCONSISTENT,
		},
		{
			name:  "CKA_EXTRACTABLE=CK_FALSE",
			extra: []Attribute{NewBoolAttribute(CKA_SENSITIVE, false), NewBoolAttribute(CKA_EXTRACTABLE, false)},
			want:  CKR_TEMPLATE_INCONSISTENT,
		},
		{
			name:  "neither, which is the storable combination",
			extra: []Attribute{NewBoolAttribute(CKA_SENSITIVE, false), NewBoolAttribute(CKA_EXTRACTABLE, true)},
			want:  CKR_OK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _, session := importFixture(t)
			defer m.Finalize()

			handle, rv := m.CreateObject(session, protectedTemplate("refused-"+tc.name, tc.extra...))
			require.Equal(t, tc.want, rv)

			if tc.want != CKR_OK {
				assert.Equal(t, ObjectHandle(InvalidHandle), handle,
					"a refused creation must hand back no handle")
			}
		})
	}
}

// TestCreateObjectAllowsAProtectedTokenKeyItImported is the other side of the
// rule above, and the reason importing resolves the defect rather than merely
// refusing it.
//
// The same CKA_TOKEN, CKA_SENSITIVE combination is admitted once the material
// is 32 bytes, because then the backend holds it and the object is metadata --
// which is the state a C_GenerateKey key has always been in. Without this case
// the rule above would be indistinguishable from a blanket ban on protected
// token keys.
func TestCreateObjectAllowsAProtectedTokenKeyItImported(t *testing.T) {
	m, _, session := importFixture(t)
	defer m.Finalize()

	handle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "protected-but-imported"),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF0123456789ABCDEF")),
	})
	require.Equal(t, CKR_OK, rv,
		"a protected token key whose material the backend holds loses nothing by being stored")

	obj, err := m.objectManager.getObjectUnchecked(handle)
	require.NoError(t, err)
	assert.NotEmpty(t, obj.KeyID, "the exemption must rest on the key id, not on the class")
}

// TestUnstorableProtectionErrorExemptsAnImportedKey pins the pairing between
// the creation rule and the modification rule.
//
// unstorableProtectionError refuses a tightening that would leave a stored
// key's only copy unstorable, and it now decides that on the key id rather than
// on how the object was created. The two rules have to agree: if the creation
// rule let a protected token key through because it was imported, but the
// modification rule still refused every imported key, an administrator could
// not tighten a key that loses nothing by it.
func TestUnstorableProtectionErrorExemptsAnImportedKey(t *testing.T) {
	tighten := []Attribute{NewBoolAttribute(CKA_SENSITIVE, true)}

	local := &Object{
		Class:         CKO_SECRET_KEY,
		IsToken:       true,
		IsExtractable: true,
		Attributes:    map[AttributeType][]byte{CKA_VALUE: []byte("material")},
	}
	assert.Error(t, unstorableProtectionError(local, tighten),
		"a key whose only copy is CKA_VALUE must still be refused")

	imported := &Object{
		Class:         CKO_SECRET_KEY,
		IsToken:       true,
		IsExtractable: true,
		KeyID:         "backend-key-id",
		Attributes:    map[AttributeType][]byte{CKA_VALUE: []byte("material")},
	}
	assert.NoError(t, unstorableProtectionError(imported, tighten),
		"a key the backend holds loses nothing by having its CKA_VALUE withheld from the store")
}

// TestSetAttributeValueDoesNotDiscloseInvisibleObjects closes an information
// leak in the pre-check ordering.
//
// The refusal above was evaluated against an object fetched without an access
// context, before the access-controlled modification ran. Its return code was
// therefore derived from an object the session might not be allowed to see, and
// that code was itself the disclosure: an unauthenticated caller could sweep
// the handle space and learn, per handle, that an object existed, that it was a
// private/secret/OTP key, that it was a token object still holding material in
// CKA_VALUE, and that it was currently unprotected.
//
// The write was refused throughout, so this is disclosure and not modification
// -- which is precisely why nothing else catches it. Both properties are
// asserted: the invisible handle must answer CKR_OBJECT_HANDLE_INVALID whatever
// attribute is being set, and a visible one must still get the real refusal.
func TestSetAttributeValueDoesNotDiscloseInvisibleObjects(t *testing.T) {
	newHiddenKey := func(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
		t.Helper()

		m := initializeTestModule(t)
		session := loginAsNormalUser(t, m)

		// CKA_PRIVATE makes the object visible only to a logged-in session,
		// and the material is a length this token cannot import, so the object
		// is exactly the kind unstorableProtectionError has an opinion about.
		handle, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
			NewStringAttribute(CKA_LABEL, "hidden-key"),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_PRIVATE, true),
			NewBoolAttribute(CKA_SENSITIVE, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, unimportableSecretKeyValue),
		})
		require.Equal(t, CKR_OK, rv)

		return m, session, handle
	}

	t.Run("an invisible handle answers alike for every attribute", func(t *testing.T) {
		m, session, handle := newHiddenKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.Logout(session))

		// The control: an attribute the pre-check has no opinion about.
		control := m.SetAttributeValue(session, handle, []Attribute{
			NewStringAttribute(CKA_LABEL, "x"),
		})
		require.Equal(t, CKR_OBJECT_HANDLE_INVALID, control,
			"a logged-out session must not see a CKA_PRIVATE object at all")

		// The probe: the attribute that used to route through the unchecked
		// lookup and answer from the hidden object's own contents.
		probe := m.SetAttributeValue(session, handle, []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, true),
		})
		assert.Equal(t, control, probe,
			"the answer must not depend on which attribute is being set, or it reports the object's contents")

		// A handle that names nothing must be indistinguishable from one that
		// names something invisible.
		unknown := m.SetAttributeValue(session, ObjectHandle(999999), []Attribute{
			NewBoolAttribute(CKA_SENSITIVE, true),
		})
		assert.Equal(t, unknown, probe,
			"an existing but invisible object must answer exactly as a nonexistent one")
	})

	t.Run("a visible handle still gets the real refusal", func(t *testing.T) {
		m, session, handle := newHiddenKey(t)
		defer m.Finalize()

		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT,
			m.SetAttributeValue(session, handle, []Attribute{NewBoolAttribute(CKA_SENSITIVE, true)}),
			"tightening the access check must not disable the rule it guards")
	})
}
