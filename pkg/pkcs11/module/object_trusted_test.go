package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins the three attribute rules that together make
// CKA_WRAP_WITH_TRUSTED enforceable. They are tested as a group because they
// fail as a group: the restriction is a pair of attributes on two different
// objects, and a caller who can forge either half defeats it entirely.
//
// PKCS#11 v3.2 Table 13 states the rules as footnotes:
//
//	footnote 10  CKA_TRUSTED "can only be set to CK_TRUE by the SO user"
//	footnote 11  CKA_TRUSTED / CKA_WRAP_WITH_TRUSTED cannot be changed once
//	             CK_TRUE; they become read-only
//
// and Table 17 gives CKA_COPYABLE the mirror rule ("Can't be set to TRUE once
// it is set to FALSE"), which is included here because it is the same class of
// defect -- a one-way protection that could be switched back off.

// trustedTestUserContext is a read-write session with the normal user
// authenticated: the role that may create and use keys, but may not assert
// CKA_TRUSTED.
func trustedTestUserContext() AccessContext {
	return AccessContext{Session: 1, Slot: 0, LoggedIn: true, ReadWrite: true}
}

// trustedTestSOContext is a read-write session with the Security Officer
// authenticated. The SO is deliberately not LoggedIn: v3.2 §4.2 keeps it out of
// private objects, and SecurityOfficer must not widen access.
func trustedTestSOContext() AccessContext {
	return AccessContext{Session: 1, Slot: 0, ReadWrite: true, SecurityOfficer: true}
}

// trustedTestSecretKeyTemplate builds a minimal public AES secret-key template
// with the caller's extra attributes appended.
func trustedTestSecretKeyTemplate(extra ...Attribute) []Attribute {
	return append([]Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}, extra...)
}

// requireAttributeReadOnly asserts the error is the CKR_ATTRIBUTE_READ_ONLY the
// spec names for a refused attribute change, rather than some other refusal
// that would pass a weaker assertion for the wrong reason.
func requireAttributeReadOnly(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	var pkcsErr *PKCS11Error
	require.ErrorAs(t, err, &pkcsErr)
	assert.Equal(t, CKR_ATTRIBUTE_READ_ONLY, pkcsErr.Code)
}

func TestCKATrustedRequiresSecurityOfficer(t *testing.T) {
	t.Run("a normal user cannot create a trusted object", func(t *testing.T) {
		om := NewObjectManager()

		_, err := om.CreateObject(trustedTestUserContext(),
			trustedTestSecretKeyTemplate(NewBoolAttribute(CKA_TRUSTED, true)))

		requireAttributeReadOnly(t, err)
	})

	t.Run("a normal user cannot assert CKA_TRUSTED after creation", func(t *testing.T) {
		om := NewObjectManager()
		ctx := trustedTestUserContext()

		handle, err := om.CreateObject(ctx, trustedTestSecretKeyTemplate())
		require.NoError(t, err)

		err = om.SetAttributeValue(ctx, handle, []Attribute{
			NewBoolAttribute(CKA_TRUSTED, true),
		})

		requireAttributeReadOnly(t, err)
	})

	t.Run("a normal user cannot launder CKA_TRUSTED through C_CopyObject", func(t *testing.T) {
		om := NewObjectManager()
		ctx := trustedTestUserContext()

		handle, err := om.CreateObject(ctx, trustedTestSecretKeyTemplate())
		require.NoError(t, err)

		_, err = om.CopyObject(ctx, handle, []Attribute{
			NewBoolAttribute(CKA_TRUSTED, true),
		})

		requireAttributeReadOnly(t, err)
	})

	t.Run("the SO can create a trusted object", func(t *testing.T) {
		om := NewObjectManager()

		handle, err := om.CreateObject(trustedTestSOContext(),
			trustedTestSecretKeyTemplate(NewBoolAttribute(CKA_TRUSTED, true)))

		require.NoError(t, err, "footnote 10 names the SO as the role that may set CKA_TRUSTED; "+
			"if it cannot, the attribute can never be set by anyone")
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})

	t.Run("CKA_TRUSTED cannot be retracted once set", func(t *testing.T) {
		om := NewObjectManager()
		ctx := trustedTestSOContext()

		handle, err := om.CreateObject(ctx,
			trustedTestSecretKeyTemplate(NewBoolAttribute(CKA_TRUSTED, true)))
		require.NoError(t, err)

		err = om.SetAttributeValue(ctx, handle, []Attribute{
			NewBoolAttribute(CKA_TRUSTED, false),
		})

		requireAttributeReadOnly(t, err)
	})
}

// TestTrustedObjectDefaultsToPublic pins the token-specific CKA_PRIVATE default
// that keeps the SO from being deadlocked out of the attribute only it may set.
//
// Only the SO may set CKA_TRUSTED, and the SO may not create private objects,
// so a trusted object that defaulted to CKA_PRIVATE=CK_TRUE could not be
// created by anyone. Table 17 makes the default the token's to choose ("Default
// value is token-specific, and may depend on the values of other attributes of
// the object"), and this token chooses public.
func TestTrustedObjectDefaultsToPublic(t *testing.T) {
	t.Run("a trusted object is public by default", func(t *testing.T) {
		om := NewObjectManager()
		ctx := trustedTestSOContext()

		handle, err := om.CreateObject(ctx, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
			NewBoolAttribute(CKA_TRUSTED, true),
		})
		require.NoError(t, err, "the SO must be able to create a trusted object without "+
			"naming CKA_PRIVATE, or the two rules deadlock")

		obj, err := om.GetObjectFor(ctx, handle)
		require.NoError(t, err)
		assert.False(t, obj.IsPrivate)
	})

	t.Run("an explicit CKA_PRIVATE in the template still wins", func(t *testing.T) {
		om := NewObjectManager()

		// The SO cannot create a private object, so an explicit CKA_PRIVATE=TRUE
		// must still be honoured -- and therefore still refused. A default that
		// overrode the caller would silently turn this into a success.
		_, err := om.CreateObject(trustedTestSOContext(), []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
			NewBoolAttribute(CKA_PRIVATE, true),
			NewBoolAttribute(CKA_TRUSTED, true),
		})

		require.Error(t, err)
		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_USER_NOT_LOGGED_IN, pkcsErr.Code)
	})
}

// TestOneWayBooleanAttributesCannotBeReversed pins the remaining one-way rules.
// Each of these guards a protection that, once switched off, cannot be
// meaningfully restored -- the key has already been exposed by then.
func TestOneWayBooleanAttributesCannotBeReversed(t *testing.T) {
	cases := []struct {
		name    string
		attr    AttributeType
		initial bool
		attempt bool
	}{
		{
			name:    "CKA_WRAP_WITH_TRUSTED cannot be cleared",
			attr:    CKA_WRAP_WITH_TRUSTED,
			initial: true,
			attempt: false,
		},
		{
			name:    "CKA_COPYABLE cannot be re-enabled",
			attr:    CKA_COPYABLE,
			initial: false,
			attempt: true,
		},
		{
			name:    "CKA_SENSITIVE cannot be cleared",
			attr:    CKA_SENSITIVE,
			initial: true,
			attempt: false,
		},
		{
			name:    "CKA_EXTRACTABLE cannot be re-enabled",
			attr:    CKA_EXTRACTABLE,
			initial: false,
			attempt: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			om := NewObjectManager()
			ctx := trustedTestUserContext()

			handle, err := om.CreateObject(ctx,
				trustedTestSecretKeyTemplate(NewBoolAttribute(tc.attr, tc.initial)))
			require.NoError(t, err)

			err = om.SetAttributeValue(ctx, handle, []Attribute{
				NewBoolAttribute(tc.attr, tc.attempt),
			})

			requireAttributeReadOnly(t, err)
		})
	}

	t.Run("the permitted direction is still allowed", func(t *testing.T) {
		om := NewObjectManager()
		ctx := trustedTestUserContext()

		handle, err := om.CreateObject(ctx,
			trustedTestSecretKeyTemplate(NewBoolAttribute(CKA_WRAP_WITH_TRUSTED, false)))
		require.NoError(t, err)

		// FALSE -> TRUE is the direction footnote 11 permits. A guard that
		// refused both directions would pass every assertion above while making
		// the attribute unusable.
		err = om.SetAttributeValue(ctx, handle, []Attribute{
			NewBoolAttribute(CKA_WRAP_WITH_TRUSTED, true),
		})
		require.NoError(t, err)
	})
}

// TestCreateObjectRequiresPerSubtypeAttributes pins PKCS#11 v3.2 Table 13
// footnote 1: attributes the per-type tables mark "MUST be specified when object
// is created with C_CreateObject".
//
// The rule is per SUBTYPE, not per class, which a class-keyed table cannot
// express: an RSA public key needs a modulus and a DSA one does not. And it is
// scoped to C_CreateObject alone -- footnote 4 is its opposite for the generate
// path, where CKA_VALUE must NOT be supplied because the token produces it.
func TestCreateObjectRequiresPerSubtypeAttributes(t *testing.T) {
	cases := []struct {
		name     string
		template []Attribute
		why      string
	}{
		{
			name: "an AES secret key without CKA_VALUE",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			},
			why: "a secret key with no material has neither a value nor a backend KeyID, " +
				"so every later *Init on it fails inside the backend instead of at the template",
		},
		{
			name: "an RSA public key without its components",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			},
			why: "ssh-keygen -D and pkcs11-provider both read CKA_MODULUS to build the key",
		},
		{
			name: "an X.509 certificate without CKA_SUBJECT",
			template: []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
				NewUint32Attribute(CKA_CERTIFICATE_TYPE, CKC_X_509),
				NewAttribute(CKA_VALUE, []byte{0x30, 0x00}),
			},
			why: "OpenSSL and NSS pair a certificate to its key by subject",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			om := NewObjectManager()

			_, err := om.CreateObject(trustedTestUserContext(), tc.template)

			require.Error(t, err, tc.why)
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_TEMPLATE_INCOMPLETE, pkcsErr.Code)
		})
	}

	t.Run("a subtype the table does not name carries no extra requirement", func(t *testing.T) {
		om := NewObjectManager()

		// CKO_DATA has no per-subtype entry, so it must still be creatable from
		// a minimal template. Without this, a blanket requirement would satisfy
		// every assertion above while making unrelated objects uncreatable.
		_, err := om.CreateObject(trustedTestUserContext(), []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "plain-data"),
		})
		require.NoError(t, err)
	})
}
