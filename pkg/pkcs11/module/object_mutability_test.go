// Copyright (C) 2025 go-xkms authors
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published
//    by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

package module

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// C15: a key's material may be supplied once at creation but is never modifiable
// afterwards (§4.1.1; the value attributes carry footnotes 1,4,6,7, never the
// "modifiable" footnote 8). Neither C_SetAttributeValue nor a modifying
// C_CopyObject template may rewrite it. The rule is class-aware: a CKO_DATA
// object's CKA_VALUE stays freely modifiable.

func TestSetAttributeValue_RejectsSecretKeyValueChange(t *testing.T) {
	om := NewObjectManager()
	ctx := trustedTestUserContext()

	handle, err := om.CreateObject(ctx, trustedTestSecretKeyTemplate())
	require.NoError(t, err)

	err = om.SetAttributeValue(ctx, handle, []Attribute{
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	requireAttributeReadOnly(t, err)
}

func TestCopyObject_RejectsSecretKeyValueChange(t *testing.T) {
	om := NewObjectManager()
	ctx := trustedTestUserContext()

	handle, err := om.CreateObject(ctx, trustedTestSecretKeyTemplate())
	require.NoError(t, err)

	_, err = om.CopyObject(ctx, handle, []Attribute{
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	requireAttributeReadOnly(t, err)
}

func TestSetAttributeValue_AllowsDataObjectValueChange(t *testing.T) {
	// CKA_VALUE on a CKO_DATA object is modifiable, so the class-aware guard
	// must not catch it. This is the counter-case proving the guard is scoped
	// to key classes rather than applied to CKA_VALUE unconditionally.
	om := NewObjectManager()
	ctx := trustedTestUserContext()

	handle, err := om.CreateObject(ctx, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_VALUE, []byte("original")),
	})
	require.NoError(t, err)

	err = om.SetAttributeValue(ctx, handle, []Attribute{
		NewAttribute(CKA_VALUE, []byte("updated")),
	})
	require.NoError(t, err, "a CKO_DATA object's CKA_VALUE is modifiable")
}

// C16: a certificate with CKA_TRUSTED = CK_TRUE is immutable — every attribute,
// not only CKA_TRUSTED. A modifying C_SetAttributeValue or C_CopyObject on such
// a certificate is refused with CKR_ATTRIBUTE_READ_ONLY.

func trustedCertTemplate(extra ...Attribute) []Attribute {
	return append([]Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
		NewUint32Attribute(CKA_CERTIFICATE_TYPE, uint32(CKC_X_509)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_SUBJECT, []byte("CN=trusted")),
		NewAttribute(CKA_VALUE, []byte("der-bytes")),
	}, extra...)
}

func TestSetAttributeValue_RejectsAnyChangeToTrustedCertificate(t *testing.T) {
	om := NewObjectManager()

	// Only the SO may mark a certificate trusted.
	handle, err := om.CreateObject(trustedTestSOContext(),
		trustedCertTemplate(NewBoolAttribute(CKA_TRUSTED, true)))
	require.NoError(t, err)

	// A change to a non-CKA_TRUSTED attribute must still be refused: the whole
	// certificate is frozen, not just its trust bit.
	err = om.SetAttributeValue(trustedTestSOContext(), handle, []Attribute{
		NewAttribute(CKA_SUBJECT, []byte("CN=attacker")),
	})
	requireAttributeReadOnly(t, err)
}

func TestCopyObject_RejectsModifyingTrustedCertificate(t *testing.T) {
	om := NewObjectManager()

	handle, err := om.CreateObject(trustedTestSOContext(),
		trustedCertTemplate(NewBoolAttribute(CKA_TRUSTED, true)))
	require.NoError(t, err)

	_, err = om.CopyObject(trustedTestSOContext(), handle, []Attribute{
		NewAttribute(CKA_SUBJECT, []byte("CN=attacker")),
	})
	requireAttributeReadOnly(t, err)
}

func TestSetAttributeValue_AllowsChangeToUntrustedCertificate(t *testing.T) {
	// The counter-case: a certificate that is NOT trusted may have its
	// modifiable attributes changed, so the guard is scoped to trusted certs.
	om := NewObjectManager()
	ctx := trustedTestUserContext()

	handle, err := om.CreateObject(ctx, trustedCertTemplate())
	require.NoError(t, err)

	err = om.SetAttributeValue(ctx, handle, []Attribute{
		NewAttribute(CKA_LABEL, []byte("relabelled")),
	})
	require.NoError(t, err, "an untrusted certificate's modifiable attributes stay modifiable")
}
