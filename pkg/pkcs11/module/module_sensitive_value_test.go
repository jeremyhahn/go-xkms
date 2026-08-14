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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A secret key whose material was supplied at C_CreateObject keeps that material
// in its attribute map. C_GetAttributeValue(CKA_VALUE) must resolve footnote 7
// (§4.9) against the object's own attributes before returning it: a key that is
// neither sensitive nor unextractable reveals its value, while a sensitive or
// unextractable key withholds it — even though the value is right there in the
// map. The regression these guard against read the map before the sensitivity
// check and handed the caller the material CKA_SENSITIVE forbids.

func createSecretKeyWithValue(t *testing.T, m *Module, session SessionHandle, label string, value []byte, extra ...Attribute) ObjectHandle {
	t.Helper()
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE, value),
	}
	template = append(template, extra...)
	handle, rv := m.CreateObject(session, template)
	require.Equal(t, CKR_OK, rv, "CreateObject(%s) should succeed", label)
	return handle
}

func TestGetAttributeValue_RevealsUnprotectedSecretKeyValue(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	value := []byte("revealable-key--")
	handle := createSecretKeyWithValue(t, m, session, "unprotected", value,
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	)

	attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv,
		"a key marked neither sensitive nor unextractable must reveal its CKA_VALUE")
	require.Len(t, attrs, 1)
	assert.False(t, attrs[0].Unavailable, "CKA_VALUE must be present")
	assert.Equal(t, value, attrs[0].Value)
}

func TestGetAttributeValue_WithholdsSensitiveSecretKeyValue(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	secret := []byte("do-not-disclose!")

	cases := []struct {
		name  string
		extra []Attribute
	}{
		{
			name: "sensitive",
			extra: []Attribute{
				NewBoolAttribute(CKA_SENSITIVE, true),
				NewBoolAttribute(CKA_EXTRACTABLE, true),
			},
		},
		{
			name: "unextractable",
			extra: []Attribute{
				NewBoolAttribute(CKA_SENSITIVE, false),
				NewBoolAttribute(CKA_EXTRACTABLE, false),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handle := createSecretKeyWithValue(t, m, session, "protected-"+tc.name, secret, tc.extra...)

			attrs, rv := m.GetAttributeValue(session, handle, []Attribute{{Type: CKA_VALUE}})

			require.Equal(t, CKR_ATTRIBUTE_SENSITIVE, rv,
				"§4.9 footnote 7: a %s key must not reveal CKA_VALUE", tc.name)
			require.Len(t, attrs, 1)
			assert.True(t, attrs[0].Unavailable,
				"the protected CKA_VALUE must be marked unavailable")
			assert.NotEqual(t, secret, attrs[0].Value,
				"the sensitive key material must never appear in the result")
			assert.Empty(t, attrs[0].Value,
				"a withheld attribute carries no value")
		})
	}
}
