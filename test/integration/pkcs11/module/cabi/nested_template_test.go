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

//go:build integration && pkcs11_cabi

package cabi

import (
	"bytes"
	"testing"
)

// wrapTemplateKey generates an AES key carrying a CKA_WRAP_TEMPLATE built as a
// genuine CK_ATTRIBUTE array, the way a C application builds one.
func wrapTemplateKey(t *testing.T, f *Fixture, nested []Attr) uint {
	t.Helper()

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrString(CKA_LABEL, UniqueLabel(t, "nested-wrap-template")),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_WRAP, true),
		AttrULong(CKA_VALUE_LEN, 32),
	}

	key, err := f.Session.GenerateKeyWithNestedTemplate(CKM_AES_KEY_GEN, nil, template,
		NestedTemplate{Type: CKA_WRAP_TEMPLATE, Nested: nested})
	if err != nil {
		t.Fatalf("C_GenerateKey with a CKA_WRAP_TEMPLATE: %v", err)
	}
	return f.Track(key)
}

// TestNestedTemplateCrossesTheABI proves a C application can set a
// *_TEMPLATE attribute at all.
//
// The cgo boundary used to copy every attribute value as raw bytes. For
// CKA_WRAP_TEMPLATE that meant handing the token an array of CK_ATTRIBUTE
// structures full of the application's own pointers — addresses that mean
// nothing on the far side of the transport and name buffers that are gone once
// the call returns. The token refused it with CKR_ATTRIBUTE_VALUE_INVALID,
// which was fail-closed but left no way for a C caller to partition a wrapping
// key at all. This is the test that could not pass before.
func TestNestedTemplateCrossesTheABI(t *testing.T) {
	f := NewFixture(t)

	nested := []Attr{
		AttrBool(CKA_SENSITIVE, true),
		AttrBool(CKA_EXTRACTABLE, true),
	}
	key := wrapTemplateKey(t, f, nested)

	got, reported, err := f.Session.NestedAttribute(key, CKA_WRAP_TEMPLATE)
	if err != nil {
		t.Fatalf("C_GetAttributeValue(CKA_WRAP_TEMPLATE): %v", err)
	}

	if want := uint(len(nested)) * SizeOfAttribute(); reported != want {
		t.Fatalf("the NULL-buffer query answered %d bytes, want %d "+
			"(%d elements of sizeof(CK_ATTRIBUTE)=%d); a length that is not a whole "+
			"number of CK_ATTRIBUTE is one no application can allocate an array from",
			reported, want, len(nested), SizeOfAttribute())
	}

	if len(got) != len(nested) {
		t.Fatalf("read back %d nested attributes, want %d", len(got), len(nested))
	}
	for i := range nested {
		if got[i].Type != nested[i].Type {
			t.Errorf("nested attribute %d: type = %#x, want %#x", i, got[i].Type, nested[i].Type)
		}
		if !bytes.Equal(got[i].Value, nested[i].Value) {
			t.Errorf("nested attribute %d (%#x): value = %v, want %v",
				i, nested[i].Type, got[i].Value, nested[i].Value)
		}
	}
}

// TestNestedTemplateRoundTripsAVariableLengthValue proves the encoding carries
// each nested value's own length, not a fixed width.
//
// A CKA_LABEL and a CK_BBOOL in the same nested template are read back
// byte-identically only if every element's length crosses in both directions.
// An encoding that assumed one width would return the label truncated or the
// boolean padded, and either one is a constraint the token would then compare
// against the wrong bytes.
func TestNestedTemplateRoundTripsAVariableLengthValue(t *testing.T) {
	f := NewFixture(t)

	nested := []Attr{
		AttrBool(CKA_SENSITIVE, true),
		AttrString(CKA_LABEL, "a-label-of-some-length"),
		AttrULong(CKA_VALUE_LEN, 32),
	}
	key := wrapTemplateKey(t, f, nested)

	got, _, err := f.Session.NestedAttribute(key, CKA_WRAP_TEMPLATE)
	if err != nil {
		t.Fatalf("C_GetAttributeValue(CKA_WRAP_TEMPLATE): %v", err)
	}
	if len(got) != len(nested) {
		t.Fatalf("read back %d nested attributes, want %d", len(got), len(nested))
	}
	for i := range nested {
		if got[i].Type != nested[i].Type || !bytes.Equal(got[i].Value, nested[i].Value) {
			t.Errorf("nested attribute %d did not round trip: got {%#x, %v}, want {%#x, %v}",
				i, got[i].Type, got[i].Value, nested[i].Type, nested[i].Value)
		}
	}
}

// TestNestedTemplateRefusesAMalformedArrayLength proves the boundary validates
// ulValueLen against sizeof(CK_ATTRIBUTE) before it indexes the array.
//
// The length is caller-supplied, so a declaration that is not a whole number of
// elements has to be refused rather than rounded: rounding it would compute an
// element count the application never wrote and read the remainder out of
// whatever follows. The call must return a CK_RV, never take the process down.
func TestNestedTemplateRefusesAMalformedArrayLength(t *testing.T) {
	f := NewFixture(t)

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrString(CKA_LABEL, UniqueLabel(t, "nested-wrap-malformed")),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_WRAP, true),
		AttrULong(CKA_VALUE_LEN, 32),
	}

	key, err := f.Session.GenerateKeyWithMalformedNestedTemplate(
		CKM_AES_KEY_GEN, template, CKA_WRAP_TEMPLATE)
	if err == nil {
		f.Track(key)
		t.Fatal("a CKA_WRAP_TEMPLATE whose ulValueLen is not a whole number of " +
			"CK_ATTRIBUTE was accepted")
	}
}
