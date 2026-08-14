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

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../cmd/pkcs11-module/include
#cgo LDFLAGS: -ldl

#include "xkabi.h"
*/
import "C"

import (
	"unsafe"
)

// Attribute types whose value is itself an array of CK_ATTRIBUTE
// (PKCS#11 v3.2 §4.8.2, §4.9).
const (
	CKA_WRAP_TEMPLATE   = uint(C.CKA_WRAP_TEMPLATE)
	CKA_UNWRAP_TEMPLATE = uint(C.CKA_UNWRAP_TEMPLATE)
	CKA_DERIVE_TEMPLATE = uint(C.CKA_DERIVE_TEMPLATE)
)

// SizeOfAttribute returns sizeof(CK_ATTRIBUTE) as this application sees it. The
// ulValueLen of a nested template attribute is a byte count of that structure,
// so a test that checks the two-call length must compute it the same way an
// application would.
func SizeOfAttribute() uint {
	return uint(unsafe.Sizeof(C.CK_ATTRIBUTE{}))
}

// NestedTemplate is an attribute whose value is a genuine CK_ATTRIBUTE array
// rather than an opaque byte string.
type NestedTemplate struct {
	// Type is the CKA_ identifier, one of the *_TEMPLATE attributes.
	Type uint
	// Nested is the array the attribute's pValue points at.
	Nested []Attr
}

// attributeArray returns the arena-allocated CK_ATTRIBUTE array as a Go slice
// so its elements can be read and written by field name. The memory is C
// memory the caller owns, which is what the module's boundary expects to be
// handed.
func attributeArray(p unsafe.Pointer, count int) []C.CK_ATTRIBUTE {
	if p == nil || count == 0 {
		return nil
	}
	return unsafe.Slice((*C.CK_ATTRIBUTE)(p), count)
}

// buildNestedTemplate lays out attrs followed by nested as one CK_ATTRIBUTE
// array in the arena, with the nested attribute's pValue pointing at a second,
// inner CK_ATTRIBUTE array. This is exactly the layout a C application builds.
func buildNestedTemplate(a *arena, attrs []Attr, nested NestedTemplate) (C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	entrySize := int(SizeOfAttribute())

	outer := a.alloc(entrySize * (len(attrs) + 1))
	elements := attributeArray(outer, len(attrs)+1)

	for i, attr := range attrs {
		value, valueLen := a.bytes(attr.Value)
		elements[i]._type = C.CK_ATTRIBUTE_TYPE(attr.Type)
		elements[i].pValue = C.CK_VOID_PTR(value)
		elements[i].ulValueLen = valueLen
	}

	inner := a.alloc(entrySize * len(nested.Nested))
	innerElements := attributeArray(inner, len(nested.Nested))
	for i, attr := range nested.Nested {
		value, valueLen := a.bytes(attr.Value)
		innerElements[i]._type = C.CK_ATTRIBUTE_TYPE(attr.Type)
		innerElements[i].pValue = C.CK_VOID_PTR(value)
		innerElements[i].ulValueLen = valueLen
	}

	last := &elements[len(attrs)]
	last._type = C.CK_ATTRIBUTE_TYPE(nested.Type)
	last.pValue = C.CK_VOID_PTR(inner)
	last.ulValueLen = C.CK_ULONG(entrySize * len(nested.Nested))

	return C.CK_ATTRIBUTE_PTR(outer), C.CK_ULONG(len(attrs) + 1)
}

// GenerateKeyWithNestedTemplate performs C_GenerateKey with a template that
// carries one nested-template attribute built as a real CK_ATTRIBUTE array.
func (s *Session) GenerateKeyWithNestedTemplate(mechType uint, params MechParams, template []Attr, nested NestedTemplate) (uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, mechType, params)
	tmpl, count := buildNestedTemplate(a, template, nested)

	var key C.CK_OBJECT_HANDLE
	if err := check("C_GenerateKey", C.xk_GenerateKey(s.mod.fl, s.handle, mech, tmpl, count, &key)); err != nil {
		return 0, err
	}
	return uint(key), nil
}

// NestedAttributeLength performs the first half of the two-call convention for
// a nested-template attribute: C_GetAttributeValue with a NULL pValue, whose
// answer is the size in bytes of the CK_ATTRIBUTE array the application must
// allocate (PKCS#11 v3.2 §5.2).
func (s *Session) NestedAttributeLength(obj uint, attrType uint) (uint, error) {
	a := &arena{}
	defer a.free()

	outer := a.alloc(int(SizeOfAttribute()))
	elements := attributeArray(outer, 1)
	elements[0]._type = C.CK_ATTRIBUTE_TYPE(attrType)

	err := check("C_GetAttributeValue", C.xk_GetAttributeValue(
		s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), C.CK_ATTRIBUTE_PTR(outer), 1))
	if err != nil {
		return 0, err
	}
	return uint(elements[0].ulValueLen), nil
}

// NestedAttribute reads a nested-template attribute back through the full
// recursive two-call convention, and reports the length the NULL-buffer query
// answered with.
//
// Three calls are made because there are two levels of buffer. The first learns
// how large the CK_ATTRIBUTE array is; the second fills that array's types and
// per-element lengths, each element still carrying a NULL pValue and so being a
// length query in its own right; the third, once the application has allocated
// a buffer for every element, copies the values.
func (s *Session) NestedAttribute(obj uint, attrType uint) ([]Attr, uint, error) {
	reported, err := s.NestedAttributeLength(obj, attrType)
	if err != nil {
		return nil, 0, err
	}
	if reported == 0 || reported == ^uint(0) {
		return nil, reported, nil
	}

	a := &arena{}
	defer a.free()

	outer := a.alloc(int(SizeOfAttribute()))
	outerElements := attributeArray(outer, 1)

	inner := a.alloc(int(reported))
	count := int(reported / SizeOfAttribute())

	outerElements[0]._type = C.CK_ATTRIBUTE_TYPE(attrType)
	outerElements[0].pValue = C.CK_VOID_PTR(inner)
	outerElements[0].ulValueLen = C.CK_ULONG(reported)

	err = check("C_GetAttributeValue", C.xk_GetAttributeValue(
		s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), C.CK_ATTRIBUTE_PTR(outer), 1))
	if err != nil {
		return nil, reported, err
	}

	innerElements := attributeArray(inner, count)
	for i := range innerElements {
		if innerElements[i].ulValueLen == 0 || innerElements[i].ulValueLen == ^C.CK_ULONG(0) {
			continue
		}
		innerElements[i].pValue = C.CK_VOID_PTR(a.alloc(int(innerElements[i].ulValueLen)))
	}

	err = check("C_GetAttributeValue", C.xk_GetAttributeValue(
		s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), C.CK_ATTRIBUTE_PTR(outer), 1))
	if err != nil {
		return nil, reported, err
	}

	result := make([]Attr, count)
	for i := range innerElements {
		result[i].Type = uint(innerElements[i]._type)
		if innerElements[i].pValue == nil || innerElements[i].ulValueLen == 0 {
			continue
		}
		result[i].Value = C.GoBytes(
			unsafe.Pointer(innerElements[i].pValue), C.int(innerElements[i].ulValueLen))
	}

	return result, reported, nil
}

// GenerateKeyWithMalformedNestedTemplate performs C_GenerateKey with a
// nested-template attribute whose ulValueLen is not a whole number of
// CK_ATTRIBUTE, which is a value the boundary cannot parse as an array.
//
// The array itself is allocated at the full declared size, so a module that
// reads past the element count it computed still reads its own arena rather
// than unmapped memory; what is being tested is that the boundary refuses the
// declaration, not what it would find if it did not.
func (s *Session) GenerateKeyWithMalformedNestedTemplate(mechType uint, template []Attr, attrType uint) (uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, mechType, nil)
	entrySize := int(SizeOfAttribute())

	outer := a.alloc(entrySize * (len(template) + 1))
	elements := attributeArray(outer, len(template)+1)
	for i, attr := range template {
		value, valueLen := a.bytes(attr.Value)
		elements[i]._type = C.CK_ATTRIBUTE_TYPE(attr.Type)
		elements[i].pValue = C.CK_VOID_PTR(value)
		elements[i].ulValueLen = valueLen
	}

	last := &elements[len(template)]
	last._type = C.CK_ATTRIBUTE_TYPE(attrType)
	last.pValue = C.CK_VOID_PTR(a.alloc(entrySize * 2))
	last.ulValueLen = C.CK_ULONG(entrySize + 1)

	var key C.CK_OBJECT_HANDLE
	err := check("C_GenerateKey", C.xk_GenerateKey(
		s.mod.fl, s.handle, mech, C.CK_ATTRIBUTE_PTR(outer), C.CK_ULONG(len(template)+1), &key))
	if err != nil {
		return 0, err
	}
	return uint(key), nil
}
