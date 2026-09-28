// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

// Tests for writeCAttributeArray's branches past the query-mode leg
// exports_template_test.go's TestCopyGoTemplateToCTemplate_NestedArrayDelegatesToWriteCAttributeArray
// already covers: the outer CKR_BUFFER_TOO_SMALL leg, the decode-error leg,
// and the per-element copy/query/undersized legs of the real expansion loop.
//
// As exports_paramdecode_test.go explains, a _test.go file cannot set a field
// *within* a cgo struct by reflection, so the outer CK_ATTRIBUTE and its
// destination element array are laid out as raw byte buffers at their field
// offsets, the same way exports_template_test.go's buildCAttribute does --
// reused here directly, including its trick of handing buildCAttributeArray a
// destination buffer as an element's "value" to make that element's pValue
// point at real, writable memory rather than nowhere.

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// writeCAttributeArrayPtr converts cAttrBuf's address into a Value of the
// exact *C.CK_ATTRIBUTE type writeCAttributeArray's first parameter expects.
func writeCAttributeArrayPtr(cAttrBuf []byte, fnType reflect.Type) reflect.Value {
	return reflect.NewAt(fnType.In(0).Elem(), unsafe.Pointer(&cAttrBuf[0]))
}

// TestWriteCAttributeArray_DecodeErrorReportsUnavailable proves malformed
// encoded bytes (a corrupt store, per writeCAttributeArray's own doc comment)
// are reported as CK_UNAVAILABLE_INFORMATION rather than treated as a
// buffer-size failure.
func TestWriteCAttributeArray_DecodeErrorReportsUnavailable(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	cAttrBuf := newAlignedBuf(cAttributeSize)
	buildCAttribute(t, cAttrBuf, 0, module.CKA_WRAP_TEMPLATE, []byte{0xFF}) // pValue non-nil, so decode is reached.
	malformed := []byte{0xFF, 0xFF, 0xFF, 0xFF}

	out := fn.Call([]reflect.Value{writeCAttributeArrayPtr(cAttrBuf, ft), reflect.ValueOf(malformed)})
	if out[0].Bool() {
		t.Error("writeCAttributeArray(malformed encoding) bufferTooSmall = true, want false")
	}
	if got := getULong(cAttrBuf, 16); got != ^uint64(0) {
		t.Errorf("ulValueLen = 0x%X, want CK_UNAVAILABLE_INFORMATION", got)
	}
}

// TestWriteCAttributeArray_OuterBufferTooSmall proves an outer destination
// shorter than count*sizeof(CK_ATTRIBUTE) is refused with the outer
// CKR_BUFFER_TOO_SMALL leg, not the per-element one.
func TestWriteCAttributeArray_OuterBufferTooSmall(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	// A 1-byte "destination" makes cAttr.pValue non-NULL (so query mode is
	// not taken) while cAttr.ulValueLen (1) is far short of the one
	// CK_ATTRIBUTE (24 bytes) the encoded single-entry array requires.
	cAttrBuf := newAlignedBuf(cAttributeSize)
	undersizedOuter := make([]byte, 1)
	buildCAttribute(t, cAttrBuf, 0, module.CKA_WRAP_TEMPLATE, undersizedOuter)

	inner := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("inner")}}
	encoded := module.EncodeAttributeArray(inner)

	out := fn.Call([]reflect.Value{writeCAttributeArrayPtr(cAttrBuf, ft), reflect.ValueOf(encoded)})
	if !out[0].Bool() {
		t.Error("writeCAttributeArray(outer buffer too small) bufferTooSmall = false, want true")
	}
	if got := getULong(cAttrBuf, 16); got != ^uint64(0) {
		t.Errorf("ulValueLen = 0x%X, want CK_UNAVAILABLE_INFORMATION", got)
	}
}

// TestWriteCAttributeArray_ElementCopiesRealValue proves the per-element copy
// leg carries the real nested attribute value into the caller's destination,
// not merely a length.
func TestWriteCAttributeArray_ElementCopiesRealValue(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	labelDest := make([]byte, 5) // exactly "inner"'s length.
	outerElems := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: labelDest}})

	cAttrBuf := newAlignedBuf(cAttributeSize)
	buildCAttribute(t, cAttrBuf, 0, module.CKA_WRAP_TEMPLATE, outerElems)

	inner := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("inner")}}
	encoded := module.EncodeAttributeArray(inner)

	out := fn.Call([]reflect.Value{writeCAttributeArrayPtr(cAttrBuf, ft), reflect.ValueOf(encoded)})
	if out[0].Bool() {
		t.Error("writeCAttributeArray(element fits) bufferTooSmall = true, want false")
	}
	if !bytes.Equal(labelDest, []byte("inner")) {
		t.Errorf("labelDest = %q, want %q: the element's value was not copied", labelDest, "inner")
	}
	if got := getULong(cAttrBuf, 16); got != cAttributeSize {
		t.Errorf("outer ulValueLen = %d, want %d", got, uint64(cAttributeSize))
	}
}

// TestWriteCAttributeArray_ElementBufferTooSmall proves a per-element
// destination shorter than its value is refused with
// CK_UNAVAILABLE_INFORMATION on that element and bufferTooSmall=true on the
// call, without disturbing the outer ulValueLen the caller reads to size a
// retry.
func TestWriteCAttributeArray_ElementBufferTooSmall(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	labelDest := make([]byte, 2) // shorter than "inner" (5 bytes).
	outerElems := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: labelDest}})

	cAttrBuf := newAlignedBuf(cAttributeSize)
	buildCAttribute(t, cAttrBuf, 0, module.CKA_WRAP_TEMPLATE, outerElems)

	inner := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("inner")}}
	encoded := module.EncodeAttributeArray(inner)

	out := fn.Call([]reflect.Value{writeCAttributeArrayPtr(cAttrBuf, ft), reflect.ValueOf(encoded)})
	if !out[0].Bool() {
		t.Error("writeCAttributeArray(element too small) bufferTooSmall = false, want true")
	}
	if got := getULong(outerElems, 16); got != ^uint64(0) {
		t.Errorf("element ulValueLen = 0x%X, want CK_UNAVAILABLE_INFORMATION", got)
	}
	if got := getULong(cAttrBuf, 16); got != cAttributeSize {
		t.Errorf("outer ulValueLen = %d, want %d (still reported so a retry can size against it)", got, uint64(cAttributeSize))
	}
}
