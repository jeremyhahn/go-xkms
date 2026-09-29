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

// Tests for the CK_ATTRIBUTE template helpers in exports.go:
// readCAttributeArray, convertCTemplateToGo, requestedAttributes and
// copyGoTemplateToCTemplate.
//
// CK_ATTRIBUTE (v3.2 section 3.2, pkcs11t.h):
//
//	CK_ATTRIBUTE_TYPE type;   offset 0,  8 bytes
//	CK_VOID_PTR pValue;       offset 8,  8 bytes
//	CK_ULONG ulValueLen;      offset 16, 8 bytes
//
// total 24 bytes, matching attributeArrayElemSize (exports.go, sizeof_CK_ATTRIBUTE).
// A CK_ATTRIBUTE array is these 24-byte records laid out contiguously, which
// buildCAttributeArray below reproduces exactly as buildPRFDataParams does for
// CK_PRF_DATA_PARAM in exports_mechdecode_test.go.
//
// convertCTemplateToGo, requestedAttributes and copyGoTemplateToCTemplate take
// C.CK_ATTRIBUTE_PTR/C.CK_ULONG (cgo-generated types), so -- like
// exports_paramdecode_test.go's cPtr/callCFn -- they are called through
// reflection; readCAttributeArray's pValue is CK_VOID_PTR, cgo's void*, which
// is already unsafe.Pointer and needs no conversion, but is driven the same
// way here for consistency with its sibling helpers.

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

const cAttributeSize = 24

// getULong reads an 8-byte little-endian CK_ULONG back out of buf[offset:],
// the mirror of putULong. exports.go writes several of its output parameters
// (ulValueLen, in particular) into memory this package's own byte buffers
// own, so the result of a write-back is read the same way it was written.
func getULong(buf []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(buf[offset : offset+8])
}

// buildCAttribute writes one CK_ATTRIBUTE record into buf[offset:], pinning
// value's backing storage for the rest of t (see putPtr/pin in
// exports_mechdecode_test.go) so it survives regardless of how long buf
// remains in use.
func buildCAttribute(t testing.TB, buf []byte, offset int, attrType module.AttributeType, value []byte) {
	putULong(buf, offset, uint64(attrType))
	putPtr(t, buf, offset+8, bytePtr(value))
	putULong(buf, offset+16, uint64(len(value)))
}

// buildCAttributeArray lays out entries as a contiguous CK_ATTRIBUTE array.
func buildCAttributeArray(t testing.TB, entries []module.Attribute) []byte {
	buf := newAlignedBuf(cAttributeSize * len(entries))
	for i, e := range entries {
		buildCAttribute(t, buf, cAttributeSize*i, e.Type, e.Value)
	}
	return buf
}

// cAttributePtr converts buf's address into a Value of the exact
// CK_ATTRIBUTE_PTR-shaped type fn's argIdx-th parameter expects.
//
// Unlike CK_VOID_PTR (which cgo represents as plain unsafe.Pointer, so
// cPtr's Convert from unsafe.Pointer is a no-op identity conversion),
// CK_ATTRIBUTE_PTR is cgo's named alias for *C.struct_CK_ATTRIBUTE, a real
// Pointer-kind type. reflect.Value.Convert refuses to convert an
// UnsafePointer-kind Value directly into it, so the address is instead
// wrapped with reflect.NewAt at the pointer's element type, which produces a
// Value already of Pointer kind and -- because cgo's typedef is a genuine Go
// type alias -- identical to the parameter type itself.
func cAttributePtr(buf []byte, fnType reflect.Type, argIdx int) reflect.Value {
	elemType := fnType.In(argIdx).Elem()
	return reflect.NewAt(elemType, unsafe.Pointer(&buf[0]))
}

// ============================================================================
// readCAttributeArray
// ============================================================================

// readCAttributeArrayLen builds the reflect.Value for readCAttributeArray's
// CK_ULONG length argument. Its pValue parameter is CK_VOID_PTR, cgo's void*,
// which is already unsafe.Pointer and needs no conversion, but ulValueLen is
// still a cgo-generated CK_ULONG, so it is built the same way
// exports_paramdecode_test.go's cPtr/callCFn build every other cgo argument.
func readCAttributeArrayLen(n uint64) reflect.Value {
	ft := reflect.ValueOf(readCAttributeArray).Type()
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(n)
	return length
}

func TestReadCAttributeArray_WellFormed(t *testing.T) {
	label := []byte("nested-label")
	entries := []module.Attribute{{Type: module.CKA_LABEL, Value: label}}
	buf := buildCAttributeArray(t, entries)

	out := callCFn(readCAttributeArray, cPtr(unsafe.Pointer(&buf[0]), reflect.ValueOf(readCAttributeArray).Type(), 0), readCAttributeArrayLen(cAttributeSize))
	if !out[1].Bool() {
		t.Fatal("readCAttributeArray(well-formed) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	if !reflect.DeepEqual(got, entries) {
		t.Errorf("readCAttributeArray = %+v, want %+v", got, entries)
	}
}

// TestReadCAttributeArray_NilValueElementHasNoValue proves an element with a
// NULL pValue decodes to a bare type with no Value, regardless of whatever
// ulValueLen it declares -- readCAttributeArray must not read through a NULL
// pointer just because a nonzero length sits next to it.
func TestReadCAttributeArray_NilValueElementHasNoValue(t *testing.T) {
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
	putULong(buf, 16, 32) // ulValueLen says 32 bytes; pValue is still NULL.

	out := callCFn(readCAttributeArray, cPtr(unsafe.Pointer(&buf[0]), reflect.ValueOf(readCAttributeArray).Type(), 0), readCAttributeArrayLen(cAttributeSize))
	if !out[1].Bool() {
		t.Fatal("readCAttributeArray(NULL pValue) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	if got[0].Value != nil {
		t.Errorf("Value = %v, want nil", got[0].Value)
	}
}

// TestReadCAttributeArray_UnaddressableElementValueLenIsRefused proves an
// element whose declared length is not addressable as a Go slice -- which is
// also the shape CK_UNAVAILABLE_INFORMATION (all bits set) takes when paired
// with a non-NULL pValue -- is refused rather than read.
func TestReadCAttributeArray_UnaddressableElementValueLenIsRefused(t *testing.T) {
	sentinel := []byte{0}
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: sentinel}})
	putULong(buf, 16, math.MaxUint64) // CK_UNAVAILABLE_INFORMATION.

	out := callCFn(readCAttributeArray, cPtr(unsafe.Pointer(&buf[0]), reflect.ValueOf(readCAttributeArray).Type(), 0), readCAttributeArrayLen(cAttributeSize))
	if out[1].Bool() {
		t.Error("readCAttributeArray(ulValueLen=CK_UNAVAILABLE_INFORMATION, non-NULL pValue) ok = true, want false")
	}
}

// ============================================================================
// convertCTemplateToGo
// ============================================================================

func TestConvertCTemplateToGo_WellFormedSimpleAttributes(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	entries := []module.Attribute{
		{Type: module.CKA_LABEL, Value: []byte("widget")},
	}
	buf := buildCAttributeArray(t, entries)

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if !out[1].Bool() {
		t.Fatal("convertCTemplateToGo(well-formed) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	if !reflect.DeepEqual(got, entries) {
		t.Errorf("convertCTemplateToGo = %+v, want %+v", got, entries)
	}
}

// TestConvertCTemplateToGo_NilValueAttributeIsTypeOnly proves an attribute
// with a NULL pValue -- the shape a caller uses to name an attribute without
// supplying a value -- decodes with Value nil rather than being refused or
// reading through the NULL pointer.
func TestConvertCTemplateToGo_NilValueAttributeIsTypeOnly(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
	putULong(buf, 16, 64) // ulValueLen says 64 bytes; pValue is still NULL.

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if !out[1].Bool() {
		t.Fatal("convertCTemplateToGo(NULL pValue) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	if got[0].Value != nil {
		t.Errorf("Value = %v, want nil", got[0].Value)
	}
}

// TestConvertCTemplateToGo_NestedArrayAttributeIsFlattened proves a
// CKA_WRAP_TEMPLATE-shaped attribute -- whose value is itself a CK_ATTRIBUTE
// array -- is flattened with module.EncodeAttributeArray rather than copied
// as the raw pointer-bearing bytes of the inner array, per the doc comment on
// convertCTemplateToGo: the pointers inside a nested CK_ATTRIBUTE address
// nothing once this call returns.
func TestConvertCTemplateToGo_NestedArrayAttributeIsFlattened(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	inner := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("inner")}}
	innerBuf := buildCAttributeArray(t, inner)
	outerBuf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_WRAP_TEMPLATE}})
	putPtr(t, outerBuf, 8, unsafe.Pointer(&innerBuf[0]))
	putULong(outerBuf, 16, cAttributeSize)

	ptr := cAttributePtr(outerBuf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if !out[1].Bool() {
		t.Fatal("convertCTemplateToGo(nested array) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	want := module.EncodeAttributeArray(inner)
	if !bytes.Equal(got[0].Value, want) {
		t.Errorf("nested attribute Value = %x, want the flattened encoding %x", got[0].Value, want)
	}
}

// TestConvertCTemplateToGo_NestedArrayFailurePropagates proves a malformed
// nested array (misaligned length) refuses the whole template rather than
// silently dropping the one bad attribute.
func TestConvertCTemplateToGo_NestedArrayFailurePropagates(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	innerBuf := newAlignedBuf(8) // not a multiple of cAttributeSize.
	outerBuf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_WRAP_TEMPLATE}})
	putPtr(t, outerBuf, 8, unsafe.Pointer(&innerBuf[0]))
	putULong(outerBuf, 16, 8)

	ptr := cAttributePtr(outerBuf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if out[1].Bool() {
		t.Error("convertCTemplateToGo(malformed nested array) ok = true, want false")
	}
}

// TestConvertCTemplateToGo_DanglingValueLenIsRefused proves an ordinary
// (non-nested) attribute with an unaddressable ulValueLen is refused.
func TestConvertCTemplateToGo_DanglingValueLenIsRefused(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	sentinel := []byte{0}
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: sentinel}})
	putULong(buf, 16, math.MaxUint64)

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if out[1].Bool() {
		t.Error("convertCTemplateToGo(unaddressable ulValueLen) ok = true, want false")
	}
}

// TestConvertCTemplateToGo_CountOverflowIsRefused proves a ulCount beyond the
// addressable range of a Go slice index is refused before the template array
// is ever indexed.
func TestConvertCTemplateToGo_CountOverflowIsRefused(t *testing.T) {
	fn := reflect.ValueOf(convertCTemplateToGo)
	ft := fn.Type()

	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(uint64(math.MaxInt32) + 1)

	out := callCFn(convertCTemplateToGo, ptr, count)
	if out[1].Bool() {
		t.Error("convertCTemplateToGo(ulCount > MaxInt32) ok = true, want false")
	}
}

// ============================================================================
// requestedAttributes
// ============================================================================

// TestRequestedAttributes_ReadsTypeOnly proves the C_GetAttributeValue
// second-call template -- whose pValue buffers are uninitialized output
// space, not input -- contributes only its attributes' types, never their
// (meaningless) buffer contents.
func TestRequestedAttributes_ReadsTypeOnly(t *testing.T) {
	fn := reflect.ValueOf(requestedAttributes)
	ft := fn.Type()

	garbage := []byte("uninitialized-heap-not-a-value")
	entries := []module.Attribute{
		{Type: module.CKA_LABEL, Value: garbage},
		{Type: module.CKA_CLASS},
	}
	buf := buildCAttributeArray(t, entries)

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(2)

	out := callCFn(requestedAttributes, ptr, count)
	if !out[1].Bool() {
		t.Fatal("requestedAttributes(well-formed) ok = false, want true")
	}
	got := out[0].Interface().([]module.Attribute)
	want := []module.Attribute{{Type: module.CKA_LABEL}, {Type: module.CKA_CLASS}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requestedAttributes = %+v, want %+v (Value must stay nil)", got, want)
	}
}

func TestRequestedAttributes_NilTemplateIsEmpty(t *testing.T) {
	fn := reflect.ValueOf(requestedAttributes)
	ft := fn.Type()

	out := callCFn(requestedAttributes, reflect.Zero(ft.In(0)), reflect.New(ft.In(1)).Elem())
	if !out[1].Bool() {
		t.Error("requestedAttributes(NULL, 0) ok = false, want true")
	}
	if !out[0].IsNil() {
		t.Errorf("requestedAttributes(NULL, 0) = %v, want nil", out[0].Interface())
	}
}

func TestRequestedAttributes_CountOverflowIsRefused(t *testing.T) {
	fn := reflect.ValueOf(requestedAttributes)
	ft := fn.Type()

	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})

	ptr := cAttributePtr(buf, ft, 0)
	count := reflect.New(ft.In(1)).Elem()
	count.SetUint(uint64(math.MaxInt32) + 1)

	out := callCFn(requestedAttributes, ptr, count)
	if out[1].Bool() {
		t.Error("requestedAttributes(ulCount > MaxInt32) ok = true, want false")
	}
}

// ============================================================================
// copyGoTemplateToCTemplate
// ============================================================================

func TestCopyGoTemplateToCTemplate_QueryModeReportsLength(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	value := []byte("copy-me")
	attrs := []module.Attribute{{Type: module.CKA_LABEL, Value: value}}
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}}) // pValue NULL: query mode.

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(query mode) bufferTooSmall = true, want false")
	}
	if got := getULong(buf, 16); got != uint64(len(value)) {
		t.Errorf("ulValueLen = %d, want %d", got, len(value))
	}
}

func TestCopyGoTemplateToCTemplate_CopiesValueWhenBufferFits(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	value := []byte("copy-me")
	attrs := []module.Attribute{{Type: module.CKA_LABEL, Value: value}}
	dest := make([]byte, len(value))
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: dest}})

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(buffer fits) bufferTooSmall = true, want false")
	}
	if !bytes.Equal(dest, value) {
		t.Errorf("dest = %q, want %q", dest, value)
	}
	if got := getULong(buf, 16); got != uint64(len(value)) {
		t.Errorf("ulValueLen = %d, want %d", got, len(value))
	}
}

// TestCopyGoTemplateToCTemplate_BufferTooSmallSetsUnavailableSentinel proves
// PKCS#11 v3.2 section 5.7.5's rule for a buffer that does not fit: report
// CK_UNAVAILABLE_INFORMATION, copy nothing, and tell the caller to retry.
func TestCopyGoTemplateToCTemplate_BufferTooSmallSetsUnavailableSentinel(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	value := []byte("this-value-is-too-long-for-the-buffer")
	attrs := []module.Attribute{{Type: module.CKA_LABEL, Value: value}}
	dest := make([]byte, 4) // shorter than value.
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: dest}})

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if !out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(buffer too small) bufferTooSmall = false, want true")
	}
	if got := getULong(buf, 16); got != math.MaxUint64 {
		t.Errorf("ulValueLen = 0x%X, want CK_UNAVAILABLE_INFORMATION (0x%X)", got, uint64(math.MaxUint64))
	}
}

// TestCopyGoTemplateToCTemplate_UnavailableAttributeSetsSentinelWithoutCopying
// proves an attribute the module marked Unavailable is reported the same way
// as a too-small buffer, but is not counted as a buffer-size failure: nothing
// was ever going to fit, regardless of what the caller allocated.
func TestCopyGoTemplateToCTemplate_UnavailableAttributeSetsSentinelWithoutCopying(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	attrs := []module.Attribute{{Type: module.CKA_LABEL, Unavailable: true}}
	dest := make([]byte, 64) // plenty of room; must still be refused.
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL, Value: dest}})

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(Unavailable) bufferTooSmall = true, want false")
	}
	if got := getULong(buf, 16); got != math.MaxUint64 {
		t.Errorf("ulValueLen = 0x%X, want CK_UNAVAILABLE_INFORMATION", got)
	}
}

// TestCopyGoTemplateToCTemplate_NestedArrayDelegatesToWriteCAttributeArray
// proves a nested-template attribute is expanded through writeCAttributeArray
// rather than copied as a flat byte string, so the application reads back a
// real CK_ATTRIBUTE array, the same shape it would have written on the way in.
func TestCopyGoTemplateToCTemplate_NestedArrayDelegatesToWriteCAttributeArray(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	inner := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("inner")}}
	attrs := []module.Attribute{{Type: module.CKA_WRAP_TEMPLATE, Value: module.EncodeAttributeArray(inner)}}
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_WRAP_TEMPLATE}}) // pValue NULL: query mode.

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(nested, query mode) bufferTooSmall = true, want false")
	}
	if got := getULong(buf, 16); got != cAttributeSize {
		t.Errorf("ulValueLen = %d, want %d (one CK_ATTRIBUTE, the query-mode size writeCAttributeArray reports)", got, uint64(cAttributeSize))
	}
}

func TestCopyGoTemplateToCTemplate_NilTemplateIsANoOp(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	attrs := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("x")}}
	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), reflect.Zero(ft.In(1)), reflect.New(ft.In(2)).Elem())
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(NULL template) bufferTooSmall = true, want false")
	}
}

func TestCopyGoTemplateToCTemplate_CountOverflowIsANoOp(t *testing.T) {
	fn := reflect.ValueOf(copyGoTemplateToCTemplate)
	ft := fn.Type()

	attrs := []module.Attribute{{Type: module.CKA_LABEL, Value: []byte("x")}}
	buf := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})

	ptr := cAttributePtr(buf, ft, 1)
	count := reflect.New(ft.In(2)).Elem()
	count.SetUint(uint64(math.MaxInt32) + 1)

	out := callCFn(copyGoTemplateToCTemplate, reflect.ValueOf(attrs), ptr, count)
	if out[0].Bool() {
		t.Error("copyGoTemplateToCTemplate(ulCount > MaxInt32) bufferTooSmall = true, want false")
	}
}
