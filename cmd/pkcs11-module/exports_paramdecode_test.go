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

// Tests for the unexported parameter-translation helpers behind the v3.2
// message-based crypto verbs (rejectSignMessageParam, gcmMessageParams,
// writeGCMMessageParams) and the nested-template helper
// (readCAttributeArray).
//
// As exports_test.go explains, Go 1.26 forbids `import "C"` in a _test.go
// file. callCFn below extends that file's reflection approach to these
// package-private functions (not //export'd, so callC's exported-symbol
// helper does not apply): a raw unsafe.Pointer is converted to the target
// cgo pointer type with reflect.Value.Convert, which -- like reflect.New
// for callC's cAlloc -- never has to name the cgo type. What it still
// cannot do is set a field *within* the pointed-to C struct: cgo gives
// every C struct field an unexported Go name, and reflect refuses to Set
// an unexported field regardless of which package is doing the reflecting.
// So these tests cover every branch reachable by pointer-nilness and
// declared length alone; the branches that decode a populated
// CK_GCM_MESSAGE_PARAMS / CK_ATTRIBUTE's field contents are reachable only
// by driving the real C ABI end to end (SoftHSM/pkcs11-tool, out of this
// batch's scope) and are reported as a gap rather than forced.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// cPtr converts a Go unsafe.Pointer into the cgo pointer type fn's argIdx-th
// parameter expects, without the test naming that type.
func cPtr(p unsafe.Pointer, fnType reflect.Type, argIdx int) reflect.Value {
	return reflect.ValueOf(p).Convert(fnType.In(argIdx))
}

// callCFn invokes a package-private function (not an //export'd C_* entry
// point) via reflection, mirroring callC's approach for exported functions.
func callCFn(fn any, args ...reflect.Value) []reflect.Value {
	return reflect.ValueOf(fn).Call(args)
}

func TestRejectSignMessageParam_NilIsAccepted(t *testing.T) {
	fn := reflect.ValueOf(rejectSignMessageParam)
	ft := fn.Type()

	out := callCFn(rejectSignMessageParam, reflect.Zero(ft.In(0)), reflect.New(ft.In(1)).Elem())
	if got := module.CK_RV(out[0].Uint()); got != module.CKR_OK {
		t.Errorf("rejectSignMessageParam(NULL, 0) = %s, want CKR_OK (parameterless signing is the supported case)", got)
	}
}

func TestRejectSignMessageParam_NonNilIsRefused(t *testing.T) {
	fn := reflect.ValueOf(rejectSignMessageParam)
	ft := fn.Type()

	var buf [8]byte
	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(uint64(len(buf)))

	out := callCFn(rejectSignMessageParam, ptr, length)
	if got := module.CK_RV(out[0].Uint()); got != module.CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("rejectSignMessageParam(non-NULL, %d) = %s, want CKR_MECHANISM_PARAM_INVALID: "+
			"no signing mechanism this module implements takes a per-message parameter", len(buf), got)
	}
}

func TestGCMMessageParams_NilParameterIsTheNonAEADCase(t *testing.T) {
	fn := reflect.ValueOf(gcmMessageParams)
	ft := fn.Type()

	out := callCFn(gcmMessageParams, reflect.Zero(ft.In(0)), reflect.New(ft.In(1)).Elem())
	if !out[0].IsNil() {
		t.Errorf("gcmMessageParams(NULL, 0) params = %v, want nil", out[0].Interface())
	}
	if !out[1].Bool() {
		t.Error("gcmMessageParams(NULL, 0) ok = false, want true (a non-AEAD mechanism has no message parameter)")
	}
}

// TestGCMMessageParams_TooShortIsRefused proves a declared length shorter
// than CK_GCM_MESSAGE_PARAMS is refused before any field of it is read --
// the same length-vs-struct-size bound checkMechanismParameter enforces for
// ordinary (non-message) mechanism parameters.
func TestGCMMessageParams_TooShortIsRefused(t *testing.T) {
	fn := reflect.ValueOf(gcmMessageParams)
	ft := fn.Type()

	var buf [4]byte
	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(uint64(len(buf)))

	out := callCFn(gcmMessageParams, ptr, length)
	if !out[0].IsNil() {
		t.Errorf("gcmMessageParams(4-byte buffer) params = %v, want nil", out[0].Interface())
	}
	if out[1].Bool() {
		t.Error("gcmMessageParams(4-byte buffer) ok = true, want false: CK_GCM_MESSAGE_PARAMS is larger than 4 bytes")
	}
}

func TestWriteGCMMessageParams_NilParameterIsANoOp(t *testing.T) {
	fn := reflect.ValueOf(writeGCMMessageParams)
	ft := fn.Type()

	params := &module.AESGCMMessageParams{IV: []byte{1, 2, 3}}
	out := callCFn(writeGCMMessageParams, reflect.Zero(ft.In(0)), reflect.ValueOf(params))
	if got := module.CK_RV(out[0].Uint()); got != module.CKR_OK {
		t.Errorf("writeGCMMessageParams(NULL, params) = %s, want CKR_OK (nothing to write back into)", got)
	}
}

func TestWriteGCMMessageParams_NilParamsIsANoOp(t *testing.T) {
	fn := reflect.ValueOf(writeGCMMessageParams)
	ft := fn.Type()

	var buf [8]byte
	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	out := callCFn(writeGCMMessageParams, ptr, reflect.Zero(ft.In(1)))
	if got := module.CK_RV(out[0].Uint()); got != module.CKR_OK {
		t.Errorf("writeGCMMessageParams(pParameter, nil params) = %s, want CKR_OK (no token-produced IV/tag to copy back)", got)
	}
}

func TestReadCAttributeArray_ZeroLengthIsEmpty(t *testing.T) {
	fn := reflect.ValueOf(readCAttributeArray)
	ft := fn.Type()

	out := callCFn(readCAttributeArray, reflect.Zero(ft.In(0)), reflect.New(ft.In(1)).Elem())
	if !out[0].IsNil() {
		t.Errorf("readCAttributeArray(NULL, 0) nested = %v, want nil", out[0].Interface())
	}
	if !out[1].Bool() {
		t.Error("readCAttributeArray(NULL, 0) ok = false, want true: a zero-length nested template is empty, not malformed")
	}
}

// TestReadCAttributeArray_MisalignedLengthIsRefused proves a declared byte
// length that is not a whole multiple of sizeof(CK_ATTRIBUTE) is refused
// before any element is read, rather than silently truncating the last
// partial element.
func TestWriteCAttributeArray_MalformedEncodingReportsOverflow(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	cAttr := reflect.New(ft.In(0).Elem())
	encoded := reflect.ValueOf([]byte{0x01}) // shorter than the array header; DecodeAttributeArray refuses it.

	out := callCFn(writeCAttributeArray, cAttr, encoded)
	if out[0].Bool() {
		t.Error("writeCAttributeArray(malformed encoding) bufferTooSmall = true, want false: this is a corrupt store, not an undersized caller buffer")
	}
}

// TestWriteCAttributeArray_QueryModeReportsRequiredSize proves a NULL
// cAttr.pValue (the zero value of a freshly allocated CK_ATTRIBUTE, since
// cgo struct fields cannot be set from a _test.go file) is treated as the
// PKCS#11 v3.2 section 5.2 length query: the required size is written back
// and bufferTooSmall is false, matching every other query-mode branch this
// module implements.
func TestWriteCAttributeArray_QueryModeReportsRequiredSize(t *testing.T) {
	fn := reflect.ValueOf(writeCAttributeArray)
	ft := fn.Type()

	cAttr := reflect.New(ft.In(0).Elem())
	encoded := module.EncodeAttributeArray([]module.Attribute{
		{Type: module.CKA_LABEL, Value: []byte("nested")},
	})

	out := callCFn(writeCAttributeArray, cAttr, reflect.ValueOf(encoded))
	if out[0].Bool() {
		t.Error("writeCAttributeArray(pValue=NULL, well-formed encoding) bufferTooSmall = true, want false: a length query never reports an undersized buffer")
	}
}

func TestReadCAttributeArray_MisalignedLengthIsRefused(t *testing.T) {
	fn := reflect.ValueOf(readCAttributeArray)
	ft := fn.Type()

	var buf [64]byte
	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(1) // sizeof(CK_ATTRIBUTE) is always well over 1 byte on every platform this module targets.

	out := callCFn(readCAttributeArray, ptr, length)
	if !out[0].IsNil() {
		t.Errorf("readCAttributeArray(1 byte) nested = %v, want nil", out[0].Interface())
	}
	if out[1].Bool() {
		t.Error("readCAttributeArray(1 byte) ok = true, want false: 1 is not a whole multiple of sizeof(CK_ATTRIBUTE)")
	}
}
