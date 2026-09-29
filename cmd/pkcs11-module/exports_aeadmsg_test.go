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

// Tests for gcmMessageParams and writeGCMMessageParams (exports.go) with a
// populated CK_GCM_MESSAGE_PARAMS, extending the pointer-nilness-only
// coverage exports_paramdecode_test.go carries. That file's introduction
// explains why a _test.go file cannot set a field *within* a cgo struct by
// reflection (every field gets an unexported Go name); the workaround is the
// same one exports_mechdecode_test.go uses for the CK_MECHANISM parameter
// decoders -- lay the structure out as a byte buffer at its field offsets and
// convert a raw pointer to it, which needs no field access at all.
//
// CK_GCM_MESSAGE_PARAMS (v3.2 section 6.13.5, pkcs11t.h):
//
//	CK_BYTE_PTR pIv;             offset 0,  8 bytes
//	CK_ULONG ulIvLen;            offset 8,  8 bytes
//	CK_ULONG ulIvFixedBits;      offset 16, 8 bytes
//	CK_ULONG ivGenerator;        offset 24, 8 bytes
//	CK_BYTE_PTR pTag;            offset 32, 8 bytes
//	CK_ULONG ulTagBits;          offset 40, 8 bytes
//
// total 48 bytes, cross-checked against unsafe.Sizeof(C.CK_GCM_MESSAGE_PARAMS{}).

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func buildGCMMessageParams(t testing.TB, iv []byte, ivFixedBits uint32, ivGenerator module.IVGenerator, tag []byte, tagBits uint32) []byte {
	buf := newAlignedBuf(48)
	putPtr(t, buf, 0, bytePtr(iv))
	putULong(buf, 8, uint64(len(iv)))
	putULong(buf, 16, uint64(ivFixedBits))
	putULong(buf, 24, uint64(ivGenerator))
	putPtr(t, buf, 32, bytePtr(tag))
	putULong(buf, 40, uint64(tagBits))
	return buf
}

func TestGCMMessageParams_WellFormedPopulatesEveryField(t *testing.T) {
	fn := reflect.ValueOf(gcmMessageParams)
	ft := fn.Type()

	iv := []byte("111122223333")
	tag := make([]byte, 16) // ulTagBits/8 = 128/8 = 16 bytes.
	buf := buildGCMMessageParams(t, iv, 64, module.CKG_GENERATE, tag, 128)

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(48)

	out := callCFn(gcmMessageParams, ptr, length)

	if !out[1].Bool() {
		t.Fatal("gcmMessageParams(well-formed) ok = false, want true")
	}
	params := out[0].Interface().(*module.AESGCMMessageParams)
	if !bytes.Equal(params.IV, iv) {
		t.Errorf("IV = %q, want %q", params.IV, iv)
	}
	if params.IVFixedBits != 64 {
		t.Errorf("IVFixedBits = %d, want 64", params.IVFixedBits)
	}
	if params.IVGenerator != module.CKG_GENERATE {
		t.Errorf("IVGenerator = %d, want CKG_GENERATE", params.IVGenerator)
	}
	if !bytes.Equal(params.Tag, tag) {
		t.Errorf("Tag = %x, want %x", params.Tag, tag)
	}
	if params.TagBits != 128 {
		t.Errorf("TagBits = %d, want 128", params.TagBits)
	}
}

// TestGCMMessageParams_DanglingIvLenIsRefused proves the IV field is checked
// before the tag is ever read.
func TestGCMMessageParams_DanglingIvLenIsRefused(t *testing.T) {
	fn := reflect.ValueOf(gcmMessageParams)
	ft := fn.Type()

	tag := make([]byte, 16)
	buf := buildGCMMessageParams(t, nil, 0, module.CKG_NO_GENERATE, tag, 128)
	putULong(buf, 8, 12) // ulIvLen says 12 bytes; pIv is still NULL.

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(48)

	out := callCFn(gcmMessageParams, ptr, length)
	if out[1].Bool() {
		t.Error("gcmMessageParams(dangling ulIvLen, NULL pIv) ok = true, want false")
	}
}

// TestGCMMessageParams_DanglingTagIsRefused proves the tag field, derived
// from ulTagBits rather than a separate byte count, is also checked.
func TestGCMMessageParams_DanglingTagIsRefused(t *testing.T) {
	fn := reflect.ValueOf(gcmMessageParams)
	ft := fn.Type()

	iv := []byte("111122223333")
	buf := buildGCMMessageParams(t, iv, 0, module.CKG_NO_GENERATE, nil, 128) // ulTagBits=128 (16 bytes); pTag is NULL.

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	length := reflect.New(ft.In(1)).Elem()
	length.SetUint(48)

	out := callCFn(gcmMessageParams, ptr, length)
	if out[1].Bool() {
		t.Error("gcmMessageParams(dangling tag, NULL pTag) ok = true, want false")
	}
}

// TestWriteGCMMessageParams_CopiesIVAndTagBack proves the token-produced IV
// and tag are written into the caller's destination buffers, and their
// length fields updated to the amount actually written -- the write-back
// C_EncryptMessage depends on to hand a generated IV back to the caller.
func TestWriteGCMMessageParams_CopiesIVAndTagBack(t *testing.T) {
	fn := reflect.ValueOf(writeGCMMessageParams)
	ft := fn.Type()

	ivDest := make([]byte, 16)  // room for more than the produced IV.
	tagDest := make([]byte, 16) // exactly the produced tag's size.
	buf := buildGCMMessageParams(t, ivDest, 0, module.CKG_GENERATE, tagDest, 0)

	producedIV := []byte("111122223333") // 12 bytes.
	producedTag := bytes.Repeat([]byte{0xAB}, 16)
	params := &module.AESGCMMessageParams{IV: producedIV, Tag: producedTag}

	// writeGCMMessageParams reads raw.ulIvLen/ulTagBits as the destination's
	// capacity, so they must describe ivDest/tagDest, not the produced values.
	putULong(buf, 8, uint64(len(ivDest)))
	putULong(buf, 40, uint64(len(tagDest)*8))

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	out := callCFn(writeGCMMessageParams, ptr, reflect.ValueOf(params))

	if got := module.CK_RV(out[0].Uint()); got != module.CKR_OK {
		t.Fatalf("writeGCMMessageParams(well-formed) = %s, want CKR_OK", got)
	}
	if !bytes.Equal(ivDest[:len(producedIV)], producedIV) {
		t.Errorf("ivDest = %x, want %x copied in", ivDest[:len(producedIV)], producedIV)
	}
	if !bytes.Equal(tagDest, producedTag) {
		t.Errorf("tagDest = %x, want %x", tagDest, producedTag)
	}
}

// TestWriteGCMMessageParams_UndersizedIVDestinationIsRefused proves a
// produced IV larger than the caller's declared ulIvLen is reported rather
// than truncated, which would silently hand back a shorter IV than the one
// actually used to encrypt.
func TestWriteGCMMessageParams_UndersizedIVDestinationIsRefused(t *testing.T) {
	fn := reflect.ValueOf(writeGCMMessageParams)
	ft := fn.Type()

	ivDest := make([]byte, 4) // shorter than the 12-byte produced IV.
	buf := buildGCMMessageParams(t, ivDest, 0, module.CKG_GENERATE, nil, 0)
	putULong(buf, 8, uint64(len(ivDest)))

	params := &module.AESGCMMessageParams{IV: []byte("111122223333")}

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	out := callCFn(writeGCMMessageParams, ptr, reflect.ValueOf(params))

	if got := module.CK_RV(out[0].Uint()); got != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("writeGCMMessageParams(undersized IV destination) = %s, want CKR_MECHANISM_PARAM_INVALID", got)
	}
}

// TestWriteGCMMessageParams_UndersizedTagDestinationIsRefused mirrors the IV
// case for the authentication tag, whose destination size is ulTagBits.
func TestWriteGCMMessageParams_UndersizedTagDestinationIsRefused(t *testing.T) {
	fn := reflect.ValueOf(writeGCMMessageParams)
	ft := fn.Type()

	tagDest := make([]byte, 8) // 64 bits, shorter than the 128-bit produced tag.
	buf := buildGCMMessageParams(t, nil, 0, module.CKG_NO_GENERATE, tagDest, 0)
	putULong(buf, 40, uint64(len(tagDest)*8))

	params := &module.AESGCMMessageParams{Tag: bytes.Repeat([]byte{0xCD}, 16)}

	ptr := cPtr(unsafe.Pointer(&buf[0]), ft, 0)
	out := callCFn(writeGCMMessageParams, ptr, reflect.ValueOf(params))

	if got := module.CK_RV(out[0].Uint()); got != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("writeGCMMessageParams(undersized tag destination) = %s, want CKR_MECHANISM_PARAM_INVALID", got)
	}
}
