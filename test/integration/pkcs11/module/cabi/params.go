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

#include "xkabi.h"
*/
import "C"

import (
	"unsafe"
)

// arena owns C heap allocations made for the duration of one Cryptoki call.
//
// Mechanism parameter structs point at further buffers (a PSS salt length is
// inline, but an OAEP label, an HKDF salt and info, and a GCM IV and AAD are
// all out-of-line). Those buffers must live in C memory: they are read by the
// module's own Go runtime through unsafe.Pointer arithmetic, and handing it
// Go-heap addresses would violate the cgo pointer rules that both runtimes
// rely on.
type arena struct {
	blocks []unsafe.Pointer
}

// alloc returns n zeroed bytes of C memory owned by the arena.
func (a *arena) alloc(n int) unsafe.Pointer {
	if n <= 0 {
		return nil
	}
	p := C.calloc(1, C.size_t(n))
	a.blocks = append(a.blocks, p)
	return p
}

// bytes copies b into C memory and returns its address and length. A nil or
// empty slice yields a NULL pointer and a zero length, which is how PKCS#11
// spells "absent".
func (a *arena) bytes(b []byte) (unsafe.Pointer, C.CK_ULONG) {
	if len(b) == 0 {
		return nil, 0
	}
	p := a.alloc(len(b))
	C.memcpy(p, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	return p, C.CK_ULONG(len(b))
}

// free releases every allocation the arena made.
func (a *arena) free() {
	for _, p := range a.blocks {
		C.free(p)
	}
	a.blocks = nil
}

// MechParams is a mechanism parameter that can be laid out as the C struct the
// specification defines for it.
//
// The interface method is unexported so that tests can only supply parameters
// built by the constructors in this file, each of which mirrors one spec
// struct field for field. A test cannot accidentally hand the module a Go
// value with a different layout than the C one.
type MechParams interface {
	build(a *arena) (unsafe.Pointer, C.CK_ULONG)
}

// RSAPSSParams is CK_RSA_PKCS_PSS_PARAMS (PKCS#11 v3.2 section 6.1.9).
type RSAPSSParams struct {
	// HashAlg is the digest mechanism the signature scheme uses.
	HashAlg uint
	// MGF is the mask generation function.
	MGF uint
	// SaltLen is the salt length in bytes.
	SaltLen uint
}

// build lays out CK_RSA_PKCS_PSS_PARAMS.
func (p RSAPSSParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}))
	raw := (*C.CK_RSA_PKCS_PSS_PARAMS)(a.alloc(int(size)))
	raw.hashAlg = C.CK_MECHANISM_TYPE(p.HashAlg)
	raw.mgf = C.CK_RSA_PKCS_MGF_TYPE(p.MGF)
	raw.sLen = C.CK_ULONG(p.SaltLen)
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// RSAOAEPParams is CK_RSA_PKCS_OAEP_PARAMS (PKCS#11 v3.2 section 6.1.10).
type RSAOAEPParams struct {
	// HashAlg is the digest used for the OAEP label and the MGF.
	HashAlg uint
	// MGF is the mask generation function.
	MGF uint
	// Source describes how the label is supplied.
	Source uint
	// SourceData is the OAEP label.
	SourceData []byte
}

// build lays out CK_RSA_PKCS_OAEP_PARAMS.
func (p RSAOAEPParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}))
	raw := (*C.CK_RSA_PKCS_OAEP_PARAMS)(a.alloc(int(size)))
	raw.hashAlg = C.CK_MECHANISM_TYPE(p.HashAlg)
	raw.mgf = C.CK_RSA_PKCS_MGF_TYPE(p.MGF)
	raw.source = C.CK_RSA_PKCS_OAEP_SOURCE_TYPE(p.Source)
	src, srcLen := a.bytes(p.SourceData)
	raw.pSourceData = C.CK_VOID_PTR(src)
	raw.ulSourceDataLen = srcLen
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// AESGCMParams is CK_GCM_PARAMS (PKCS#11 v3.2 section 6.10.9).
type AESGCMParams struct {
	// IV is the initialization vector.
	IV []byte
	// AAD is the additional authenticated data.
	AAD []byte
	// TagBits is the authentication tag length in bits.
	TagBits uint
}

// build lays out CK_GCM_PARAMS.
func (p AESGCMParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_GCM_PARAMS{}))
	raw := (*C.CK_GCM_PARAMS)(a.alloc(int(size)))
	iv, ivLen := a.bytes(p.IV)
	raw.pIv = C.CK_BYTE_PTR(iv)
	raw.ulIvLen = ivLen
	raw.ulIvBits = ivLen * 8
	aad, aadLen := a.bytes(p.AAD)
	raw.pAAD = C.CK_BYTE_PTR(aad)
	raw.ulAADLen = aadLen
	raw.ulTagBits = C.CK_ULONG(p.TagBits)
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// HKDFParams is CK_HKDF_PARAMS (PKCS#11 v3.2 section 6.62.2).
type HKDFParams struct {
	// Extract runs the HKDF extract step.
	Extract bool
	// Expand runs the HKDF expand step.
	Expand bool
	// PRFHashMech is the HMAC digest mechanism.
	PRFHashMech uint
	// SaltType selects among no salt, inline salt data and a salt key.
	SaltType uint
	// Salt is the inline salt when SaltType is CKF_HKDF_SALT_DATA.
	Salt []byte
	// SaltKey is the salt object handle when SaltType is CKF_HKDF_SALT_KEY.
	SaltKey uint
	// Info is the HKDF info string.
	Info []byte
}

// build lays out CK_HKDF_PARAMS.
func (p HKDFParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_HKDF_PARAMS{}))
	raw := (*C.CK_HKDF_PARAMS)(a.alloc(int(size)))
	raw.bExtract = cBool(p.Extract)
	raw.bExpand = cBool(p.Expand)
	raw.prfHashMechanism = C.CK_MECHANISM_TYPE(p.PRFHashMech)
	raw.ulSaltType = C.CK_ULONG(p.SaltType)
	salt, saltLen := a.bytes(p.Salt)
	raw.pSalt = C.CK_BYTE_PTR(salt)
	raw.ulSaltLen = saltLen
	raw.hSaltKey = C.CK_OBJECT_HANDLE(p.SaltKey)
	info, infoLen := a.bytes(p.Info)
	raw.pInfo = C.CK_BYTE_PTR(info)
	raw.ulInfoLen = infoLen
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// PRFDataParam is CK_PRF_DATA_PARAM, one input segment of an SP800-108 KDF.
type PRFDataParam struct {
	// Type is one of the CK_SP800_108_* segment types.
	Type uint
	// Value is the segment payload.
	Value []byte
}

// SP800108Params is CK_SP800_108_KDF_PARAMS (PKCS#11 v3.2 section 6.42).
type SP800108Params struct {
	// PRF is the CKM_*_HMAC or CKM_*_CMAC mechanism driving the KDF.
	PRF uint
	// DataParams are the PRF input segments in order.
	DataParams []PRFDataParam
}

// build lays out CK_SP800_108_KDF_PARAMS together with its CK_PRF_DATA_PARAM
// array.
func (p SP800108Params) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_SP800_108_KDF_PARAMS{}))
	raw := (*C.CK_SP800_108_KDF_PARAMS)(a.alloc(int(size)))
	raw.prfType = C.CK_SP800_108_PRF_TYPE(p.PRF)
	raw.ulNumberOfDataParams = C.CK_ULONG(len(p.DataParams))

	if len(p.DataParams) > 0 {
		entrySize := int(unsafe.Sizeof(C.CK_PRF_DATA_PARAM{}))
		array := (*C.CK_PRF_DATA_PARAM)(a.alloc(entrySize * len(p.DataParams)))
		for i, dp := range p.DataParams {
			value, valueLen := a.bytes(dp.Value)
			C.xk_prf_set(array, C.CK_ULONG(i), C.CK_PRF_DATA_TYPE(dp.Type), C.CK_VOID_PTR(value), valueLen)
		}
		raw.pDataParams = C.CK_PRF_DATA_PARAM_PTR(array)
	}

	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// EdDSAParams is CK_EDDSA_PARAMS (PKCS#11 v3.2 section 6.24). Supplying it at
// all selects a contextualised or prehashed EdDSA variant; omitting the
// mechanism parameter entirely selects pure Ed25519 or Ed448.
type EdDSAParams struct {
	// PreHash selects the ph variant (Ed25519ph, Ed448ph).
	PreHash bool
	// Context is the RFC 8032 context string.
	Context []byte
}

// build lays out CK_EDDSA_PARAMS.
func (p EdDSAParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_EDDSA_PARAMS{}))
	raw := (*C.CK_EDDSA_PARAMS)(a.alloc(int(size)))
	raw.phFlag = cBool(p.PreHash)
	ctx, ctxLen := a.bytes(p.Context)
	raw.pContextData = C.CK_BYTE_PTR(ctx)
	raw.ulContextDataLen = ctxLen
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// ECDH1DeriveParams is CK_ECDH1_DERIVE_PARAMS (PKCS#11 v3.2 section 6.3.7),
// used by CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE.
//
// The whole mechanism depends on this struct being parsed at the cgo
// boundary: deriveKeyECDH in pkg/pkcs11/module refuses to look at raw
// parameter bytes and returns CKR_MECHANISM_PARAM_INVALID unless the boundary
// handed it a populated *ECDHParams.
type ECDH1DeriveParams struct {
	// KDF is the CK_EC_KDF_TYPE applied to the raw shared secret.
	KDF uint
	// SharedData is the KDF's shared info. It contributes to the derived key,
	// so dropping it yields a plausible but wrong result.
	SharedData []byte
	// PublicData is the peer's public EC point.
	PublicData []byte
}

// build lays out CK_ECDH1_DERIVE_PARAMS.
func (p ECDH1DeriveParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}))
	raw := (*C.CK_ECDH1_DERIVE_PARAMS)(a.alloc(int(size)))
	raw.kdf = C.CK_EC_KDF_TYPE(p.KDF)
	shared, sharedLen := a.bytes(p.SharedData)
	raw.pSharedData = C.CK_BYTE_PTR(shared)
	raw.ulSharedDataLen = sharedLen
	public, publicLen := a.bytes(p.PublicData)
	raw.pPublicData = C.CK_BYTE_PTR(public)
	raw.ulPublicDataLen = publicLen
	return unsafe.Pointer(raw), C.CK_ULONG(size)
}

// TruncatedParams wraps another parameter and declares a shorter
// ulParameterLen than the struct really occupies.
//
// It exists to prove the boundary length-checks before it dereferences: a
// parser that trusts ulParameterLen reads a whole struct out of a buffer the
// caller says is smaller, which is a read past the end of caller memory.
type TruncatedParams struct {
	// Params is the parameter to lay out in full.
	Params MechParams
	// Length is the ulParameterLen to declare instead of the real size.
	Length uint
}

// build lays out the wrapped parameter but reports the truncated length.
func (p TruncatedParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	ptr, _ := p.Params.build(a)
	return ptr, C.CK_ULONG(p.Length)
}

// SizeOfECDH1DeriveParams returns sizeof(CK_ECDH1_DERIVE_PARAMS), so a test
// can express a truncation relative to the real struct rather than hardcoding
// a byte count that a 32-bit build would make wrong.
func SizeOfECDH1DeriveParams() uint {
	return uint(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}))
}

// SizeOfGCMMessageParams returns sizeof(CK_GCM_MESSAGE_PARAMS).
func SizeOfGCMMessageParams() uint {
	return uint(unsafe.Sizeof(C.CK_GCM_MESSAGE_PARAMS{}))
}

// RawParams is an opaque mechanism parameter passed through byte for byte. It
// exists so a test can present a deliberately malformed or truncated struct
// and assert the module rejects it rather than reading past the end.
type RawParams []byte

// build copies the raw bytes into the arena.
func (p RawParams) build(a *arena) (unsafe.Pointer, C.CK_ULONG) {
	return a.bytes(p)
}

// cBool converts a Go bool to CK_BBOOL.
func cBool(v bool) C.CK_BBOOL {
	if v {
		return C.CK_BBOOL(1)
	}
	return C.CK_BBOOL(0)
}

// Attr is one CK_ATTRIBUTE of an object template.
type Attr struct {
	// Type is the CKA_ identifier.
	Type uint
	// Value is the attribute's raw encoding.
	Value []byte
}

// AttrBool builds a CK_BBOOL attribute.
func AttrBool(t uint, v bool) Attr {
	b := byte(0)
	if v {
		b = 1
	}
	return Attr{Type: t, Value: []byte{b}}
}

// AttrULong builds a CK_ULONG attribute in the platform's native encoding,
// which is what the C ABI expects.
func AttrULong(t uint, v uint) Attr {
	size := int(unsafe.Sizeof(C.CK_ULONG(0)))
	buf := make([]byte, size)
	value := v
	for i := 0; i < size; i++ {
		buf[i] = byte(value)
		value >>= 8
	}
	return Attr{Type: t, Value: buf}
}

// AttrBytes builds an attribute from raw bytes.
func AttrBytes(t uint, v []byte) Attr {
	return Attr{Type: t, Value: v}
}

// AttrString builds an attribute from a string, used for CKA_LABEL.
func AttrString(t uint, v string) Attr {
	return Attr{Type: t, Value: []byte(v)}
}

// buildTemplate lays out attrs as a CK_ATTRIBUTE array in the arena.
func buildTemplate(a *arena, attrs []Attr) (C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	if len(attrs) == 0 {
		return nil, 0
	}
	entrySize := int(unsafe.Sizeof(C.CK_ATTRIBUTE{}))
	array := (*C.CK_ATTRIBUTE)(a.alloc(entrySize * len(attrs)))
	for i, attr := range attrs {
		value, valueLen := a.bytes(attr.Value)
		C.xk_attr_set(array, C.CK_ULONG(i), C.CK_ATTRIBUTE_TYPE(attr.Type), C.CK_VOID_PTR(value), valueLen)
	}
	return C.CK_ATTRIBUTE_PTR(array), C.CK_ULONG(len(attrs))
}

// buildMechanism lays out a CK_MECHANISM carrying params, which may be nil for
// a mechanism that takes none.
func buildMechanism(a *arena, mechType uint, params MechParams) C.CK_MECHANISM_PTR {
	size := int(unsafe.Sizeof(C.CK_MECHANISM{}))
	mech := (*C.CK_MECHANISM)(a.alloc(size))
	mech.mechanism = C.CK_MECHANISM_TYPE(mechType)
	if params != nil {
		p, pLen := params.build(a)
		mech.pParameter = C.CK_VOID_PTR(p)
		mech.ulParameterLen = pLen
	}
	return C.CK_MECHANISM_PTR(mech)
}
