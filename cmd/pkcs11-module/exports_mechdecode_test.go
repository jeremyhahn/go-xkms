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

// Tests for the mechanism-parameter decoders in exports.go
// (decodeECDH1DeriveParams, decodeRSAPSSParams, decodeRSAOAEPParams,
// decodeGCMParams, decodeHKDFParams, decodeSP800108KDFParams,
// decodeSP800108FeedbackKDFParams, decodeEdDSAParams) and the shared array
// helper they call through (convertSP800108DataParams).
//
// Every one of these has the signature func(pParameter unsafe.Pointer) (any,
// bool): unsafe.Pointer is an ordinary Go type, not a cgo-generated one, so
// unlike the exported C_* entry points (see exports_test.go) these can be
// called directly without reflection. What a _test.go file still cannot do
// is name a C struct type to build the argument with, so each test hand-lays
// the CK_*_PARAMS structure out as a byte buffer at the field offsets
// pkcs11t.h declares, using the standard SysV amd64 layout (8-byte CK_ULONG
// and pointer fields, natural alignment, 1-byte CK_BBOOL). Those offsets are
// cross-checked against unsafe.Sizeof(C.CK_*_PARAMS{}) captured from the
// package's own mechanismParameterDecoders table, which exports.go builds
// with cgo, so a struct-layout assumption that drifted from the real ABI
// would show up as a size mismatch in TestMechanismParameterDecoders_CoverEveryParameterisedMechanism
// (exports_paramdecode_test.go) before it could hide a bug here.
//
// A pointer field is written as the numeric address of a second, independent
// byte slice. Go's non-cgo-aware GC cannot see that relationship -- the
// address is just an integer to it -- so putPtr pins the memory that address
// points into (see pin) for the lifetime of the test, which is what actually
// keeps the referenced slice's backing storage from being collected or moved
// out from under the raw pointer value while a decoder still reads through
// it.

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// newAlignedBuf allocates an n-byte buffer guaranteed to start on an 8-byte
// boundary, by carving it out of a []uint64 backing array. Every CK_*_PARAMS
// structure here has a CK_ULONG or pointer field, both 8-byte aligned in the
// real C ABI; go vet's checkptr instrumentation (enabled under -race) enforces
// that alignment on the unsafe.Pointer-to-C-struct-pointer cast the decoders
// make, and a plain make([]byte, n) is not guaranteed to land on an 8-byte
// boundary for every size class.
func newAlignedBuf(n int) []byte {
	if n == 0 {
		return nil
	}
	words := (n + 7) / 8
	u := make([]uint64, words)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), n)
}

// putULong writes v as an 8-byte little-endian CK_ULONG at buf[offset:].
func putULong(buf []byte, offset int, v uint64) {
	binary.LittleEndian.PutUint64(buf[offset:offset+8], v)
}

// pin pins the Go allocation p points into for the remainder of t, so the
// pointer putPtr writes as a raw integer stays valid regardless of how long
// the buffer that carries it remains in use. A []byte buffer built by hand to
// mimic a C struct's layout has no field the GC recognizes as a pointer --
// only a variable's static type tells the collector which words to trace --
// so nothing else here keeps p's target reachable once its address has been
// copied into buf as bytes. This is the cgo pointer-passing rule (a Go
// pointer the runtime cannot see as a pointer must be pinned) applied to
// Go-only test helpers that reproduce a C struct's byte layout without ever
// crossing into C.
func pin(t testing.TB, p unsafe.Pointer) {
	if p == nil {
		return
	}
	var pinner runtime.Pinner
	pinner.Pin(p)
	t.Cleanup(pinner.Unpin)
}

// putPtr writes p's address as an 8-byte little-endian pointer field at
// buf[offset:], pinning p's target for the rest of t (see pin). A nil p
// writes the null pointer and pins nothing.
func putPtr(t testing.TB, buf []byte, offset int, p unsafe.Pointer) {
	binary.LittleEndian.PutUint64(buf[offset:offset+8], uint64(uintptr(p)))
	pin(t, p)
}

// bytePtr returns a pointer to b's first byte, or nil for an empty/nil slice
// -- the same NULL a real CK_BYTE_PTR carries for an absent buffer.
func bytePtr(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

// ---------------------------------------------------------------------------
// CK_ECDH1_DERIVE_PARAMS (v3.2 section 6.3.16):
//
//	CK_EC_KDF_TYPE kdf;          offset 0,  8 bytes
//	CK_ULONG ulSharedDataLen;    offset 8,  8 bytes
//	CK_BYTE_PTR pSharedData;     offset 16, 8 bytes
//	CK_ULONG ulPublicDataLen;    offset 24, 8 bytes
//	CK_BYTE_PTR pPublicData;     offset 32, 8 bytes
//
// total 40 bytes, matching the decoder's StructSize.
// ---------------------------------------------------------------------------

func buildECDH1DeriveParams(t testing.TB, kdf module.KDFType, sharedData, publicData []byte) []byte {
	buf := newAlignedBuf(40)
	putULong(buf, 0, uint64(kdf))
	putULong(buf, 8, uint64(len(sharedData)))
	putPtr(t, buf, 16, bytePtr(sharedData))
	putULong(buf, 24, uint64(len(publicData)))
	putPtr(t, buf, 32, bytePtr(publicData))
	return buf
}

func TestDecodeECDH1DeriveParams_WellFormed(t *testing.T) {
	shared := []byte("shared-info")
	public := []byte("uncompressed-point")
	buf := buildECDH1DeriveParams(t, module.CKD_SHA256_KDF, shared, public)

	got, ok := decodeECDH1DeriveParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeECDH1DeriveParams(well-formed) ok = false, want true")
	}
	params, isType := got.(*module.ECDHParams)
	if !isType {
		t.Fatalf("decodeECDH1DeriveParams returned %T, want *module.ECDHParams", got)
	}
	if params.KDF != module.CKD_SHA256_KDF {
		t.Errorf("KDF = 0x%X, want CKD_SHA256_KDF", uint32(params.KDF))
	}
	if !bytes.Equal(params.SharedData, shared) {
		t.Errorf("SharedData = %q, want %q", params.SharedData, shared)
	}
	if !bytes.Equal(params.PublicData, public) {
		t.Errorf("PublicData = %q, want %q", params.PublicData, public)
	}
}

// TestDecodeECDH1DeriveParams_ZeroLengthFieldsAreEmpty proves the ECDH1
// SharedData field is genuinely optional (v3.2 section 6.3.16): a zero
// ulSharedDataLen with a NULL pSharedData decodes to a nil slice rather than
// being refused, distinguishing an absent optional field from a malformed one.
func TestDecodeECDH1DeriveParams_ZeroLengthFieldsAreEmpty(t *testing.T) {
	buf := buildECDH1DeriveParams(t, module.CKD_NULL, nil, nil)

	got, ok := decodeECDH1DeriveParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeECDH1DeriveParams(no shared/public data) ok = false, want true")
	}
	params := got.(*module.ECDHParams)
	if params.SharedData != nil {
		t.Errorf("SharedData = %v, want nil", params.SharedData)
	}
	if params.PublicData != nil {
		t.Errorf("PublicData = %v, want nil", params.PublicData)
	}
}

// TestDecodeECDH1DeriveParams_DanglingSharedDataLenIsRefused proves a
// declared length with no buffer behind it is refused rather than
// dereferencing a NULL pointer, mirroring cBytes's contract.
func TestDecodeECDH1DeriveParams_DanglingSharedDataLenIsRefused(t *testing.T) {
	buf := buildECDH1DeriveParams(t, module.CKD_NULL, nil, []byte("public"))
	putULong(buf, 8, 16) // ulSharedDataLen says 16 bytes; pSharedData is still NULL.

	_, ok := decodeECDH1DeriveParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeECDH1DeriveParams(dangling ulSharedDataLen, NULL pSharedData) ok = true, want false")
	}
}

// TestDecodeECDH1DeriveParams_DanglingPublicDataLenIsRefused is the same
// check for the second byte-buffer pair, proving the function does not stop
// checking after the first field succeeds.
func TestDecodeECDH1DeriveParams_DanglingPublicDataLenIsRefused(t *testing.T) {
	buf := buildECDH1DeriveParams(t, module.CKD_NULL, []byte("shared"), nil)
	putULong(buf, 24, 16) // ulPublicDataLen says 16 bytes; pPublicData is still NULL.

	_, ok := decodeECDH1DeriveParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeECDH1DeriveParams(dangling ulPublicDataLen, NULL pPublicData) ok = true, want false")
	}
}

// ---------------------------------------------------------------------------
// CK_RSA_PKCS_PSS_PARAMS (v3.2 section 6.1.9): hashAlg, mgf, sLen, three
// 8-byte CK_ULONG-family fields with no pointers -- decodeRSAPSSParams
// always succeeds once checkMechanismParameter has admitted the buffer.
// ---------------------------------------------------------------------------

func buildRSAPSSParams(hashAlg module.MechanismType, mgf module.MGFType, saltLen uint32) []byte {
	buf := newAlignedBuf(24)
	putULong(buf, 0, uint64(hashAlg))
	putULong(buf, 8, uint64(mgf))
	putULong(buf, 16, uint64(saltLen))
	return buf
}

func TestDecodeRSAPSSParams(t *testing.T) {
	buf := buildRSAPSSParams(module.CKM_SHA256, module.CKG_MGF1_SHA256, 32)

	got, ok := decodeRSAPSSParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeRSAPSSParams ok = false, want true")
	}
	want := &module.RSAPSSParams{HashAlg: module.CKM_SHA256, MGF: module.CKG_MGF1_SHA256, SaltLen: 32}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decodeRSAPSSParams = %+v, want %+v", got, want)
	}
}

// ---------------------------------------------------------------------------
// CK_RSA_PKCS_OAEP_PARAMS (v3.2 section 6.1.7):
//
//	CK_MECHANISM_TYPE hashAlg;             offset 0,  8 bytes
//	CK_RSA_PKCS_MGF_TYPE mgf;               offset 8,  8 bytes
//	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;    offset 16, 8 bytes
//	CK_VOID_PTR pSourceData;                offset 24, 8 bytes
//	CK_ULONG ulSourceDataLen;               offset 32, 8 bytes
//
// total 40 bytes.
// ---------------------------------------------------------------------------

func buildRSAOAEPParams(t testing.TB, hashAlg module.MechanismType, mgf module.MGFType, source uint32, sourceData []byte) []byte {
	buf := newAlignedBuf(40)
	putULong(buf, 0, uint64(hashAlg))
	putULong(buf, 8, uint64(mgf))
	putULong(buf, 16, uint64(source))
	putPtr(t, buf, 24, bytePtr(sourceData))
	putULong(buf, 32, uint64(len(sourceData)))
	return buf
}

func TestDecodeRSAOAEPParams_WellFormed(t *testing.T) {
	label := []byte("oaep-label")
	buf := buildRSAOAEPParams(t, module.CKM_SHA256, module.CKG_MGF1_SHA256, module.CKZ_DATA_SPECIFIED, label)

	got, ok := decodeRSAOAEPParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeRSAOAEPParams(well-formed) ok = false, want true")
	}
	params := got.(*module.RSAOAEPParams)
	if params.HashAlg != module.CKM_SHA256 || params.MGF != module.CKG_MGF1_SHA256 || params.Source != module.CKZ_DATA_SPECIFIED {
		t.Errorf("decodeRSAOAEPParams scalar fields = %+v, want HashAlg=CKM_SHA256 MGF=CKG_MGF1_SHA256 Source=CKZ_DATA_SPECIFIED", params)
	}
	if !bytes.Equal(params.SourceData, label) {
		t.Errorf("SourceData = %q, want %q", params.SourceData, label)
	}
}

// TestDecodeRSAOAEPParams_NoSourceDataIsEmpty proves the label is optional
// even though CKM_RSA_PKCS_OAEP's parameter structure as a whole is required
// (checkMechanismParameter enforces that at the mechanism-admission layer,
// not here): a zero ulSourceDataLen and NULL pSourceData is CKZ_DATA_SPECIFIED
// with no label, which section 6.1.7 permits.
func TestDecodeRSAOAEPParams_NoSourceDataIsEmpty(t *testing.T) {
	buf := buildRSAOAEPParams(t, module.CKM_SHA256, module.CKG_MGF1_SHA256, module.CKZ_DATA_SPECIFIED, nil)

	got, ok := decodeRSAOAEPParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeRSAOAEPParams(no source data) ok = false, want true")
	}
	if params := got.(*module.RSAOAEPParams); params.SourceData != nil {
		t.Errorf("SourceData = %v, want nil", params.SourceData)
	}
}

// TestDecodeRSAOAEPParams_DanglingSourceDataLenIsRefused proves a declared
// source-data length with no buffer behind it is refused rather than read.
func TestDecodeRSAOAEPParams_DanglingSourceDataLenIsRefused(t *testing.T) {
	buf := buildRSAOAEPParams(t, module.CKM_SHA256, module.CKG_MGF1_SHA256, module.CKZ_DATA_SPECIFIED, nil)
	putULong(buf, 32, 8) // ulSourceDataLen says 8 bytes; pSourceData is still NULL.

	_, ok := decodeRSAOAEPParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeRSAOAEPParams(dangling ulSourceDataLen, NULL pSourceData) ok = true, want false")
	}
}

// ---------------------------------------------------------------------------
// CK_GCM_PARAMS (v3.2 section 6.13.7):
//
//	CK_BYTE_PTR pIv;      offset 0,  8 bytes
//	CK_ULONG ulIvLen;     offset 8,  8 bytes
//	CK_ULONG ulIvBits;    offset 16, 8 bytes
//	CK_BYTE_PTR pAAD;     offset 24, 8 bytes
//	CK_ULONG ulAADLen;    offset 32, 8 bytes
//	CK_ULONG ulTagBits;   offset 40, 8 bytes
//
// total 48 bytes.
// ---------------------------------------------------------------------------

func buildGCMParams(t testing.TB, iv []byte, ivBits uint64, aad []byte, tagBits uint32) []byte {
	buf := newAlignedBuf(48)
	putPtr(t, buf, 0, bytePtr(iv))
	putULong(buf, 8, uint64(len(iv)))
	putULong(buf, 16, ivBits)
	putPtr(t, buf, 24, bytePtr(aad))
	putULong(buf, 32, uint64(len(aad)))
	putULong(buf, 40, uint64(tagBits))
	return buf
}

func TestDecodeGCMParams_WellFormed(t *testing.T) {
	iv := []byte("111122223333")
	aad := []byte("additional-data")
	buf := buildGCMParams(t, iv, 96, aad, 128)

	got, ok := decodeGCMParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeGCMParams(well-formed) ok = false, want true")
	}
	params := got.(*module.AESGCMParams)
	if !bytes.Equal(params.IV, iv) {
		t.Errorf("IV = %q, want %q", params.IV, iv)
	}
	if !bytes.Equal(params.AAD, aad) {
		t.Errorf("AAD = %q, want %q", params.AAD, aad)
	}
	if params.TagBits != 128 {
		t.Errorf("TagBits = %d, want 128", params.TagBits)
	}
}

// TestDecodeGCMParams_NoAADIsEmpty proves AAD, which NIST SP 800-38D makes
// optional, decodes to nil rather than being refused when absent.
func TestDecodeGCMParams_NoAADIsEmpty(t *testing.T) {
	iv := []byte("111122223333")
	buf := buildGCMParams(t, iv, 96, nil, 128)

	got, ok := decodeGCMParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeGCMParams(no AAD) ok = false, want true")
	}
	if params := got.(*module.AESGCMParams); params.AAD != nil {
		t.Errorf("AAD = %v, want nil", params.AAD)
	}
}

// TestDecodeGCMParams_DanglingIvLenIsRefused proves the IV field is checked
// before AAD is ever read.
func TestDecodeGCMParams_DanglingIvLenIsRefused(t *testing.T) {
	buf := buildGCMParams(t, nil, 96, []byte("aad"), 128)
	putULong(buf, 8, 12) // ulIvLen says 12 bytes; pIv is still NULL.

	_, ok := decodeGCMParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeGCMParams(dangling ulIvLen, NULL pIv) ok = true, want false")
	}
}

// TestDecodeGCMParams_DanglingAADLenIsRefused proves the AAD field is also
// checked, after a well-formed IV.
func TestDecodeGCMParams_DanglingAADLenIsRefused(t *testing.T) {
	iv := []byte("111122223333")
	buf := buildGCMParams(t, iv, 96, nil, 128)
	putULong(buf, 32, 5) // ulAADLen says 5 bytes; pAAD is still NULL.

	_, ok := decodeGCMParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeGCMParams(dangling ulAADLen, NULL pAAD) ok = true, want false")
	}
}

// ---------------------------------------------------------------------------
// CK_HKDF_PARAMS (v3.2 section 6.62.2):
//
//	CK_BBOOL bExtract;                offset 0,  1 byte
//	CK_BBOOL bExpand;                 offset 1,  1 byte
//	(6 bytes padding to the next 8-byte-aligned field)
//	CK_MECHANISM_TYPE prfHashMechanism; offset 8,  8 bytes
//	CK_ULONG ulSaltType;              offset 16, 8 bytes
//	CK_BYTE_PTR pSalt;                offset 24, 8 bytes
//	CK_ULONG ulSaltLen;               offset 32, 8 bytes
//	CK_OBJECT_HANDLE hSaltKey;        offset 40, 8 bytes
//	CK_BYTE_PTR pInfo;                offset 48, 8 bytes
//	CK_ULONG ulInfoLen;               offset 56, 8 bytes
//
// total 64 bytes.
// ---------------------------------------------------------------------------

func buildHKDFParams(t testing.TB, extract, expand bool, prf module.MechanismType, saltType module.HKDFSaltType, salt []byte, saltKey module.ObjectHandle, info []byte) []byte {
	buf := newAlignedBuf(64)
	if extract {
		buf[0] = 1
	}
	if expand {
		buf[1] = 1
	}
	putULong(buf, 8, uint64(prf))
	putULong(buf, 16, uint64(saltType))
	putPtr(t, buf, 24, bytePtr(salt))
	putULong(buf, 32, uint64(len(salt)))
	putULong(buf, 40, uint64(saltKey))
	putPtr(t, buf, 48, bytePtr(info))
	putULong(buf, 56, uint64(len(info)))
	return buf
}

func TestDecodeHKDFParams_WellFormed(t *testing.T) {
	salt := []byte("hkdf-salt")
	info := []byte("hkdf-info")
	buf := buildHKDFParams(t, true, true, module.CKM_SHA256, module.CKF_HKDF_SALT_DATA, salt, module.ObjectHandle(0x1234), info)

	got, ok := decodeHKDFParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeHKDFParams(well-formed) ok = false, want true")
	}
	params := got.(*module.HKDFParams)
	if !params.Extract || !params.Expand {
		t.Errorf("Extract/Expand = %v/%v, want true/true", params.Extract, params.Expand)
	}
	if params.PRFHashMech != module.CKM_SHA256 {
		t.Errorf("PRFHashMech = 0x%X, want CKM_SHA256", uint32(params.PRFHashMech))
	}
	if params.SaltType != module.CKF_HKDF_SALT_DATA {
		t.Errorf("SaltType = 0x%X, want CKF_HKDF_SALT_DATA", uint32(params.SaltType))
	}
	if params.SaltKey != module.ObjectHandle(0x1234) {
		t.Errorf("SaltKey = 0x%X, want 0x1234", uint64(params.SaltKey))
	}
	if !bytes.Equal(params.Salt, salt) {
		t.Errorf("Salt = %q, want %q", params.Salt, salt)
	}
	if !bytes.Equal(params.Info, info) {
		t.Errorf("Info = %q, want %q", params.Info, info)
	}
}

// TestDecodeHKDFParams_ExtractOnlyHasNoSaltOrInfo proves the boolean fields
// decode independently of the byte-buffer fields: an extract-only request
// (CKF_HKDF_SALT_NULL, no salt, no info -- section 6.62.2's "no salt" case)
// still decodes cleanly with nil Salt/Info.
func TestDecodeHKDFParams_ExtractOnlyHasNoSaltOrInfo(t *testing.T) {
	buf := buildHKDFParams(t, true, false, module.CKM_SHA256, module.CKF_HKDF_SALT_NULL, nil, 0, nil)

	got, ok := decodeHKDFParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeHKDFParams(extract-only) ok = false, want true")
	}
	params := got.(*module.HKDFParams)
	if params.Extract != true || params.Expand != false {
		t.Errorf("Extract/Expand = %v/%v, want true/false", params.Extract, params.Expand)
	}
	if params.Salt != nil || params.Info != nil {
		t.Errorf("Salt/Info = %v/%v, want nil/nil", params.Salt, params.Info)
	}
}

// TestDecodeHKDFParams_DanglingSaltLenIsRefused proves the salt field is
// checked before info is read.
func TestDecodeHKDFParams_DanglingSaltLenIsRefused(t *testing.T) {
	buf := buildHKDFParams(t, true, true, module.CKM_SHA256, module.CKF_HKDF_SALT_DATA, nil, 0, []byte("info"))
	putULong(buf, 32, 16) // ulSaltLen says 16 bytes; pSalt is still NULL.

	_, ok := decodeHKDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeHKDFParams(dangling ulSaltLen, NULL pSalt) ok = true, want false")
	}
}

// TestDecodeHKDFParams_DanglingInfoLenIsRefused proves the info field is
// also checked, after a well-formed salt.
func TestDecodeHKDFParams_DanglingInfoLenIsRefused(t *testing.T) {
	salt := []byte("hkdf-salt")
	buf := buildHKDFParams(t, true, true, module.CKM_SHA256, module.CKF_HKDF_SALT_DATA, salt, 0, nil)
	putULong(buf, 56, 16) // ulInfoLen says 16 bytes; pInfo is still NULL.

	_, ok := decodeHKDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeHKDFParams(dangling ulInfoLen, NULL pInfo) ok = true, want false")
	}
}

// ---------------------------------------------------------------------------
// CK_PRF_DATA_PARAM (v3.2 section 6.42, Table 197):
//
//	CK_PRF_DATA_TYPE type;   offset 0,  8 bytes
//	CK_VOID_PTR pValue;      offset 8,  8 bytes
//	CK_ULONG ulValueLen;     offset 16, 8 bytes
//
// total 24 bytes each, packed contiguously into an array.
//
// CK_SP800_108_KDF_PARAMS (v3.2 section 6.42):
//
//	CK_SP800_108_PRF_TYPE prfType;             offset 0,  8 bytes
//	CK_ULONG ulNumberOfDataParams;              offset 8,  8 bytes
//	CK_PRF_DATA_PARAM_PTR pDataParams;          offset 16, 8 bytes
//	CK_ULONG ulAdditionalDerivedKeys;           offset 24, 8 bytes
//	CK_DERIVED_KEY_PTR pAdditionalDerivedKeys;  offset 32, 8 bytes
//
// total 40 bytes.
// ---------------------------------------------------------------------------

// buildPRFDataParams packs entries into a contiguous CK_PRF_DATA_PARAM array,
// returning the array bytes alongside the count -- convertSP800108DataParams
// reads count as a separate CK_ULONG field on the enclosing struct, not a
// terminator within the array itself.
func buildPRFDataParams(t testing.TB, entries []module.SP800108DataParam) []byte {
	buf := newAlignedBuf(24 * len(entries))
	for i, e := range entries {
		off := 24 * i
		putULong(buf, off, uint64(e.Type))
		putPtr(t, buf, off+8, bytePtr(e.Value))
		putULong(buf, off+16, uint64(len(e.Value)))
	}
	return buf
}

func buildSP800108KDFParams(t testing.TB, prf module.MechanismType, dataParams []byte, count int) []byte {
	buf := newAlignedBuf(40)
	putULong(buf, 0, uint64(prf))
	putULong(buf, 8, uint64(count))
	putPtr(t, buf, 16, bytePtr(dataParams))
	return buf
}

func TestDecodeSP800108KDFParams_WellFormed(t *testing.T) {
	segA := []byte("label")
	segB := []byte("context")
	entries := []module.SP800108DataParam{
		{Type: module.SP800108ByteArray, Value: segA},
		{Type: module.SP800108ByteArray, Value: segB},
	}
	dataParams := buildPRFDataParams(t, entries)
	buf := buildSP800108KDFParams(t, module.CKM_SHA256_HMAC, dataParams, len(entries))

	got, ok := decodeSP800108KDFParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeSP800108KDFParams(well-formed) ok = false, want true")
	}
	params := got.(*module.SP800108KDFParams)
	if params.PRF != module.CKM_SHA256_HMAC {
		t.Errorf("PRF = 0x%X, want CKM_SHA256_HMAC", uint32(params.PRF))
	}
	if !reflect.DeepEqual(params.DataParams, entries) {
		t.Errorf("DataParams = %+v, want %+v", params.DataParams, entries)
	}
}

// TestDecodeSP800108KDFParams_NoDataParamsIsEmpty proves a zero-count array
// (pDataParams NULL, ulNumberOfDataParams 0) decodes to an empty result
// rather than being refused -- convertSP800108DataParams's own nil/zero
// short-circuit.
func TestDecodeSP800108KDFParams_NoDataParamsIsEmpty(t *testing.T) {
	buf := buildSP800108KDFParams(t, module.CKM_SHA256_HMAC, nil, 0)

	got, ok := decodeSP800108KDFParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeSP800108KDFParams(no data params) ok = false, want true")
	}
	if params := got.(*module.SP800108KDFParams); params.DataParams != nil {
		t.Errorf("DataParams = %+v, want nil", params.DataParams)
	}
}

// TestDecodeSP800108KDFParams_DanglingEntryValueLenIsRefused proves a
// CK_PRF_DATA_PARAM entry whose declared ulValueLen has no pValue behind it
// fails the whole decode, rather than truncating that one segment.
func TestDecodeSP800108KDFParams_DanglingEntryValueLenIsRefused(t *testing.T) {
	entries := []module.SP800108DataParam{{Type: module.SP800108ByteArray, Value: nil}}
	dataParams := buildPRFDataParams(t, entries)
	putULong(dataParams, 16, 8) // entry 0's ulValueLen says 8 bytes; pValue is still NULL.
	buf := buildSP800108KDFParams(t, module.CKM_SHA256_HMAC, dataParams, 1)

	_, ok := decodeSP800108KDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeSP800108KDFParams(dangling entry ulValueLen) ok = true, want false")
	}
}

// TestDecodeSP800108KDFParams_UnaddressableCountIsRefused proves
// convertSP800108DataParams's own overflow guard: a ulNumberOfDataParams
// larger than the largest addressable Go slice index is refused rather than
// used to index into memory, even though pDataParams is non-NULL.
func TestDecodeSP800108KDFParams_UnaddressableCountIsRefused(t *testing.T) {
	buf := buildSP800108KDFParams(t, module.CKM_SHA256_HMAC, buf40Placeholder(), 0)
	putULong(buf, 8, uint64(math.MaxInt32)+1) // ulNumberOfDataParams exceeds math.MaxInt32.

	_, ok := decodeSP800108KDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeSP800108KDFParams(count > MaxInt32) ok = true, want false")
	}
}

// buf40Placeholder returns a non-empty, non-nil buffer to stand in for a
// pDataParams pointer that TestDecodeSP800108KDFParams_UnaddressableCountIsRefused
// needs to be non-NULL; convertSP800108DataParams's count bound is checked
// before the pointer is ever dereferenced, so its contents are never read.
func buf40Placeholder() []byte { return newAlignedBuf(8) }

// ---------------------------------------------------------------------------
// CK_SP800_108_FEEDBACK_KDF_PARAMS (v3.2 section 6.42):
//
//	CK_SP800_108_PRF_TYPE prfType;             offset 0,  8 bytes
//	CK_ULONG ulNumberOfDataParams;              offset 8,  8 bytes
//	CK_PRF_DATA_PARAM_PTR pDataParams;          offset 16, 8 bytes
//	CK_ULONG ulIVLen;                           offset 24, 8 bytes
//	CK_BYTE_PTR pIV;                            offset 32, 8 bytes
//	CK_ULONG ulAdditionalDerivedKeys;           offset 40, 8 bytes
//	CK_DERIVED_KEY_PTR pAdditionalDerivedKeys;  offset 48, 8 bytes
//
// total 56 bytes.
// ---------------------------------------------------------------------------

func buildSP800108FeedbackKDFParams(t testing.TB, prf module.MechanismType, dataParams []byte, count int, iv []byte) []byte {
	buf := newAlignedBuf(56)
	putULong(buf, 0, uint64(prf))
	putULong(buf, 8, uint64(count))
	putPtr(t, buf, 16, bytePtr(dataParams))
	putULong(buf, 24, uint64(len(iv)))
	putPtr(t, buf, 32, bytePtr(iv))
	return buf
}

func TestDecodeSP800108FeedbackKDFParams_WellFormed(t *testing.T) {
	seg := []byte("label")
	entries := []module.SP800108DataParam{{Type: module.SP800108ByteArray, Value: seg}}
	dataParams := buildPRFDataParams(t, entries)
	iv := []byte("0123456789ABCDEF")
	buf := buildSP800108FeedbackKDFParams(t, module.CKM_SHA256_HMAC, dataParams, len(entries), iv)

	got, ok := decodeSP800108FeedbackKDFParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeSP800108FeedbackKDFParams(well-formed) ok = false, want true")
	}
	params := got.(*module.SP800108KDFParams)
	if params.PRF != module.CKM_SHA256_HMAC {
		t.Errorf("PRF = 0x%X, want CKM_SHA256_HMAC", uint32(params.PRF))
	}
	if !reflect.DeepEqual(params.DataParams, entries) {
		t.Errorf("DataParams = %+v, want %+v", params.DataParams, entries)
	}
	if !bytes.Equal(params.IV, iv) {
		t.Errorf("IV = %q, want %q", params.IV, iv)
	}
}

// TestDecodeSP800108FeedbackKDFParams_DataParamsFailurePropagates proves the
// feedback variant refuses the whole parameter, the same as the
// counter/double-pipeline variant, when one PRF input segment is malformed --
// it must not silently keep the IV and drop the malformed segments.
func TestDecodeSP800108FeedbackKDFParams_DataParamsFailurePropagates(t *testing.T) {
	entries := []module.SP800108DataParam{{Type: module.SP800108ByteArray, Value: nil}}
	dataParams := buildPRFDataParams(t, entries)
	putULong(dataParams, 16, 8) // entry 0's ulValueLen says 8 bytes; pValue is still NULL.
	buf := buildSP800108FeedbackKDFParams(t, module.CKM_SHA256_HMAC, dataParams, 1, []byte("0123456789ABCDEF"))

	_, ok := decodeSP800108FeedbackKDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeSP800108FeedbackKDFParams(dangling entry ulValueLen) ok = true, want false")
	}
}

// TestDecodeSP800108FeedbackKDFParams_DanglingIVLenIsRefused proves the IV
// field, unique to the feedback variant, is checked after a well-formed
// (here, empty) data-params array.
func TestDecodeSP800108FeedbackKDFParams_DanglingIVLenIsRefused(t *testing.T) {
	buf := buildSP800108FeedbackKDFParams(t, module.CKM_SHA256_HMAC, nil, 0, nil)
	putULong(buf, 24, 16) // ulIVLen says 16 bytes; pIV is still NULL.

	_, ok := decodeSP800108FeedbackKDFParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeSP800108FeedbackKDFParams(dangling ulIVLen, NULL pIV) ok = true, want false")
	}
}

// ---------------------------------------------------------------------------
// CK_EDDSA_PARAMS (v3.2 section 6.24):
//
//	CK_BBOOL phFlag;             offset 0,  1 byte
//	(7 bytes padding to the next 8-byte-aligned field)
//	CK_ULONG ulContextDataLen;   offset 8,  8 bytes
//	CK_BYTE_PTR pContextData;    offset 16, 8 bytes
//
// total 24 bytes.
// ---------------------------------------------------------------------------

func buildEdDSAParams(t testing.TB, phFlag bool, context []byte) []byte {
	buf := newAlignedBuf(24)
	if phFlag {
		buf[0] = 1
	}
	putULong(buf, 8, uint64(len(context)))
	putPtr(t, buf, 16, bytePtr(context))
	return buf
}

func TestDecodeEdDSAParams_WellFormed(t *testing.T) {
	ctx := []byte("domain-separation-context")
	buf := buildEdDSAParams(t, true, ctx)

	got, ok := decodeEdDSAParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeEdDSAParams(well-formed) ok = false, want true")
	}
	params := got.(*module.EdDSAParams)
	if !params.PreHash {
		t.Error("PreHash = false, want true")
	}
	if !bytes.Equal(params.Context, ctx) {
		t.Errorf("Context = %q, want %q", params.Context, ctx)
	}
}

// TestDecodeEdDSAParams_NoContextIsEmpty proves Ed25519ctx/Ed448 with an
// empty context (phFlag false, ulContextDataLen 0, per Table 73) decodes
// with a nil Context rather than being refused.
func TestDecodeEdDSAParams_NoContextIsEmpty(t *testing.T) {
	buf := buildEdDSAParams(t, false, nil)

	got, ok := decodeEdDSAParams(unsafe.Pointer(&buf[0]))
	if !ok {
		t.Fatal("decodeEdDSAParams(no context) ok = false, want true")
	}
	params := got.(*module.EdDSAParams)
	if params.PreHash {
		t.Error("PreHash = true, want false")
	}
	if params.Context != nil {
		t.Errorf("Context = %v, want nil", params.Context)
	}
}

// TestDecodeEdDSAParams_DanglingContextLenIsRefused proves a declared
// context length with no buffer behind it is refused rather than read.
func TestDecodeEdDSAParams_DanglingContextLenIsRefused(t *testing.T) {
	buf := buildEdDSAParams(t, true, nil)
	putULong(buf, 8, 16) // ulContextDataLen says 16 bytes; pContextData is still NULL.

	_, ok := decodeEdDSAParams(unsafe.Pointer(&buf[0]))
	if ok {
		t.Error("decodeEdDSAParams(dangling ulContextDataLen, NULL pContextData) ok = true, want false")
	}
}
