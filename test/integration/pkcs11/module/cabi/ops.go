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

// GenerateKey performs C_GenerateKey and returns the new object handle.
func (s *Session) GenerateKey(mechType uint, params MechParams, template []Attr) (uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, mechType, params)
	tmpl, count := buildTemplate(a, template)

	var key C.CK_OBJECT_HANDLE
	if err := check("C_GenerateKey", C.xk_GenerateKey(s.mod.fl, s.handle, mech, tmpl, count, &key)); err != nil {
		return 0, err
	}
	return uint(key), nil
}

// GenerateKeyPair performs C_GenerateKeyPair and returns the public and
// private object handles.
func (s *Session) GenerateKeyPair(mechType uint, params MechParams, pubTemplate, privTemplate []Attr) (uint, uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, mechType, params)
	pubTmpl, pubCount := buildTemplate(a, pubTemplate)
	privTmpl, privCount := buildTemplate(a, privTemplate)

	var pub, priv C.CK_OBJECT_HANDLE
	err := check("C_GenerateKeyPair", C.xk_GenerateKeyPair(s.mod.fl, s.handle, mech,
		pubTmpl, pubCount, privTmpl, privCount, &pub, &priv))
	if err != nil {
		return 0, 0, err
	}
	return uint(pub), uint(priv), nil
}

// Attribute reads a single attribute using the two-call convention: a first
// C_GetAttributeValue with a NULL pValue to learn the length, then a second to
// fetch the bytes.
func (s *Session) Attribute(obj uint, attrType uint) ([]byte, error) {
	a := &arena{}
	defer a.free()

	entrySize := int(unsafe.Sizeof(C.CK_ATTRIBUTE{}))
	array := (*C.CK_ATTRIBUTE)(a.alloc(entrySize))
	C.xk_attr_set(array, 0, C.CK_ATTRIBUTE_TYPE(attrType), nil, 0)

	tmpl := C.CK_ATTRIBUTE_PTR(array)
	if err := check("C_GetAttributeValue", C.xk_GetAttributeValue(s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), tmpl, 1)); err != nil {
		return nil, err
	}

	size := C.xk_attr_len(tmpl, 0)
	if size == 0 || size == C.CK_ULONG(^C.CK_ULONG(0)) {
		return nil, nil
	}

	buf := a.alloc(int(size))
	C.xk_attr_set(array, 0, C.CK_ATTRIBUTE_TYPE(attrType), C.CK_VOID_PTR(buf), size)
	if err := check("C_GetAttributeValue", C.xk_GetAttributeValue(s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), tmpl, 1)); err != nil {
		return nil, err
	}

	return C.GoBytes(buf, C.int(C.xk_attr_len(tmpl, 0))), nil
}

// SignInit performs C_SignInit.
func (s *Session) SignInit(mechType uint, params MechParams, key uint) error {
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_SignInit", C.xk_SignInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// SignProbe performs the length-query half of the two-call convention: it
// calls C_Sign with a NULL signature buffer and returns the length the module
// reports. Per PKCS#11 v3.2 section 5.2 this must not terminate the
// operation, so a following SignFinish on the same session must still succeed.
func (s *Session) SignProbe(data []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(data)
	var outLen C.CK_ULONG
	err := check("C_Sign", C.xk_Sign(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
	return uint(outLen), err
}

// SignInto calls C_Sign with a buffer of exactly bufLen bytes. It returns the
// signature bytes the module wrote, the length it reported, and any error, so
// a caller can assert the CKR_BUFFER_TOO_SMALL contract directly.
func (s *Session) SignInto(data []byte, bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(data)
	out := a.alloc(int(bufLen))
	outLen := C.CK_ULONG(bufLen)

	err := check("C_Sign", C.xk_Sign(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// Sign performs a complete two-call C_Sign.
func (s *Session) Sign(data []byte) ([]byte, error) {
	size, err := s.SignProbe(data)
	if err != nil {
		return nil, err
	}
	sig, _, err := s.SignInto(data, size)
	return sig, err
}

// VerifyInit performs C_VerifyInit.
func (s *Session) VerifyInit(mechType uint, params MechParams, key uint) error {
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_VerifyInit", C.xk_VerifyInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// Verify performs C_Verify.
func (s *Session) Verify(data, signature []byte) error {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(data)
	sig, sigLen := a.bytes(signature)
	return check("C_Verify", C.xk_Verify(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(sig), sigLen))
}

// EncryptInit performs C_EncryptInit.
func (s *Session) EncryptInit(mechType uint, params MechParams, key uint) error {
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_EncryptInit", C.xk_EncryptInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// EncryptProbe calls C_Encrypt with a NULL output buffer and returns the
// reported length.
func (s *Session) EncryptProbe(plaintext []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(plaintext)
	var outLen C.CK_ULONG
	err := check("C_Encrypt", C.xk_Encrypt(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
	return uint(outLen), err
}

// EncryptInto calls C_Encrypt with a buffer of exactly bufLen bytes.
func (s *Session) EncryptInto(plaintext []byte, bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(plaintext)
	out := a.alloc(int(bufLen))
	outLen := C.CK_ULONG(bufLen)

	err := check("C_Encrypt", C.xk_Encrypt(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// Encrypt performs a complete two-call C_Encrypt.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	size, err := s.EncryptProbe(plaintext)
	if err != nil {
		return nil, err
	}
	out, _, err := s.EncryptInto(plaintext, size)
	return out, err
}

// DecryptInit performs C_DecryptInit.
func (s *Session) DecryptInit(mechType uint, params MechParams, key uint) error {
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_DecryptInit", C.xk_DecryptInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// DecryptProbe calls C_Decrypt with a NULL output buffer and returns the
// reported length.
func (s *Session) DecryptProbe(ciphertext []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(ciphertext)
	var outLen C.CK_ULONG
	err := check("C_Decrypt", C.xk_Decrypt(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
	return uint(outLen), err
}

// DecryptInto calls C_Decrypt with a buffer of exactly bufLen bytes.
func (s *Session) DecryptInto(ciphertext []byte, bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(ciphertext)
	out := a.alloc(int(bufLen))
	outLen := C.CK_ULONG(bufLen)

	err := check("C_Decrypt", C.xk_Decrypt(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// Decrypt performs a complete two-call C_Decrypt.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	size, err := s.DecryptProbe(ciphertext)
	if err != nil {
		return nil, err
	}
	out, _, err := s.DecryptInto(ciphertext, size)
	return out, err
}

// outputBuffer allocates a non-NULL output buffer of at least bufLen bytes.
//
// PKCS#11 v3.2 section 5.2 distinguishes the two calls of the two-call
// convention by the output pointer alone, and arena.alloc answers a zero-length
// request with NULL. A caller that probed a required length of zero -- which is
// what every buffering *Update reports -- would therefore have its real call
// silently reinterpreted as a second length query, so the floor of one byte is
// what keeps the two calls distinguishable.
func (a *arena) outputBuffer(bufLen uint) unsafe.Pointer {
	if bufLen == 0 {
		return a.alloc(1)
	}
	return a.alloc(int(bufLen))
}

// EncryptUpdateProbe calls C_EncryptUpdate with a NULL output buffer and
// returns the length the module reports.
//
// Per PKCS#11 v3.2 section 5.2 this is a length query and must not otherwise
// affect the operation. That matters more here than for the single-part calls:
// C_EncryptUpdate consumes its input into a buffer, so a module that forwarded
// the part on the query as well as on the retry would encrypt it twice and
// still answer CKR_OK throughout.
func (s *Session) EncryptUpdateProbe(part []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(part)
	var outLen C.CK_ULONG
	err := check("C_EncryptUpdate", C.xk_EncryptUpdate(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
	return uint(outLen), err
}

// EncryptUpdateInto calls C_EncryptUpdate with a non-NULL output buffer sized
// bufLen. It returns the bytes the module wrote and the length it reported.
func (s *Session) EncryptUpdateInto(part []byte, bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(part)
	out := a.outputBuffer(bufLen)
	outLen := C.CK_ULONG(bufLen)

	err := check("C_EncryptUpdate", C.xk_EncryptUpdate(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// EncryptFinalProbe calls C_EncryptFinal with a NULL output buffer and returns
// the reported length.
func (s *Session) EncryptFinalProbe() (uint, error) {
	var outLen C.CK_ULONG
	err := check("C_EncryptFinal", C.xk_EncryptFinal(s.mod.fl, s.handle, nil, &outLen))
	return uint(outLen), err
}

// EncryptFinalInto calls C_EncryptFinal with a non-NULL buffer sized bufLen.
func (s *Session) EncryptFinalInto(bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	out := a.outputBuffer(bufLen)
	outLen := C.CK_ULONG(bufLen)

	err := check("C_EncryptFinal", C.xk_EncryptFinal(s.mod.fl, s.handle, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// EncryptFinal performs a complete two-call C_EncryptFinal.
func (s *Session) EncryptFinal() ([]byte, error) {
	size, err := s.EncryptFinalProbe()
	if err != nil {
		return nil, err
	}
	out, _, err := s.EncryptFinalInto(size)
	return out, err
}

// DecryptUpdateProbe calls C_DecryptUpdate with a NULL output buffer and
// returns the reported length. It carries the same length-query contract as
// EncryptUpdateProbe.
func (s *Session) DecryptUpdateProbe(part []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(part)
	var outLen C.CK_ULONG
	err := check("C_DecryptUpdate", C.xk_DecryptUpdate(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
	return uint(outLen), err
}

// DecryptUpdateInto calls C_DecryptUpdate with a non-NULL output buffer sized
// bufLen.
func (s *Session) DecryptUpdateInto(part []byte, bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	in, inLen := a.bytes(part)
	out := a.outputBuffer(bufLen)
	outLen := C.CK_ULONG(bufLen)

	err := check("C_DecryptUpdate", C.xk_DecryptUpdate(s.mod.fl, s.handle, C.CK_BYTE_PTR(in), inLen, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// DecryptFinalProbe calls C_DecryptFinal with a NULL output buffer and returns
// the reported length.
func (s *Session) DecryptFinalProbe() (uint, error) {
	var outLen C.CK_ULONG
	err := check("C_DecryptFinal", C.xk_DecryptFinal(s.mod.fl, s.handle, nil, &outLen))
	return uint(outLen), err
}

// DecryptFinalInto calls C_DecryptFinal with a non-NULL buffer sized bufLen.
func (s *Session) DecryptFinalInto(bufLen uint) ([]byte, uint, error) {
	a := &arena{}
	defer a.free()

	out := a.outputBuffer(bufLen)
	outLen := C.CK_ULONG(bufLen)

	err := check("C_DecryptFinal", C.xk_DecryptFinal(s.mod.fl, s.handle, C.CK_BYTE_PTR(out), &outLen))
	if err != nil {
		return nil, uint(outLen), err
	}
	return C.GoBytes(out, C.int(outLen)), uint(outLen), nil
}

// DecryptFinal performs a complete two-call C_DecryptFinal.
func (s *Session) DecryptFinal() ([]byte, error) {
	size, err := s.DecryptFinalProbe()
	if err != nil {
		return nil, err
	}
	out, _, err := s.DecryptFinalInto(size)
	return out, err
}

// DeriveKey performs C_DeriveKey and returns the derived object handle.
func (s *Session) DeriveKey(mechType uint, params MechParams, baseKey uint, template []Attr) (uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, mechType, params)
	tmpl, count := buildTemplate(a, template)

	var key C.CK_OBJECT_HANDLE
	if err := check("C_DeriveKey", C.xk_DeriveKey(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(baseKey), tmpl, count, &key)); err != nil {
		return 0, err
	}
	return uint(key), nil
}

// GCMMessageParams is CK_GCM_MESSAGE_PARAMS (PKCS#11 v3.2 section 6.13.5).
//
// Unlike every other parameter struct here it is in-out: with an ivGenerator
// other than CKG_NO_GENERATE the token chooses the IV and must write it back,
// and pTag is always an output of encryption. A module that reads this struct
// but never writes to it makes the round trip impossible, because the caller
// never learns the IV or tag it must present to decrypt.
type GCMMessageParams struct {
	// IV is the initialization vector buffer. It is an input when IVGenerator
	// is CKG_NO_GENERATE and an output otherwise; its length always states the
	// buffer size the token may fill.
	IV []byte
	// IVFixedBits is the number of leading IV bits the caller fixed.
	IVFixedBits uint
	// IVGenerator selects who produces the IV.
	IVGenerator uint
	// Tag receives the authentication tag on encrypt and supplies it on
	// decrypt.
	Tag []byte
	// TagBits is the tag length in bits.
	TagBits uint
}

// MessageSignInit performs C_MessageSignInit.
func (s *Session) MessageSignInit(mechType uint, params MechParams, key uint) error {
	if !s.mod.hasV3 {
		return &InterfaceError{Path: s.mod.path, Function: "C_MessageSignInit"}
	}
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_MessageSignInit", C.xk_MessageSignInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// SignMessageProbe calls C_SignMessage with the given per-message parameter and a
// NULL signature buffer (the length-query half of the two-call convention). It
// exists so a test can assert how the module treats the parameter without
// needing a real output buffer.
func (s *Session) SignMessageProbe(param []byte, data []byte) error {
	a := &arena{}
	defer a.free()

	var paramPtr unsafe.Pointer
	var paramLen C.CK_ULONG
	if len(param) > 0 {
		p, pl := a.bytes(param)
		paramPtr, paramLen = unsafe.Pointer(p), pl
	}
	in, inLen := a.bytes(data)
	var outLen C.CK_ULONG
	return check("C_SignMessage", C.xk_SignMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(paramPtr), paramLen, C.CK_BYTE_PTR(in), inLen, nil, &outLen))
}

// MessageEncryptInit performs C_MessageEncryptInit.
func (s *Session) MessageEncryptInit(mechType uint, params MechParams, key uint) error {
	if !s.mod.hasV3 {
		return &InterfaceError{Path: s.mod.path, Function: "C_MessageEncryptInit"}
	}
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_MessageEncryptInit", C.xk_MessageEncryptInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// buildGCMMessageParams lays out CK_GCM_MESSAGE_PARAMS with the IV and tag in
// caller-owned C buffers so the module can write into them.
func buildGCMMessageParams(a *arena, p *GCMMessageParams) (*C.CK_GCM_MESSAGE_PARAMS, C.CK_ULONG) {
	size := C.size_t(unsafe.Sizeof(C.CK_GCM_MESSAGE_PARAMS{}))
	raw := (*C.CK_GCM_MESSAGE_PARAMS)(a.alloc(int(size)))

	if len(p.IV) > 0 {
		iv, ivLen := a.bytes(p.IV)
		raw.pIv = C.CK_BYTE_PTR(iv)
		raw.ulIvLen = ivLen
	}
	raw.ulIvFixedBits = C.CK_ULONG(p.IVFixedBits)
	raw.ivGenerator = C.CK_ULONG(p.IVGenerator)

	tagBytes := int(p.TagBits / 8)
	if len(p.Tag) > tagBytes {
		tagBytes = len(p.Tag)
	}
	if tagBytes > 0 {
		tag := a.alloc(tagBytes)
		if len(p.Tag) > 0 {
			C.memcpy(tag, unsafe.Pointer(&p.Tag[0]), C.size_t(len(p.Tag)))
		}
		raw.pTag = C.CK_BYTE_PTR(tag)
	}
	raw.ulTagBits = C.CK_ULONG(p.TagBits)

	return raw, C.CK_ULONG(size)
}

// readGCMMessageParams copies the IV and tag the module produced back into p.
func readGCMMessageParams(raw *C.CK_GCM_MESSAGE_PARAMS, p *GCMMessageParams) {
	if raw.pIv != nil && raw.ulIvLen > 0 {
		p.IV = C.GoBytes(unsafe.Pointer(raw.pIv), C.int(raw.ulIvLen))
	}
	if raw.pTag != nil && raw.ulTagBits > 0 {
		p.Tag = C.GoBytes(unsafe.Pointer(raw.pTag), C.int(raw.ulTagBits/8))
	}
	p.TagBits = uint(raw.ulTagBits)
	p.IVFixedBits = uint(raw.ulIvFixedBits)
}

// EncryptMessage performs C_EncryptMessage with the two-call convention and
// copies any IV and tag the token generated back into params.
func (s *Session) EncryptMessage(params *GCMMessageParams, aad, plaintext []byte) ([]byte, error) {
	if !s.mod.hasV3 {
		return nil, &InterfaceError{Path: s.mod.path, Function: "C_EncryptMessage"}
	}
	a := &arena{}
	defer a.free()

	raw, rawLen := buildGCMMessageParams(a, params)
	cAAD, aadLen := a.bytes(aad)
	cPT, ptLen := a.bytes(plaintext)

	var ctLen C.CK_ULONG
	err := check("C_EncryptMessage", C.xk_EncryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), rawLen,
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cPT), ptLen, nil, &ctLen))
	if err != nil {
		return nil, err
	}

	out := a.alloc(int(ctLen))
	err = check("C_EncryptMessage", C.xk_EncryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), rawLen,
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cPT), ptLen, C.CK_BYTE_PTR(out), &ctLen))
	if err != nil {
		return nil, err
	}

	readGCMMessageParams(raw, params)
	return C.GoBytes(out, C.int(ctLen)), nil
}

// EncryptMessageOnce performs a single C_EncryptMessage call with a buffer of
// exactly bufLen bytes, without a preceding length probe.
//
// It exists so a test can state the buffer size itself and assert on what one
// call does — the message form carries the tag in CK_GCM_MESSAGE_PARAMS.pTag
// rather than appended to the ciphertext, so the ciphertext is exactly as long
// as the plaintext, and a caller-supplied length is what proves it.
//
// It is not a way around the length probe. This comment used to say the probe
// had to be avoided because each run generates a different IV, which read as a
// property of AES-GCM but was a description of a defect: the probe ran the
// encryption and left the operation finalized without caching anything, so the
// second call the two-call convention requires (PKCS#11 v3.2 §5.2) was refused
// with CKR_OPERATION_NOT_INITIALIZED. Every message test used this helper, so
// nothing exercised the probe at all. C_EncryptMessage now releases the result
// on the probe, and the IV written back by the call that produced the
// ciphertext is the one that matches it; EncryptMessage is the two-call form
// and TestTwoCallEncryptMessageProbeDoesNotTerminateTheOperation proves the
// round trip closes through it.
func (s *Session) EncryptMessageOnce(params *GCMMessageParams, aad, plaintext []byte, bufLen uint) ([]byte, error) {
	if !s.mod.hasV3 {
		return nil, &InterfaceError{Path: s.mod.path, Function: "C_EncryptMessage"}
	}
	a := &arena{}
	defer a.free()

	raw, rawLen := buildGCMMessageParams(a, params)
	cAAD, aadLen := a.bytes(aad)
	cPT, ptLen := a.bytes(plaintext)

	out := a.alloc(int(bufLen))
	ctLen := C.CK_ULONG(bufLen)
	err := check("C_EncryptMessage", C.xk_EncryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), rawLen,
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cPT), ptLen, C.CK_BYTE_PTR(out), &ctLen))
	if err != nil {
		return nil, err
	}

	readGCMMessageParams(raw, params)
	return C.GoBytes(out, C.int(ctLen)), nil
}

// EncryptMessageTruncated performs C_EncryptMessage while declaring a
// ulParameterLen shorter than CK_GCM_MESSAGE_PARAMS really is.
//
// It exists so a test can prove the module length-checks the struct before
// writing the generated IV and tag through the pointers inside it.
func (s *Session) EncryptMessageTruncated(params *GCMMessageParams, aad, plaintext []byte, bufLen, declaredLen uint) ([]byte, error) {
	if !s.mod.hasV3 {
		return nil, &InterfaceError{Path: s.mod.path, Function: "C_EncryptMessage"}
	}

	a := &arena{}
	defer a.free()

	raw, _ := buildGCMMessageParams(a, params)
	cAAD, aadLen := a.bytes(aad)
	cPT, ptLen := a.bytes(plaintext)

	out := a.alloc(int(bufLen))
	ctLen := C.CK_ULONG(bufLen)
	err := check("C_EncryptMessage", C.xk_EncryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), C.CK_ULONG(declaredLen),
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cPT), ptLen, C.CK_BYTE_PTR(out), &ctLen))
	if err != nil {
		return nil, err
	}
	return C.GoBytes(out, C.int(ctLen)), nil
}

// MessageEncryptFinal performs C_MessageEncryptFinal.
func (s *Session) MessageEncryptFinal() error {
	if !s.mod.hasV3 {
		return &InterfaceError{Path: s.mod.path, Function: "C_MessageEncryptFinal"}
	}
	return check("C_MessageEncryptFinal", C.xk_MessageEncryptFinal(s.mod.fl, s.handle))
}

// MessageDecryptInit performs C_MessageDecryptInit.
func (s *Session) MessageDecryptInit(mechType uint, params MechParams, key uint) error {
	if !s.mod.hasV3 {
		return &InterfaceError{Path: s.mod.path, Function: "C_MessageDecryptInit"}
	}
	a := &arena{}
	defer a.free()
	mech := buildMechanism(a, mechType, params)
	return check("C_MessageDecryptInit", C.xk_MessageDecryptInit(s.mod.fl, s.handle, mech, C.CK_OBJECT_HANDLE(key)))
}

// DecryptMessageProbe performs the length-query half of C_DecryptMessage: a
// NULL pPlaintext asks the module how many bytes the decryption will produce
// and must leave the message operation usable (PKCS#11 v3.2 §5.2).
func (s *Session) DecryptMessageProbe(params *GCMMessageParams, aad, ciphertext []byte) (uint, error) {
	if !s.mod.hasV3 {
		return 0, &InterfaceError{Path: s.mod.path, Function: "C_DecryptMessage"}
	}
	a := &arena{}
	defer a.free()

	raw, rawLen := buildGCMMessageParams(a, params)
	cAAD, aadLen := a.bytes(aad)
	cCT, ctLen := a.bytes(ciphertext)

	var ptLen C.CK_ULONG
	err := check("C_DecryptMessage", C.xk_DecryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), rawLen,
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cCT), ctLen, nil, &ptLen))
	if err != nil {
		return uint(ptLen), err
	}
	return uint(ptLen), nil
}

// DecryptMessage performs C_DecryptMessage with a caller-sized output buffer.
func (s *Session) DecryptMessage(params *GCMMessageParams, aad, ciphertext []byte, bufLen uint) ([]byte, error) {
	if !s.mod.hasV3 {
		return nil, &InterfaceError{Path: s.mod.path, Function: "C_DecryptMessage"}
	}
	a := &arena{}
	defer a.free()

	raw, rawLen := buildGCMMessageParams(a, params)
	cAAD, aadLen := a.bytes(aad)
	cCT, ctLen := a.bytes(ciphertext)

	out := a.alloc(int(bufLen))
	ptLen := C.CK_ULONG(bufLen)
	err := check("C_DecryptMessage", C.xk_DecryptMessage(s.mod.fl, s.handle,
		C.CK_VOID_PTR(unsafe.Pointer(raw)), rawLen,
		C.CK_BYTE_PTR(cAAD), aadLen, C.CK_BYTE_PTR(cCT), ctLen, C.CK_BYTE_PTR(out), &ptLen))
	if err != nil {
		return nil, err
	}
	return C.GoBytes(out, C.int(ptLen)), nil
}

// MessageDecryptFinal performs C_MessageDecryptFinal.
func (s *Session) MessageDecryptFinal() error {
	if !s.mod.hasV3 {
		return &InterfaceError{Path: s.mod.path, Function: "C_MessageDecryptFinal"}
	}
	return check("C_MessageDecryptFinal", C.xk_MessageDecryptFinal(s.mod.fl, s.handle))
}
