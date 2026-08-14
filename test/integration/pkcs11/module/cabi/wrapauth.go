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

// redZoneFill is the byte a guarded output buffer's red zone is painted with.
// Any other value found there after a call means the module wrote past the
// length the caller declared.
const redZoneFill = 0xA5

// CreateObject performs C_CreateObject and returns the new object handle.
//
// Authenticated wrapping is tested against keys created this way rather than
// generated, because the tests need to know the exact CKA_VALUE the token
// holds: the wrapped output length is a function of it, and that relationship
// is what the buffer arithmetic under test depends on.
func (s *Session) CreateObject(attrs []Attr) (uint, error) {
	a := &arena{}
	defer a.free()

	tmpl, count := buildTemplate(a, attrs)

	var obj C.CK_OBJECT_HANDLE
	if err := check("C_CreateObject", C.xk_CreateObject(s.mod.fl, s.handle, tmpl, count, &obj)); err != nil {
		return 0, err
	}
	return uint(obj), nil
}

// SetAttributeValue performs C_SetAttributeValue.
func (s *Session) SetAttributeValue(obj uint, attrs []Attr) error {
	a := &arena{}
	defer a.free()

	tmpl, count := buildTemplate(a, attrs)
	return check("C_SetAttributeValue",
		C.xk_SetAttributeValue(s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj), tmpl, count))
}

// WrapKeyAuthenticatedProbe performs the size query half of
// C_WrapKeyAuthenticated: a NULL pWrappedKey asks the module for the length
// the wrap will produce without performing it (PKCS#11 v3.2 section 5.2).
func (s *Session) WrapKeyAuthenticatedProbe(wrappingKey, key uint, aad []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, CKM_AES_GCM, nil)
	aadPtr, aadLen := a.bytes(aad)

	var outLen C.CK_ULONG
	err := check("C_WrapKeyAuthenticated", C.xk_WrapKeyAuthenticated(
		s.mod.fl, s.handle, mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		C.CK_BYTE_PTR(aadPtr), aadLen,
		nil, &outLen))
	if err != nil {
		return uint(outLen), err
	}
	return uint(outLen), nil
}

// GuardedWrap is the outcome of one guarded C_WrapKeyAuthenticated call.
type GuardedWrap struct {
	// RV is the return code the module produced.
	RV uint
	// Reported is the value the module left in *pulWrappedKeyLen.
	Reported uint
	// Output holds the bytes the module wrote inside the declared buffer.
	// It is only populated when RV is CKR_OK.
	Output []byte
	// RedZone holds the bytes found past the declared buffer length. Every
	// one of them must still be redZoneFill.
	RedZone []byte
}

// RedZoneClobbered reports the offset past the declared buffer length at which
// the module overwrote the red zone, or -1 when the red zone is intact.
func (g GuardedWrap) RedZoneClobbered() int {
	for i, b := range g.RedZone {
		if b != redZoneFill {
			return i
		}
	}
	return -1
}

// WrapKeyAuthenticatedGuarded performs C_WrapKeyAuthenticated into a buffer
// that is physically larger than the length declared to the module, so a write
// past the declared length lands in a red zone this harness can inspect rather
// than in memory the allocator is using for something else.
//
// declaredLen is what *pulWrappedKeyLen carries into the call, which is the
// only length the module is permitted to write. redZoneLen bytes past it are
// painted with redZoneFill and read back afterwards.
//
// The error is deliberately not returned separately: a caller driving a race
// needs the return code and the red zone together on every iteration,
// including the iterations that fail.
func (s *Session) WrapKeyAuthenticatedGuarded(wrappingKey, key uint, aad []byte, declaredLen, redZoneLen uint) GuardedWrap {
	a := &arena{}
	defer a.free()

	mech := buildMechanism(a, CKM_AES_GCM, nil)
	aadPtr, aadLen := a.bytes(aad)

	total := int(declaredLen + redZoneLen)
	buf := a.alloc(total)
	C.memset(buf, C.int(redZoneFill), C.size_t(total))

	outLen := C.CK_ULONG(declaredLen)
	rv := C.xk_WrapKeyAuthenticated(
		s.mod.fl, s.handle, mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		C.CK_BYTE_PTR(aadPtr), aadLen,
		C.CK_BYTE_PTR(buf), &outLen)

	result := GuardedWrap{RV: uint(rv), Reported: uint(outLen)}
	result.RedZone = C.GoBytes(unsafe.Add(buf, int(declaredLen)), C.int(redZoneLen))

	if result.RV == CKR_OK {
		copied := result.Reported
		if copied > declaredLen {
			copied = declaredLen
		}
		result.Output = C.GoBytes(buf, C.int(copied))
	}

	return result
}

// buildMessageParamsMechanism lays out a CKM_AES_GCM mechanism whose
// pParameter is a CK_GCM_MESSAGE_PARAMS, which is the structure PKCS#11 v3.2
// section 5.18.6 defines for the authenticated wrap verbs and the one its own
// example passes.
//
// The raw struct is returned alongside the mechanism so the caller can read
// back the fields the token writes: pIv is an output whenever ivGenerator is
// not CKG_NO_GENERATE (section 6.13.5), and that write-back is the only way an
// application ever learns a token-generated IV.
func buildMessageParamsMechanism(a *arena, p *GCMMessageParams) (C.CK_MECHANISM_PTR, *C.CK_GCM_MESSAGE_PARAMS) {
	raw, rawLen := buildGCMMessageParams(a, p)

	size := int(unsafe.Sizeof(C.CK_MECHANISM{}))
	mech := (*C.CK_MECHANISM)(a.alloc(size))
	mech.mechanism = C.CK_MECHANISM_TYPE(CKM_AES_GCM)
	mech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(raw))
	mech.ulParameterLen = rawLen

	return C.CK_MECHANISM_PTR(mech), raw
}

// WrapKeyAuthenticatedMessage performs C_WrapKeyAuthenticated with a
// CK_GCM_MESSAGE_PARAMS mechanism parameter, using the two-call convention,
// and copies whatever the token wrote back into params.
func (s *Session) WrapKeyAuthenticatedMessage(params *GCMMessageParams, wrappingKey, key uint, aad []byte) ([]byte, error) {
	a := &arena{}
	defer a.free()

	mech, raw := buildMessageParamsMechanism(a, params)
	aadPtr, aadLen := a.bytes(aad)

	// The two calls are labelled apart so a failure names the half that
	// produced it: the size query and the wrap take the module lock
	// separately and can disagree about the output length.
	var outLen C.CK_ULONG
	if err := check("C_WrapKeyAuthenticated size query", C.xk_WrapKeyAuthenticated(
		s.mod.fl, s.handle, mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		C.CK_BYTE_PTR(aadPtr), aadLen,
		nil, &outLen)); err != nil {
		return nil, err
	}

	buf := a.alloc(int(outLen))
	if err := check("C_WrapKeyAuthenticated", C.xk_WrapKeyAuthenticated(
		s.mod.fl, s.handle, mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		C.CK_BYTE_PTR(aadPtr), aadLen,
		C.CK_BYTE_PTR(buf), &outLen)); err != nil {
		return nil, err
	}

	readGCMMessageParams(raw, params)
	return C.GoBytes(buf, C.int(outLen)), nil
}

// UnwrapKeyAuthenticatedMessage performs C_UnwrapKeyAuthenticated with a
// CK_GCM_MESSAGE_PARAMS mechanism parameter and returns the new object handle.
func (s *Session) UnwrapKeyAuthenticatedMessage(params *GCMMessageParams, unwrappingKey uint, wrapped []byte, template []Attr, aad []byte) (uint, error) {
	a := &arena{}
	defer a.free()

	mech, _ := buildMessageParamsMechanism(a, params)
	tmpl, count := buildTemplate(a, template)
	aadPtr, aadLen := a.bytes(aad)
	wrappedPtr, wrappedLen := a.bytes(wrapped)

	var obj C.CK_OBJECT_HANDLE
	if err := check("C_UnwrapKeyAuthenticated", C.xk_UnwrapKeyAuthenticated(
		s.mod.fl, s.handle, mech,
		C.CK_OBJECT_HANDLE(unwrappingKey),
		C.CK_BYTE_PTR(wrappedPtr), wrappedLen,
		tmpl, count,
		C.CK_BYTE_PTR(aadPtr), aadLen,
		&obj)); err != nil {
		return 0, err
	}
	return uint(obj), nil
}
