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

// Package main provides CGO exports for PKCS#11 v3.2 C_* functions.
//
// Each function uses the //export directive to make it available to C code.
// Functions delegate to the Go module layer via module.GetGlobalModule(),
// handling C<->Go type marshaling for byte pointers, lengths, and output buffers.
//
// References:
//   - OASIS PKCS#11 v3.2: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "pkcs11.h"
#include <string.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	module "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// goErrorToCKRV extracts a CK_RV code from a Go error.
// Returns CKR_OK if err is nil, or CKR_FUNCTION_FAILED if the error
// is not a PKCS11Error.
func goErrorToCKRV(err error) C.CK_RV {
	if err == nil {
		return C.CKR_OK
	}
	var pkcsErr *module.PKCS11Error
	if errors.As(err, &pkcsErr) {
		return C.CK_RV(pkcsErr.Code)
	}
	return C.CK_RV(C.CKR_FUNCTION_FAILED)
}

// ============================================================================
// PKCS#11 v3.2 KEM Functions
// ============================================================================

//export C_EncapsulateKey
func C_EncapsulateKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
	pCiphertext C.CK_BYTE_PTR,
	pulCiphertextLen C.CK_ULONG_PTR,
	phKey C.CK_OBJECT_HANDLE_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || pulCiphertextLen == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	// Size query: when pCiphertext is NULL, return the required ciphertext
	// length without performing the actual encapsulation or creating objects.
	// Per PKCS#11 spec, this avoids side effects on size queries.
	if pCiphertext == nil {
		ctSize, err := module.GetGlobalModule().KEMCiphertextSize(
			module.SessionHandle(hSession),
			mech,
			module.ObjectHandle(hKey),
		)
		if err != nil {
			return goErrorToCKRV(err)
		}
		*pulCiphertextLen = C.CK_ULONG(ctSize)
		return C.CKR_OK
	}

	// Pre-check buffer size before performing the actual encapsulation to
	// avoid creating orphaned key objects when the buffer is too small.
	ctSize, err := module.GetGlobalModule().KEMCiphertextSize(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hKey),
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	if *pulCiphertextLen < C.CK_ULONG(ctSize) {
		*pulCiphertextLen = C.CK_ULONG(ctSize)
		return C.CKR_BUFFER_TOO_SMALL
	}

	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	keyHandle, ciphertext, err := module.GetGlobalModule().EncapsulateKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hKey),
		template,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	// The pre-check above measured the ciphertext through its own lock
	// acquisition, which KEMCiphertextSize released before EncapsulateKey took
	// it again. Anything that changes the public key in between -- a concurrent
	// C_SetAttributeValue on CKA_VALUE or CKA_PARAMETER_SET -- makes the
	// encapsulation produce a length the pre-check never saw. Copying the
	// predicted length would then run past the end of the caller's buffer, so
	// the guard is against the bytes actually about to be written.
	if C.CK_ULONG(len(ciphertext)) > *pulCiphertextLen {
		// EncapsulateKey has already created the shared-secret object, and this
		// call is about to fail without writing phKey -- so the application is
		// given no handle to the object and no way to destroy it. Destroying it
		// here is what keeps the failure retryable: v3.2 §5.2 lets the caller
		// re-issue the call with a larger buffer, and a token that accumulated
		// an unreachable secret key on every such retry would leak one per
		// attempt.
		if drv := module.GetGlobalModule().DestroyObject(
			module.SessionHandle(hSession), keyHandle); drv != module.CKR_OK {
			return C.CK_RV(drv)
		}
		*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(ciphertext) > 0 {
		C.memcpy(unsafe.Pointer(pCiphertext), unsafe.Pointer(&ciphertext[0]), C.size_t(len(ciphertext)))
	}
	*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
	*phKey = C.CK_OBJECT_HANDLE(keyHandle)

	return C.CKR_OK
}

//export C_DecapsulateKey
func C_DecapsulateKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
	pCiphertext C.CK_BYTE_PTR,
	ulCiphertextLen C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pCiphertext == nil && ulCiphertextLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	ciphertext, ok := cBytes(unsafe.Pointer(pCiphertext), ulCiphertextLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	keyHandle, err := module.GetGlobalModule().DecapsulateKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hKey),
		template,
		ciphertext,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	*phKey = C.CK_OBJECT_HANDLE(keyHandle)
	return C.CKR_OK
}

// ============================================================================
// PKCS#11 v3.2 Signature-first Verification Functions
// ============================================================================

//export C_VerifySignatureInit
func C_VerifySignatureInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
	pSignature C.CK_BYTE_PTR,
	ulSignatureLen C.CK_ULONG,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// Per PKCS#11 v3.2 spec section 5.15.7: NULL mechanism cancels
	// an active signature-first verification operation.
	var mech *module.Mechanism
	if pMechanism != nil {
		var paramRV C.CK_RV
		mech, paramRV = convertCMechanismToGo(pMechanism)
		if paramRV != C.CKR_OK {
			return paramRV
		}
	}

	if pSignature == nil && ulSignatureLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	err := module.GetGlobalModule().VerifySignatureInit(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hKey),
		signature,
	)
	return goErrorToCKRV(err)
}

//export C_VerifySignature
func C_VerifySignature(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pData == nil && ulDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	err := module.GetGlobalModule().VerifySignature(
		module.SessionHandle(hSession),
		data,
	)
	return goErrorToCKRV(err)
}

//export C_VerifySignatureUpdate
func C_VerifySignatureUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pPart == nil && ulPartLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	err := module.GetGlobalModule().VerifySignatureUpdate(
		module.SessionHandle(hSession),
		part,
	)
	return goErrorToCKRV(err)
}

//export C_VerifySignatureFinal
func C_VerifySignatureFinal(
	hSession C.CK_SESSION_HANDLE,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	err := module.GetGlobalModule().VerifySignatureFinal(
		module.SessionHandle(hSession),
	)
	return goErrorToCKRV(err)
}

// ============================================================================
// PKCS#11 v3.2 Session Validation Functions
// ============================================================================

//export C_GetSessionValidationFlags
func C_GetSessionValidationFlags(
	hSession C.CK_SESSION_HANDLE,
	flagsType C.CK_SESSION_VALIDATION_FLAGS_TYPE,
	pFlags C.CK_FLAGS_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pFlags == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	flags, err := module.GetGlobalModule().GetSessionValidationFlags(
		module.SessionHandle(hSession),
		uint64(flagsType),
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	*pFlags = C.CK_FLAGS(flags)
	return C.CKR_OK
}

// ============================================================================
// PKCS#11 v3.2 Async Operation Functions
// ============================================================================

//export C_AsyncComplete
func C_AsyncComplete(
	hSession C.CK_SESSION_HANDLE,
	pFunctionName C.CK_UTF8CHAR_PTR,
	pResult C.CK_ASYNC_DATA_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pFunctionName == nil || pResult == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	functionName := C.GoString((*C.char)(unsafe.Pointer(pFunctionName)))

	result, err := module.GetGlobalModule().AsyncComplete(
		module.SessionHandle(hSession),
		functionName,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	// Populate the CK_ASYNC_DATA output structure from the Go result
	pResult.ulVersion = C.CK_ULONG(result.Version)
	if len(result.Value) > 0 {
		// CK_ASYNC_DATA.pValue / ulValue are an ordinary output buffer pair, so
		// a NULL buffer is the PKCS#11 v3.2 §5.2 length query and is answered
		// with the required size under CKR_OK. Writing the size and then failing
		// the call left the async result unreachable except by guessing a buffer
		// size -- the CKR_BUFFER_TOO_SMALL leg immediately below already gets
		// this right, which is what made the divergence an oversight.
		if pResult.pValue == nil {
			pResult.ulValue = C.CK_ULONG(len(result.Value))
			return C.CKR_OK
		}
		if pResult.ulValue < C.CK_ULONG(len(result.Value)) {
			pResult.ulValue = C.CK_ULONG(len(result.Value))
			return C.CKR_BUFFER_TOO_SMALL
		}
		C.memcpy(unsafe.Pointer(pResult.pValue), unsafe.Pointer(&result.Value[0]), C.size_t(len(result.Value)))
	}
	pResult.ulValue = C.CK_ULONG(len(result.Value))
	pResult.hObject = C.CK_OBJECT_HANDLE(result.Object)
	pResult.hAdditionalObject = C.CK_OBJECT_HANDLE(result.AdditionalObject)

	return C.CKR_OK
}

//export C_AsyncGetID
func C_AsyncGetID(
	hSession C.CK_SESSION_HANDLE,
	pFunctionName C.CK_UTF8CHAR_PTR,
	pulID C.CK_ULONG_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pFunctionName == nil || pulID == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	functionName := C.GoString((*C.char)(unsafe.Pointer(pFunctionName)))

	id, err := module.GetGlobalModule().AsyncGetID(
		module.SessionHandle(hSession),
		functionName,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	*pulID = C.CK_ULONG(id)
	return C.CKR_OK
}

//export C_AsyncJoin
func C_AsyncJoin(
	hSession C.CK_SESSION_HANDLE,
	pFunctionName C.CK_UTF8CHAR_PTR,
	ulID C.CK_ULONG,
	pData C.CK_BYTE_PTR,
	ulData C.CK_ULONG,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pFunctionName == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pData == nil && ulData > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	functionName := C.GoString((*C.char)(unsafe.Pointer(pFunctionName)))

	data, ok := cBytes(unsafe.Pointer(pData), ulData)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	err := module.GetGlobalModule().AsyncJoin(
		module.SessionHandle(hSession),
		functionName,
		uint64(ulID),
		data,
	)
	return goErrorToCKRV(err)
}

// ============================================================================
// PKCS#11 v3.2 Authenticated Wrapping Functions
// ============================================================================

// authenticatedWrapMechanism reads the mechanism of C_WrapKeyAuthenticated and
// C_UnwrapKeyAuthenticated.
//
// PKCS#11 v3.2 section 5.18.6 defines both verbs in terms of the
// CK_*_MESSAGE_PARAMS structures, and the example it gives passes
// CK_GCM_MESSAGE_PARAMS. Routing them through convertCMechanismToGo instead
// decoded that buffer as CK_GCM_PARAMS, which the table registers for
// CKM_AES_GCM unconditionally. The two structures are both 48 bytes on
// linux/amd64, so the length gate passed and the fields transposed from offset
// 16 onward: ulIvFixedBits was read as ulIvBits, ivGenerator -- a small enum --
// as the pAAD pointer, and pTag as ulAADLen. Every spec-conforming call
// therefore ended in cBytes(0x1, <address of the tag buffer>), which the
// MaxInt32 length gate refused, so the verbs answered
// CKR_MECHANISM_PARAM_INVALID to every application that used them correctly.
//
// The parameter is read with gcmMessageParams, the same reader
// C_EncryptMessage and C_DecryptMessage use, so there is one decoder for
// CK_GCM_MESSAGE_PARAMS in this file rather than two that can drift.
//
// A mechanism other than CKM_AES_GCM keeps the ordinary conversion: the module
// layer refuses it with CKR_MECHANISM_INVALID, and the mechanism-specific
// parameter has to survive intact for that answer to be about the mechanism.
func authenticatedWrapMechanism(pMechanism C.CK_MECHANISM_PTR) (*module.Mechanism, C.CK_RV) {
	if pMechanism == nil {
		return nil, C.CKR_ARGUMENTS_BAD
	}
	if module.MechanismType(pMechanism.mechanism) != module.CKM_AES_GCM {
		return convertCMechanismToGo(pMechanism)
	}

	params, ok := gcmMessageParams(C.CK_VOID_PTR(pMechanism.pParameter), pMechanism.ulParameterLen)
	if !ok {
		return nil, C.CKR_MECHANISM_PARAM_INVALID
	}

	mech := &module.Mechanism{Type: module.CKM_AES_GCM}
	if params != nil {
		mech.TypedParameter = params
	}
	return mech, C.CKR_OK
}

// writeAuthenticatedWrapIV hands a token-generated IV back to the caller.
//
// CK_GCM_MESSAGE_PARAMS.pIv is an output whenever ivGenerator is not
// CKG_NO_GENERATE (v3.2 section 6.13.5). It is the only channel by which an
// application can learn the IV a wrap generated, and without it that wrapped
// key could never be unwrapped -- which is why the module refuses such a wrap
// unless the caller left a buffer here, and why this write happens on the
// success path of every wrap that used one.
//
// The authentication tag is deliberately not written back: for these verbs it
// travels inside pWrappedKey, so that the wrapped key is a self-contained blob
// its holder can unwrap from the IV alone.
func writeAuthenticatedWrapIV(pMechanism C.CK_MECHANISM_PTR, mech *module.Mechanism) C.CK_RV {
	if pMechanism == nil || pMechanism.pParameter == nil || mech == nil {
		return C.CKR_OK
	}
	params, ok := mech.GetAESGCMMessageParams()
	if !ok {
		return C.CKR_OK
	}
	return writeGCMMessageParams(C.CK_VOID_PTR(pMechanism.pParameter),
		&module.AESGCMMessageParams{IV: params.IV})
}

//export C_WrapKeyAuthenticated
func C_WrapKeyAuthenticated(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hWrappingKey C.CK_OBJECT_HANDLE,
	hKey C.CK_OBJECT_HANDLE,
	pAssociatedData C.CK_BYTE_PTR,
	ulAssociatedDataLen C.CK_ULONG,
	pWrappedKey C.CK_BYTE_PTR,
	pulWrappedKeyLen C.CK_ULONG_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || pulWrappedKeyLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pAssociatedData == nil && ulAssociatedDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := authenticatedWrapMechanism(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Size query: when pWrappedKey is NULL, return the required output
	// length without performing the actual AES-GCM wrap or consuming entropy.
	if pWrappedKey == nil {
		size, err := module.GetGlobalModule().WrapKeyAuthenticatedSize(
			module.SessionHandle(hSession),
			mech,
			module.ObjectHandle(hWrappingKey),
			module.ObjectHandle(hKey),
		)
		if err != nil {
			return goErrorToCKRV(err)
		}
		*pulWrappedKeyLen = C.CK_ULONG(size)
		return C.CKR_OK
	}

	// Pre-check buffer size without performing crypto or consuming entropy
	expectedSize, sizeErr := module.GetGlobalModule().WrapKeyAuthenticatedSize(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hWrappingKey),
		module.ObjectHandle(hKey),
	)
	if sizeErr != nil {
		return goErrorToCKRV(sizeErr)
	}

	if *pulWrappedKeyLen < C.CK_ULONG(expectedSize) {
		*pulWrappedKeyLen = C.CK_ULONG(expectedSize)
		return C.CKR_BUFFER_TOO_SMALL
	}

	// Buffer is large enough - proceed with actual wrap
	wrappedKey, err := module.GetGlobalModule().WrapKeyAuthenticated(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hWrappingKey),
		module.ObjectHandle(hKey),
		aad,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	// The pre-check above sized the output through its own lock acquisition,
	// which WrapKeyAuthenticatedSize released before WrapKeyAuthenticated took
	// it again. Both read the target key's CKA_VALUE, and CKA_VALUE is not a
	// read-only attribute, so a concurrent C_SetAttributeValue that lengthens
	// it (16 -> 32 bytes) lands between the two and the wrap returns more bytes
	// than were predicted. Copying the predicted length would write past the
	// end of the caller's buffer, so the guard is against the bytes actually
	// about to be written.
	if C.CK_ULONG(len(wrappedKey)) > *pulWrappedKeyLen {
		*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(wrappedKey) > 0 {
		C.memcpy(unsafe.Pointer(pWrappedKey), unsafe.Pointer(&wrappedKey[0]), C.size_t(len(wrappedKey)))
	}
	*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))

	// A token-generated IV goes back to the caller through pIv; see
	// writeAuthenticatedWrapIV.
	if ivRV := writeAuthenticatedWrapIV(pMechanism, mech); ivRV != C.CKR_OK {
		return ivRV
	}

	return C.CKR_OK
}

//export C_UnwrapKeyAuthenticated
func C_UnwrapKeyAuthenticated(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hUnwrappingKey C.CK_OBJECT_HANDLE,
	pWrappedKey C.CK_BYTE_PTR,
	ulWrappedKeyLen C.CK_ULONG,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulAttributeCount C.CK_ULONG,
	pAssociatedData C.CK_BYTE_PTR,
	ulAssociatedDataLen C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pWrappedKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pAssociatedData == nil && ulAssociatedDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := authenticatedWrapMechanism(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	wrappedKey, ok := cBytes(unsafe.Pointer(pWrappedKey), ulWrappedKeyLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	template, ok := convertCTemplateToGo(pTemplate, ulAttributeCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	keyHandle, err := module.GetGlobalModule().UnwrapKeyAuthenticated(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hUnwrappingKey),
		wrappedKey,
		template,
		aad,
	)
	if err != nil {
		return goErrorToCKRV(err)
	}

	*phKey = C.CK_OBJECT_HANDLE(keyHandle)
	return C.CKR_OK
}
