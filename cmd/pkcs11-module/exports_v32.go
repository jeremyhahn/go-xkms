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
	phKey C.CK_OBJECT_HANDLE_PTR,
	pCiphertext C.CK_BYTE_PTR,
	pulCiphertextLen C.CK_ULONG_PTR,
) C.CK_RV {
	if pMechanism == nil || pulCiphertextLen == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

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

	template := convertCTemplateToGo(pTemplate, ulCount)

	keyHandle, ciphertext, err := module.GetGlobalModule().EncapsulateKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hKey),
		template,
	)
	if err != nil {
		return goErrorToCKRV(err)
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
) C.CK_RV {
	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pCiphertext == nil && ulCiphertextLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)
	template := convertCTemplateToGo(pTemplate, ulCount)

	var ciphertext []byte
	if pCiphertext != nil && ulCiphertextLen > 0 {
		ciphertext = C.GoBytes(unsafe.Pointer(pCiphertext), C.int(ulCiphertextLen))
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
) C.CK_RV {
	// Per PKCS#11 v3.2 spec section 5.15.7: NULL mechanism cancels
	// an active signature-first verification operation.
	var mech *module.Mechanism
	if pMechanism != nil {
		mech = convertCMechanismToGo(pMechanism)
	}

	if pSignature == nil && ulSignatureLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	var signature []byte
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
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
) C.CK_RV {
	if pData == nil && ulDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
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
) C.CK_RV {
	if pPart == nil && ulPartLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
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
) C.CK_RV {
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
) C.CK_RV {
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
) C.CK_RV {
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
		if pResult.pValue == nil {
			pResult.ulValue = C.CK_ULONG(len(result.Value))
			return C.CKR_ARGUMENTS_BAD
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
) C.CK_RV {
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
) C.CK_RV {
	if pFunctionName == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pData == nil && ulData > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	functionName := C.GoString((*C.char)(unsafe.Pointer(pFunctionName)))

	var data []byte
	if pData != nil && ulData > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulData))
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
) C.CK_RV {
	if pMechanism == nil || pulWrappedKeyLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pAssociatedData == nil && ulAssociatedDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
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

	if len(wrappedKey) > 0 {
		C.memcpy(unsafe.Pointer(pWrappedKey), unsafe.Pointer(&wrappedKey[0]), C.size_t(len(wrappedKey)))
	}
	*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))

	return C.CKR_OK
}

//export C_UnwrapKeyAuthenticated
func C_UnwrapKeyAuthenticated(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hUnwrappingKey C.CK_OBJECT_HANDLE,
	pAssociatedData C.CK_BYTE_PTR,
	ulAssociatedDataLen C.CK_ULONG,
	pWrappedKey C.CK_BYTE_PTR,
	ulWrappedKeyLen C.CK_ULONG,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulAttributeCount C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) C.CK_RV {
	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pWrappedKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if pAssociatedData == nil && ulAssociatedDataLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
	}

	var wrappedKey []byte
	if pWrappedKey != nil && ulWrappedKeyLen > 0 {
		wrappedKey = C.GoBytes(unsafe.Pointer(pWrappedKey), C.int(ulWrappedKeyLen))
	}

	template := convertCTemplateToGo(pTemplate, ulAttributeCount)

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
