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

// Package main provides CGO exports for all PKCS#11 C_* functions.
//
// Each function uses the //export directive to make it available to C code.
// The functions convert between C and Go types and delegate to the Go module
// implementation in pkg/pkcs11/module.
//
// Unlike the root module's exports (which uses a remote daemon connection),
// the xkey module initializes an embedded (in-process) xkms service,
// eliminating all network overhead. The xkms singleton is initialized
// during C_Initialize and all operations are delegated through the embedded
// transport.
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "pkcs11.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"log"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	xkeypkcs11 "github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

// ============================================================================
// General-purpose Functions
// ============================================================================

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	// Create the embedded transport that delegates directly to the xkms singleton.
	adapter, err := xkeypkcs11.NewEmbeddedTransport()
	if err != nil {
		log.Printf("xkey/pkcs11: failed to create embedded transport: %v", err)
		return C.CKR_GENERAL_ERROR
	}

	// Create the PKCS#11 module with the embedded transport.
	m, err := module.New(module.WithClient(adapter))
	if err != nil {
		log.Printf("xkey/pkcs11: failed to create module: %v", err)
		return C.CKR_GENERAL_ERROR
	}

	// Set as the global module so all C_* functions can access it.
	module.SetGlobalModule(m)

	// Initialize the module (loads config, creates slots/tokens).
	rv := module.GetGlobalModule().Initialize(nil)
	return C.CK_RV(rv)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	// pReserved must be NULL per PKCS#11 spec
	if pReserved != nil {
		return C.CKR_ARGUMENTS_BAD
	}
	rv := module.GetGlobalModule().Finalize()
	return C.CK_RV(rv)
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, rv := module.GetGlobalModule().GetInfo()
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	// Copy Go info to C struct
	pInfo.cryptokiVersion.major = C.CK_BYTE(info.CryptokiVersion.Major)
	pInfo.cryptokiVersion.minor = C.CK_BYTE(info.CryptokiVersion.Minor)

	for i := 0; i < 32; i++ {
		pInfo.manufacturerID[i] = C.CK_UTF8CHAR(info.ManufacturerID[i])
		pInfo.libraryDescription[i] = C.CK_UTF8CHAR(info.LibraryDescription[i])
	}

	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.libraryVersion.major = C.CK_BYTE(info.LibraryVersion.Major)
	pInfo.libraryVersion.minor = C.CK_BYTE(info.LibraryVersion.Minor)

	return C.CKR_OK
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	if ppFunctionList == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = GetFunctionListPtr()
	return C.CKR_OK
}

// ============================================================================
// PKCS#11 v3.0 Interface Functions
// ============================================================================

//export C_GetInterfaceList
func C_GetInterfaceList(pInterfacesList C.CK_INTERFACE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// We support one interface: PKCS#11 v3.0
	if pInterfacesList == nil {
		*pulCount = 1
		return C.CKR_OK
	}

	if *pulCount < 1 {
		*pulCount = 1
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pInterfacesList = *GetInterfacePtr()
	*pulCount = 1
	return C.CKR_OK
}

//export C_GetInterface
func C_GetInterface(pInterfaceName C.CK_UTF8CHAR_PTR, pVersion C.CK_VERSION_PTR, ppInterface C.CK_INTERFACE_PTR_PTR, flags C.CK_FLAGS) C.CK_RV {
	if ppInterface == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Per OASIS PKCS#11 v3.0 Section 5.2.2: Validate flags parameter.
	// Only CKF_INTERFACE_FORK_SAFE (0x00000001) is a valid flag.
	// Unknown flags should result in CKR_ARGUMENTS_BAD.
	const CKF_INTERFACE_FORK_SAFE = 0x00000001
	if flags != 0 && flags != CKF_INTERFACE_FORK_SAFE {
		return C.CKR_ARGUMENTS_BAD
	}

	// If interface name is NULL, return the default (standard PKCS#11) interface
	if pInterfaceName == nil {
		*ppInterface = GetInterfacePtr()
		return C.CKR_OK
	}

	// Check if requested interface is "PKCS 11"
	name := C.GoString((*C.char)(unsafe.Pointer(pInterfaceName)))
	if name != "PKCS 11" {
		return C.CKR_ARGUMENTS_BAD
	}

	// Check version if specified
	if pVersion != nil {
		if pVersion.major > 3 || (pVersion.major == 3 && pVersion.minor > 0) {
			return C.CKR_ARGUMENTS_BAD
		}
	}

	*ppInterface = GetInterfacePtr()
	return C.CKR_OK
}

// ============================================================================
// Slot and Token Management Functions
// ============================================================================

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	slots, rv := module.GetGlobalModule().GetSlotList(tokenPresent == C.CK_TRUE)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	count := C.CK_ULONG(len(slots))

	if pSlotList == nil {
		*pulCount = count
		return C.CKR_OK
	}

	if *pulCount < count {
		*pulCount = count
		return C.CKR_BUFFER_TOO_SMALL
	}

	slotArray := unsafe.Slice(pSlotList, count)
	for i, slot := range slots {
		slotArray[i] = C.CK_SLOT_ID(slot)
	}
	*pulCount = count

	return C.CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, rv := module.GetGlobalModule().GetSlotInfo(module.SlotID(slotID))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	for i := 0; i < 64; i++ {
		pInfo.slotDescription[i] = C.CK_UTF8CHAR(info.SlotDescription[i])
	}
	for i := 0; i < 32; i++ {
		pInfo.manufacturerID[i] = C.CK_UTF8CHAR(info.ManufacturerID[i])
	}
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.hardwareVersion.major = C.CK_BYTE(info.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(info.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(info.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(info.FirmwareVersion.Minor)

	return C.CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, rv := module.GetGlobalModule().GetTokenInfo(module.SlotID(slotID))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	for i := 0; i < 32; i++ {
		pInfo.label[i] = C.CK_UTF8CHAR(info.Label[i])
		pInfo.manufacturerID[i] = C.CK_UTF8CHAR(info.ManufacturerID[i])
	}
	for i := 0; i < 16; i++ {
		pInfo.model[i] = C.CK_UTF8CHAR(info.Model[i])
		pInfo.serialNumber[i] = C.CK_CHAR(info.SerialNumber[i])
		pInfo.utcTime[i] = C.CK_CHAR(info.UtcTime[i])
	}
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulMaxSessionCount = C.CK_ULONG(info.MaxSessionCount)
	pInfo.ulSessionCount = C.CK_ULONG(info.SessionCount)
	pInfo.ulMaxRwSessionCount = C.CK_ULONG(info.MaxRwSessionCount)
	pInfo.ulRwSessionCount = C.CK_ULONG(info.RwSessionCount)
	pInfo.ulMaxPinLen = C.CK_ULONG(info.MaxPinLen)
	pInfo.ulMinPinLen = C.CK_ULONG(info.MinPinLen)
	pInfo.ulTotalPublicMemory = C.CK_ULONG(info.TotalPublicMemory)
	pInfo.ulFreePublicMemory = C.CK_ULONG(info.FreePublicMemory)
	pInfo.ulTotalPrivateMemory = C.CK_ULONG(info.TotalPrivateMemory)
	pInfo.ulFreePrivateMemory = C.CK_ULONG(info.FreePrivateMemory)
	pInfo.hardwareVersion.major = C.CK_BYTE(info.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(info.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(info.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(info.FirmwareVersion.Minor)

	return C.CKR_OK
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mechs, rv := module.GetGlobalModule().GetMechanismList(module.SlotID(slotID))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	count := C.CK_ULONG(len(mechs))

	if pMechanismList == nil {
		*pulCount = count
		return C.CKR_OK
	}

	if *pulCount < count {
		*pulCount = count
		return C.CKR_BUFFER_TOO_SMALL
	}

	mechArray := unsafe.Slice(pMechanismList, count)
	for i, mech := range mechs {
		mechArray[i] = C.CK_MECHANISM_TYPE(mech)
	}
	*pulCount = count

	return C.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, rv := module.GetGlobalModule().GetMechanismInfo(module.SlotID(slotID), module.MechanismType(mechType))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	pInfo.ulMinKeySize = C.CK_ULONG(info.MinKeySize)
	pInfo.ulMaxKeySize = C.CK_ULONG(info.MaxKeySize)
	pInfo.flags = C.CK_FLAGS(info.Flags)

	return C.CKR_OK
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pLabel C.CK_UTF8CHAR_PTR) C.CK_RV {
	if pLabel == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var pin []byte
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen))
	}

	label := C.GoStringN((*C.char)(unsafe.Pointer(pLabel)), 32)

	rv := module.GetGlobalModule().InitToken(module.SlotID(slotID), pin, label)
	return C.CK_RV(rv)
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	var pin []byte
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen))
	}

	rv := module.GetGlobalModule().InitPIN(module.SessionHandle(hSession), pin)
	return C.CK_RV(rv)
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewLen C.CK_ULONG) C.CK_RV {
	var oldPin, newPin []byte

	if pOldPin != nil && ulOldLen > 0 {
		oldPin = C.GoBytes(unsafe.Pointer(pOldPin), C.int(ulOldLen))
	}
	if pNewPin != nil && ulNewLen > 0 {
		newPin = C.GoBytes(unsafe.Pointer(pNewPin), C.int(ulNewLen))
	}

	rv := module.GetGlobalModule().SetPIN(module.SessionHandle(hSession), oldPin, newPin)
	return C.CK_RV(rv)
}

// ============================================================================
// Session Management Functions
// ============================================================================

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Note: We ignore pApplication and Notify callback for now
	handle, rv := module.GetGlobalModule().OpenSession(module.SlotID(slotID), module.SessionFlag(flags))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phSession = C.CK_SESSION_HANDLE(handle)
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().CloseSession(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV {
	rv := module.GetGlobalModule().CloseAllSessions(module.SlotID(slotID))
	return C.CK_RV(rv)
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, rv := module.GetGlobalModule().GetSessionInfo(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	pInfo.slotID = C.CK_SLOT_ID(info.SlotID)
	pInfo.state = C.CK_STATE(info.State)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulDeviceError = C.CK_ULONG(info.DeviceError)

	return C.CKR_OK
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV {
	if pulOperationStateLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	state, rv := module.GetGlobalModule().GetOperationStateBytes(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pOperationState == nil {
		*pulOperationStateLen = C.CK_ULONG(len(state))
		return C.CKR_OK
	}

	if *pulOperationStateLen < C.CK_ULONG(len(state)) {
		*pulOperationStateLen = C.CK_ULONG(len(state))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(state) > 0 {
		C.memcpy(unsafe.Pointer(pOperationState), unsafe.Pointer(&state[0]), C.size_t(len(state)))
	}
	*pulOperationStateLen = C.CK_ULONG(len(state))

	return C.CKR_OK
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pOperationState == nil && ulOperationStateLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	var state []byte
	if pOperationState != nil && ulOperationStateLen > 0 {
		state = C.GoBytes(unsafe.Pointer(pOperationState), C.int(ulOperationStateLen))
	}

	rv := module.GetGlobalModule().SetOperationStateBytes(
		module.SessionHandle(hSession),
		state,
		module.ObjectHandle(hEncryptionKey),
		module.ObjectHandle(hAuthenticationKey),
	)
	return C.CK_RV(rv)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	var pin []byte
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen))
	}

	rv := module.GetGlobalModule().Login(module.SessionHandle(hSession), module.UserType(userType), pin)
	return C.CK_RV(rv)
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().Logout(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// Object Management Functions
// ============================================================================

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if phObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	template := convertCTemplateToGo(pTemplate, ulCount)

	handle, rv := module.GetGlobalModule().CreateObject(module.SessionHandle(hSession), template)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phObject = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if phNewObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	template := convertCTemplateToGo(pTemplate, ulCount)

	handle, rv := module.GetGlobalModule().CopyObject(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phNewObject = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().DestroyObject(module.SessionHandle(hSession), module.ObjectHandle(hObject))
	return C.CK_RV(rv)
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR) C.CK_RV {
	if pulSize == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	size, rv := module.GetGlobalModule().GetObjectSize(module.SessionHandle(hSession), module.ObjectHandle(hObject))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*pulSize = C.CK_ULONG(size)
	return C.CKR_OK
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if pTemplate == nil && ulCount > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	template := convertCTemplateToGo(pTemplate, ulCount)

	result, rv := module.GetGlobalModule().GetAttributeValue(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	// Copy results back to C template
	copyGoTemplateToCTemplate(result, pTemplate, ulCount)

	return C.CKR_OK
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	template := convertCTemplateToGo(pTemplate, ulCount)

	rv := module.GetGlobalModule().SetAttributeValue(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)
	return C.CK_RV(rv)
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	template := convertCTemplateToGo(pTemplate, ulCount)

	rv := module.GetGlobalModule().FindObjectsInit(module.SessionHandle(hSession), template)
	return C.CK_RV(rv)
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	if pulObjectCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	handles, rv := module.GetGlobalModule().FindObjects(module.SessionHandle(hSession), uint32(ulMaxObjectCount))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	count := len(handles)
	if phObject != nil && count > 0 {
		handleArray := unsafe.Slice(phObject, ulMaxObjectCount)
		for i := 0; i < count && i < int(ulMaxObjectCount); i++ {
			handleArray[i] = C.CK_OBJECT_HANDLE(handles[i])
		}
	}
	*pulObjectCount = C.CK_ULONG(count)

	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().FindObjectsFinal(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// Encryption Functions
// ============================================================================

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().EncryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pulEncryptedDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	encrypted, rv := module.GetGlobalModule().Encrypt(module.SessionHandle(hSession), data)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pEncryptedData == nil {
		*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulEncryptedDataLen < C.CK_ULONG(len(encrypted)) {
		*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pEncryptedData), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))

	return C.CKR_OK
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	encrypted, rv := module.GetGlobalModule().EncryptUpdate(module.SessionHandle(hSession), part)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	// EncryptUpdate with buffering returns nil until EncryptFinal
	if encrypted == nil {
		*pulEncryptedPartLen = 0
		return C.CKR_OK
	}

	if pEncryptedPart == nil {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulEncryptedPartLen < C.CK_ULONG(len(encrypted)) {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(encrypted) > 0 {
		C.memcpy(unsafe.Pointer(pEncryptedPart), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	}
	*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))

	return C.CKR_OK
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulLastEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	encrypted, rv := module.GetGlobalModule().EncryptFinal(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pLastEncryptedPart == nil {
		*pulLastEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulLastEncryptedPartLen < C.CK_ULONG(len(encrypted)) {
		*pulLastEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(encrypted) > 0 {
		C.memcpy(unsafe.Pointer(pLastEncryptedPart), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	}
	*pulLastEncryptedPartLen = C.CK_ULONG(len(encrypted))

	return C.CKR_OK
}

// ============================================================================
// Decryption Functions
// ============================================================================

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().DecryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pulDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var encryptedData []byte
	if pEncryptedData != nil && ulEncryptedDataLen > 0 {
		encryptedData = C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))
	}

	data, rv := module.GetGlobalModule().Decrypt(module.SessionHandle(hSession), encryptedData)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pData == nil {
		*pulDataLen = C.CK_ULONG(len(data))
		return C.CKR_OK
	}

	if *pulDataLen < C.CK_ULONG(len(data)) {
		*pulDataLen = C.CK_ULONG(len(data))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(data) > 0 {
		C.memcpy(unsafe.Pointer(pData), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}
	*pulDataLen = C.CK_ULONG(len(data))

	return C.CKR_OK
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var encryptedPart []byte
	if pEncryptedPart != nil && ulEncryptedPartLen > 0 {
		encryptedPart = C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	}

	decrypted, rv := module.GetGlobalModule().DecryptUpdate(module.SessionHandle(hSession), encryptedPart)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	// DecryptUpdate with buffering returns nil until DecryptFinal
	if decrypted == nil {
		*pulPartLen = 0
		return C.CKR_OK
	}

	if pPart == nil {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_OK
	}

	if *pulPartLen < C.CK_ULONG(len(decrypted)) {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(decrypted) > 0 {
		C.memcpy(unsafe.Pointer(pPart), unsafe.Pointer(&decrypted[0]), C.size_t(len(decrypted)))
	}
	*pulPartLen = C.CK_ULONG(len(decrypted))

	return C.CKR_OK
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulLastPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	decrypted, rv := module.GetGlobalModule().DecryptFinal(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pLastPart == nil {
		*pulLastPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_OK
	}

	if *pulLastPartLen < C.CK_ULONG(len(decrypted)) {
		*pulLastPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(decrypted) > 0 {
		C.memcpy(unsafe.Pointer(pLastPart), unsafe.Pointer(&decrypted[0]), C.size_t(len(decrypted)))
	}
	*pulLastPartLen = C.CK_ULONG(len(decrypted))

	return C.CKR_OK
}

// ============================================================================
// Message Digesting Functions
// ============================================================================

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().DigestInit(module.SessionHandle(hSession), mech)
	return C.CK_RV(rv)
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	if pulDigestLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	digest, rv := module.GetGlobalModule().Digest(module.SessionHandle(hSession), data)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pDigest == nil {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_OK
	}

	if *pulDigestLen < C.CK_ULONG(len(digest)) {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pDigest), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))
	*pulDigestLen = C.CK_ULONG(len(digest))

	return C.CKR_OK
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	rv := module.GetGlobalModule().DigestUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(rv)
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().DigestKey(module.SessionHandle(hSession), module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	if pulDigestLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	digest, rv := module.GetGlobalModule().DigestFinal(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pDigest == nil {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_OK
	}

	if *pulDigestLen < C.CK_ULONG(len(digest)) {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pDigest), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))
	*pulDigestLen = C.CK_ULONG(len(digest))

	return C.CKR_OK
}

// ============================================================================
// Signing and MACing Functions
// ============================================================================

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().SignInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	signature, rv := module.GetGlobalModule().Sign(module.SessionHandle(hSession), data)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_OK
	}

	if *pulSignatureLen < C.CK_ULONG(len(signature)) {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))
	*pulSignatureLen = C.CK_ULONG(len(signature))

	return C.CKR_OK
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	rv := module.GetGlobalModule().SignUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(rv)
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	signature, rv := module.GetGlobalModule().SignFinal(module.SessionHandle(hSession))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_OK
	}

	if *pulSignatureLen < C.CK_ULONG(len(signature)) {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))
	*pulSignatureLen = C.CK_ULONG(len(signature))

	return C.CKR_OK
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().SignRecoverInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	signature, rv := module.GetGlobalModule().SignRecover(module.SessionHandle(hSession), data)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_OK
	}

	if *pulSignatureLen < C.CK_ULONG(len(signature)) {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(signature) > 0 {
		C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))
	}
	*pulSignatureLen = C.CK_ULONG(len(signature))

	return C.CKR_OK
}

// ============================================================================
// Verification Functions
// ============================================================================

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().VerifyInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	var data, signature []byte

	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	}

	rv := module.GetGlobalModule().Verify(module.SessionHandle(hSession), data, signature)
	return C.CK_RV(rv)
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	rv := module.GetGlobalModule().VerifyUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(rv)
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	var signature []byte
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	}

	rv := module.GetGlobalModule().VerifyFinal(module.SessionHandle(hSession), signature)
	return C.CK_RV(rv)
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	rv := module.GetGlobalModule().VerifyRecoverInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pulDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var signature []byte
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	}

	data, rv := module.GetGlobalModule().VerifyRecover(module.SessionHandle(hSession), signature)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pData == nil {
		*pulDataLen = C.CK_ULONG(len(data))
		return C.CKR_OK
	}

	if *pulDataLen < C.CK_ULONG(len(data)) {
		*pulDataLen = C.CK_ULONG(len(data))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(data) > 0 {
		C.memcpy(unsafe.Pointer(pData), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}
	*pulDataLen = C.CK_ULONG(len(data))

	return C.CKR_OK
}

// ============================================================================
// Dual-function Cryptographic Functions
// ============================================================================

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	encrypted, rv := module.GetGlobalModule().DigestEncryptUpdate(module.SessionHandle(hSession), part)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pEncryptedPart == nil {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulEncryptedPartLen < C.CK_ULONG(len(encrypted)) {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(encrypted) > 0 {
		C.memcpy(unsafe.Pointer(pEncryptedPart), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	}
	*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))

	return C.CKR_OK
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var encryptedPart []byte
	if pEncryptedPart != nil && ulEncryptedPartLen > 0 {
		encryptedPart = C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	}

	decrypted, rv := module.GetGlobalModule().DecryptDigestUpdate(module.SessionHandle(hSession), encryptedPart)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pPart == nil {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_OK
	}

	if *pulPartLen < C.CK_ULONG(len(decrypted)) {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(decrypted) > 0 {
		C.memcpy(unsafe.Pointer(pPart), unsafe.Pointer(&decrypted[0]), C.size_t(len(decrypted)))
	}
	*pulPartLen = C.CK_ULONG(len(decrypted))

	return C.CKR_OK
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var part []byte
	if pPart != nil && ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}

	encrypted, rv := module.GetGlobalModule().SignEncryptUpdate(module.SessionHandle(hSession), part)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pEncryptedPart == nil {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulEncryptedPartLen < C.CK_ULONG(len(encrypted)) {
		*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(encrypted) > 0 {
		C.memcpy(unsafe.Pointer(pEncryptedPart), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	}
	*pulEncryptedPartLen = C.CK_ULONG(len(encrypted))

	return C.CKR_OK
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var encryptedPart []byte
	if pEncryptedPart != nil && ulEncryptedPartLen > 0 {
		encryptedPart = C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	}

	decrypted, rv := module.GetGlobalModule().DecryptVerifyUpdate(module.SessionHandle(hSession), encryptedPart)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pPart == nil {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_OK
	}

	if *pulPartLen < C.CK_ULONG(len(decrypted)) {
		*pulPartLen = C.CK_ULONG(len(decrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(decrypted) > 0 {
		C.memcpy(unsafe.Pointer(pPart), unsafe.Pointer(&decrypted[0]), C.size_t(len(decrypted)))
	}
	*pulPartLen = C.CK_ULONG(len(decrypted))

	return C.CKR_OK
}

// ============================================================================
// Key Management Functions
// ============================================================================

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)
	template := convertCTemplateToGo(pTemplate, ulCount)

	handle, rv := module.GetGlobalModule().GenerateKey(module.SessionHandle(hSession), mech, template)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || phPublicKey == nil || phPrivateKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)
	pubTemplate := convertCTemplateToGo(pPublicKeyTemplate, ulPublicKeyAttributeCount)
	privTemplate := convertCTemplateToGo(pPrivateKeyTemplate, ulPrivateKeyAttributeCount)

	pubHandle, privHandle, rv := module.GetGlobalModule().GenerateKeyPair(module.SessionHandle(hSession), mech, pubTemplate, privTemplate)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phPublicKey = C.CK_OBJECT_HANDLE(pubHandle)
	*phPrivateKey = C.CK_OBJECT_HANDLE(privHandle)
	return C.CKR_OK
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR) C.CK_RV {
	if pMechanism == nil || pulWrappedKeyLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)

	wrappedKey, rv := module.GetGlobalModule().WrapKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hWrappingKey),
		module.ObjectHandle(hKey),
	)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pWrappedKey == nil {
		*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))
		return C.CKR_OK
	}

	if *pulWrappedKeyLen < C.CK_ULONG(len(wrappedKey)) {
		*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(wrappedKey) > 0 {
		C.memcpy(unsafe.Pointer(pWrappedKey), unsafe.Pointer(&wrappedKey[0]), C.size_t(len(wrappedKey)))
	}
	*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))

	return C.CKR_OK
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)
	template := convertCTemplateToGo(pTemplate, ulAttributeCount)

	var wrappedKey []byte
	if pWrappedKey != nil && ulWrappedKeyLen > 0 {
		wrappedKey = C.GoBytes(unsafe.Pointer(pWrappedKey), C.int(ulWrappedKeyLen))
	}

	handle, rv := module.GetGlobalModule().UnwrapKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hUnwrappingKey),
		wrappedKey,
		template,
	)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := convertCMechanismToGo(pMechanism)
	template := convertCTemplateToGo(pTemplate, ulAttributeCount)

	handle, rv := module.GetGlobalModule().DeriveKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hBaseKey),
		template,
	)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

// ============================================================================
// Random Number Generation Functions
// ============================================================================

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) C.CK_RV {
	// Seeding not supported - we use crypto/rand
	return C.CKR_RANDOM_SEED_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) C.CK_RV {
	if pRandomData == nil && ulRandomLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	data, rv := module.GetGlobalModule().GenerateRandom(module.SessionHandle(hSession), uint32(ulRandomLen))
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if len(data) > 0 {
		C.memcpy(unsafe.Pointer(pRandomData), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}

	return C.CKR_OK
}

// ============================================================================
// Parallel Function Management Functions (Legacy)
// ============================================================================

//export C_GetFunctionStatus
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	// Legacy function - always return CKR_FUNCTION_NOT_PARALLEL
	return C.CKR_FUNCTION_NOT_PARALLEL
}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	// Legacy function - always return CKR_FUNCTION_NOT_PARALLEL
	return C.CKR_FUNCTION_NOT_PARALLEL
}

// ============================================================================
// Slot Event Functions
// ============================================================================

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV {
	// Slot events not supported
	return C.CKR_NO_EVENT
}

// ============================================================================
// PKCS#11 v3.0 Session Functions
// ============================================================================

//export C_LoginUser
func C_LoginUser(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pUsername C.CK_UTF8CHAR_PTR, ulUsernameLen C.CK_ULONG) C.CK_RV {
	// PKCS#11 v3.0 context-specific login with username
	var pin []byte
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen))
	}
	var username string
	if pUsername != nil && ulUsernameLen > 0 {
		username = C.GoStringN((*C.char)(unsafe.Pointer(pUsername)), C.int(ulUsernameLen))
	}
	rv := module.GetGlobalModule().LoginUser(module.SessionHandle(hSession), module.UserType(userType), pin, username)
	return C.CK_RV(rv)
}

//export C_SessionCancel
func C_SessionCancel(hSession C.CK_SESSION_HANDLE, flags C.CK_FLAGS) C.CK_RV {
	// PKCS#11 v3.0 session operation cancellation
	rv := module.GetGlobalModule().SessionCancel(module.SessionHandle(hSession), uint64(flags))
	return C.CK_RV(rv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Encryption Functions
// ============================================================================

//export C_MessageEncryptInit
func C_MessageEncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mech := convertCMechanismToGo(pMechanism)
	rv := module.GetGlobalModule().MessageEncryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_EncryptMessage
func C_EncryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, ulPlaintextLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, pulCiphertextLen C.CK_ULONG_PTR) C.CK_RV {
	if pulCiphertextLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
	}

	var plaintext []byte
	if pPlaintext != nil && ulPlaintextLen > 0 {
		plaintext = C.GoBytes(unsafe.Pointer(pPlaintext), C.int(ulPlaintextLen))
	}

	ciphertext, rv := module.GetGlobalModule().EncryptMessage(module.SessionHandle(hSession), aad, plaintext)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pCiphertext == nil {
		*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(ciphertext)) > *pulCiphertextLen {
		*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
	copy((*[1 << 30]byte)(unsafe.Pointer(pCiphertext))[:len(ciphertext)], ciphertext)
	return C.CKR_OK
}

//export C_EncryptMessageBegin
func C_EncryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV {
	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
	}

	rv := module.GetGlobalModule().EncryptMessageBegin(module.SessionHandle(hSession), aad)
	return C.CK_RV(rv)
}

//export C_EncryptMessageNext
func C_EncryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, ulPlaintextPartLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, pulCiphertextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV {
	if pulCiphertextPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var plaintext []byte
	if pPlaintextPart != nil && ulPlaintextPartLen > 0 {
		plaintext = C.GoBytes(unsafe.Pointer(pPlaintextPart), C.int(ulPlaintextPartLen))
	}

	// Check if this is the final part (CKF_END_OF_MESSAGE = 0x00000001)
	final := (flags & 0x00000001) != 0

	ciphertext, rv := module.GetGlobalModule().EncryptMessageNext(module.SessionHandle(hSession), plaintext, final)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pCiphertextPart == nil {
		*pulCiphertextPartLen = C.CK_ULONG(len(ciphertext))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(ciphertext)) > *pulCiphertextPartLen {
		*pulCiphertextPartLen = C.CK_ULONG(len(ciphertext))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulCiphertextPartLen = C.CK_ULONG(len(ciphertext))
	if len(ciphertext) > 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pCiphertextPart))[:len(ciphertext)], ciphertext)
	}
	return C.CKR_OK
}

//export C_MessageEncryptFinal
func C_MessageEncryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().MessageEncryptFinal(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Decryption Functions
// ============================================================================

//export C_MessageDecryptInit
func C_MessageDecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mech := convertCMechanismToGo(pMechanism)
	rv := module.GetGlobalModule().MessageDecryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_DecryptMessage
func C_DecryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, ulCiphertextLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, pulPlaintextLen C.CK_ULONG_PTR) C.CK_RV {
	if pulPlaintextLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
	}

	var ciphertext []byte
	if pCiphertext != nil && ulCiphertextLen > 0 {
		ciphertext = C.GoBytes(unsafe.Pointer(pCiphertext), C.int(ulCiphertextLen))
	}

	plaintext, rv := module.GetGlobalModule().DecryptMessage(module.SessionHandle(hSession), aad, ciphertext)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pPlaintext == nil {
		*pulPlaintextLen = C.CK_ULONG(len(plaintext))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(plaintext)) > *pulPlaintextLen {
		*pulPlaintextLen = C.CK_ULONG(len(plaintext))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulPlaintextLen = C.CK_ULONG(len(plaintext))
	if len(plaintext) > 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pPlaintext))[:len(plaintext)], plaintext)
	}
	return C.CKR_OK
}

//export C_DecryptMessageBegin
func C_DecryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV {
	var aad []byte
	if pAssociatedData != nil && ulAssociatedDataLen > 0 {
		aad = C.GoBytes(unsafe.Pointer(pAssociatedData), C.int(ulAssociatedDataLen))
	}

	rv := module.GetGlobalModule().DecryptMessageBegin(module.SessionHandle(hSession), aad)
	return C.CK_RV(rv)
}

//export C_DecryptMessageNext
func C_DecryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, ulCiphertextPartLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, pulPlaintextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV {
	if pulPlaintextPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var ciphertext []byte
	if pCiphertextPart != nil && ulCiphertextPartLen > 0 {
		ciphertext = C.GoBytes(unsafe.Pointer(pCiphertextPart), C.int(ulCiphertextPartLen))
	}

	// Check if this is the final part (CKF_END_OF_MESSAGE = 0x00000001)
	final := (flags & 0x00000001) != 0

	plaintext, rv := module.GetGlobalModule().DecryptMessageNext(module.SessionHandle(hSession), ciphertext, final)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pPlaintextPart == nil {
		*pulPlaintextPartLen = C.CK_ULONG(len(plaintext))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(plaintext)) > *pulPlaintextPartLen {
		*pulPlaintextPartLen = C.CK_ULONG(len(plaintext))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulPlaintextPartLen = C.CK_ULONG(len(plaintext))
	if len(plaintext) > 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pPlaintextPart))[:len(plaintext)], plaintext)
	}
	return C.CKR_OK
}

//export C_MessageDecryptFinal
func C_MessageDecryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().MessageDecryptFinal(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Signing Functions
// ============================================================================

//export C_MessageSignInit
func C_MessageSignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mech := convertCMechanismToGo(pMechanism)
	rv := module.GetGlobalModule().MessageSignInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_SignMessage
func C_SignMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	signature, rv := module.GetGlobalModule().SignMessage(module.SessionHandle(hSession), data)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(signature)) > *pulSignatureLen {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulSignatureLen = C.CK_ULONG(len(signature))
	if len(signature) > 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pSignature))[:len(signature)], signature)
	}
	return C.CKR_OK
}

//export C_SignMessageBegin
func C_SignMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV {
	rv := module.GetGlobalModule().SignMessageBegin(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

//export C_SignMessageNext
func C_SignMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	// For SignMessageNext, signature is only returned on final call
	if pulSignatureLen == nil {
		// Non-final call - just update with data
		signature, rv := module.GetGlobalModule().SignMessageNext(module.SessionHandle(hSession), data, false)
		_ = signature
		return C.CK_RV(rv)
	}

	// Final call - get signature
	signature, rv := module.GetGlobalModule().SignMessageNext(module.SessionHandle(hSession), data, true)
	if rv != module.CKR_OK {
		return C.CK_RV(rv)
	}

	if pSignature == nil {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_OK
	}

	if C.CK_ULONG(len(signature)) > *pulSignatureLen {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulSignatureLen = C.CK_ULONG(len(signature))
	if len(signature) > 0 {
		copy((*[1 << 30]byte)(unsafe.Pointer(pSignature))[:len(signature)], signature)
	}
	return C.CKR_OK
}

//export C_MessageSignFinal
func C_MessageSignFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().MessageSignFinal(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Verification Functions
// ============================================================================

//export C_MessageVerifyInit
func C_MessageVerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mech := convertCMechanismToGo(pMechanism)
	rv := module.GetGlobalModule().MessageVerifyInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(rv)
}

//export C_VerifyMessage
func C_VerifyMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	var signature []byte
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	}

	rv := module.GetGlobalModule().VerifyMessage(module.SessionHandle(hSession), data, signature)
	return C.CK_RV(rv)
}

//export C_VerifyMessageBegin
func C_VerifyMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV {
	rv := module.GetGlobalModule().VerifyMessageBegin(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

//export C_VerifyMessageNext
func C_VerifyMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	var data []byte
	if pData != nil && ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}

	var signature []byte
	if pSignature != nil && ulSignatureLen > 0 {
		signature = C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	}

	rv := module.GetGlobalModule().VerifyMessageNext(module.SessionHandle(hSession), data, signature)
	return C.CK_RV(rv)
}

//export C_MessageVerifyFinal
func C_MessageVerifyFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	rv := module.GetGlobalModule().MessageVerifyFinal(module.SessionHandle(hSession))
	return C.CK_RV(rv)
}

// ============================================================================
// Helper Functions for Type Conversion
// ============================================================================

// convertCTemplateToGo converts a C attribute template to Go attributes.
func convertCTemplateToGo(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) []module.Attribute {
	if pTemplate == nil || ulCount == 0 {
		return nil
	}

	attrs := make([]module.Attribute, ulCount)
	templateArray := unsafe.Slice(pTemplate, ulCount)

	for i := C.CK_ULONG(0); i < ulCount; i++ {
		cAttr := templateArray[i]
		attrs[i] = module.Attribute{
			Type: module.AttributeType(cAttr._type),
		}

		if cAttr.pValue != nil && cAttr.ulValueLen > 0 {
			attrs[i].Value = C.GoBytes(unsafe.Pointer(cAttr.pValue), C.int(cAttr.ulValueLen))
		}
	}

	return attrs
}

// copyGoTemplateToCTemplate copies Go attributes back to a C template.
func copyGoTemplateToCTemplate(attrs []module.Attribute, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) {
	if pTemplate == nil || ulCount == 0 || len(attrs) == 0 {
		return
	}

	templateArray := unsafe.Slice(pTemplate, ulCount)

	for i := 0; i < len(attrs) && i < int(ulCount); i++ {
		cAttr := &templateArray[i]

		if cAttr.pValue == nil {
			// Query mode - just set the length
			cAttr.ulValueLen = C.CK_ULONG(len(attrs[i].Value))
		} else if cAttr.ulValueLen >= C.CK_ULONG(len(attrs[i].Value)) {
			// Copy the value
			if len(attrs[i].Value) > 0 {
				C.memcpy(unsafe.Pointer(cAttr.pValue), unsafe.Pointer(&attrs[i].Value[0]), C.size_t(len(attrs[i].Value)))
			}
			cAttr.ulValueLen = C.CK_ULONG(len(attrs[i].Value))
		} else {
			// Buffer too small - set ulValueLen to -1 per PKCS#11 spec
			cAttr.ulValueLen = C.CK_ULONG(0xFFFFFFFF)
		}
	}
}

// convertCMechanismToGo converts a C mechanism to a Go mechanism.
func convertCMechanismToGo(pMechanism C.CK_MECHANISM_PTR) *module.Mechanism {
	if pMechanism == nil {
		return nil
	}

	mech := &module.Mechanism{
		Type: module.MechanismType(pMechanism.mechanism),
	}

	if pMechanism.pParameter != nil && pMechanism.ulParameterLen > 0 {
		mech.Parameter = C.GoBytes(unsafe.Pointer(pMechanism.pParameter), C.int(pMechanism.ulParameterLen))

		// Parse mechanism-specific parameters
		switch module.MechanismType(pMechanism.mechanism) {
		case module.CKM_ECDH1_DERIVE, module.CKM_ECDH1_COFACTOR_DERIVE:
			// Parse CK_ECDH1_DERIVE_PARAMS
			if pMechanism.ulParameterLen >= C.CK_ULONG(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{})) {
				cParams := (*C.CK_ECDH1_DERIVE_PARAMS)(pMechanism.pParameter)
				ecdhParams := &module.ECDHParams{
					KDF: module.KDFType(cParams.kdf),
				}
				if cParams.pSharedData != nil && cParams.ulSharedDataLen > 0 {
					ecdhParams.SharedData = C.GoBytes(unsafe.Pointer(cParams.pSharedData), C.int(cParams.ulSharedDataLen))
				}
				if cParams.pPublicData != nil && cParams.ulPublicDataLen > 0 {
					ecdhParams.PublicData = C.GoBytes(unsafe.Pointer(cParams.pPublicData), C.int(cParams.ulPublicDataLen))
				}
				mech.TypedParameter = ecdhParams
			}
		}
	}

	return mech
}
