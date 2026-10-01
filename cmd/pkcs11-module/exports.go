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
	"math"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// recoverCKRV converts a panic escaping a Cryptoki entry point into
// CKR_FUNCTION_FAILED. A panic must never cross the cgo boundary: doing so
// would abort the process that loaded this shared library rather than
// return a CK_RV to the caller.
func recoverCKRV(rv *C.CK_RV) {
	if r := recover(); r != nil {
		*rv = C.CKR_FUNCTION_FAILED
	}
}

// cBytes copies ulLen bytes from a caller-supplied C buffer into a new Go
// byte slice, rejecting lengths that exceed the addressable range of a Go
// slice index. It returns ok=false when ulLen exceeds math.MaxInt32; the
// caller must then reject the request (typically with CKR_ARGUMENTS_BAD)
// rather than risk a panic inside cgo's GoBytes.
//
// A zero length yields a nil slice with ok=true, whatever the pointer: an empty
// input is legitimate, and C_Digest of nothing has a defined answer.
//
// A NULL pointer with a NONZERO length is refused. The two are not the same
// request: NULL/0 says "no data", while NULL/32 says "thirty-two bytes live
// here" and is simply malformed. Accepting it as an empty buffer meant
// C_Digest(h, NULL, 32, out, &len) hashed the empty string and reported CKR_OK,
// and the same helper backs the sign, verify, encrypt and decrypt paths, so each
// of them could be driven to operate on data the caller never supplied.
func cBytes(p unsafe.Pointer, ulLen C.CK_ULONG) (data []byte, ok bool) {
	if ulLen == 0 {
		return nil, true
	}
	if p == nil {
		return nil, false
	}
	// CK_ULONG is 64-bit on a 64-bit platform, so bound against Go's own slice
	// ceiling (math.MaxInt) rather than C.int's MaxInt32 — the old bound
	// rejected valid buffers between 2 GiB and the addressable maximum. Copy out
	// of C memory immediately (unsafe.Slice aliases it) so the returned slice is
	// pure Go memory the caller can retain.
	if uint64(ulLen) > uint64(math.MaxInt) {
		return nil, false
	}
	return append([]byte(nil), unsafe.Slice((*byte)(p), int(ulLen))...), true
}

// badArgumentTerminating reports CKR_ARGUMENTS_BAD from a terminal operation,
// ending that operation first.
//
// PKCS#11 v3.2 states the rule for each terminal function in the same words --
// §5.8.2 for C_Encrypt: "A call to C_Encrypt always terminates the active
// encryption operation unless it returns CKR_BUFFER_TOO_SMALL or is a
// successful call ... to determine the length of the buffer needed." An argument
// the C layer rejects before ever reaching the module is neither exception, so
// the operation must not be left running: it was, and a later well-formed call
// could still complete the operation the failed one was supposed to have ended.
//
// The FinishOperation result is deliberately discarded. The call being answered
// has already failed, CKR_ARGUMENTS_BAD is the code the application needs, and
// there is nothing useful to say about tearing down an operation that may not
// have been started in the first place.
func badArgumentTerminating(hSession C.CK_SESSION_HANDLE, opType module.OperationType) C.CK_RV {
	_ = module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), opType)
	return C.CKR_ARGUMENTS_BAD
}

// terminateInitOperation implements the NULL pMechanism contract that PKCS#11
// v3.2 gives every operation initializer.
//
// §5.13.1 states it for C_SignInit: "C_SignInit can be called with pMechanism
// set to NULL_PTR to terminate an active signature operation. If an operation
// has been initialized and it cannot be cancelled, CKR_OPERATION_CANCEL_FAILED
// must be returned." The same sentence, with the operation renamed, appears for
// C_EncryptInit (§5.8.1), C_MessageEncryptInit (§5.9.1), C_DecryptInit
// (§5.10.1), C_DigestInit (§5.12.1), C_SignRecoverInit (§5.13.5), C_VerifyInit
// (§5.15.1), C_VerifyRecoverInit (§5.15.5) and C_VerifySignatureInit (§5.15.7),
// which is why CKR_OPERATION_CANCEL_FAILED appears in each of their return
// tables. C_MessageDecryptInit (§5.11.1) lists CKR_OPERATION_CANCEL_FAILED in
// its return table without restating the sentence, and C_MessageSignInit
// (§5.14.1) and C_MessageVerifyInit (§5.16.1) state neither. All four
// message-based initializers are otherwise defined in parallel, so treating the
// two omissions as editorial keeps a single rule for the whole family; an
// application cannot be expected to discover that message-based signing alone
// answers CKR_ARGUMENTS_BAD to the cancellation its siblings accept.
//
// Termination runs through Module.FinishOperation because that is already the
// module's one way to end a single operation category: it resolves the session
// and calls SessionManager.FinalizeOperationType, the same primitive
// C_SessionCancel uses. A second cancellation path would be free to drift from
// the one C_SessionCancel is tested against.
//
// The mapping from the module's answer to the CK_RV an initializer may return
// is in cancelResult.
func terminateInitOperation(hSession module.SessionHandle, opType module.OperationType) module.CK_RV {
	return cancelResult(module.GetGlobalModule().FinishOperation(hSession, opType))
}

// cancelResult translates Module.FinishOperation's result into a CK_RV that
// belongs to an initializer's return table.
//
// Cancelling when nothing is active is CKR_OK, not CKR_OPERATION_NOT_INITIALIZED.
// The spec makes only the *failure* to cancel an error, and C_SessionCancel —
// the function written expressly to cancel operations — says a flag naming an
// uninitialized operation "will be ignored and C_SessionCancel will behave as if
// the operation flag was not set". The caller's postcondition, that no operation
// of this category is active, holds either way, so reporting an error would
// describe a state the caller asked for.
func cancelResult(rv module.CK_RV) module.CK_RV {
	switch rv {
	case module.CKR_OK, module.CKR_OPERATION_NOT_INITIALIZED:
		return module.CKR_OK

	case module.CKR_CRYPTOKI_NOT_INITIALIZED, module.CKR_SESSION_HANDLE_INVALID, module.CKR_SESSION_CLOSED:
		// The library or the session, not the operation, is what the module
		// could not resolve. Each of these codes is listed in the initializers'
		// return tables, whereas answering CKR_OPERATION_CANCEL_FAILED here
		// would tell the application its token refused a cancellation that was
		// never attempted.
		return rv

	default:
		// "If an operation has been initialized and it cannot be cancelled,
		// CKR_OPERATION_CANCEL_FAILED must be returned." Anything else the
		// module reports is a refusal to end the operation, which is exactly
		// what that code names. C_SessionCancel treats the same class of
		// failure the same way.
		return module.CKR_OPERATION_CANCEL_FAILED
	}
}

// ============================================================================
// General-purpose Functions
// ============================================================================

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInitArgs != nil {
		args := (*C.CK_C_INITIALIZE_ARGS)(pInitArgs)

		// Per PKCS#11 spec section 5.4.1, pReserved must be NULL_PTR.
		if args.pReserved != nil {
			return C.CKR_ARGUMENTS_BAD
		}

		// The "some but not all" rule is unconditional. PKCS#11 v3.2 §5.6.1: "If
		// some, but not all, of the supplied function pointers to C_Initialize
		// are NULL_PTR, then C_Initialize should return with the value
		// CKR_ARGUMENTS_BAD." It is not conditioned on CKF_OS_LOCKING_OK, so
		// counting only when that flag is clear let a partially populated
		// callback set through unremarked whenever the application also granted
		// native locking -- a malformed argument answered with CKR_OK.
		callbacks := 0
		if args.CreateMutex != nil {
			callbacks++
		}
		if args.DestroyMutex != nil {
			callbacks++
		}
		if args.LockMutex != nil {
			callbacks++
		}
		if args.UnlockMutex != nil {
			callbacks++
		}
		if callbacks != 0 && callbacks != 4 {
			return C.CKR_ARGUMENTS_BAD
		}

		// Only the combination that demands application-supplied locking is
		// refused: the application declined native OS locking and provided its
		// own mutex routines, which this module never invokes and so cannot
		// honor. Zero callbacks without the flag is a single-threaded
		// application, which needs nothing; with the flag, this module is
		// natively thread-safe (Go's runtime serializes access internally).
		if args.flags&C.CKF_OS_LOCKING_OK == 0 && callbacks == 4 {
			return C.CKR_CANT_LOCK
		}
	}

	// Offline mode: the library builds the embedded in-process service and
	// installs it as the global module, so the module uses the injected
	// in-process client instead of dialing a remote xkmsd. initializeOffline
	// leaves a module a Go caller installed (xkey injects its own client) in
	// place, and rebuilds the library's own module after C_Finalize so the
	// application can initialize again.
	if offlineModeRequested() {
		return C.CK_RV(initializeOffline())
	}

	mrv := module.GetGlobalModule().Initialize(nil)
	return C.CK_RV(mrv)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// pReserved must be NULL per PKCS#11 spec
	if pReserved != nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mrv := module.GetGlobalModule().Finalize()
	return C.CK_RV(mrv)
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, mrv := module.GetGlobalModule().GetInfo()
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

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
func C_GetInterfaceList(pInterfacesList C.CK_INTERFACE_PTR, pulCount C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// C_GetInterface serves three interfaces (v2.x, v3.0, v3.2); enumerate
	// all of them here so callers that discover interfaces via
	// C_GetInterfaceList see the same set C_GetInterface can resolve.
	const interfaceCount = 3

	if pInterfacesList == nil {
		*pulCount = interfaceCount
		return C.CKR_OK
	}

	if *pulCount < interfaceCount {
		*pulCount = interfaceCount
		return C.CKR_BUFFER_TOO_SMALL
	}

	interfaces := unsafe.Slice(pInterfacesList, interfaceCount)
	interfaces[0] = *GetInterfaceV2Ptr()
	interfaces[1] = *GetInterfaceV30Ptr()
	interfaces[2] = *GetInterfacePtr()
	*pulCount = interfaceCount

	return C.CKR_OK
}

//export C_GetInterface
func C_GetInterface(pInterfaceName C.CK_UTF8CHAR_PTR, pVersion C.CK_VERSION_PTR, ppInterface C.CK_INTERFACE_PTR_PTR, flags C.CK_FLAGS) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if ppInterface == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Per OASIS PKCS#11 v3.0 §5.2.2 the flags select the interface to return,
	// and CKF_INTERFACE_FORK_SAFE (0x00000001) is the only one defined.
	//
	// It is refused rather than honoured. None of the interfaces this module
	// publishes carries the flag (see function_list.go), because none of them is
	// fork-safe: the Go runtime and the daemon connection behind these functions
	// do not survive fork(2). Answering CKR_OK with an interface whose flags are
	// zero left a caller that had asked for fork safety, and trusted the return
	// code rather than re-reading the flags, driving a Go runtime and an
	// inherited socket in a forked child.
	const CKF_INTERFACE_FORK_SAFE = 0x00000001
	if flags != 0 {
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

	// Version negotiation per PKCS#11 v3.2 spec:
	// If no version specified, return the latest available (v3.2)
	if pVersion == nil {
		*ppInterface = GetInterfacePtr()
		return C.CKR_OK
	}

	// Exact version matching: return the interface for the requested version
	major := pVersion.major
	minor := pVersion.minor

	switch {
	case major == 2:
		// Any v2.x request returns the CK_FUNCTION_LIST (v2.40)
		*ppInterface = GetInterfaceV2Ptr()
		return C.CKR_OK
	case major == 3 && minor == 0:
		// v3.0 request returns CK_FUNCTION_LIST_3_0
		*ppInterface = GetInterfaceV30Ptr()
		return C.CKR_OK
	case major == 3 && minor == 2:
		// v3.2 request returns CK_FUNCTION_LIST_3_2
		*ppInterface = GetInterfacePtr()
		return C.CKR_OK
	default:
		// Unsupported version
		return C.CKR_ARGUMENTS_BAD
	}
}

// ============================================================================
// Slot and Token Management Functions
// ============================================================================

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	slots, mrv := module.GetGlobalModule().GetSlotList(tokenPresent == C.CK_TRUE)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	if len(slots) > math.MaxInt32 {
		return C.CKR_GENERAL_ERROR
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
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, mrv := module.GetGlobalModule().GetSlotInfo(module.SlotID(slotID))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, mrv := module.GetGlobalModule().GetTokenInfo(module.SlotID(slotID))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mechs, mrv := module.GetGlobalModule().GetMechanismList(module.SlotID(slotID))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	if len(mechs) > math.MaxInt32 {
		return C.CKR_GENERAL_ERROR
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
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, mrv := module.GetGlobalModule().GetMechanismInfo(module.SlotID(slotID), module.MechanismType(mechType))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	pInfo.ulMinKeySize = C.CK_ULONG(info.MinKeySize)
	pInfo.ulMaxKeySize = C.CK_ULONG(info.MaxKeySize)
	pInfo.flags = C.CK_FLAGS(info.Flags)

	return C.CKR_OK
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pLabel C.CK_UTF8CHAR_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pLabel == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	pin, ok := cBytes(unsafe.Pointer(pPin), ulPinLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	label := C.GoStringN((*C.char)(unsafe.Pointer(pLabel)), 32)

	mrv := module.GetGlobalModule().InitToken(module.SlotID(slotID), pin, label)
	return C.CK_RV(mrv)
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	pin, ok := cBytes(unsafe.Pointer(pPin), ulPinLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().InitPIN(module.SessionHandle(hSession), pin)
	return C.CK_RV(mrv)
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	oldPin, ok := cBytes(unsafe.Pointer(pOldPin), ulOldLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}
	newPin, ok := cBytes(unsafe.Pointer(pNewPin), ulNewLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().SetPIN(module.SessionHandle(hSession), oldPin, newPin)
	return C.CK_RV(mrv)
}

// ============================================================================
// Session Management Functions
// ============================================================================

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Note: We ignore pApplication and Notify callback for now
	handle, mrv := module.GetGlobalModule().OpenSession(module.SlotID(slotID), module.SessionFlag(flags))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phSession = C.CK_SESSION_HANDLE(handle)
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().CloseSession(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().CloseAllSessions(module.SlotID(slotID))
	return C.CK_RV(mrv)
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, mrv := module.GetGlobalModule().GetSessionInfo(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	pInfo.slotID = C.CK_SLOT_ID(info.SlotID)
	pInfo.state = C.CK_STATE(info.State)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulDeviceError = C.CK_ULONG(info.DeviceError)

	return C.CKR_OK
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulOperationStateLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	state, mrv := module.GetGlobalModule().GetOperationStateBytes(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pOperationState == nil && ulOperationStateLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	state, ok := cBytes(unsafe.Pointer(pOperationState), ulOperationStateLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().SetOperationStateBytes(
		module.SessionHandle(hSession),
		state,
		module.ObjectHandle(hEncryptionKey),
		module.ObjectHandle(hAuthenticationKey),
	)
	return C.CK_RV(mrv)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	pin, ok := cBytes(unsafe.Pointer(pPin), ulPinLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().Login(module.SessionHandle(hSession), module.UserType(userType), pin)
	return C.CK_RV(mrv)
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().Logout(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// Object Management Functions
// ============================================================================

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if phObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, mrv := module.GetGlobalModule().CreateObject(module.SessionHandle(hSession), template)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phObject = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phNewObject C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if phNewObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, mrv := module.GetGlobalModule().CopyObject(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phNewObject = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().DestroyObject(module.SessionHandle(hSession), module.ObjectHandle(hObject))
	return C.CK_RV(mrv)
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulSize == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	size, mrv := module.GetGlobalModule().GetObjectSize(module.SessionHandle(hSession), module.ObjectHandle(hObject))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*pulSize = C.CK_ULONG(size)
	return C.CKR_OK
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pTemplate == nil && ulCount > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	template, ok := requestedAttributes(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	result, mrv := module.GetGlobalModule().GetAttributeValue(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)

	// Per PKCS#11 spec section 5.7.5: when the module returns
	// CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, or
	// CKR_BUFFER_TOO_SMALL, it must nonetheless have processed every
	// attribute in the template. Copy back whatever was recovered even on
	// these partial-failure codes; only skip the copy if the module
	// returned no result at all (a true failure).
	bufferTooSmall := false
	if result != nil {
		bufferTooSmall = copyGoTemplateToCTemplate(result, pTemplate, ulCount)
	}

	// A caller buffer that was too short for a value is only visible here, not
	// to the module: it returns whole values and knows nothing about the
	// caller's allocation. Report it, unless the module already returned a
	// different partial-failure code, in which case either is spec-legal.
	if bufferTooSmall && mrv == module.CKR_OK {
		return C.CKR_BUFFER_TOO_SMALL
	}

	return C.CK_RV(mrv)
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().SetAttributeValue(module.SessionHandle(hSession), module.ObjectHandle(hObject), template)
	return C.CK_RV(mrv)
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	template, ok := convertCTemplateToGo(pTemplate, ulCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().FindObjectsInit(module.SessionHandle(hSession), template)
	return C.CK_RV(mrv)
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulObjectCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if ulMaxObjectCount > C.CK_ULONG(math.MaxInt32) {
		return C.CKR_ARGUMENTS_BAD
	}
	// phObject is not optional. C_FindObjects has no length-query form -- v3.2
	// §5.7.8 describes it as "the location that receives the list of additional
	// object handles" -- and the search cursor advances inside the module, so
	// handles matched for a NULL destination are consumed and can never be
	// retrieved by that search again. Accepting it reported those handles as
	// delivered under CKR_OK to a caller with nowhere to have received them.
	if phObject == nil && ulMaxObjectCount > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	handles, mrv := module.GetGlobalModule().FindObjects(module.SessionHandle(hSession), uint32(ulMaxObjectCount))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// The count reported is the count written. §5.7.8 gives pulObjectCount "the
	// actual number of object handles returned", so a module answer longer than
	// the caller's array must be clamped here rather than inviting the caller to
	// read past the end of its own allocation.
	count := len(handles)
	if count > int(ulMaxObjectCount) {
		count = int(ulMaxObjectCount)
	}
	if count > 0 {
		handleArray := unsafe.Slice(phObject, ulMaxObjectCount)
		for i := 0; i < count; i++ {
			handleArray[i] = C.CK_OBJECT_HANDLE(handles[i])
		}
	}
	*pulObjectCount = C.CK_ULONG(count)

	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().FindObjectsFinal(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// Encryption Functions
// ============================================================================

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.8.1: "C_EncryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active encryption operation."
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationEncrypt))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().EncryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulEncryptedDataLen == nil {
		return badArgumentTerminating(hSession, module.OperationEncrypt)
	}

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationEncrypt)
	}

	encrypted, mrv := module.GetGlobalModule().Encrypt(module.SessionHandle(hSession), data)
	if mrv != module.CKR_OK {
		// The module already terminated the operation on error.
		return C.CK_RV(mrv)
	}

	if pEncryptedData == nil {
		// Length query: the operation stays active for the follow-up call.
		*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))
		return C.CKR_OK
	}

	if *pulEncryptedDataLen < C.CK_ULONG(len(encrypted)) {
		// Retryable: the operation stays active for the follow-up call.
		*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(encrypted) > 0 {
		C.memcpy(unsafe.Pointer(pEncryptedData), unsafe.Pointer(&encrypted[0]), C.size_t(len(encrypted)))
	}
	*pulEncryptedDataLen = C.CK_ULONG(len(encrypted))

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationEncrypt))
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pEncryptedPart == nil {
		if _, mrv := module.GetGlobalModule().EncryptUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulEncryptedPartLen = 0
		return C.CKR_OK
	}

	encrypted, mrv := module.GetGlobalModule().EncryptUpdate(module.SessionHandle(hSession), part)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// EncryptUpdate with buffering returns nil until EncryptFinal
	if encrypted == nil {
		*pulEncryptedPartLen = 0
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
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulLastEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	encrypted, mrv := module.GetGlobalModule().EncryptFinal(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationEncrypt))
}

// ============================================================================
// Decryption Functions
// ============================================================================

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.10.1: "C_DecryptInit can be called with pMechanism set to
	// NULL_PTR to terminate an active decryption operation."
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationDecrypt))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().DecryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulDataLen == nil {
		return badArgumentTerminating(hSession, module.OperationDecrypt)
	}

	encryptedData, ok := cBytes(unsafe.Pointer(pEncryptedData), ulEncryptedDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationDecrypt)
	}

	data, mrv := module.GetGlobalModule().Decrypt(module.SessionHandle(hSession), encryptedData)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationDecrypt))
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	encryptedPart, ok := cBytes(unsafe.Pointer(pEncryptedPart), ulEncryptedPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pPart == nil {
		if _, mrv := module.GetGlobalModule().DecryptUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulPartLen = 0
		return C.CKR_OK
	}

	decrypted, mrv := module.GetGlobalModule().DecryptUpdate(module.SessionHandle(hSession), encryptedPart)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// DecryptUpdate with buffering returns nil until DecryptFinal
	if decrypted == nil {
		*pulPartLen = 0
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
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulLastPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	decrypted, mrv := module.GetGlobalModule().DecryptFinal(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationDecrypt))
}

// ============================================================================
// Message Digesting Functions
// ============================================================================

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.12.1: "C_DigestInit can be called with pMechanism set to
	// NULL_PTR to terminate an active message-digesting operation."
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationDigest))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().DigestInit(module.SessionHandle(hSession), mech)
	return C.CK_RV(mrv)
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulDigestLen == nil {
		return badArgumentTerminating(hSession, module.OperationDigest)
	}

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationDigest)
	}

	digest, mrv := module.GetGlobalModule().Digest(module.SessionHandle(hSession), data)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	if pDigest == nil {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_OK
	}

	if *pulDigestLen < C.CK_ULONG(len(digest)) {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(digest) > 0 {
		C.memcpy(unsafe.Pointer(pDigest), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))
	}
	*pulDigestLen = C.CK_ULONG(len(digest))

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationDigest))
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().DigestUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(mrv)
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().DigestKey(module.SessionHandle(hSession), module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulDigestLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	digest, mrv := module.GetGlobalModule().DigestFinal(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	if pDigest == nil {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_OK
	}

	if *pulDigestLen < C.CK_ULONG(len(digest)) {
		*pulDigestLen = C.CK_ULONG(len(digest))
		return C.CKR_BUFFER_TOO_SMALL
	}

	if len(digest) > 0 {
		C.memcpy(unsafe.Pointer(pDigest), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))
	}
	*pulDigestLen = C.CK_ULONG(len(digest))

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationDigest))
}

// ============================================================================
// Signing and MACing Functions
// ============================================================================

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.13.1: "C_SignInit can be called with pMechanism set to
	// NULL_PTR to terminate an active signature operation."
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationSign))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().SignInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulSignatureLen == nil {
		return badArgumentTerminating(hSession, module.OperationSign)
	}

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationSign)
	}

	signature, mrv := module.GetGlobalModule().Sign(module.SessionHandle(hSession), data)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationSign))
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().SignUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(mrv)
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	signature, mrv := module.GetGlobalModule().SignFinal(module.SessionHandle(hSession))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationSign))
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.13.5: "C_SignRecoverInit can be called with pMechanism set
	// to NULL_PTR to terminate an active signature with data recovery
	// operation." Recovery shares the session's signature slot, so the category
	// to end is the same one C_SignRecover finishes.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationSign))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().SignRecoverInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulSignatureLen == nil {
		return badArgumentTerminating(hSession, module.OperationSign)
	}

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationSign)
	}

	signature, mrv := module.GetGlobalModule().SignRecover(module.SessionHandle(hSession), data)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationSign))
}

// ============================================================================
// Verification Functions
// ============================================================================

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.15.1: "C_VerifyInit can be called with pMechanism set to
	// NULL_PTR to terminate an active verification operation."
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationVerify))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().VerifyInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationVerify)
	}
	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationVerify)
	}

	mrv := module.GetGlobalModule().Verify(module.SessionHandle(hSession), data, signature)
	return C.CK_RV(mrv)
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().VerifyUpdate(module.SessionHandle(hSession), part)
	return C.CK_RV(mrv)
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().VerifyFinal(module.SessionHandle(hSession), signature)
	return C.CK_RV(mrv)
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.15.5: "C_VerifyRecoverInit can be called with pMechanism
	// set to NULL_PTR to terminate an active verification with data recovery
	// operation." Recovery shares the session's verification slot, so the
	// category to end is the same one C_VerifyRecover finishes.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationVerify))
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	mrv := module.GetGlobalModule().VerifyRecoverInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulDataLen == nil {
		return badArgumentTerminating(hSession, module.OperationVerify)
	}

	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return badArgumentTerminating(hSession, module.OperationVerify)
	}

	data, mrv := module.GetGlobalModule().VerifyRecover(module.SessionHandle(hSession), signature)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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

	return C.CK_RV(module.GetGlobalModule().FinishOperation(module.SessionHandle(hSession), module.OperationVerify))
}

// ============================================================================
// Dual-function Cryptographic Functions
// ============================================================================

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pEncryptedPart == nil {
		if _, mrv := module.GetGlobalModule().DigestEncryptUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulEncryptedPartLen = 0
		return C.CKR_OK
	}

	encrypted, mrv := module.GetGlobalModule().DigestEncryptUpdate(module.SessionHandle(hSession), part)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	encryptedPart, ok := cBytes(unsafe.Pointer(pEncryptedPart), ulEncryptedPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pPart == nil {
		if _, mrv := module.GetGlobalModule().DecryptDigestUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulPartLen = 0
		return C.CKR_OK
	}

	decrypted, mrv := module.GetGlobalModule().DecryptDigestUpdate(module.SessionHandle(hSession), encryptedPart)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	part, ok := cBytes(unsafe.Pointer(pPart), ulPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pEncryptedPart == nil {
		if _, mrv := module.GetGlobalModule().SignEncryptUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulEncryptedPartLen = 0
		return C.CKR_OK
	}

	encrypted, mrv := module.GetGlobalModule().SignEncryptUpdate(module.SessionHandle(hSession), part)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	encryptedPart, ok := cBytes(unsafe.Pointer(pEncryptedPart), ulEncryptedPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// PKCS#11 v3.2 §5.2 makes a NULL output buffer a length query, which must
	// report the required size without otherwise affecting the operation. These
	// updates buffer their input and emit nothing until the matching *Final, so
	// the size is always zero -- but the call is still made, with no data, for
	// two reasons: a query against a session with no active operation must
	// still answer CKR_OPERATION_NOT_INITIALIZED rather than a spurious
	// CKR_OK, and passing the caller's part here would append it a second time
	// when the caller retries with a real buffer, silently encrypting or
	// digesting it twice.
	if pPart == nil {
		if _, mrv := module.GetGlobalModule().DecryptVerifyUpdate(module.SessionHandle(hSession), nil); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulPartLen = 0
		return C.CKR_OK
	}

	decrypted, mrv := module.GetGlobalModule().DecryptVerifyUpdate(module.SessionHandle(hSession), encryptedPart)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phKey == nil {
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

	handle, mrv := module.GetGlobalModule().GenerateKey(module.SessionHandle(hSession), mech, template)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phPublicKey == nil || phPrivateKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	pubTemplate, ok := convertCTemplateToGo(pPublicKeyTemplate, ulPublicKeyAttributeCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}
	privTemplate, ok := convertCTemplateToGo(pPrivateKeyTemplate, ulPrivateKeyAttributeCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	pubHandle, privHandle, mrv := module.GetGlobalModule().GenerateKeyPair(module.SessionHandle(hSession), mech, pubTemplate, privTemplate)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phPublicKey = C.CK_OBJECT_HANDLE(pubHandle)
	*phPrivateKey = C.CK_OBJECT_HANDLE(privHandle)
	return C.CKR_OK
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || pulWrappedKeyLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}

	wrappedKey, mrv := module.GetGlobalModule().WrapKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hWrappingKey),
		module.ObjectHandle(hKey),
	)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	template, ok := convertCTemplateToGo(pTemplate, ulAttributeCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	wrappedKey, ok := cBytes(unsafe.Pointer(pWrappedKey), ulWrappedKeyLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, mrv := module.GetGlobalModule().UnwrapKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hUnwrappingKey),
		wrappedKey,
		template,
	)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pMechanism == nil || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	template, ok := convertCTemplateToGo(pTemplate, ulAttributeCount)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, mrv := module.GetGlobalModule().DeriveKey(
		module.SessionHandle(hSession),
		mech,
		module.ObjectHandle(hBaseKey),
		template,
	)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	*phKey = C.CK_OBJECT_HANDLE(handle)
	return C.CKR_OK
}

// ============================================================================
// Random Number Generation Functions
// ============================================================================

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	seed, ok := cBytes(unsafe.Pointer(pSeed), ulSeedLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Module.SeedRandom is where this library decides what seeding means, and it
	// applies the preconditions §5.19.1 requires of the entry point:
	// CKR_CRYPTOKI_NOT_INITIALIZED before C_Initialize, and
	// CKR_SESSION_HANDLE_INVALID for a handle that names no session. Returning a
	// constant here skipped both, so C_SeedRandom answered on an uninitialized
	// library and the C ABI disagreed with the Go API about the same call.
	mrv := module.GetGlobalModule().SeedRandom(module.SessionHandle(hSession), seed)
	return C.CK_RV(mrv)
}

// C_GenerateRandom fills the caller's buffer with ulRandomLen bytes of random
// data, per PKCS#11 v3.2 section 5.19.2.
//
// A request longer than math.MaxInt32 bytes is refused with
// CKR_ARGUMENTS_BAD rather than served in part. Section 5.19.2's return table
// is CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
// CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
// CKR_OPERATION_ACTIVE, CKR_PENDING, CKR_RANDOM_NO_RNG,
// CKR_SEED_RANDOM_REQUIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID
// and CKR_USER_NOT_LOGGED_IN: it offers no "length too large" code, so the
// choice is between a code in that table and generating the whole amount.
// CKR_ARGUMENTS_BAD is the one section 5.1 defines as "the arguments supplied
// to the Cryptoki function were in some way not appropriate", and it is the
// honest answer to a length this entry point cannot carry: the module's own
// GenerateRandom takes a uint32, and cBytes already fixes math.MaxInt32 as
// the largest buffer this library moves across the C ABI in one call.
// CKR_HOST_MEMORY and CKR_DEVICE_MEMORY are in the table but would both be
// untrue, since nothing was allocated and no allocation was attempted.
//
// What must not happen is the third option. Without this check the conversion
// to uint32 silently reduced the request modulo 2^32 -- it can only shrink, so
// there was never a buffer overrun -- and the module filled that many bytes
// and returned CKR_OK. A caller asking for more than 4 GiB got a prefix of its
// buffer filled, the tail left as whatever the heap held, and no indication
// that anything was short. An application drawing key material from the tail
// would be drawing uninitialized memory under a success return, so a partially
// filled buffer is never reported as success.
//
//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pRandomData == nil && ulRandomLen > 0 {
		return C.CKR_ARGUMENTS_BAD
	}
	if ulRandomLen > C.CK_ULONG(math.MaxInt32) {
		return C.CKR_ARGUMENTS_BAD
	}

	data, mrv := module.GetGlobalModule().GenerateRandom(module.SessionHandle(hSession), uint32(ulRandomLen))
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
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
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	// The guard is redundant for today's constant return, but every one of the
	// 92 Cryptoki entry points carries it unconditionally. Dropping it here
	// would make this the one //export that silently loses panic protection the
	// moment its body grows past a constant, and a panic crossing cgo aborts
	// the host process rather than returning a CK_RV.
	defer recoverCKRV(&rv) //nolint:gocritic // uniform cgo panic guard, see above
	// Legacy function - always return CKR_FUNCTION_NOT_PARALLEL
	return C.CKR_FUNCTION_NOT_PARALLEL
}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	// See C_GetFunctionStatus above: the recover guard is uniform across every
	// Cryptoki entry point by design.
	defer recoverCKRV(&rv) //nolint:gocritic // uniform cgo panic guard, see above
	// Legacy function - always return CKR_FUNCTION_NOT_PARALLEL
	return C.CKR_FUNCTION_NOT_PARALLEL
}

// ============================================================================
// Slot Event Functions
// ============================================================================

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pReserved != nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// This module's slots are fixed at C_Initialize, so no slot event can ever
	// occur. PKCS#11 v3.2 §5.5.9 allows CKR_NO_EVENT only when CKF_DONT_BLOCK is
	// set -- it is the answer to a poll, not to a wait. A blocking call that can
	// never be satisfied is refused instead: returning CKR_NO_EVENT immediately
	// turned a monitoring thread's blocking wait into a spin at full CPU.
	if flags&C.CKF_DONT_BLOCK == 0 {
		return C.CKR_FUNCTION_NOT_SUPPORTED
	}

	return C.CKR_NO_EVENT
}

// ============================================================================
// PKCS#11 v3.0 Session Functions
// ============================================================================

//export C_LoginUser
func C_LoginUser(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pUsername C.CK_UTF8CHAR_PTR, ulUsernameLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.0 context-specific login with username
	pin, ok := cBytes(unsafe.Pointer(pPin), ulPinLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}
	var username string
	if pUsername != nil && ulUsernameLen > 0 {
		if ulUsernameLen > C.CK_ULONG(math.MaxInt32) {
			return C.CKR_ARGUMENTS_BAD
		}
		username = C.GoStringN((*C.char)(unsafe.Pointer(pUsername)), C.int(ulUsernameLen))
	}
	mrv := module.GetGlobalModule().LoginUser(module.SessionHandle(hSession), module.UserType(userType), pin, username)
	return C.CK_RV(mrv)
}

//export C_SessionCancel
func C_SessionCancel(hSession C.CK_SESSION_HANDLE, flags C.CK_FLAGS) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	// PKCS#11 v3.0 session operation cancellation
	mrv := module.GetGlobalModule().SessionCancel(module.SessionHandle(hSession), uint64(flags))
	return C.CK_RV(mrv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Encryption Functions
// ============================================================================

//export C_MessageEncryptInit
func C_MessageEncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.9.1: "C_MessageEncryptInit can be called with pMechanism
	// set to NULL_PTR to terminate a message-based encryption process. If a
	// multi-part message encryption operation is active, it will also be
	// terminated." Both live in the session's single encryption slot, so ending
	// that category satisfies the whole sentence.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationEncrypt))
	}
	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	mrv := module.GetGlobalModule().MessageEncryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

// gcmMessageParams reads a CK_GCM_MESSAGE_PARAMS out of the message functions'
// pParameter.
//
// The message-based AEAD functions carry their IV and authentication tag here
// rather than on the Init, because C_MessageEncryptInit binds a mechanism and
// key that outlive any one message (PKCS#11 v3.2 §5.9.1, §6.13.5). These
// arguments used to be accepted and then ignored, which made the round trip
// impossible: with a token-generated IV the caller had no way to learn it.
//
// A NULL pParameter is not an error — a caller using a non-AEAD mechanism has
// nothing to pass — so it yields a nil result and the module falls back to the
// mechanism's own parameters.
// rejectSignMessageParam refuses a per-message sign/verify parameter the module
// cannot honour. No signature mechanism this module implements takes one:
// RSA, ECDSA and EdDSA message signing are parameterless, and ML-DSA's optional
// CK_SIGN_ADDITIONAL_CONTEXT (a non-empty domain-separation context) is not
// implemented — the module only does the empty-context "pure" form. A non-NULL
// parameter is therefore a request for behaviour the token does not provide, so
// it is refused with CKR_MECHANISM_PARAM_INVALID rather than silently ignored,
// which would return a signature made under a different (empty) context than the
// caller asked for. A NULL/empty parameter is the parameterless case and passes.
func rejectSignMessageParam(pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV {
	if pParameter != nil && ulParameterLen != 0 {
		return C.CKR_MECHANISM_PARAM_INVALID
	}
	return C.CKR_OK
}

func gcmMessageParams(pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) (*module.AESGCMMessageParams, bool) {
	if pParameter == nil {
		return nil, true
	}
	if ulParameterLen < C.CK_ULONG(unsafe.Sizeof(C.CK_GCM_MESSAGE_PARAMS{})) {
		return nil, false
	}

	raw := (*C.CK_GCM_MESSAGE_PARAMS)(unsafe.Pointer(pParameter))

	iv, ok := cBytes(unsafe.Pointer(raw.pIv), raw.ulIvLen)
	if !ok {
		return nil, false
	}

	// The tag buffer's length comes from ulTagBits: unlike the IV there is no
	// separate byte count, and pTag is an output on encrypt.
	tagBytes := C.CK_ULONG(raw.ulTagBits / 8)
	tag, ok := cBytes(unsafe.Pointer(raw.pTag), tagBytes)
	if !ok {
		return nil, false
	}

	return &module.AESGCMMessageParams{
		IV:          iv,
		IVFixedBits: uint32(raw.ulIvFixedBits),
		IVGenerator: module.IVGenerator(raw.ivGenerator),
		Tag:         tag,
		TagBits:     uint32(raw.ulTagBits),
	}, true
}

// writeGCMMessageParams copies the IV and authentication tag the token produced
// back into the caller's CK_GCM_MESSAGE_PARAMS.
//
// Both pIv and pTag are outputs of C_EncryptMessage (v3.2 §6.13.5). The caller
// owns those buffers and told us their sizes, so a value that does not fit is
// reported rather than truncated — a half-written IV or tag would produce
// ciphertext nobody can ever decrypt.
func writeGCMMessageParams(pParameter C.CK_VOID_PTR, params *module.AESGCMMessageParams) C.CK_RV {
	if pParameter == nil || params == nil {
		return C.CKR_OK
	}

	raw := (*C.CK_GCM_MESSAGE_PARAMS)(unsafe.Pointer(pParameter))

	if len(params.IV) > 0 && raw.pIv != nil {
		if C.CK_ULONG(len(params.IV)) > raw.ulIvLen {
			return C.CKR_MECHANISM_PARAM_INVALID
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(raw.pIv)), len(params.IV)), params.IV)
		raw.ulIvLen = C.CK_ULONG(len(params.IV))
	}

	if len(params.Tag) > 0 && raw.pTag != nil {
		if C.CK_ULONG(len(params.Tag)*8) > raw.ulTagBits {
			return C.CKR_MECHANISM_PARAM_INVALID
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(raw.pTag)), len(params.Tag)), params.Tag)
		raw.ulTagBits = C.CK_ULONG(len(params.Tag) * 8)
	}

	return C.CKR_OK
}

//export C_EncryptMessage
func C_EncryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, ulPlaintextLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, pulCiphertextLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulCiphertextLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert associated data
	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert plaintext
	plaintext, ok := cBytes(unsafe.Pointer(pPlaintext), ulPlaintextLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	ciphertext, mrv := module.GetGlobalModule().EncryptMessage(module.SessionHandle(hSession), params, aad, plaintext)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	if wrv := writeGCMMessageParams(pParameter, params); wrv != C.CKR_OK {
		return wrv
	}

	// Two-call pattern: first call returns required size.
	//
	// The probe must release the result exactly as the copying call below does.
	// Module.EncryptMessage runs the real encryption before it can report a
	// length, and that leaves the underlying EncryptOperation finalized; unlike
	// C_EncryptMessageNext it caches nothing, so there is no replay to fall back
	// on. Returning here without ReleaseOperationResult -- which is what rearms
	// the operation, via CryptoOperation.Reset -- left the operation finalized
	// and the second call, the one PKCS#11 v3.2 §5.2 says every application
	// makes after a NULL-buffer probe, was refused with
	// CKR_OPERATION_NOT_INITIALIZED. The message process then tore down on the
	// next C_DecryptMessage. The release must not finalize the operation:
	// C_MessageEncryptInit stays live until C_MessageEncryptFinal (v3.2 §5.9.1).
	if pCiphertext == nil {
		*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
		return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationEncrypt))
	}

	// Check buffer size. PKCS#11 v3.2 §5.2 gives CKR_BUFFER_TOO_SMALL the same
	// standing as the NULL-buffer probe -- the operation survives so the caller
	// can retry with a larger buffer -- so this leg releases the result for the
	// reason the probe above does. Returning without it made an undersized
	// buffer unrecoverable rather than merely refused.
	if C.CK_ULONG(len(ciphertext)) > *pulCiphertextLen {
		*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
		if rrv := module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationEncrypt); rrv != module.CKR_OK {
			return C.CK_RV(rrv)
		}
		return C.CKR_BUFFER_TOO_SMALL
	}

	// Copy ciphertext
	*pulCiphertextLen = C.CK_ULONG(len(ciphertext))
	if len(ciphertext) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pCiphertext)), len(ciphertext)), ciphertext)
	}

	// Drop the cached result so the NEXT message encrypts its own plaintext.
	// C_MessageEncryptInit stays live until C_MessageEncryptFinal (v3.2
	// §5.9.1), which is the entire reason to use the message-based functions
	// rather than C_EncryptInit; the underlying operation is the one C_Encrypt
	// uses and marks itself finished, so without this release the second
	// C_EncryptMessage under one initialization is refused with
	// CKR_OPERATION_NOT_INITIALIZED. This must not finalize the operation,
	// which is what distinguishes it from C_Encrypt's FinishOperation.
	return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
		module.SessionHandle(hSession), module.OperationEncrypt))
}

//export C_EncryptMessageBegin
func C_EncryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// Convert associated data
	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// The message parameter (CK_GCM_MESSAGE_PARAMS) is supplied to Begin as well
	// as to every Next; decode and forward it so a caller-supplied IV governs
	// the whole message and a malformed parameter is refused at the start. A
	// token-generated IV is produced when the last part is encrypted, so its
	// write-back stays on the final C_EncryptMessageNext, not here.
	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	mrv := module.GetGlobalModule().EncryptMessageBegin(module.SessionHandle(hSession), params, aad)
	return C.CK_RV(mrv)
}

//export C_EncryptMessageNext
func C_EncryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, ulPlaintextPartLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, pulCiphertextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulCiphertextPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert plaintext
	plaintext, ok := cBytes(unsafe.Pointer(pPlaintextPart), ulPlaintextPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// CKF_END_OF_MESSAGE indicates the final chunk in a multi-part message operation
	final := (flags & C.CKF_END_OF_MESSAGE) != 0

	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	// A NULL output buffer is the §5.2 length query. On a non-final part the
	// answer is always zero, because a non-final part produces no ciphertext --
	// and the part must NOT be handed over here, since EncryptMessageNext
	// buffers it and the caller's retry with a real buffer would buffer it a
	// second time, encrypting the same plaintext twice. The call is still made
	// with no data so the operation's state is still validated.
	//
	// The final part falls through instead: it does produce output, and the
	// module caches that output so the retry replays it rather than re-running
	// the encryption.
	if pCiphertextPart == nil && !final {
		if _, mrv := module.GetGlobalModule().EncryptMessageNext(
			module.SessionHandle(hSession), params, nil, false); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulCiphertextPartLen = 0
		return C.CKR_OK
	}

	ciphertext, mrv := module.GetGlobalModule().EncryptMessageNext(module.SessionHandle(hSession), params, plaintext, final)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// The IV and tag are only settled once the last part has been processed,
	// so the write-back happens here rather than on every part.
	if final {
		if wrv := writeGCMMessageParams(pParameter, params); wrv != C.CKR_OK {
			return wrv
		}
	}

	// Two-call pattern
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
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pCiphertextPart)), len(ciphertext)), ciphertext)
	}

	// Only the last part produces a cached result, and only it needs releasing
	// so the next message encrypts its own plaintext. The message operation
	// itself lives until C_MessageEncryptFinal, so this must not finalize.
	if final {
		return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationEncrypt))
	}

	return C.CKR_OK
}

//export C_MessageEncryptFinal
func C_MessageEncryptFinal(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().MessageEncryptFinal(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Decryption Functions
// ============================================================================

//export C_MessageDecryptInit
func C_MessageDecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.11.1 lists CKR_OPERATION_CANCEL_FAILED among
	// C_MessageDecryptInit's return values, which is only reachable through the
	// NULL pMechanism cancellation its sibling C_MessageEncryptInit spells out.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationDecrypt))
	}
	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	mrv := module.GetGlobalModule().MessageDecryptInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_DecryptMessage
func C_DecryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, ulCiphertextLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, pulPlaintextLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulPlaintextLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert associated data
	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert ciphertext
	ciphertext, ok := cBytes(unsafe.Pointer(pCiphertext), ulCiphertextLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	plaintext, mrv := module.GetGlobalModule().DecryptMessage(module.SessionHandle(hSession), params, aad, ciphertext)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// Two-call pattern. Both non-copying legs release the result, for the reason
	// C_EncryptMessage's probe does: Module.DecryptMessage caches nothing, so
	// the decryption the probe just ran leaves the operation finalized and only
	// ReleaseOperationResult rearms it. Without this the second call PKCS#11
	// v3.2 §5.2 promises the application -- and the retry after
	// CKR_BUFFER_TOO_SMALL -- returned CKR_OPERATION_NOT_INITIALIZED, which the
	// module then treated as reason to finalize the whole message process.
	if pPlaintext == nil {
		*pulPlaintextLen = C.CK_ULONG(len(plaintext))
		return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationDecrypt))
	}

	if C.CK_ULONG(len(plaintext)) > *pulPlaintextLen {
		*pulPlaintextLen = C.CK_ULONG(len(plaintext))
		if rrv := module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationDecrypt); rrv != module.CKR_OK {
			return C.CK_RV(rrv)
		}
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pulPlaintextLen = C.CK_ULONG(len(plaintext))
	if len(plaintext) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pPlaintext)), len(plaintext)), plaintext)
	}

	// Drop the cached result so the next message decrypts its own ciphertext.
	// See C_EncryptMessage for why this releases the result rather than
	// finalizing the operation C_MessageDecryptInit established.
	return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
		module.SessionHandle(hSession), module.OperationDecrypt))
}

//export C_DecryptMessageBegin
func C_DecryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// Convert associated data
	aad, ok := cBytes(unsafe.Pointer(pAssociatedData), ulAssociatedDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// For decryption the message parameter is always an input IV; decode and
	// forward it so it is established at the start of the message and an absent
	// or malformed parameter is refused here rather than at the first part.
	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	mrv := module.GetGlobalModule().DecryptMessageBegin(module.SessionHandle(hSession), params, aad)
	return C.CK_RV(mrv)
}

//export C_DecryptMessageNext
func C_DecryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, ulCiphertextPartLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, pulPlaintextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if pulPlaintextPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert ciphertext
	ciphertext, ok := cBytes(unsafe.Pointer(pCiphertextPart), ulCiphertextPartLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// CKF_END_OF_MESSAGE indicates the final chunk in a multi-part message operation
	final := (flags & C.CKF_END_OF_MESSAGE) != 0

	params, ok := gcmMessageParams(pParameter, ulParameterLen)
	if !ok {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	// A NULL output buffer is the §5.2 length query, answered as zero on a
	// non-final part for the reason C_EncryptMessageNext gives: a non-final part
	// yields no plaintext, and handing the part over here would buffer it a
	// second time when the caller retries with a real buffer. The final part
	// falls through, since it produces output the module caches for the retry.
	if pPlaintextPart == nil && !final {
		if _, mrv := module.GetGlobalModule().DecryptMessageNext(
			module.SessionHandle(hSession), params, nil, false); mrv != module.CKR_OK {
			return C.CK_RV(mrv)
		}
		*pulPlaintextPartLen = 0
		return C.CKR_OK
	}

	plaintext, mrv := module.GetGlobalModule().DecryptMessageNext(module.SessionHandle(hSession), params, ciphertext, final)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// Two-call pattern
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
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pPlaintextPart)), len(plaintext)), plaintext)
	}

	// Only the last part caches a result. Releasing it also wipes the cached
	// plaintext, which matters more here than on the encrypt side.
	if final {
		return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
			module.SessionHandle(hSession), module.OperationDecrypt))
	}

	return C.CKR_OK
}

//export C_MessageDecryptFinal
func C_MessageDecryptFinal(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().MessageDecryptFinal(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Signing Functions
// ============================================================================

//export C_MessageSignInit
func C_MessageSignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.14.1 omits the NULL pMechanism sentence its three sibling
	// message-based initializers carry. The omission is editorial: the four are
	// defined in parallel, and a caller has no way to know that message-based
	// signing alone refuses the cancellation the others accept.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationSign))
	}
	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	mrv := module.GetGlobalModule().MessageSignInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_SignMessage
func C_SignMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}

	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert data
	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	signature, mrv := module.GetGlobalModule().SignMessage(module.SessionHandle(hSession), data)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// Two-call pattern
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
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pSignature)), len(signature)), signature)
	}

	// The signing operation is shared with C_Sign, which caches its result so a
	// length query can be answered without signing twice. Releasing the cache
	// here is what makes the NEXT message sign its own data: without it the
	// cached signature is returned again under CKR_OK, so a loop over several
	// messages silently receives the first message's signature every time.
	// Unlike C_Sign this must not finalize the operation — C_MessageSignInit
	// stays live until C_MessageSignFinal.
	return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
		module.SessionHandle(hSession), module.OperationSign))
}

//export C_SignMessageBegin
func C_SignMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}
	mrv := module.GetGlobalModule().SignMessageBegin(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

//export C_SignMessageNext
func C_SignMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}

	// Convert data
	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// For SignMessageNext, signature is only returned on final call
	// Check if pulSignatureLen is non-nil to determine if this is final
	if pulSignatureLen == nil {
		// Non-final call - just update with data
		_, mrv := module.GetGlobalModule().SignMessageNext(module.SessionHandle(hSession), data, false)
		return C.CK_RV(mrv)
	}

	// Final call - get signature
	signature, mrv := module.GetGlobalModule().SignMessageNext(module.SessionHandle(hSession), data, true)
	if mrv != module.CKR_OK {
		return C.CK_RV(mrv)
	}

	// Two-call pattern
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
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pSignature)), len(signature)), signature)
	}

	// Drop the cached signature so the next message signs its own data. See
	// C_SignMessage for why this releases the result rather than finalizing the
	// operation.
	return C.CK_RV(module.GetGlobalModule().ReleaseOperationResult(
		module.SessionHandle(hSession), module.OperationSign))
}

//export C_MessageSignFinal
func C_MessageSignFinal(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().MessageSignFinal(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// PKCS#11 v3.0 Message-based Verification Functions
// ============================================================================

//export C_MessageVerifyInit
func C_MessageVerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	// PKCS#11 v3.2 §5.16.1 omits the NULL pMechanism sentence its three sibling
	// message-based initializers carry, for the same editorial reason noted on
	// C_MessageSignInit.
	if pMechanism == nil {
		return C.CK_RV(terminateInitOperation(module.SessionHandle(hSession), module.OperationVerify))
	}
	mech, paramRV := convertCMechanismToGo(pMechanism)
	if paramRV != C.CKR_OK {
		return paramRV
	}
	mrv := module.GetGlobalModule().MessageVerifyInit(module.SessionHandle(hSession), mech, module.ObjectHandle(hKey))
	return C.CK_RV(mrv)
}

//export C_VerifyMessage
func C_VerifyMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}

	// Convert data
	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Convert signature
	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().VerifyMessage(module.SessionHandle(hSession), data, signature)
	return C.CK_RV(mrv)
}

//export C_VerifyMessageBegin
func C_VerifyMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}
	mrv := module.GetGlobalModule().VerifyMessageBegin(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

//export C_VerifyMessageNext
func C_VerifyMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) (rv C.CK_RV) {
	defer recoverCKRV(&rv)

	if crv := rejectSignMessageParam(pParameter, ulParameterLen); crv != C.CKR_OK {
		return crv
	}

	// Convert data
	data, ok := cBytes(unsafe.Pointer(pData), ulDataLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	// Finality is decided by pSignature being non-NULL, not by ulSignatureLen:
	// a non-NULL pointer with a zero length is still the final call and must run
	// the verification (which then rejects the empty signature), while a NULL
	// pointer means another message follows. Deciding on length instead would
	// treat a zero-length final signature as a continuation and leave the
	// operation open.
	final := pSignature != nil
	signature, ok := cBytes(unsafe.Pointer(pSignature), ulSignatureLen)
	if !ok {
		return C.CKR_ARGUMENTS_BAD
	}

	mrv := module.GetGlobalModule().VerifyMessageNext(module.SessionHandle(hSession), data, signature, final)
	return C.CK_RV(mrv)
}

//export C_MessageVerifyFinal
func C_MessageVerifyFinal(hSession C.CK_SESSION_HANDLE) (rv C.CK_RV) {
	defer recoverCKRV(&rv)
	mrv := module.GetGlobalModule().MessageVerifyFinal(module.SessionHandle(hSession))
	return C.CK_RV(mrv)
}

// ============================================================================
// Helper Functions for Type Conversion
// ============================================================================

// attributeArrayElemSize is sizeof(CK_ATTRIBUTE) as the application that loaded
// this library sees it. It is the unit in which the ulValueLen of a nested
// template attribute is expressed: PKCS#11 v3.2 §3.4 defines the value of
// CKA_WRAP_TEMPLATE and its siblings as "an array of CK_ATTRIBUTE" whose
// ulValueLen is the length of that array in bytes, so the element count is
// ulValueLen divided by this size.
const attributeArrayElemSize = C.CK_ULONG(C.sizeof_CK_ATTRIBUTE)

// readCAttributeArray reads a caller-supplied CK_ATTRIBUTE array — the value of
// a nested template attribute — into Go attributes.
//
// Every field is validated before anything is dereferenced, because the array
// and each element's buffer belong to the application: ulValueLen must be a
// whole number of CK_ATTRIBUTE, the element count must be addressable as a Go
// slice index, and each element's own ulValueLen goes through cBytes, which
// refuses a length beyond that range. An element carrying
// CK_UNAVAILABLE_INFORMATION, which is how a token reports a value it did not
// supply, is refused by that same bound rather than read as a length.
//
// ok=false means the array is malformed and the request must be rejected; a
// value the boundary cannot parse must never reach the token as if it had been
// understood.
func readCAttributeArray(pValue C.CK_VOID_PTR, ulValueLen C.CK_ULONG) (nested []module.Attribute, ok bool) {
	if ulValueLen == 0 {
		return nil, true
	}
	if ulValueLen%attributeArrayElemSize != 0 {
		return nil, false
	}

	count := ulValueLen / attributeArrayElemSize
	if count > C.CK_ULONG(math.MaxInt32) {
		return nil, false
	}

	elements := unsafe.Slice((C.CK_ATTRIBUTE_PTR)(unsafe.Pointer(pValue)), count)
	nested = make([]module.Attribute, count)

	for i := C.CK_ULONG(0); i < count; i++ {
		element := elements[i]
		nested[i] = module.Attribute{Type: module.AttributeType(element._type)}

		if element.pValue == nil || element.ulValueLen == 0 {
			continue
		}
		value, valueOK := cBytes(unsafe.Pointer(element.pValue), element.ulValueLen)
		if !valueOK {
			return nil, false
		}
		nested[i].Value = value
	}

	return nested, true
}

// writeCAttributeArray expands a flattened nested template back into the
// caller's CK_ATTRIBUTE array, and reports whether any part of it did not fit.
//
// The two-call convention of PKCS#11 v3.2 §5.2 applies at both levels. A NULL
// pValue is a length query and is answered with the size of the array the
// expanded C form needs — count × sizeof(CK_ATTRIBUTE) — never with the size of
// the flat encoding the token stores, which is an internal representation no
// application can allocate against. Once the application has allocated that
// array, each element is a length query in its own right: an element with a
// NULL pValue receives its type and the length of its value, and an element
// with a buffer large enough receives the value itself.
//
// A value the token holds but cannot decode is reported as
// CK_UNAVAILABLE_INFORMATION, which §5.7.5 defines for an attribute whose value
// could not be supplied. It is not a buffer-size failure and so does not raise
// CKR_BUFFER_TOO_SMALL; the object layer validates every template attribute
// before storing it, so this describes a corrupt store rather than a caller
// error.
func writeCAttributeArray(cAttr *C.CK_ATTRIBUTE, encoded []byte) (bufferTooSmall bool) {
	nested, err := module.DecodeAttributeArray(encoded)
	if err != nil {
		cAttr.ulValueLen = ^C.CK_ULONG(0)
		return false
	}

	required := C.CK_ULONG(len(nested)) * attributeArrayElemSize

	if cAttr.pValue == nil {
		cAttr.ulValueLen = required
		return false
	}
	if cAttr.ulValueLen < required {
		cAttr.ulValueLen = ^C.CK_ULONG(0)
		return true
	}

	elements := unsafe.Slice((C.CK_ATTRIBUTE_PTR)(unsafe.Pointer(cAttr.pValue)), len(nested))
	for i := range nested {
		element := &elements[i]
		element._type = C.CK_ATTRIBUTE_TYPE(nested[i].Type)

		switch {
		case element.pValue == nil:
			element.ulValueLen = C.CK_ULONG(len(nested[i].Value))
		case element.ulValueLen >= C.CK_ULONG(len(nested[i].Value)):
			if len(nested[i].Value) > 0 {
				C.memcpy(unsafe.Pointer(element.pValue), unsafe.Pointer(&nested[i].Value[0]), C.size_t(len(nested[i].Value)))
			}
			element.ulValueLen = C.CK_ULONG(len(nested[i].Value))
		default:
			element.ulValueLen = ^C.CK_ULONG(0)
			bufferTooSmall = true
		}
	}

	cAttr.ulValueLen = required
	return bufferTooSmall
}

// convertCTemplateToGo converts a C attribute template to Go attributes. It
// returns ok=false when ulCount, or any single attribute's ulValueLen,
// exceeds the addressable range of a Go slice index, in which case the
// caller must reject the request rather than risk a panic inside
// unsafe.Slice or cgo's GoBytes.
//
// An attribute whose value is itself an array of CK_ATTRIBUTE
// (module.IsAttributeArrayType) is flattened with module.EncodeAttributeArray
// rather than copied as raw bytes. The token stores objects on the far side of
// a transport from the application, where the pointers inside a CK_ATTRIBUTE
// address nothing and the buffers they name no longer exist once the call
// returns, so the flat encoding is the only form in which a nested template can
// be carried. Copying the raw bytes of the array instead meant no C
// application could set a wrap, unwrap or derive template at all: the value
// reached the object layer as a pointer-bearing structure it correctly refused
// with CKR_ATTRIBUTE_VALUE_INVALID.
// requestedAttributes converts a C_GetAttributeValue template into the list of
// attributes to ask the module for, reading only each entry's type.
//
// It exists because that template is not an input template. On the second call
// of the §5.2 two-call sequence every pValue is a buffer the application just
// allocated to RECEIVE a value, and its contents are undefined. Running it
// through convertCTemplateToGo copied that uninitialized heap into the request
// as "the value of CKA_VALUE", and for a nested-template attribute
// (CKA_WRAP_TEMPLATE and its siblings) parsed it as a CK_ATTRIBUTE array --
// so an application that merely over-allocated the buffer, to a size that was
// not a whole multiple of sizeof(CK_ATTRIBUTE), had its entire read refused
// with CKR_ARGUMENTS_BAD.
func requestedAttributes(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (attrs []module.Attribute, ok bool) {
	if pTemplate == nil || ulCount == 0 {
		return nil, true
	}
	if ulCount > C.CK_ULONG(math.MaxInt32) {
		return nil, false
	}

	attrs = make([]module.Attribute, ulCount)
	templateArray := unsafe.Slice(pTemplate, ulCount)
	for i := C.CK_ULONG(0); i < ulCount; i++ {
		attrs[i] = module.Attribute{Type: module.AttributeType(templateArray[i]._type)}
	}

	return attrs, true
}

func convertCTemplateToGo(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (attrs []module.Attribute, ok bool) {
	if pTemplate == nil || ulCount == 0 {
		return nil, true
	}
	if ulCount > C.CK_ULONG(math.MaxInt32) {
		return nil, false
	}

	attrs = make([]module.Attribute, ulCount)
	templateArray := unsafe.Slice(pTemplate, ulCount)

	for i := C.CK_ULONG(0); i < ulCount; i++ {
		cAttr := templateArray[i]
		attrs[i] = module.Attribute{
			Type: module.AttributeType(cAttr._type),
		}
		if cAttr.pValue == nil {
			continue
		}

		if module.IsAttributeArrayType(attrs[i].Type) {
			nested, nestedOK := readCAttributeArray(cAttr.pValue, cAttr.ulValueLen)
			if !nestedOK {
				return nil, false
			}
			attrs[i].Value = module.EncodeAttributeArray(nested)
			continue
		}

		if cAttr.ulValueLen > 0 {
			value, valueOK := cBytes(unsafe.Pointer(cAttr.pValue), cAttr.ulValueLen)
			if !valueOK {
				return nil, false
			}
			attrs[i].Value = value
		}
	}

	return attrs, true
}

// copyGoTemplateToCTemplate copies Go attributes back into a caller's C
// template. It reports whether any attribute could not be copied because the
// caller's buffer was too short, which the caller must surface as
// CKR_BUFFER_TOO_SMALL. It is a no-op when ulCount exceeds the addressable
// range of a Go slice index; callers are expected to have already validated
// ulCount (e.g. via convertCTemplateToGo) before requesting a copy back.
//
// An attribute whose value is a nested template is expanded back into a real
// CK_ATTRIBUTE array by writeCAttributeArray, so what an application reads out
// of C_GetAttributeValue is the same structure it wrote in and never the flat
// encoding the token stores it as.
func copyGoTemplateToCTemplate(attrs []module.Attribute, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) bool {
	if pTemplate == nil || ulCount == 0 || len(attrs) == 0 {
		return false
	}
	if ulCount > C.CK_ULONG(math.MaxInt32) {
		return false
	}

	bufferTooSmall := false

	templateArray := unsafe.Slice(pTemplate, ulCount)

	for i := 0; i < len(attrs) && i < int(ulCount); i++ {
		cAttr := &templateArray[i]

		if attrs[i].Unavailable {
			// Per PKCS#11 spec section 5.7.5: an attribute the token could
			// not reveal (sensitive, unextractable, or invalid for the
			// object) is reported by setting ulValueLen to
			// CK_UNAVAILABLE_INFORMATION and copying nothing.
			cAttr.ulValueLen = ^C.CK_ULONG(0)
			continue
		}

		if module.IsAttributeArrayType(attrs[i].Type) {
			if writeCAttributeArray(cAttr, attrs[i].Value) {
				bufferTooSmall = true
			}
			continue
		}

		switch {
		case cAttr.pValue == nil:
			// Query mode - just set the length
			cAttr.ulValueLen = C.CK_ULONG(len(attrs[i].Value))
		case cAttr.ulValueLen >= C.CK_ULONG(len(attrs[i].Value)):
			// Copy the value
			if len(attrs[i].Value) > 0 {
				C.memcpy(unsafe.Pointer(cAttr.pValue), unsafe.Pointer(&attrs[i].Value[0]), C.size_t(len(attrs[i].Value)))
			}
			cAttr.ulValueLen = C.CK_ULONG(len(attrs[i].Value))
		default:
			// Buffer too small - per PKCS#11 spec, report
			// CK_UNAVAILABLE_INFORMATION and let the caller return
			// CKR_BUFFER_TOO_SMALL.
			cAttr.ulValueLen = ^C.CK_ULONG(0)
			bufferTooSmall = true
		}
	}

	return bufferTooSmall
}

// mechanismParameterDecoders maps every mechanism this module implements whose
// CK_MECHANISM parameter is a fixed-layout C structure to that structure's size
// and reader.
//
// It is the single place the boundary learns how long a mechanism's parameter
// has to be, which is what makes each decoder's pointer cast safe: a caller
// that declares a shorter ulParameterLen is refused by
// checkMechanismParameter before any decoder runs, instead of having the full
// structure read out of the short buffer it owns.
//
// A mechanism absent from this map takes no structured parameter; its raw
// bytes still reach Mechanism.Parameter and the module layer decides what to
// do with them.
var mechanismParameterDecoders = map[module.MechanismType]*mechanismParameterDecoder{
	// CK_ECDH1_DERIVE_PARAMS (PKCS#11 v3.2 section 6.3.16).
	module.CKM_ECDH1_DERIVE: {
		StructSize: unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}),
		Decode:     decodeECDH1DeriveParams,
	},
	module.CKM_ECDH1_COFACTOR_DERIVE: {
		StructSize: unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}),
		Decode:     decodeECDH1DeriveParams,
	},

	// CK_RSA_PKCS_PSS_PARAMS (PKCS#11 v3.2 section 6.1.9). Without the
	// decoder the typed parameter stays nil and SignInit rejects every PSS
	// request as having invalid parameters, so PSS is unusable through the C
	// ABI even though the Go layer implements it.
	module.CKM_RSA_PKCS_PSS: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		Decode:     decodeRSAPSSParams,
	},
	module.CKM_SHA1_RSA_PKCS_PSS: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		Decode:     decodeRSAPSSParams,
	},
	module.CKM_SHA256_RSA_PKCS_PSS: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		Decode:     decodeRSAPSSParams,
	},
	module.CKM_SHA384_RSA_PKCS_PSS: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		Decode:     decodeRSAPSSParams,
	},
	module.CKM_SHA512_RSA_PKCS_PSS: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		Decode:     decodeRSAPSSParams,
	},

	// CK_RSA_PKCS_OAEP_PARAMS (PKCS#11 v3.2 section 6.1.7), which carries
	// the OAEP digest, mask generation function and optional label.
	// Required: the mechanism has no meaning without them, and defaulting
	// them encrypts under a digest the caller never chose -- a failure that
	// only shows up at the peer, as ciphertext nobody can decrypt.
	module.CKM_RSA_PKCS_OAEP: {
		StructSize: unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}),
		Required:   true,
		Decode:     decodeRSAOAEPParams,
	},

	// CK_GCM_PARAMS (PKCS#11 v3.2 section 6.13.7).
	module.CKM_AES_GCM: {
		StructSize: unsafe.Sizeof(C.CK_GCM_PARAMS{}),
		Decode:     decodeGCMParams,
	},

	// CK_HKDF_PARAMS (PKCS#11 v3.2 section 6.62.2). Without the decoder the
	// derive layer has no salt, info or PRF hash to work with and previously
	// fabricated all three, silently deriving under a hardcoded
	// SHA-256/no-salt/no-info HKDF regardless of what the caller asked for.
	module.CKM_HKDF_DERIVE: {
		StructSize: unsafe.Sizeof(C.CK_HKDF_PARAMS{}),
		Decode:     decodeHKDFParams,
	},
	module.CKM_HKDF_DATA: {
		StructSize: unsafe.Sizeof(C.CK_HKDF_PARAMS{}),
		Decode:     decodeHKDFParams,
	},

	// CK_SP800_108_KDF_PARAMS (PKCS#11 v3.2 section 6.42.2).
	module.CKM_SP800_108_COUNTER_KDF: {
		StructSize: unsafe.Sizeof(C.CK_SP800_108_KDF_PARAMS{}),
		Decode:     decodeSP800108KDFParams,
	},
	module.CKM_SP800_108_DOUBLE_PIPELINE_KDF: {
		StructSize: unsafe.Sizeof(C.CK_SP800_108_KDF_PARAMS{}),
		Decode:     decodeSP800108KDFParams,
	},

	// CK_SP800_108_FEEDBACK_KDF_PARAMS (PKCS#11 v3.2 section 6.42.2), which
	// additionally carries the feedback-mode IV.
	module.CKM_SP800_108_FEEDBACK_KDF: {
		StructSize: unsafe.Sizeof(C.CK_SP800_108_FEEDBACK_KDF_PARAMS{}),
		Decode:     decodeSP800108FeedbackKDFParams,
	},

	// CK_EDDSA_PARAMS (PKCS#11 v3.2 section 6.3.16). Its presence at all
	// selects one of Ed25519ctx, Ed25519ph, Ed448 or Ed448ph (section 6.3.14,
	// Table 73) -- never the pure scheme, not even with phFlag false and no
	// context data, because Ed25519ctx prefixes the dom2 separator that pure
	// Ed25519 omits. An absent parameter is what means pure Ed25519/Ed448,
	// which is why it is not Required.
	//
	// Unsupported: phFlag and pContextData reach CryptoManager.Sign, which
	// puts them on transport.SignRequest, but no wire format carries them.
	// The protobuf SignRequest and VerifyRequest have no field for either, so
	// the gRPC and Unix-socket transports this shared library speaks drop both
	// and the daemon signs pure Ed25519. See mechanismParameterDecoder.
	// Unsupported for why that is refused rather than performed.
	module.CKM_EDDSA: {
		StructSize:  unsafe.Sizeof(C.CK_EDDSA_PARAMS{}),
		Unsupported: true,
		Decode:      decodeEdDSAParams,
	},
}

// decodeECDH1DeriveParams reads CK_ECDH1_DERIVE_PARAMS (v3.2 section 6.3.16).
func decodeECDH1DeriveParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_ECDH1_DERIVE_PARAMS)(pParameter)
	params := &module.ECDHParams{
		KDF: module.KDFType(cParams.kdf),
	}
	sharedData, ok := cBytes(unsafe.Pointer(cParams.pSharedData), cParams.ulSharedDataLen)
	if !ok {
		return nil, false
	}
	params.SharedData = sharedData
	publicData, ok := cBytes(unsafe.Pointer(cParams.pPublicData), cParams.ulPublicDataLen)
	if !ok {
		return nil, false
	}
	params.PublicData = publicData
	return params, true
}

// decodeRSAPSSParams reads CK_RSA_PKCS_PSS_PARAMS (v3.2 section 6.1.9).
func decodeRSAPSSParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_RSA_PKCS_PSS_PARAMS)(pParameter)
	return &module.RSAPSSParams{
		HashAlg: module.MechanismType(cParams.hashAlg),
		MGF:     module.MGFType(cParams.mgf),
		SaltLen: uint32(cParams.sLen),
	}, true
}

// decodeRSAOAEPParams reads CK_RSA_PKCS_OAEP_PARAMS (v3.2 section 6.1.7).
func decodeRSAOAEPParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_RSA_PKCS_OAEP_PARAMS)(pParameter)
	params := &module.RSAOAEPParams{
		HashAlg: module.MechanismType(cParams.hashAlg),
		MGF:     module.MGFType(cParams.mgf),
		Source:  uint32(cParams.source),
	}
	sourceData, ok := cBytes(unsafe.Pointer(cParams.pSourceData), cParams.ulSourceDataLen)
	if !ok {
		return nil, false
	}
	params.SourceData = sourceData
	return params, true
}

// decodeGCMParams reads CK_GCM_PARAMS (v3.2 section 6.13.7).
func decodeGCMParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_GCM_PARAMS)(pParameter)
	params := &module.AESGCMParams{
		TagBits: uint32(cParams.ulTagBits),
	}
	iv, ok := cBytes(unsafe.Pointer(cParams.pIv), cParams.ulIvLen)
	if !ok {
		return nil, false
	}
	params.IV = iv
	aad, ok := cBytes(unsafe.Pointer(cParams.pAAD), cParams.ulAADLen)
	if !ok {
		return nil, false
	}
	params.AAD = aad
	return params, true
}

// decodeHKDFParams reads CK_HKDF_PARAMS (v3.2 section 6.62.2).
func decodeHKDFParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_HKDF_PARAMS)(pParameter)
	params := &module.HKDFParams{
		Extract:     cParams.bExtract != 0,
		Expand:      cParams.bExpand != 0,
		PRFHashMech: module.MechanismType(cParams.prfHashMechanism),
		SaltType:    module.HKDFSaltType(cParams.ulSaltType),
		SaltKey:     module.ObjectHandle(cParams.hSaltKey),
	}
	salt, ok := cBytes(unsafe.Pointer(cParams.pSalt), cParams.ulSaltLen)
	if !ok {
		return nil, false
	}
	params.Salt = salt
	info, ok := cBytes(unsafe.Pointer(cParams.pInfo), cParams.ulInfoLen)
	if !ok {
		return nil, false
	}
	params.Info = info
	return params, true
}

// decodeSP800108KDFParams reads CK_SP800_108_KDF_PARAMS (v3.2 section 6.42.2).
func decodeSP800108KDFParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_SP800_108_KDF_PARAMS)(pParameter)
	dataParams, ok := convertSP800108DataParams(cParams.pDataParams, cParams.ulNumberOfDataParams)
	if !ok {
		return nil, false
	}
	return &module.SP800108KDFParams{
		PRF:        module.MechanismType(cParams.prfType),
		DataParams: dataParams,
	}, true
}

// decodeSP800108FeedbackKDFParams reads CK_SP800_108_FEEDBACK_KDF_PARAMS
// (v3.2 section 6.42.2).
func decodeSP800108FeedbackKDFParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_SP800_108_FEEDBACK_KDF_PARAMS)(pParameter)
	dataParams, ok := convertSP800108DataParams(cParams.pDataParams, cParams.ulNumberOfDataParams)
	if !ok {
		return nil, false
	}
	params := &module.SP800108KDFParams{
		PRF:        module.MechanismType(cParams.prfType),
		DataParams: dataParams,
	}
	iv, ok := cBytes(unsafe.Pointer(cParams.pIV), cParams.ulIVLen)
	if !ok {
		return nil, false
	}
	params.IV = iv
	return params, true
}

// decodeEdDSAParams reads CK_EDDSA_PARAMS (v3.2 section 6.3.16).
//
// phFlag and pContextData are what select Ed25519ph and Ed25519ctx over pure
// Ed25519 (section 6.3.14, Table 73). The decoder is kept complete and
// correct even though the table currently marks the mechanism's parameter
// Unsupported, so that lifting that flag is a one-line change.
func decodeEdDSAParams(pParameter unsafe.Pointer) (any, bool) {
	cParams := (*C.CK_EDDSA_PARAMS)(pParameter)
	params := &module.EdDSAParams{
		PreHash: cParams.phFlag != 0,
	}
	context, ok := cBytes(unsafe.Pointer(cParams.pContextData), cParams.ulContextDataLen)
	if !ok {
		return nil, false
	}
	params.Context = context
	return params, true
}

// convertCMechanismToGo converts a C mechanism to a Go mechanism, returning the
// CK_RV the calling entry point must propagate when the caller's parameter is
// malformed.
//
// A returned value other than CKR_OK means the mechanism must not be used: the
// parameter was absent for a mechanism that requires one, shorter than the
// structure the mechanism is defined with, carried an internal length that is
// not addressable as a Go slice, or selected something this module cannot
// perform. Each of those used to leave the typed parameter nil and continue,
// which handed the module layer a mechanism whose parameters looked simply
// unset and let it substitute defaults -- so the caller received output from a
// scheme it had not asked for, under CKR_OK.
func convertCMechanismToGo(pMechanism C.CK_MECHANISM_PTR) (*module.Mechanism, C.CK_RV) {
	if pMechanism == nil {
		return nil, C.CKR_OK
	}

	mechType := module.MechanismType(pMechanism.mechanism)
	decoder := mechanismParameterDecoders[mechType]

	if rv := checkMechanismParameter(decoder, pMechanism.pParameter != nil, uint64(pMechanism.ulParameterLen)); rv != module.CKR_OK {
		return nil, C.CK_RV(rv)
	}

	mech := &module.Mechanism{Type: mechType}

	if pMechanism.pParameter == nil || pMechanism.ulParameterLen == 0 {
		return mech, C.CKR_OK
	}

	param, ok := cBytes(unsafe.Pointer(pMechanism.pParameter), pMechanism.ulParameterLen)
	if !ok {
		return nil, C.CKR_MECHANISM_PARAM_INVALID
	}
	mech.Parameter = param

	if decoder != nil {
		typed, decoded := decoder.Decode(unsafe.Pointer(pMechanism.pParameter))
		if !decoded {
			return nil, C.CKR_MECHANISM_PARAM_INVALID
		}
		mech.TypedParameter = typed
	}

	return mech, C.CKR_OK
}

// convertSP800108DataParams converts a C array of CK_PRF_DATA_PARAM
// entries into Go SP800108DataParam values. Each entry's pValue/ulValueLen
// is copied verbatim regardless of its `type`; interpreting a segment's
// bytes according to its declared type (e.g. deciding whether a
// CK_SP800_108_BYTE_ARRAY, CK_SP800_108_COUNTER_FORMAT or
// CK_SP800_108_DKM_LENGTH_FORMAT payload is one this module's derivation
// backend can honor) is deliberately left to the Go-level caller
// (sp800108LabelContext in pkg/pkcs11/module/crypto.go), matching how this
// file leaves ECDH KDF-type acceptance to deriveKeyECDH rather than
// deciding it at the cgo boundary. Returns ok=false when count exceeds the
// addressable range of a Go slice index.
func convertSP800108DataParams(pDataParams C.CK_PRF_DATA_PARAM_PTR, count C.CK_ULONG) ([]module.SP800108DataParam, bool) {
	if pDataParams == nil || count == 0 {
		return nil, true
	}
	if count > C.CK_ULONG(math.MaxInt32) {
		return nil, false
	}

	cArray := unsafe.Slice(pDataParams, count)
	dataParams := make([]module.SP800108DataParam, 0, count)

	for i := C.CK_ULONG(0); i < count; i++ {
		entry := cArray[i]
		dp := module.SP800108DataParam{
			Type: module.SP800108DataType(entry._type),
		}
		if value, ok := cBytes(unsafe.Pointer(entry.pValue), entry.ulValueLen); ok {
			dp.Value = value
		} else {
			return nil, false
		}
		dataParams = append(dataParams, dp)
	}

	return dataParams, true
}
