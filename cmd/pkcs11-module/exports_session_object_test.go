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

// Tests for the session and object management entry points in exports.go:
// argument marshalling and invalid-handle CK_RV mapping, driven through the
// real C-ABI entry points via callExport/callC (see exports_test.go and
// exports_twocall_test.go for why a _test.go file cannot import "C" and
// therefore cannot call them directly).

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// ============================================================================
// C_OpenSession / C_CloseSession / C_CloseAllSessions / C_GetSessionInfo
// ============================================================================

func TestCOpenSession_NullHandleIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_OpenSession, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_OpenSession(phSession=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCOpenSession_Success(t *testing.T) {
	newTestFixture(t)

	var handleAlloc reflect.Value
	rv := callExport(t, C_OpenSession, map[int]func(reflect.Value){
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKF_SERIAL_SESSION | module.CKF_RW_SESSION)) },
		4: func(v reflect.Value) {
			handleAlloc = reflect.New(v.Type().Elem())
			v.Set(handleAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_OpenSession(slot 0) = %s, want CKR_OK", rv)
	}
	if handleAlloc.Elem().Uint() == 0 {
		t.Fatal("C_OpenSession reported the zero handle, which names no session")
	}

	// The session it opened must be independently closeable through the C ABI.
	closeRV, _ := callC(t, C_CloseSession, cScalar(handleAlloc.Elem().Uint()))
	if closeRV != module.CKR_OK {
		t.Fatalf("C_CloseSession(the session C_OpenSession just opened) = %s, want CKR_OK", closeRV)
	}
}

func TestCCloseSession_InvalidHandle(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_CloseSession, cScalar(0xDEADBEEF))
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_CloseSession(unknown handle) = %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
}

func TestCCloseAllSessions_Success(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_CloseAllSessions, cScalar(0))
	if rv != module.CKR_OK {
		t.Fatalf("C_CloseAllSessions(slot 0) = %s, want CKR_OK", rv)
	}

	// f.session was open on slot 0 and must be gone: further use reports an
	// unknown session rather than silently succeeding against a closed one.
	if rv := f.m.CloseSession(f.session); rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("session outlived C_CloseAllSessions: CloseSession = %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
}

func TestCGetSessionInfo_NullArgumentIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetSessionInfo, cScalar(uint64(f.session)), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetSessionInfo(pInfo=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetSessionInfo_Success(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetSessionInfo, cScalar(uint64(f.session)), cAlloc())
	if rv != module.CKR_OK {
		t.Fatalf("C_GetSessionInfo(the fixture's logged-in session) = %s, want CKR_OK", rv)
	}
}

func TestCGetSessionInfo_InvalidHandle(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_GetSessionInfo, cScalar(0xDEADBEEF), cAlloc())
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_GetSessionInfo(unknown handle) = %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
}

// ============================================================================
// C_Login / C_Logout / C_LoginUser / C_SessionCancel
// ============================================================================

// TestCLogin_RoundTripThroughTheCABI proves the whole login/logout cycle
// works through the real C entry points, not just Module.Login/Logout (which
// newTestFixture already drives directly to provision its fixture).
func TestCLogin_RoundTripThroughTheCABI(t *testing.T) {
	f := newTestFixture(t)

	// PKCS#11 login state is per-token, not per-session (v3.2 §5.6.4): the
	// fixture's session is already logged in as the normal user, so logging
	// in again -- on this session or any other sharing the token -- would
	// report CKR_USER_ALREADY_LOGGED_IN rather than exercise C_Login's
	// success path. Log out first so the round trip starts from a clean
	// state.
	if mrv := f.m.Logout(f.session); mrv != module.CKR_OK {
		t.Fatalf("Logout: %s", mrv)
	}

	pin := []byte(testUserPIN)
	rv := callExport(t, C_Login, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKU_USER)) },
		2: setBufferArg(pin),
		3: func(v reflect.Value) { v.SetUint(uint64(len(pin))) },
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_Login(CKU_USER) = %s, want CKR_OK", rv)
	}

	logoutRV, _ := callC(t, C_Logout, cScalar(uint64(f.session)))
	if logoutRV != module.CKR_OK {
		t.Fatalf("C_Logout = %s, want CKR_OK", logoutRV)
	}
}

func TestCLogin_WrongPINIsRefused(t *testing.T) {
	f := newTestFixture(t)

	// Log out first (see TestCLogin_RoundTripThroughTheCABI): otherwise the
	// token's already-logged-in state would refuse the call before the PIN
	// is ever checked, which is a different failure than the one this test
	// pins.
	if mrv := f.m.Logout(f.session); mrv != module.CKR_OK {
		t.Fatalf("Logout: %s", mrv)
	}

	pin := []byte("not-the-right-pin")
	rv := callExport(t, C_Login, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKU_USER)) },
		2: setBufferArg(pin),
		3: func(v reflect.Value) { v.SetUint(uint64(len(pin))) },
	})
	if rv == module.CKR_OK {
		t.Fatal("C_Login accepted the wrong PIN")
	}
}

func TestCLogin_NullPinWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv := callExport(t, C_Login, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKU_USER)) },
		3: func(v reflect.Value) { v.SetUint(16) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Login(pPin=NULL, ulPinLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCLoginUser_WithUsername(t *testing.T) {
	f := newTestFixture(t)

	session, mrv := f.m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if mrv != module.CKR_OK {
		t.Fatalf("OpenSession: %s", mrv)
	}

	pin := []byte(testUserPIN)
	username := []byte("administrator")
	rv := callExport(t, C_LoginUser, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(session)) },
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKU_USER)) },
		2: setBufferArg(pin),
		3: func(v reflect.Value) { v.SetUint(uint64(len(pin))) },
		4: setBufferArg(username),
		5: func(v reflect.Value) { v.SetUint(uint64(len(username))) },
	})
	// v3.0 context-specific login with a username is accepted at the C ABI
	// layer and forwarded to Module.LoginUser; whether this deployment's
	// backend honours a per-user PIN is a Module-level policy this test does
	// not assert on. What matters here is that the marshalling itself (a
	// second cBytes-decoded buffer alongside the PIN) does not refuse a
	// well-formed call.
	if rv == module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_LoginUser(with username) = %s, want anything but CKR_ARGUMENTS_BAD for a well-formed call", rv)
	}
}

func TestCSessionCancel_InvalidSession(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_SessionCancel, cScalar(0xDEADBEEF), cScalar(0))
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_SessionCancel(unknown handle) = %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
}

// ============================================================================
// C_GetOperationState / C_SetOperationState
// ============================================================================

func TestCGetOperationState_NullArgumentIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetOperationState, cScalar(uint64(f.session)), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetOperationState(pulOperationStateLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCSetOperationState_NullStateWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv := callExport(t, C_SetOperationState, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		2: func(v reflect.Value) { v.SetUint(16) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SetOperationState(pOperationState=NULL, ulOperationStateLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// ============================================================================
// C_CreateObject / C_CopyObject / C_DestroyObject / C_GetObjectSize
// ============================================================================

func TestCCreateObject_NullHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_CreateObject, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_CreateObject(phObject=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCCopyObject_NullHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_CopyObject,
		cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_CopyObject(phNewObject=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCDestroyObject_InvalidHandle(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DestroyObject, cScalar(uint64(f.session)), cScalar(0xDEADBEEF))
	if rv == module.CKR_OK {
		t.Fatal("C_DestroyObject accepted a handle that names no object")
	}
}

func TestCDestroyObject_Success(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DestroyObject, cScalar(uint64(f.session)), cScalar(uint64(f.privKey)))
	if rv != module.CKR_OK {
		t.Fatalf("C_DestroyObject(the fixture's private key) = %s, want CKR_OK", rv)
	}

	// The object must actually be gone: GetObjectSize on the destroyed
	// handle must no longer resolve it.
	sizeRV, _ := callC(t, C_GetObjectSize, cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cAlloc())
	if sizeRV == module.CKR_OK {
		t.Fatal("C_DestroyObject left the object resolvable by its old handle")
	}
}

func TestCGetObjectSize_NullArgumentIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetObjectSize, cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetObjectSize(pulSize=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetObjectSize_Success(t *testing.T) {
	f := newTestFixture(t)

	rv, out := callC(t, C_GetObjectSize, cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cAlloc())
	if rv != module.CKR_OK {
		t.Fatalf("C_GetObjectSize(the fixture's private key) = %s, want CKR_OK", rv)
	}
	if out[2].Elem().Uint() == 0 {
		t.Fatal("C_GetObjectSize reported a zero-byte object for a key carrying a modulus and an exponent")
	}
}

// ============================================================================
// C_GetAttributeValue / C_SetAttributeValue: the empty-template edge, which is
// the one shape a _test.go file can drive through the real C ABI without
// naming the unexported cgo CK_ATTRIBUTE fields (see exports_test.go's file
// doc comment on why "C" cannot appear here at all).
// ============================================================================

func TestCGetAttributeValue_NullTemplateWithNonzeroCountIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv := callExport(t, C_GetAttributeValue, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: func(v reflect.Value) { v.SetUint(uint64(f.privKey)) },
		3: func(v reflect.Value) { v.SetUint(1) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetAttributeValue(pTemplate=NULL, ulCount=1) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetAttributeValue_EmptyTemplateIsOK(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetAttributeValue,
		cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cNull(), cScalar(0))
	if rv != module.CKR_OK {
		t.Fatalf("C_GetAttributeValue(ulCount=0) = %s, want CKR_OK: an empty template asks for nothing and cannot fail", rv)
	}
}

func TestCGetAttributeValue_InvalidObjectHandle(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetAttributeValue,
		cScalar(uint64(f.session)), cScalar(0xDEADBEEF), cNull(), cScalar(0))
	if rv != module.CKR_OBJECT_HANDLE_INVALID {
		t.Fatalf("C_GetAttributeValue(unknown object) = %s, want CKR_OBJECT_HANDLE_INVALID", rv)
	}
}

func TestCSetAttributeValue_EmptyTemplateIsOK(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_SetAttributeValue,
		cScalar(uint64(f.session)), cScalar(uint64(f.privKey)), cNull(), cScalar(0))
	if rv != module.CKR_OK {
		t.Fatalf("C_SetAttributeValue(ulCount=0) = %s, want CKR_OK: an empty template changes nothing and cannot fail", rv)
	}
}

// ============================================================================
// C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal: the full search
// flow, matched against the fixture's own known object count.
// ============================================================================

func TestCFindObjects_FindsEveryFixtureObject(t *testing.T) {
	f := newTestFixture(t)

	initRV, _ := callC(t, C_FindObjectsInit, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if initRV != module.CKR_OK {
		t.Fatalf("C_FindObjectsInit(empty template) = %s, want CKR_OK", initRV)
	}

	var handlesAlloc, countAlloc reflect.Value
	rv := callExport(t, C_FindObjects, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setArrayArg(8, &handlesAlloc),
		2: func(v reflect.Value) { v.SetUint(8) },
		3: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_FindObjects = %s, want CKR_OK", rv)
	}
	// The fixture creates exactly two objects (privKey, pubKey).
	if got := countAlloc.Elem().Uint(); got != 2 {
		t.Fatalf("C_FindObjects reported %d objects, want 2 (the fixture's privKey and pubKey)", got)
	}

	finalRV, _ := callC(t, C_FindObjectsFinal, cScalar(uint64(f.session)))
	if finalRV != module.CKR_OK {
		t.Fatalf("C_FindObjectsFinal = %s, want CKR_OK", finalRV)
	}
}
