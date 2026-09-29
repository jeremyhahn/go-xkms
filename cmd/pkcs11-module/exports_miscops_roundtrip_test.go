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

// Tests for C_CopyObject's success path and the two reachable branches of
// C_GetOperationState/C_SetOperationState, extending
// exports_session_object_test.go's NULL-argument-only coverage of the latter
// pair.
//
// module.go's GetOperationStateBytes/SetOperationStateBytes doc comments
// explain why those two entry points have no reachable success path at all:
// every operation's running state lives in the crypto manager or the
// backend and cannot leave the token, so C_GetOperationState answers
// CKR_STATE_UNSAVEABLE for any active operation and
// CKR_OPERATION_NOT_INITIALIZED for none, and C_SetOperationState answers
// CKR_SAVED_STATE_INVALID for every byte string (PKCS#11 v3.2 §5.6.6/§5.6.7).
// The pOperationState==nil/CKR_BUFFER_TOO_SMALL/memcpy branches below that in
// C_GetOperationState are therefore dead code reachable only if
// GetOperationStateBytes ever starts returning a byte string, which is not
// this batch's concern; this file exercises every branch production
// behaviour can actually reach.

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestCGetOperationState_NoActiveOperation proves a session with nothing
// active is refused with CKR_OPERATION_NOT_INITIALIZED rather than the
// CKR_STATE_UNSAVEABLE an active-but-unsaveable operation gets.
func TestCGetOperationState_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetOperationState, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_GetOperationState(no active operation) = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// TestCGetOperationState_ActiveOperationIsUnsaveable proves an active
// operation is refused with CKR_STATE_UNSAVEABLE (v3.2 §5.6.6): this
// module's running crypto state lives in the crypto manager or the backend
// and has no serialized form to hand back.
func TestCGetOperationState_ActiveOperationIsUnsaveable(t *testing.T) {
	f := newTestFixture(t)
	if rv := startDigest(t, f); rv != module.CKR_OK {
		t.Fatalf("starting digest: %s", rv)
	}

	rv, _ := callC(t, C_GetOperationState, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_STATE_UNSAVEABLE {
		t.Fatalf("C_GetOperationState(active digest) = %s, want CKR_STATE_UNSAVEABLE", rv)
	}
}

// TestCSetOperationState_ValidSessionIsSavedStateInvalid proves
// C_SetOperationState reaches Module.SetOperationStateBytes for a
// well-formed call and is refused with CKR_SAVED_STATE_INVALID (v3.2
// §5.6.7): no byte string this module could be handed is ever state
// C_GetOperationState produced, since it never produces any.
func TestCSetOperationState_ValidSessionIsSavedStateInvalid(t *testing.T) {
	f := newTestFixture(t)

	state := []byte{0x01, 0x02, 0x03, 0x04}
	rv := callExport(t, C_SetOperationState, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(state),
		2: func(v reflect.Value) { v.SetUint(uint64(len(state))) },
		3: func(v reflect.Value) { v.SetUint(uint64(f.privKey)) },
		4: func(v reflect.Value) { v.SetUint(uint64(f.pubKey)) },
	})
	if rv != module.CKR_SAVED_STATE_INVALID {
		t.Fatalf("C_SetOperationState(well-formed) = %s, want CKR_SAVED_STATE_INVALID", rv)
	}
}

// TestCCopyObject_RoundTrip proves C_CopyObject creates a genuine second
// object rather than merely reporting success: the copy has its own handle,
// distinct from the source, and the same key material.
func TestCCopyObject_RoundTrip(t *testing.T) {
	f := newTestFixture(t)

	fn := reflect.ValueOf(C_CopyObject)
	ft := fn.Type()
	newHandle := allocOf(ft, 4)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		scalarOf(ft, 1, uint64(f.privKey)),
		reflect.Zero(ft.In(2)),
		scalarOf(ft, 3, 0),
		newHandle,
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_CopyObject = %s, want CKR_OK", rv)
	}
	copyHandle := handleOf(newHandle)
	if copyHandle == f.privKey {
		t.Fatal("C_CopyObject returned the same handle as the source object")
	}

	srcAttrs, rv := f.m.GetAttributeValue(f.session, f.privKey, []module.Attribute{{Type: module.CKA_MODULUS}})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(source CKA_MODULUS) = %s, want CKR_OK", rv)
	}
	copyAttrs, rv := f.m.GetAttributeValue(f.session, copyHandle, []module.Attribute{{Type: module.CKA_MODULUS}})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(copy CKA_MODULUS) = %s, want CKR_OK", rv)
	}
	if string(srcAttrs[0].Value) != string(copyAttrs[0].Value) {
		t.Fatal("the copy's CKA_MODULUS does not match the source object's")
	}
}

// TestCCopyObject_InvalidObjectHandleIsRefused proves a handle naming
// nothing is refused rather than silently producing an empty copy.
func TestCCopyObject_InvalidObjectHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_CopyObject, cScalar(uint64(f.session)), cScalar(0xDEADBEEF), cNull(), cScalar(0), cAlloc())
	if rv == module.CKR_OK {
		t.Fatal("C_CopyObject(invalid handle) = CKR_OK, want an error")
	}
}

// TestCAsyncComplete_WellFormedIsFunctionNotSupported proves a well-formed
// call (a real session, a non-empty function name, a real CK_ASYNC_DATA
// output) reaches Module.AsyncComplete rather than stopping at an argument
// guard. module_async.go's own doc comment is explicit that every async verb
// answers CKR_FUNCTION_NOT_SUPPORTED unconditionally past that point --
// "Async operations require hardware backend support that is not yet
// available" -- so that is the one outcome a well-formed call can ever
// produce today, and the result-population branches later in C_AsyncComplete
// are unreachable until a backend implements the feature.
func TestCAsyncComplete_WellFormedIsFunctionNotSupported(t *testing.T) {
	f := newTestFixture(t)

	fn := reflect.ValueOf(C_AsyncComplete)
	ft := fn.Type()
	functionName := append([]byte("C_Sign"), 0)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		setBufferPtr(functionName, ft, 1),
		allocOf(ft, 2),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_FUNCTION_NOT_SUPPORTED {
		t.Fatalf("C_AsyncComplete(well-formed) = %s, want CKR_FUNCTION_NOT_SUPPORTED", rv)
	}
}
