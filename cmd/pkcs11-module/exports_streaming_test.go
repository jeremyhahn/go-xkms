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

// Tests for the multi-part encrypt/decrypt state machine (C_EncryptUpdate,
// C_DecryptUpdate, C_EncryptFinal, C_DecryptFinal) and C_SignFinal's
// no-active-operation and backend-reaching branches.
//
// As exports_crypto_test.go explains, Module.EncryptUpdate/DecryptUpdate only
// buffer into an in-memory io.Writer (pkg/pkcs11/module/crypto.go) and never
// reach the backend transport, so their success paths -- the v3.2 section 5.2
// length-query convention and the "nothing to emit until *Final" contract --
// are exercised here directly. EncryptFinal/DecryptFinal/SignFinal do reach
// the backend to produce their output, which the fixture's offlineTransport
// (exports_test.go) cannot serve; those are covered on the branches reachable
// without it, plus the panic-to-CKR_FUNCTION_FAILED guard exports_test.go's
// TestRecoverCKRV_ConvertsAPanicIntoAReturnCode already pins for C_Sign.

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// ============================================================================
// C_EncryptUpdate
// ============================================================================

func TestCEncryptUpdate_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_EncryptUpdate, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_EncryptUpdate with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCEncryptUpdate_NullPartWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)
	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}

	rv, _ := callC(t, C_EncryptUpdate, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_EncryptUpdate(NULL, 16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCEncryptUpdate_QueryModeReportsZeroWithoutDisturbingTheOperation proves
// the v3.2 section 5.2 length-query convention holds even though this
// operation always has nothing to report: a NULL pEncryptedPart still reaches
// Module.EncryptUpdate (buffering the caller's data) rather than short-
// circuiting, so a session with no active operation still gets
// CKR_OPERATION_NOT_INITIALIZED instead of a spurious CKR_OK.
func TestCEncryptUpdate_QueryModeReportsZeroWithoutDisturbingTheOperation(t *testing.T) {
	f := newTestFixture(t)
	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}

	part := []byte("plaintext-chunk")
	var lenAlloc reflect.Value
	rv := callExport(t, C_EncryptUpdate, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(part),
		2: func(v reflect.Value) { v.SetUint(uint64(len(part))) },
		4: func(v reflect.Value) {
			lenAlloc = reflect.New(v.Type().Elem())
			v.Set(lenAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptUpdate(pEncryptedPart=NULL) = %s, want CKR_OK", rv)
	}
	if got := lenAlloc.Elem().Uint(); got != 0 {
		t.Fatalf("C_EncryptUpdate(query) reported length %d, want 0: this operation buffers until C_EncryptFinal", got)
	}

	// The operation must still be active: a second EncryptInit is refused.
	if rv := startEncrypt(t, f); rv != module.CKR_OPERATION_ACTIVE {
		t.Fatalf("EncryptInit after C_EncryptUpdate = %s, want CKR_OPERATION_ACTIVE: the update must not have finished the operation", rv)
	}
}

// TestCEncryptUpdate_ProvidedBufferAlsoReportsZero proves the same "nothing to
// emit yet" contract when the caller supplies a real destination buffer
// instead of querying: the two-call idiom's second call must not be treated
// as though a nonzero amount of ciphertext were now expected.
func TestCEncryptUpdate_ProvidedBufferAlsoReportsZero(t *testing.T) {
	f := newTestFixture(t)
	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}

	part := []byte("plaintext-chunk")
	outBuf := make([]byte, 64)
	var lenAlloc reflect.Value
	rv := callExport(t, C_EncryptUpdate, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(part),
		2: func(v reflect.Value) { v.SetUint(uint64(len(part))) },
		3: setBufferArg(outBuf),
		4: func(v reflect.Value) {
			lenAlloc = reflect.New(v.Type().Elem())
			lenAlloc.Elem().SetUint(uint64(len(outBuf)))
			v.Set(lenAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptUpdate(real buffer) = %s, want CKR_OK", rv)
	}
	if got := lenAlloc.Elem().Uint(); got != 0 {
		t.Fatalf("C_EncryptUpdate(real buffer) reported length %d, want 0", got)
	}
}

// ============================================================================
// C_DecryptUpdate: the same contract as C_EncryptUpdate, mirrored.
// ============================================================================

func TestCDecryptUpdate_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DecryptUpdate, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DecryptUpdate with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCDecryptUpdate_NullPartWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)
	if rv := startDecrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting decrypt: %s", rv)
	}

	rv, _ := callC(t, C_DecryptUpdate, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecryptUpdate(NULL, 16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCDecryptUpdate_QueryModeReportsZeroWithoutDisturbingTheOperation(t *testing.T) {
	f := newTestFixture(t)
	if rv := startDecrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting decrypt: %s", rv)
	}

	part := []byte("ciphertext-chunk")
	var lenAlloc reflect.Value
	rv := callExport(t, C_DecryptUpdate, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(part),
		2: func(v reflect.Value) { v.SetUint(uint64(len(part))) },
		4: func(v reflect.Value) {
			lenAlloc = reflect.New(v.Type().Elem())
			v.Set(lenAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate(pPart=NULL) = %s, want CKR_OK", rv)
	}
	if got := lenAlloc.Elem().Uint(); got != 0 {
		t.Fatalf("C_DecryptUpdate(query) reported length %d, want 0: this operation buffers until C_DecryptFinal", got)
	}

	if rv := startDecrypt(t, f); rv != module.CKR_OPERATION_ACTIVE {
		t.Fatalf("DecryptInit after C_DecryptUpdate = %s, want CKR_OPERATION_ACTIVE: the update must not have finished the operation", rv)
	}
}

// ============================================================================
// C_EncryptFinal / C_DecryptFinal / C_SignFinal: no-active-operation, and the
// panic-to-CKR_FUNCTION_FAILED guard when a query reaches the backend.
// ============================================================================

func TestCEncryptFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_EncryptFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_EncryptFinal with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCDecryptFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DecryptFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DecryptFinal with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCSignFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_SignFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_SignFinal with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// TestCEncryptFinal_ReachesBackendAndConvertsPanic proves C_EncryptFinal is
// called unconditionally -- even for a NULL pLastEncryptedPart length query --
// once an operation is active: the buffered plaintext must actually be
// encrypted to learn its length, and that reaches the nil offlineTransport,
// which panics. recoverCKRV must turn that into CKR_FUNCTION_FAILED (v3.2
// section 5.1 admits only a CK_RV) rather than letting it unwind into C.
func TestCEncryptFinal_ReachesBackendAndConvertsPanic(t *testing.T) {
	f := newTestFixture(t)
	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}
	if _, mrv := f.m.EncryptUpdate(f.session, []byte("plaintext")); mrv != module.CKR_OK {
		t.Fatalf("EncryptUpdate: %s", mrv)
	}

	rv, _ := callC(t, C_EncryptFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_FUNCTION_FAILED {
		t.Fatalf("C_EncryptFinal over a panicking backend = %s, want CKR_FUNCTION_FAILED", rv)
	}
}

// TestCDecryptFinal_ReachesBackendAndConvertsPanic mirrors the encrypt case.
func TestCDecryptFinal_ReachesBackendAndConvertsPanic(t *testing.T) {
	f := newTestFixture(t)
	if rv := startDecrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting decrypt: %s", rv)
	}
	if _, mrv := f.m.DecryptUpdate(f.session, []byte("ciphertext")); mrv != module.CKR_OK {
		t.Fatalf("DecryptUpdate: %s", mrv)
	}

	rv, _ := callC(t, C_DecryptFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_FUNCTION_FAILED {
		t.Fatalf("C_DecryptFinal over a panicking backend = %s, want CKR_FUNCTION_FAILED", rv)
	}
}

// TestCSignFinal_ReachesBackendAndConvertsPanic proves the same guard on
// C_SignFinal, which needs no prior SignUpdate: SignInit alone leaves an
// active signature operation ready for a terminal call.
func TestCSignFinal_ReachesBackendAndConvertsPanic(t *testing.T) {
	f := newTestFixture(t)
	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("starting sign: %s", rv)
	}

	rv, _ := callC(t, C_SignFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_FUNCTION_FAILED {
		t.Fatalf("C_SignFinal over a panicking backend = %s, want CKR_FUNCTION_FAILED", rv)
	}
}
