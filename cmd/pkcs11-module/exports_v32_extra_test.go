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

// Tests for the PKCS#11 v3.2 message-based crypto verbs
// (C_*Message*/C_Message*Final), C_DecapsulateKey, C_VerifySignature and
// friends, and the async/session-validation entry points
// (C_GetSessionValidationFlags, C_AsyncComplete, C_AsyncGetID). These share
// the argument-marshalling and operation-bookkeeping shape already proven
// for the single-part verbs in exports_crypto_test.go: a NULL required
// pointer is refused, and a well-formed call with no active operation
// reports that rather than proceeding. As with exports_dualfunction_test.go,
// the branches that decode a populated CK_GCM_MESSAGE_PARAMS are out of
// reach from a _test.go file (see exports_paramdecode_test.go) and are not
// exercised here.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestCEncryptMessage_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_EncryptMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_EncryptMessage(pulCiphertextLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCEncryptMessage_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_EncryptMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_EncryptMessage with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCEncryptMessageBegin_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_EncryptMessageBegin, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_EncryptMessageBegin with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCEncryptMessageNext_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_EncryptMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_EncryptMessageNext(pulCiphertextPartLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCEncryptMessageNext_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_EncryptMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_EncryptMessageNext with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCMessageEncryptFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_MessageEncryptFinal, cScalar(uint64(f.session)))
	if rv == module.CKR_OK {
		t.Fatalf("C_MessageEncryptFinal with nothing initialized = CKR_OK, want an error")
	}
}

func TestCDecryptMessage_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_DecryptMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecryptMessage(pulPlaintextLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCDecryptMessage_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_DecryptMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DecryptMessage with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCDecryptMessageBegin_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_DecryptMessageBegin, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DecryptMessageBegin with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCDecryptMessageNext_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_DecryptMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecryptMessageNext(pulPlaintextPartLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCDecryptMessageNext_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_DecryptMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DecryptMessageNext with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCMessageDecryptFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_MessageDecryptFinal, cScalar(uint64(f.session)))
	if rv == module.CKR_OK {
		t.Fatalf("C_MessageDecryptFinal with nothing initialized = CKR_OK, want an error")
	}
}

func TestCSignMessage_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_SignMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_SignMessage with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// TestCSignMessage_NonNilMessageParamIsRefused proves C_SignMessage rejects a
// non-NULL per-message parameter (rejectSignMessageParam, checked before the
// operation-state lookup). pParameter is CK_VOID_PTR (unsafe.Pointer kind),
// which callC's cAlloc cannot build (it requires a Go pointer kind to take
// Elem() of), so this constructs the argument list directly via reflection,
// the same technique exports_paramdecode_test.go uses.
func TestCSignMessage_NonNilMessageParamIsRefused(t *testing.T) {
	f := newTestFixture(t)

	fn := reflect.ValueOf(C_SignMessage)
	ft := fn.Type()

	var buf [8]byte
	args := []reflect.Value{
		reflect.New(ft.In(0)).Elem(),         // hSession
		cPtr(unsafe.Pointer(&buf[0]), ft, 1), // pParameter (non-NULL)
		reflect.New(ft.In(2)).Elem(),         // ulParameterLen
		reflect.Zero(ft.In(3)),               // pData
		reflect.New(ft.In(4)).Elem(),         // ulDataLen
		reflect.Zero(ft.In(5)),               // pSignature
		reflect.New(ft.In(6).Elem()),         // pulSignatureLen (alloc)
	}
	args[0].SetUint(uint64(f.session))
	args[2].SetUint(uint64(len(buf)))

	out := fn.Call(args)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_SignMessage(non-NULL pParameter) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}

func TestCSignMessageBegin_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_SignMessageBegin, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_SignMessageBegin with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCSignMessageNext_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_SignMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_SignMessageNext with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCMessageSignFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_MessageSignFinal, cScalar(uint64(f.session)))
	if rv == module.CKR_OK {
		t.Fatalf("C_MessageSignFinal with nothing initialized = CKR_OK, want an error")
	}
}

func TestCVerifyMessage_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifyMessage,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_VerifyMessage with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCVerifyMessageBegin_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifyMessageBegin, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_VerifyMessageBegin with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCVerifyMessageNext_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifyMessageNext,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_VerifyMessageNext with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCMessageVerifyFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_MessageVerifyFinal, cScalar(uint64(f.session)))
	if rv == module.CKR_OK {
		t.Fatalf("C_MessageVerifyFinal with nothing initialized = CKR_OK, want an error")
	}
}

func TestCDecapsulateKey_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DecapsulateKey,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecapsulateKey(pMechanism=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	rv, _ = callC(t, C_DecapsulateKey,
		cScalar(uint64(f.session)), cAlloc(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecapsulateKey(phKey=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerifySignature_NullDataWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifySignature, cScalar(uint64(f.session)), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_VerifySignature(pData=NULL, ulDataLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerifySignature_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifySignature, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv == module.CKR_OK {
		t.Fatalf("C_VerifySignature with nothing initialized = CKR_OK, want an error")
	}
}

func TestCVerifySignatureUpdate_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifySignatureUpdate, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv == module.CKR_OK {
		t.Fatalf("C_VerifySignatureUpdate with nothing initialized = CKR_OK, want an error")
	}
}

func TestCVerifySignatureFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_VerifySignatureFinal, cScalar(uint64(f.session)))
	if rv == module.CKR_OK {
		t.Fatalf("C_VerifySignatureFinal with nothing initialized = CKR_OK, want an error")
	}
}

func TestCGetSessionValidationFlags_NullArgumentIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_GetSessionValidationFlags, cScalar(uint64(f.session)), cScalar(module.CKS_LAST_VALIDATION_OK), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetSessionValidationFlags(pFlags=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetSessionValidationFlags_UnknownFlagsTypeIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_GetSessionValidationFlags, cScalar(uint64(f.session)), cScalar(0xDEADBEEF), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetSessionValidationFlags(unknown flagsType) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCGetSessionValidationFlags_Success proves the one currently-defined
// flags type (CKS_LAST_VALIDATION_OK) is answered rather than refused, and
// that an unvalidated (non-FIPS) configuration reports no validation flags
// set.
func TestCGetSessionValidationFlags_Success(t *testing.T) {
	f := newTestFixture(t)
	rv, args := callC(t, C_GetSessionValidationFlags, cScalar(uint64(f.session)), cScalar(module.CKS_LAST_VALIDATION_OK), cAlloc())
	if rv != module.CKR_OK {
		t.Fatalf("C_GetSessionValidationFlags(CKS_LAST_VALIDATION_OK) = %s, want CKR_OK", rv)
	}
	got := args[2].Elem().Uint()
	if got != 0 {
		t.Errorf("*pFlags = %#x, want 0 (this module reports no FIPS/CC validation)", got)
	}
}

func TestCAsyncComplete_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_AsyncComplete, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncComplete(pFunctionName=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	rv, _ = callC(t, C_AsyncComplete, cScalar(uint64(f.session)), cAlloc(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncComplete(pResult=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCAsyncComplete_EmptyFunctionNameIsRefused drives the module layer's
// own argument check: a zeroed CK_UTF8CHAR_PTR buffer decodes as the empty
// string, which AsyncComplete refuses before ever asking whether async
// operations are supported.
func TestCAsyncComplete_EmptyFunctionNameIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_AsyncComplete, cScalar(uint64(f.session)), cAlloc(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncComplete(functionName=\"\") = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCAsyncGetID_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_AsyncGetID, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncGetID(pFunctionName=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	rv, _ = callC(t, C_AsyncGetID, cScalar(uint64(f.session)), cAlloc(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncGetID(pulID=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCAsyncGetID_EmptyFunctionNameIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_AsyncGetID, cScalar(uint64(f.session)), cAlloc(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncGetID(functionName=\"\") = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}
