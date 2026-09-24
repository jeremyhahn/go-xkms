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

// Tests for the cryptographic entry points in exports.go.
//
// C_Digest is this file's workhorse for the two-call buffer-too-small idiom
// and the terminal-operation lifecycle: unlike C_Encrypt/C_Decrypt/C_Sign/
// C_Verify, Module.Digest computes locally (crypto/sha256 under the hood) and
// never reaches the backend transport, so it is the one terminal operation
// the fixture's offlineTransport (exports_test.go: every method but Connect
// and Close is a nil embedded interface, so a real backend call panics) can
// drive to a genuine, verifiable success. The others are exercised only on
// their argument-marshalling and no-active-operation branches, which do not
// reach the transport either.

import (
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// ============================================================================
// C_Digest: two-call idiom, buffer-too-small, and operation termination
// ============================================================================

func TestCDigest_TwoCallSuccessAndTermination(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	msg := []byte("the quick brown fox jumps over the lazy dog")
	want := sha256.Sum256(msg)

	// First call: a NULL pDigest is a length query, and must report the
	// correct digest length without disturbing the operation.
	var lenAlloc reflect.Value
	rv := callExport(t, C_Digest, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(msg),
		2: func(v reflect.Value) { v.SetUint(uint64(len(msg))) },
		4: func(v reflect.Value) {
			lenAlloc = reflect.New(v.Type().Elem())
			v.Set(lenAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_Digest(pDigest=NULL) = %s, want CKR_OK", rv)
	}
	if got := lenAlloc.Elem().Uint(); got != sha256.Size {
		t.Fatalf("C_Digest length query reported %d bytes, want %d", got, sha256.Size)
	}

	// Second call: a buffer one byte short of the digest is refused, and the
	// required length is reported again. The operation must still be alive
	// afterwards -- this is retryable, not terminal.
	shortBuf := make([]byte, sha256.Size-1)
	var shortLenAlloc reflect.Value
	rv = callExport(t, C_Digest, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(msg),
		2: func(v reflect.Value) { v.SetUint(uint64(len(msg))) },
		3: setBufferArg(shortBuf),
		4: func(v reflect.Value) {
			shortLenAlloc = reflect.New(v.Type().Elem())
			shortLenAlloc.Elem().SetUint(uint64(len(shortBuf)))
			v.Set(shortLenAlloc)
		},
	})
	if rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_Digest(short buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := shortLenAlloc.Elem().Uint(); got != sha256.Size {
		t.Fatalf("C_Digest(BUFFER_TOO_SMALL) reported required length %d, want %d", got, sha256.Size)
	}

	// Third call: a correctly sized buffer completes the operation and the
	// digest matches Go's own SHA-256, proving the two-call sequence carried
	// the right bytes through cBytes and back rather than merely the right
	// length.
	fullBuf := make([]byte, sha256.Size)
	var fullLenAlloc reflect.Value
	rv = callExport(t, C_Digest, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(msg),
		2: func(v reflect.Value) { v.SetUint(uint64(len(msg))) },
		3: setBufferArg(fullBuf),
		4: func(v reflect.Value) {
			fullLenAlloc = reflect.New(v.Type().Elem())
			fullLenAlloc.Elem().SetUint(uint64(len(fullBuf)))
			v.Set(fullLenAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_Digest(full buffer) = %s, want CKR_OK", rv)
	}
	if [sha256.Size]byte(fullBuf) != want {
		t.Fatalf("C_Digest = %x, want %x", fullBuf, want)
	}

	// The operation must be gone: a fresh DigestInit must succeed rather than
	// report CKR_OPERATION_ACTIVE.
	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit after a completed C_Digest = %s, want CKR_OK: the operation was not terminated", rv)
	}
}

func TestCDigest_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_Digest, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_Digest with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// TestCDigestUpdate_NullPartWithNonzeroLengthIsRefused pins the cBytes
// contract C_DigestUpdate shares with every other terminal/streaming
// function: NULL with a nonzero length is malformed, not empty input.
func TestCDigestUpdate_NullPartWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	rv, _ := callC(t, C_DigestUpdate, cScalar(uint64(f.session)), cNull(), cScalar(32))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DigestUpdate(NULL, 32) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCDigestUpdate_NullPartWithZeroLengthIsEmptyInput proves the other half
// of the same contract: NULL with a zero length is legitimate empty input,
// not a malformed buffer description.
func TestCDigestUpdate_NullPartWithZeroLengthIsEmptyInput(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	rv, _ := callC(t, C_DigestUpdate, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv != module.CKR_OK {
		t.Fatalf("C_DigestUpdate(NULL, 0) = %s, want CKR_OK", rv)
	}
}

func TestCDigestUpdateFinal_Success(t *testing.T) {
	f := newTestFixture(t)

	part1 := []byte("hello, ")
	part2 := []byte("world")
	want := sha256.Sum256(append(append([]byte(nil), part1...), part2...))

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	if rv := f.m.DigestUpdate(f.session, part1); rv != module.CKR_OK {
		t.Fatalf("DigestUpdate(part1): %s", rv)
	}
	if rv := f.m.DigestUpdate(f.session, part2); rv != module.CKR_OK {
		t.Fatalf("DigestUpdate(part2): %s", rv)
	}

	fullBuf := make([]byte, sha256.Size)
	digestRV := callExport(t, C_DigestFinal, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(fullBuf),
		2: func(v reflect.Value) {
			alloc := reflect.New(v.Type().Elem())
			alloc.Elem().SetUint(uint64(len(fullBuf)))
			v.Set(alloc)
		},
	})
	if digestRV != module.CKR_OK {
		t.Fatalf("C_DigestFinal = %s, want CKR_OK", digestRV)
	}
	if [sha256.Size]byte(fullBuf) != want {
		t.Fatalf("C_DigestFinal = %x, want %x", fullBuf, want)
	}
}

func TestCDigestFinal_NullArgumentIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DigestFinal, cScalar(uint64(f.session)), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DigestFinal(pulDigestLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// ============================================================================
// C_Encrypt / C_Decrypt / C_Sign / C_Verify / *Recover: argument marshalling
// and the no-active-operation branch, which are reachable without a live
// backend transport.
// ============================================================================

func TestCEncrypt_NullLengthPointerTerminatesTheOperation(t *testing.T) {
	f := newTestFixture(t)

	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}

	rv, _ := callC(t, C_Encrypt, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Encrypt(pulEncryptedDataLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	// Per v3.2 5.8.3, an argument error terminates the operation: a fresh
	// EncryptInit must succeed rather than report CKR_OPERATION_ACTIVE.
	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("EncryptInit after a refused C_Encrypt = %s, want CKR_OK: the operation was not terminated", rv)
	}
}

func TestCEncrypt_NullDataWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	if rv := startEncrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting encrypt: %s", rv)
	}

	rv, _ := callC(t, C_Encrypt, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Encrypt(pData=NULL, ulDataLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCEncrypt_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_Encrypt, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_Encrypt with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCDecrypt_NullLengthPointerTerminatesTheOperation(t *testing.T) {
	f := newTestFixture(t)

	if rv := startDecrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("starting decrypt: %s", rv)
	}

	rv, _ := callC(t, C_Decrypt, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Decrypt(pulDataLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	if rv := startDecrypt(t, f); rv != module.CKR_OK {
		t.Fatalf("DecryptInit after a refused C_Decrypt = %s, want CKR_OK: the operation was not terminated", rv)
	}
}

func TestCDecrypt_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_Decrypt, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_Decrypt with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCSign_NullLengthPointerTerminatesTheOperation(t *testing.T) {
	f := newTestFixture(t)

	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("starting sign: %s", rv)
	}

	rv, _ := callC(t, C_Sign, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Sign(pulSignatureLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("SignInit after a refused C_Sign = %s, want CKR_OK: the operation was not terminated", rv)
	}
}

func TestCSign_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_Sign, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_Sign with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCVerify_NullDataWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	if rv := startVerify(t, f); rv != module.CKR_OK {
		t.Fatalf("starting verify: %s", rv)
	}

	rv, _ := callC(t, C_Verify, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Verify(pData=NULL, ulDataLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerify_NullSignatureWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	if rv := startVerify(t, f); rv != module.CKR_OK {
		t.Fatalf("starting verify: %s", rv)
	}

	rv, _ := callC(t, C_Verify, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Verify(pSignature=NULL, ulSignatureLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerify_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_Verify, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_Verify with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCVerifyFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_VerifyFinal, cScalar(uint64(f.session)), cNull(), cScalar(0))
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_VerifyFinal with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

func TestCSignRecover_NullLengthPointerTerminatesTheOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_SignRecover, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SignRecover(pulSignatureLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerifyRecover_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_VerifyRecover, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_VerifyRecover(pulDataLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// ============================================================================
// C_EncryptUpdate / C_DecryptUpdate / C_EncryptFinal / C_DecryptFinal /
// C_SignUpdate / C_SignFinal: the null-length-pointer refusal every streaming
// and terminal function shares.
// ============================================================================

func TestStreamingAndFinal_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		fn   any
		args []cArg
	}{
		{"C_EncryptUpdate", C_EncryptUpdate, []cArg{cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull()}},
		{"C_DecryptUpdate", C_DecryptUpdate, []cArg{cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull()}},
		{"C_EncryptFinal", C_EncryptFinal, []cArg{cScalar(uint64(f.session)), cNull(), cNull()}},
		{"C_DecryptFinal", C_DecryptFinal, []cArg{cScalar(uint64(f.session)), cNull(), cNull()}},
		{"C_SignFinal", C_SignFinal, []cArg{cScalar(uint64(f.session)), cNull(), cNull()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, tc.fn, tc.args...)
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("%s(length pointer = NULL) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestCSignUpdate_NullPartWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_SignUpdate, cScalar(uint64(f.session)), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SignUpdate(NULL, 16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCVerifyUpdate_NullPartWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_VerifyUpdate, cScalar(uint64(f.session)), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_VerifyUpdate(NULL, 16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// ============================================================================
// C_GetFunctionStatus / C_CancelFunction: legacy parallel-function stubs.
// ============================================================================

func TestCDigestKey_InvalidSession(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_DigestKey, cScalar(0xDEADBEEF), cScalar(0))
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_DigestKey(unknown session) = %s, want CKR_SESSION_HANDLE_INVALID", rv)
	}
}

func TestGetFunctionList30Ptr_AndV32Ptr_AreNonNil(t *testing.T) {
	// These wrap a cgo call whose return type (CK_FUNCTION_LIST_3_0_PTR /
	// CK_FUNCTION_LIST_3_2_PTR) a _test.go file cannot name directly (Go 1.26
	// forbids `import "C"` there), but calling them and letting `:=` infer
	// the type needs no such name. C_GetInterface's version-negotiation
	// switch is the only caller today (major==3, minor==0 or minor==2); this
	// pins that the C struct each resolves to is populated and non-NULL on
	// its own, independent of which branch of that switch runs in a given
	// test.
	if ptr := GetFunctionList30Ptr(); ptr == nil {
		t.Fatal("GetFunctionList30Ptr returned NULL")
	}
	if ptr := GetFunctionList32Ptr(); ptr == nil {
		t.Fatal("GetFunctionList32Ptr returned NULL")
	}
}

func TestLegacyParallelFunctions_AlwaysNotParallel(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GetFunctionStatus, cScalar(uint64(f.session)))
	if rv != module.CKR_FUNCTION_NOT_PARALLEL {
		t.Fatalf("C_GetFunctionStatus = %s, want CKR_FUNCTION_NOT_PARALLEL", rv)
	}

	rv, _ = callC(t, C_CancelFunction, cScalar(uint64(f.session)))
	if rv != module.CKR_FUNCTION_NOT_PARALLEL {
		t.Fatalf("C_CancelFunction = %s, want CKR_FUNCTION_NOT_PARALLEL", rv)
	}
}
