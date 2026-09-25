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

// Tests for C_Initialize and C_Finalize. newTestFixture (exports_test.go)
// already leaves the global module initialized for every other test in this
// package, which doubles as the fixture these two need: C_Initialize on an
// already-initialized module is the one branch reachable without either
// standing up a real transport (offlineModeRequested's embedded-service path)
// or tearing down every other test's shared setup, and C_Finalize's success
// path is safe to exercise precisely because it runs last, with
// module.ResetGlobalModule already registered via t.Cleanup.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestCInitialize_NullArgsOnAlreadyInitializedModule(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_Initialize, cNull())
	if rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Fatalf("C_Initialize(NULL) on an initialized module = %s, want CKR_CRYPTOKI_ALREADY_INITIALIZED", rv)
	}
}

// TestCInitialize_ZeroedArgsStruct proves a non-NULL pInitArgs whose fields
// are all zero (no mutex callbacks, no locking flag, no reserved pointer)
// passes CK_C_INITIALIZE_ARGS' own validation and reaches the same
// already-initialized module check as the NULL case, exercising the
// pInitArgs != nil branch's field reads. The buffer is oversized and zeroed
// rather than built to the exact struct layout, since cgo gives every field
// of it an unexported Go name (see exports_paramdecode_test.go) and a
// zeroed buffer answers "no callbacks, no reserved pointer" regardless of
// the platform's exact field offsets.
func TestCInitialize_ZeroedArgsStruct(t *testing.T) {
	newTestFixture(t)

	fn := reflect.ValueOf(C_Initialize)
	ft := fn.Type()

	var buf [128]byte
	out := fn.Call([]reflect.Value{cPtr(unsafe.Pointer(&buf[0]), ft, 0)})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Fatalf("C_Initialize(zeroed args) on an initialized module = %s, want CKR_CRYPTOKI_ALREADY_INITIALIZED", rv)
	}
}

func TestCFinalize_NonNullReservedIsRefused(t *testing.T) {
	newTestFixture(t)

	var buf [8]byte
	fn := reflect.ValueOf(C_Finalize)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{cPtr(unsafe.Pointer(&buf[0]), ft, 0)})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Finalize(non-NULL pReserved) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCFinalize_Success proves C_Finalize actually tears the module down
// when called correctly. It must run last: module.ResetGlobalModule is
// already registered via newTestFixture's t.Cleanup, so a finalized module
// here does not leak into any other test.
func TestCFinalize_Success(t *testing.T) {
	newTestFixture(t)

	rv, _ := callC(t, C_Finalize, cNull())
	if rv != module.CKR_OK {
		t.Fatalf("C_Finalize(NULL) = %s, want CKR_OK", rv)
	}

	// A second Finalize on an already-finalized module must be refused
	// rather than succeed again or panic.
	rv, _ = callC(t, C_Finalize, cNull())
	if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
		t.Fatalf("C_Finalize(NULL) on an already-finalized module = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rv)
	}
}
