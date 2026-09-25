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

// Tests for the PKCS#11 v3.2 KEM (C_EncapsulateKey) and authenticated
// wrap/unwrap (C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated,
// C_AsyncJoin) entry points' argument-marshalling branches, reachable
// without a hand-built CK_MECHANISM/CK_GCM_MESSAGE_PARAMS (see
// exports_paramdecode_test.go for why those are out of reach from a
// _test.go file).

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestCEncapsulateKey_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		args []cArg
	}{
		{"pMechanism=NULL", []cArg{cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc(), cAlloc()}},
		{"pulCiphertextLen=NULL", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(0), cNull(), cScalar(0), cNull(), cNull(), cAlloc()}},
		{"phKey=NULL", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(0), cNull(), cScalar(0), cNull(), cAlloc(), cNull()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, C_EncapsulateKey, tc.args...)
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("C_EncapsulateKey(%s) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestAuthenticatedWrapMechanism_NilIsRefused(t *testing.T) {
	fn := reflect.ValueOf(authenticatedWrapMechanism)
	ft := fn.Type()

	out := fn.Call([]reflect.Value{reflect.Zero(ft.In(0))})
	if !out[0].IsNil() {
		t.Errorf("authenticatedWrapMechanism(NULL) mech = %v, want nil", out[0].Interface())
	}
	if got := module.CK_RV(out[1].Uint()); got != module.CKR_ARGUMENTS_BAD {
		t.Errorf("authenticatedWrapMechanism(NULL) = %s, want CKR_ARGUMENTS_BAD", got)
	}
}

func TestWriteAuthenticatedWrapIV_NilMechanismPtrIsANoOp(t *testing.T) {
	fn := reflect.ValueOf(writeAuthenticatedWrapIV)
	ft := fn.Type()

	out := fn.Call([]reflect.Value{reflect.Zero(ft.In(0)), reflect.Zero(ft.In(1))})
	if got := module.CK_RV(out[0].Uint()); got != module.CKR_OK {
		t.Errorf("writeAuthenticatedWrapIV(NULL, nil) = %s, want CKR_OK", got)
	}
}

func TestCWrapKeyAuthenticated_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		args []cArg
	}{
		{"pMechanism=NULL", []cArg{cScalar(uint64(f.session)), cNull(), cScalar(uint64(f.privKey)), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cAlloc()}},
		{"pulWrappedKeyLen=NULL", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cNull()}},
		{"pAssociatedData=NULL,len>0", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cScalar(uint64(f.privKey)), cNull(), cScalar(16), cNull(), cAlloc()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, C_WrapKeyAuthenticated, tc.args...)
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("C_WrapKeyAuthenticated(%s) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestCUnwrapKeyAuthenticated_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		args []cArg
	}{
		{"pMechanism=NULL", []cArg{cScalar(uint64(f.session)), cNull(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cAlloc()}},
		{"phKey=NULL", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cNull()}},
		{"pWrappedKey=NULL", []cArg{cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cScalar(0), cAlloc()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, C_UnwrapKeyAuthenticated, tc.args...)
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("C_UnwrapKeyAuthenticated(%s) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestCAsyncJoin_NullArgumentsAreRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_AsyncJoin, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncJoin(pFunctionName=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	rv, _ = callC(t, C_AsyncJoin, cScalar(uint64(f.session)), cAlloc(), cScalar(0), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncJoin(pData=NULL, ulData=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCAsyncJoin_EmptyFunctionNameIsRefused(t *testing.T) {
	f := newTestFixture(t)
	rv, _ := callC(t, C_AsyncJoin, cScalar(uint64(f.session)), cAlloc(), cScalar(0), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_AsyncJoin(functionName=\"\") = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}
