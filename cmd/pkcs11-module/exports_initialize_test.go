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

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// initializeArgs mirrors CK_C_INITIALIZE_ARGS (PKCS#11 v3.2 §5.6.1): four
// mutex callbacks, the flags word and pReserved.
type initializeArgs struct {
	createMutex  unsafe.Pointer
	destroyMutex unsafe.Pointer
	lockMutex    unsafe.Pointer
	unlockMutex  unsafe.Pointer
	flags        uint64
	reserved     unsafe.Pointer
}

// ckfOSLockingOK is CKF_OS_LOCKING_OK (v3.2 §5.6.1).
const ckfOSLockingOK = 0x00000002

// callbackStandIn gives the mutex callbacks a valid, non-NULL address. The
// module only checks whether each one is NULL and never calls them.
var callbackStandIn byte

// TestInitialize_RefusesMalformedArguments pins C_Initialize's refusals of
// CK_C_INITIALIZE_ARGS (v3.2 §5.6.1), each answered before the module is
// touched: a non-NULL pReserved and a partial callback set are
// CKR_ARGUMENTS_BAD, and a full callback set without CKF_OS_LOCKING_OK is
// CKR_CANT_LOCK, because the module never calls application mutexes.
func TestInitialize_RefusesMalformedArguments(t *testing.T) {
	cb := unsafe.Pointer(&callbackStandIn)
	tests := []struct {
		name string
		args initializeArgs
		want module.CK_RV
	}{
		{"reserved pointer set", initializeArgs{reserved: cb, flags: ckfOSLockingOK}, module.CKR_ARGUMENTS_BAD},
		{"only CreateMutex", initializeArgs{createMutex: cb}, module.CKR_ARGUMENTS_BAD},
		{"three of four callbacks", initializeArgs{createMutex: cb, destroyMutex: cb, lockMutex: cb, flags: ckfOSLockingOK}, module.CKR_ARGUMENTS_BAD},
		{"CreateMutex missing only", initializeArgs{destroyMutex: cb, lockMutex: cb, unlockMutex: cb}, module.CKR_ARGUMENTS_BAD},
		{"all callbacks without OS locking", initializeArgs{createMutex: cb, destroyMutex: cb, lockMutex: cb, unlockMutex: cb}, module.CKR_CANT_LOCK},
	}
	ft := reflect.TypeOf(C_Initialize)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			out := reflect.ValueOf(C_Initialize).Call([]reflect.Value{
				reflect.ValueOf(unsafe.Pointer(&args)).Convert(ft.In(0)),
			})
			if rv := module.CK_RV(out[0].Uint()); rv != tt.want {
				t.Fatalf("C_Initialize(%s) = %s, want %s", tt.name, rv, tt.want)
			}
		})
	}
}
