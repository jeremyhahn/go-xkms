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

// Tests for every branch of C_GetInterface (PKCS#11 v3.2 §5.2.2): the
// version-negotiation switch it drives has no dependency on module state, so
// each case is reachable directly rather than only through the NULL-argument
// guards other tests in this package confine themselves to.

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// buildCKVersion lays out a CK_VERSION { CK_BYTE major; CK_BYTE minor; }
// (v3.2 section 3.2, pkcs11t.h) as a two-byte buffer.
func buildCKVersion(major, minor byte) []byte {
	return []byte{major, minor}
}

// getInterfaceViaC drives C_GetInterface with the given interface name
// ("" for NULL), version (nil for NULL) and flags.
func getInterfaceViaC(t *testing.T, name string, version []byte, flags uint64) module.CK_RV {
	t.Helper()
	fn := reflect.ValueOf(C_GetInterface)
	ft := fn.Type()

	var nameArg reflect.Value
	if name == "" {
		nameArg = reflect.Zero(ft.In(0))
	} else {
		nameBytes := append([]byte(name), 0) // NUL-terminated, per C_GetInterface's C.GoString read.
		nameArg = setBufferPtr(nameBytes, ft, 0)
		defer runtime.KeepAlive(nameBytes)
	}

	var versionArg reflect.Value
	if version == nil {
		versionArg = reflect.Zero(ft.In(1))
	} else {
		versionArg = setBufferPtr(version, ft, 1)
		defer runtime.KeepAlive(version)
	}

	out := fn.Call([]reflect.Value{
		nameArg,
		versionArg,
		allocOf(ft, 2),
		scalarOf(ft, 3, flags),
	})
	return module.CK_RV(out[0].Uint())
}

func TestCGetInterface_NullOutputIsRefused(t *testing.T) {
	fn := reflect.ValueOf(C_GetInterface)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		reflect.Zero(ft.In(0)),
		reflect.Zero(ft.In(1)),
		reflect.Zero(ft.In(2)),
		scalarOf(ft, 3, 0),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterface(ppInterface=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetInterface_NonzeroFlagsIsRefused(t *testing.T) {
	if rv := getInterfaceViaC(t, "", nil, 0x00000001); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterface(flags=CKF_INTERFACE_FORK_SAFE) = %s, want CKR_ARGUMENTS_BAD: "+
			"this module publishes no fork-safe interface", rv)
	}
}

func TestCGetInterface_NullNameReturnsDefault(t *testing.T) {
	if rv := getInterfaceViaC(t, "", nil, 0); rv != module.CKR_OK {
		t.Fatalf("C_GetInterface(pInterfaceName=NULL) = %s, want CKR_OK", rv)
	}
}

func TestCGetInterface_UnknownNameIsRefused(t *testing.T) {
	if rv := getInterfaceViaC(t, "not a real interface", nil, 0); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterface(unknown name) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetInterface_KnownNameNullVersionReturnsLatest(t *testing.T) {
	if rv := getInterfaceViaC(t, "PKCS 11", nil, 0); rv != module.CKR_OK {
		t.Fatalf(`C_GetInterface("PKCS 11", pVersion=NULL) = %s, want CKR_OK`, rv)
	}
}

func TestCGetInterface_VersionNegotiation(t *testing.T) {
	cases := []struct {
		name         string
		major, minor byte
		want         module.CK_RV
	}{
		{"v2.x", 2, 40, module.CKR_OK},
		{"v3.0", 3, 0, module.CKR_OK},
		{"v3.2", 3, 2, module.CKR_OK},
		{"unsupported v3.1", 3, 1, module.CKR_ARGUMENTS_BAD},
		{"unsupported v4.0", 4, 0, module.CKR_ARGUMENTS_BAD},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := buildCKVersion(tc.major, tc.minor)
			if rv := getInterfaceViaC(t, "PKCS 11", version, 0); rv != tc.want {
				t.Fatalf("C_GetInterface(v%d.%d) = %s, want %s", tc.major, tc.minor, rv, tc.want)
			}
		})
	}
}
