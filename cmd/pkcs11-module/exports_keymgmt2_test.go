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

// Extends exports_keymgmt_test.go's coverage of C_GenerateKey/
// C_GenerateKeyPair/C_WrapKey/C_UnwrapKey/C_DeriveKey past the NULL-argument
// guards, which that file's doc comment explains are as far as it could
// reach: building a CK_ATTRIBUTE template requires setting cgo's unexported
// struct fields by reflection, which is not possible from a _test.go file.
//
// A bare CK_MECHANISM has no such obstacle. It is three scalar/pointer fields
// with no nested structure, so it can be laid out as a byte buffer at its
// field offsets exactly as exports_mechdecode_test.go does for every CK_MECHANISM
// *parameter* structure, and exports_template_test.go's cAttributePtr pattern
// converts the resulting address into the exact CK_MECHANISM_PTR-shaped type
// each entry point expects. That unblocks the next branch in every one of
// these functions: with a well-formed, parameterless mechanism (e.g.
// CKM_AES_KEY_GEN) admitted by convertCMechanismToGo, the call reaches
// Module's own session lookup and is refused with CKR_SESSION_HANDLE_INVALID
// for an unknown session -- without an empty template (nil, 0 is always
// well-formed, see TestReadCAttributeArray_ZeroLengthIsEmpty's sibling
// convertCTemplateToGo behaviour) and without ever reaching the absent
// backend transport.
//
// CK_MECHANISM (v3.2 section 5.2, pkcs11t.h):
//
//	CK_MECHANISM_TYPE mechanism;   offset 0,  8 bytes
//	CK_VOID_PTR pParameter;        offset 8,  8 bytes
//	CK_ULONG ulParameterLen;       offset 16, 8 bytes
//
// total 24 bytes.

import (
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

const cMechanismSize = 24

// buildCMechanism lays out a parameterless CK_MECHANISM selecting mechType.
func buildCMechanism(mechType module.MechanismType) []byte {
	buf := newAlignedBuf(cMechanismSize)
	putULong(buf, 0, uint64(mechType))
	return buf
}

// cMechanismPtr converts buf's address into a Value of the exact
// CK_MECHANISM_PTR-shaped type fnType's argIdx-th parameter expects, the same
// way exports_template_test.go's cAttributePtr does for CK_ATTRIBUTE_PTR:
// cgo's typedef is a genuine Go type alias for *C.struct_CK_MECHANISM, so
// reflect.NewAt at the pointer's element type produces a Value already of
// that exact type.
func cMechanismPtr(buf []byte, fnType reflect.Type, argIdx int) reflect.Value {
	elemType := fnType.In(argIdx).Elem()
	return reflect.NewAt(elemType, unsafe.Pointer(&buf[0]))
}

// scalarOf builds a zeroed argument of fnType's argIdx-th parameter type set
// to v -- the reflect equivalent of callC's cScalar, usable here because
// these calls also need a real CK_MECHANISM_PTR argument, which is outside
// callC's cArg vocabulary (scalar, NULL, or a freshly zeroed allocation).
func scalarOf(fnType reflect.Type, argIdx int, v uint64) reflect.Value {
	arg := reflect.New(fnType.In(argIdx)).Elem()
	arg.SetUint(v)
	return arg
}

// allocOf builds a freshly zeroed output argument of fnType's argIdx-th
// (pointer) parameter type -- the reflect equivalent of callC's cAlloc.
func allocOf(fnType reflect.Type, argIdx int) reflect.Value {
	return reflect.New(fnType.In(argIdx).Elem())
}

// TestKeyManagement_InvalidSessionIsReportedWithAWellFormedMechanism proves
// that once a real CK_MECHANISM clears convertCMechanismToGo, each of these
// five entry points forwards to Module rather than short-circuiting, and
// Module's own session lookup answers CKR_SESSION_HANDLE_INVALID for a
// session handle that names nothing.
func TestKeyManagement_InvalidSessionIsReportedWithAWellFormedMechanism(t *testing.T) {
	newTestFixture(t)
	buf := buildCMechanism(module.CKM_AES_KEY_GEN)
	const unknownSession = 0xDEADBEEF

	cases := []struct {
		name string
		fn   any
		args func(ft reflect.Type, mech reflect.Value) []reflect.Value
	}{
		{"C_GenerateKey", C_GenerateKey, func(ft reflect.Type, mech reflect.Value) []reflect.Value {
			return []reflect.Value{
				scalarOf(ft, 0, unknownSession), mech,
				reflect.Zero(ft.In(2)), scalarOf(ft, 3, 0),
				allocOf(ft, 4),
			}
		}},
		{"C_GenerateKeyPair", C_GenerateKeyPair, func(ft reflect.Type, mech reflect.Value) []reflect.Value {
			return []reflect.Value{
				scalarOf(ft, 0, unknownSession), mech,
				reflect.Zero(ft.In(2)), scalarOf(ft, 3, 0),
				reflect.Zero(ft.In(4)), scalarOf(ft, 5, 0),
				allocOf(ft, 6), allocOf(ft, 7),
			}
		}},
		{"C_WrapKey", C_WrapKey, func(ft reflect.Type, mech reflect.Value) []reflect.Value {
			return []reflect.Value{
				scalarOf(ft, 0, unknownSession), mech,
				scalarOf(ft, 2, 0), scalarOf(ft, 3, 0),
				reflect.Zero(ft.In(4)), allocOf(ft, 5),
			}
		}},
		{"C_UnwrapKey", C_UnwrapKey, func(ft reflect.Type, mech reflect.Value) []reflect.Value {
			return []reflect.Value{
				scalarOf(ft, 0, unknownSession), mech,
				scalarOf(ft, 2, 0), reflect.Zero(ft.In(3)), scalarOf(ft, 4, 0),
				reflect.Zero(ft.In(5)), scalarOf(ft, 6, 0),
				allocOf(ft, 7),
			}
		}},
		{"C_DeriveKey", C_DeriveKey, func(ft reflect.Type, mech reflect.Value) []reflect.Value {
			return []reflect.Value{
				scalarOf(ft, 0, unknownSession), mech,
				scalarOf(ft, 2, 0), reflect.Zero(ft.In(3)), scalarOf(ft, 4, 0),
				allocOf(ft, 5),
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft := reflect.ValueOf(tc.fn).Type()
			mech := cMechanismPtr(buf, ft, 1)
			out := reflect.ValueOf(tc.fn).Call(tc.args(ft, mech))
			runtime.KeepAlive(buf)

			if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_SESSION_HANDLE_INVALID {
				t.Fatalf("%s(unknown session, well-formed mechanism) = %s, want CKR_SESSION_HANDLE_INVALID", tc.name, rv)
			}
		})
	}
}
