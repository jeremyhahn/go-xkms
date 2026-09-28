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

// Tests for C_WrapKeyAuthenticated's error branches past the NULL-argument
// guards exports_v32_kem_wrap_test.go's checks reach: a malformed mechanism
// parameter, and an invalid wrapping key handle on both the size-query and
// real-buffer legs.
//
// module_authwrap.go performs the AES-GCM wrap itself from each key's own
// CKA_VALUE rather than through the backend transport (see its package
// comment, also quoted in exports_cryptoroundtrip_test.go), so these tests
// use the offlineTransport fixture like the rest of this package's
// argument-marshalling tests rather than pkcs11test.CryptoMockClient.

import (
	"math"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestCWrapKeyAuthenticated_MalformedMechanismParamIsRefused proves a
// CK_GCM_MESSAGE_PARAMS shorter than the structure requires is refused with
// CKR_MECHANISM_PARAM_INVALID by authenticatedWrapMechanism, before any key
// lookup.
func TestCWrapKeyAuthenticated_MalformedMechanismParamIsRefused(t *testing.T) {
	f := newTestFixture(t)

	shortParam := make([]byte, 8) // CK_GCM_MESSAGE_PARAMS is 48 bytes.
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, shortParam)

	fn := reflect.ValueOf(C_WrapKeyAuthenticated)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(f.privKey)),
		scalarOf(ft, 3, uint64(f.privKey)),
		reflect.Zero(ft.In(4)),
		scalarOf(ft, 5, 0),
		reflect.Zero(ft.In(6)),
		allocOf(ft, 7),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_WrapKeyAuthenticated(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}

// TestCWrapKeyAuthenticated_InvalidWrappingKeyIsRefused proves an invalid
// wrapping key handle is refused with CKR_WRAPPING_KEY_HANDLE_INVALID on
// both the size-query leg (pWrappedKey=NULL) and the real-buffer leg, which
// answer through separate WrapKeyAuthenticatedSize call sites in
// exports_v32.go.
func TestCWrapKeyAuthenticated_InvalidWrappingKeyIsRefused(t *testing.T) {
	f := newTestFixture(t)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, nil, 0, module.CKG_NO_GENERATE, nil, 0))

	fn := reflect.ValueOf(C_WrapKeyAuthenticated)
	ft := fn.Type()

	t.Run("query mode", func(t *testing.T) {
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, 0xDEADBEEF),
			scalarOf(ft, 3, uint64(f.privKey)),
			reflect.Zero(ft.In(4)),
			scalarOf(ft, 5, 0),
			reflect.Zero(ft.In(6)),
			allocOf(ft, 7),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_WRAPPING_KEY_HANDLE_INVALID {
			t.Fatalf("C_WrapKeyAuthenticated(invalid wrapping key, query) = %s, want CKR_WRAPPING_KEY_HANDLE_INVALID", rv)
		}
	})

	t.Run("real buffer", func(t *testing.T) {
		wrappedBuf := make([]byte, 64)
		fillLen := reflect.New(ft.In(7).Elem())
		fillLen.Elem().SetUint(uint64(len(wrappedBuf)))
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, 0xDEADBEEF),
			scalarOf(ft, 3, uint64(f.privKey)),
			reflect.Zero(ft.In(4)),
			scalarOf(ft, 5, 0),
			setBufferPtr(wrappedBuf, ft, 6),
			fillLen,
		})
		runtime.KeepAlive(wrappedBuf)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_WRAPPING_KEY_HANDLE_INVALID {
			t.Fatalf("C_WrapKeyAuthenticated(invalid wrapping key, real buffer) = %s, want CKR_WRAPPING_KEY_HANDLE_INVALID", rv)
		}
	})

}

// TestCUnwrapKeyAuthenticated_InvalidUnwrappingKeyIsRefused proves an
// invalid unwrapping key handle is refused with
// CKR_UNWRAPPING_KEY_HANDLE_INVALID.
func TestCUnwrapKeyAuthenticated_InvalidUnwrappingKeyIsRefused(t *testing.T) {
	f := newTestFixture(t)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, []byte("authwrap-iv1"), 0, module.CKG_NO_GENERATE, nil, 0))
	wrappedKey := make([]byte, 32)
	template := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
	})

	fn := reflect.ValueOf(C_UnwrapKeyAuthenticated)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, 0xDEADBEEF),
		setBufferPtr(wrappedKey, ft, 3),
		scalarOf(ft, 4, uint64(len(wrappedKey))),
		cAttributePtr(template, ft, 5),
		scalarOf(ft, 6, attrCount(template)),
		reflect.Zero(ft.In(7)),
		scalarOf(ft, 8, 0),
		allocOf(ft, 9),
	})
	runtime.KeepAlive(wrappedKey)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_UNWRAPPING_KEY_HANDLE_INVALID {
		t.Fatalf("C_UnwrapKeyAuthenticated(invalid unwrapping key) = %s, want CKR_UNWRAPPING_KEY_HANDLE_INVALID", rv)
	}
}

// TestCUnwrapKeyAuthenticated_ArgumentValidation covers
// C_UnwrapKeyAuthenticated's argument-marshalling branches past NULL
// pMechanism/phKey/pWrappedKey (exports_v32_kem_wrap_test.go): a NULL
// pAssociatedData with a nonzero declared length, a malformed mechanism
// parameter, and a template whose declared count overflows a Go slice
// index.
func TestCUnwrapKeyAuthenticated_ArgumentValidation(t *testing.T) {
	f := newTestFixture(t)
	wrappedKey := make([]byte, 32)

	t.Run("NULL associated data with nonzero length", func(t *testing.T) {
		mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, []byte("authwrap-ivvv"), 0, module.CKG_NO_GENERATE, nil, 0))
		fn := reflect.ValueOf(C_UnwrapKeyAuthenticated)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(f.privKey)),
			setBufferPtr(wrappedKey, ft, 3),
			scalarOf(ft, 4, uint64(len(wrappedKey))),
			reflect.Zero(ft.In(5)),
			scalarOf(ft, 6, 0),
			reflect.Zero(ft.In(7)),
			scalarOf(ft, 8, 16),
			allocOf(ft, 9),
		})
		runtime.KeepAlive(wrappedKey)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_UnwrapKeyAuthenticated(pAssociatedData=NULL, len=16) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})

	t.Run("malformed mechanism param", func(t *testing.T) {
		shortParam := make([]byte, 8)
		mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, shortParam)
		fn := reflect.ValueOf(C_UnwrapKeyAuthenticated)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(f.privKey)),
			setBufferPtr(wrappedKey, ft, 3),
			scalarOf(ft, 4, uint64(len(wrappedKey))),
			reflect.Zero(ft.In(5)),
			scalarOf(ft, 6, 0),
			reflect.Zero(ft.In(7)),
			scalarOf(ft, 8, 0),
			allocOf(ft, 9),
		})
		runtime.KeepAlive(wrappedKey)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_UnwrapKeyAuthenticated(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("template count overflow", func(t *testing.T) {
		mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, []byte("authwrap-ivvv"), 0, module.CKG_NO_GENERATE, nil, 0))
		template := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
		fn := reflect.ValueOf(C_UnwrapKeyAuthenticated)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(f.privKey)),
			setBufferPtr(wrappedKey, ft, 3),
			scalarOf(ft, 4, uint64(len(wrappedKey))),
			cAttributePtr(template, ft, 5),
			scalarOf(ft, 6, uint64(math.MaxInt32)+1),
			reflect.Zero(ft.In(7)),
			scalarOf(ft, 8, 0),
			allocOf(ft, 9),
		})
		runtime.KeepAlive(wrappedKey)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_UnwrapKeyAuthenticated(ulAttributeCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})
}
