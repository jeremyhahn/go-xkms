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

// Tests for the general-purpose, slot and token query entry points in
// exports.go: argument marshalling (null required pointers, the two-call
// buffer-too-small idiom) and their success paths.
//
// As exports_test.go explains, Go 1.26 forbids `import "C"` in a _test.go
// file, so these drive the real exported functions through reflection
// (callExport / callC, both defined alongside the other exports_*_test.go
// files in this package) rather than a Go-only stand-in.

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// setArrayArg returns a callExport setter that points a pointer argument at a
// freshly allocated, zeroed Go array of n elements of the pointer's pointee
// type, and records the allocation in *out so the caller can inspect what the
// entry point wrote. reflect.New(reflect.ArrayOf(...)) builds real, correctly
// sized and aligned memory for the parameter's own cgo-generated type without
// the test ever naming it, which is what setBufferArg (exports_random_test.go)
// already does for a caller-supplied []byte; this is the same trick
// generalized to an element type the test does not control, including a cgo
// struct such as CK_INTERFACE.
func setArrayArg(n int, out *reflect.Value) func(reflect.Value) {
	return func(v reflect.Value) {
		elemType := v.Type().Elem()
		arr := reflect.New(reflect.ArrayOf(n, elemType))
		*out = arr
		v.Set(arr.Elem().Index(0).Addr())
	}
}

// ============================================================================
// C_GetInfo / C_GetFunctionList
// ============================================================================

func TestCGetInfo_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetInfo, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInfo(NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetInfo_Success(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetInfo, map[int]func(reflect.Value){
		0: setArrayArg(1, &infoAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetInfo = %s, want CKR_OK", rv)
	}
}

func TestCGetFunctionList_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetFunctionList, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetFunctionList(NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetFunctionList_Success(t *testing.T) {
	newTestFixture(t)

	var listAlloc reflect.Value
	rv := callExport(t, C_GetFunctionList, map[int]func(reflect.Value){
		0: setArrayArg(1, &listAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetFunctionList = %s, want CKR_OK", rv)
	}
	// The function list pointer itself must be non-nil: a caller that
	// dereferences it to find C_Initialize et al. must not follow a NULL.
	if listAlloc.Elem().Index(0).IsNil() {
		t.Fatal("C_GetFunctionList wrote a NULL *CK_FUNCTION_LIST")
	}
}

// ============================================================================
// C_GetInterfaceList / C_GetInterface
// ============================================================================

func TestCGetInterfaceList_NullCountIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetInterfaceList, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterfaceList(pulCount=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetInterfaceList_LengthQuery(t *testing.T) {
	newTestFixture(t)

	var countAlloc reflect.Value
	rv := callExport(t, C_GetInterfaceList, map[int]func(reflect.Value){
		1: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetInterfaceList(pInterfacesList=NULL) = %s, want CKR_OK", rv)
	}
	if got := countAlloc.Elem().Uint(); got != 3 {
		t.Fatalf("C_GetInterfaceList length query reported %d interfaces, want 3", got)
	}
}

func TestCGetInterfaceList_BufferTooSmallReportsRequiredCount(t *testing.T) {
	newTestFixture(t)

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetInterfaceList, map[int]func(reflect.Value){
		0: setArrayArg(2, &listAlloc),
		1: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(2)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_GetInterfaceList(*pulCount=2) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := countAlloc.Elem().Uint(); got != 3 {
		t.Fatalf("C_GetInterfaceList(BUFFER_TOO_SMALL) reported required count %d, want 3", got)
	}
}

func TestCGetInterfaceList_SuccessFillsEveryInterface(t *testing.T) {
	newTestFixture(t)

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetInterfaceList, map[int]func(reflect.Value){
		0: setArrayArg(3, &listAlloc),
		1: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(3)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetInterfaceList(*pulCount=3) = %s, want CKR_OK", rv)
	}
	if got := countAlloc.Elem().Uint(); got != 3 {
		t.Fatalf("C_GetInterfaceList wrote count %d, want 3", got)
	}
}

func TestCGetInterface_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetInterface, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterface(ppInterface=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetInterface_RefusesNonzeroFlags(t *testing.T) {
	newTestFixture(t)

	var ifaceAlloc reflect.Value
	rv := callExport(t, C_GetInterface, map[int]func(reflect.Value){
		2: setArrayArg(1, &ifaceAlloc),
		3: func(v reflect.Value) { v.SetUint(1) }, // CKF_INTERFACE_FORK_SAFE
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetInterface(flags=1) = %s, want CKR_ARGUMENTS_BAD; this module publishes no fork-safe interface", rv)
	}
}

func TestCGetInterface_DefaultsToLatestWhenNameAndVersionAreNull(t *testing.T) {
	newTestFixture(t)

	var ifaceAlloc reflect.Value
	rv := callExport(t, C_GetInterface, map[int]func(reflect.Value){
		2: setArrayArg(1, &ifaceAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetInterface(NULL, NULL) = %s, want CKR_OK", rv)
	}
	if ifaceAlloc.Elem().Index(0).IsNil() {
		t.Fatal("C_GetInterface(NULL, NULL) wrote a NULL *CK_INTERFACE")
	}
}

// ============================================================================
// C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo
// ============================================================================

func TestCGetSlotList_NullCountIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetSlotList, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetSlotList(pulCount=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// slotCount runs the C_GetSlotList length query and returns how many slots
// this module reports, so the buffer-too-small and success cases below are
// not hard-coded against the fixture's slot topology.
func slotCount(t *testing.T) uint64 {
	t.Helper()
	var countAlloc reflect.Value
	rv := callExport(t, C_GetSlotList, map[int]func(reflect.Value){
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetSlotList length query = %s, want CKR_OK", rv)
	}
	return countAlloc.Elem().Uint()
}

func TestCGetSlotList_BufferTooSmallReportsRequiredCount(t *testing.T) {
	f := newTestFixture(t)
	_ = f

	want := slotCount(t)
	if want == 0 {
		t.Skip("module reports no slots; nothing to undersize")
	}

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetSlotList, map[int]func(reflect.Value){
		1: setArrayArg(int(want), &listAlloc),
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(want - 1)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_GetSlotList(*pulCount=%d) = %s, want CKR_BUFFER_TOO_SMALL", want-1, rv)
	}
	if got := countAlloc.Elem().Uint(); got != want {
		t.Fatalf("C_GetSlotList(BUFFER_TOO_SMALL) reported required count %d, want %d", got, want)
	}
}

func TestCGetSlotList_SuccessFillsSlotArray(t *testing.T) {
	newTestFixture(t)

	want := slotCount(t)
	if want == 0 {
		t.Skip("module reports no slots")
	}

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetSlotList, map[int]func(reflect.Value){
		1: setArrayArg(int(want), &listAlloc),
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(want)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetSlotList(*pulCount=%d) = %s, want CKR_OK", want, rv)
	}
	// Slot 0 is the fixture's provisioned token and must be among the slots
	// reported.
	found := false
	for i := 0; i < int(want); i++ {
		if listAlloc.Elem().Index(i).Uint() == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("C_GetSlotList did not report slot 0")
	}
}

func TestCGetSlotInfo_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetSlotInfo, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetSlotInfo(pInfo=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetSlotInfo_Success(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetSlotInfo, map[int]func(reflect.Value){
		1: setArrayArg(1, &infoAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetSlotInfo(slot 0) = %s, want CKR_OK", rv)
	}
}

func TestCGetSlotInfo_InvalidSlot(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetSlotInfo, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(0xFFFFFFFF) },
		1: setArrayArg(1, &infoAlloc),
	})
	if rv == module.CKR_OK {
		t.Fatal("C_GetSlotInfo accepted a slot ID that names no slot")
	}
}

func TestCGetTokenInfo_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetTokenInfo, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetTokenInfo(pInfo=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetTokenInfo_Success(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetTokenInfo, map[int]func(reflect.Value){
		1: setArrayArg(1, &infoAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetTokenInfo(slot 0) = %s, want CKR_OK: the fixture provisions a token on slot 0", rv)
	}
}

// ============================================================================
// C_GetMechanismList / C_GetMechanismInfo
// ============================================================================

func TestCGetMechanismList_NullCountIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetMechanismList, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetMechanismList(pulCount=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func mechanismCount(t *testing.T) uint64 {
	t.Helper()
	var countAlloc reflect.Value
	rv := callExport(t, C_GetMechanismList, map[int]func(reflect.Value){
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetMechanismList length query = %s, want CKR_OK", rv)
	}
	return countAlloc.Elem().Uint()
}

func TestCGetMechanismList_BufferTooSmallReportsRequiredCount(t *testing.T) {
	newTestFixture(t)

	want := mechanismCount(t)
	if want == 0 {
		t.Skip("module reports no mechanisms; nothing to undersize")
	}

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetMechanismList, map[int]func(reflect.Value){
		1: setArrayArg(int(want), &listAlloc),
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(want - 1)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_GetMechanismList(*pulCount=%d) = %s, want CKR_BUFFER_TOO_SMALL", want-1, rv)
	}
	if got := countAlloc.Elem().Uint(); got != want {
		t.Fatalf("C_GetMechanismList(BUFFER_TOO_SMALL) reported required count %d, want %d", got, want)
	}
}

func TestCGetMechanismList_Success(t *testing.T) {
	newTestFixture(t)

	want := mechanismCount(t)
	if want == 0 {
		t.Skip("module reports no mechanisms")
	}

	var listAlloc, countAlloc reflect.Value
	rv := callExport(t, C_GetMechanismList, map[int]func(reflect.Value){
		1: setArrayArg(int(want), &listAlloc),
		2: func(v reflect.Value) {
			countAlloc = reflect.New(v.Type().Elem())
			countAlloc.Elem().SetUint(want)
			v.Set(countAlloc)
		},
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetMechanismList(*pulCount=%d) = %s, want CKR_OK", want, rv)
	}
}

func TestCGetMechanismInfo_NullArgumentIsRefused(t *testing.T) {
	newTestFixture(t)
	rv := callExport(t, C_GetMechanismInfo, nil)
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GetMechanismInfo(pInfo=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGetMechanismInfo_Success(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetMechanismInfo, map[int]func(reflect.Value){
		1: func(v reflect.Value) { v.SetUint(uint64(module.CKM_RSA_PKCS)) },
		2: setArrayArg(1, &infoAlloc),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetMechanismInfo(CKM_RSA_PKCS) = %s, want CKR_OK", rv)
	}
}

func TestCGetMechanismInfo_UnknownMechanism(t *testing.T) {
	newTestFixture(t)

	var infoAlloc reflect.Value
	rv := callExport(t, C_GetMechanismInfo, map[int]func(reflect.Value){
		1: func(v reflect.Value) { v.SetUint(0xDEADBEEF) },
		2: setArrayArg(1, &infoAlloc),
	})
	if rv == module.CKR_OK {
		t.Fatal("C_GetMechanismInfo accepted a mechanism type this module does not support")
	}
}

// ============================================================================
// main (build-mode entry point)
// ============================================================================

// TestMain_IsANoOp proves the buildmode=c-shared entry point does nothing and
// never panics: it exists only so `go build -buildmode=c-shared` produces a
// package main, and is never called by the C side (the shared library is
// loaded and driven entirely through the C_* exports).
func TestMain_IsANoOp(t *testing.T) {
	main()
}
