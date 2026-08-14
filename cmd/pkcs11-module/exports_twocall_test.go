// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

// Tests for the argument and two-call conventions at the C ABI.
//
// As exports_test.go explains, Go 1.26 forbids `import "C"` in a _test.go file,
// so these drive the real exported functions through reflection rather than a
// Go-only stand-in.

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// cArg describes one argument to an exported Cryptoki function for callC.
type cArg struct {
	// scalar is the value for an integral parameter.
	scalar uint64
	// alloc requests a freshly zeroed object of the parameter's pointed-to
	// type, which is how an output pointer is supplied without the test naming
	// a cgo type.
	alloc bool
	// null requests the zero value, i.e. a NULL pointer.
	null bool
}

func cScalar(v uint64) cArg { return cArg{scalar: v} }
func cNull() cArg           { return cArg{null: true} }
func cAlloc() cArg          { return cArg{alloc: true} }

// callC invokes an exported C_* function, building each argument from the
// function's own reflected parameter types so the test never names one.
// It returns both the CK_RV and the allocated argument values, so a caller can
// read back an output parameter such as *pulObjectCount.
func callC(t *testing.T, fn any, args ...cArg) (module.CK_RV, []reflect.Value) {
	t.Helper()

	value := reflect.ValueOf(fn)
	fnType := value.Type()
	if fnType.NumIn() != len(args) {
		t.Fatalf("callC: function takes %d arguments, %d supplied", fnType.NumIn(), len(args))
	}

	in := make([]reflect.Value, len(args))
	for i, spec := range args {
		paramType := fnType.In(i)
		switch {
		case spec.alloc:
			if paramType.Kind() != reflect.Pointer {
				t.Fatalf("callC: argument %d is %s, which cannot be allocated", i, paramType)
			}
			in[i] = reflect.New(paramType.Elem())
		case spec.null:
			in[i] = reflect.Zero(paramType)
		default:
			arg := reflect.New(paramType).Elem()
			arg.SetUint(spec.scalar)
			in[i] = arg
		}
	}

	return module.CK_RV(value.Call(in)[0].Uint()), in
}

// TestCDigest_NullDataWithNonzeroLengthIsRefused pins the distinction between
// "no data" and a malformed buffer description.
//
// A NULL pData with ulDataLen == 0 is an empty input and has a defined digest.
// A NULL pData with ulDataLen == 32 claims thirty-two bytes that are not there.
// Treating the second as the first meant C_Digest hashed the empty string and
// returned CKR_OK, and the same helper backs the sign, verify, encrypt and
// decrypt paths -- so each could be driven to operate on data the application
// never supplied.
func TestCDigest_NullDataWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	rv, _ := callC(t, C_Digest,
		cScalar(uint64(f.session)), cNull(), cScalar(32), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Digest(NULL, 32) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCDigest_ArgumentErrorTerminatesTheOperation pins the rule PKCS#11 v3.2
// states for every terminal function, in §5.9.2's words for C_Digest: the call
// "always terminates the active digest operation unless it returns
// CKR_BUFFER_TOO_SMALL or is a successful call ... to determine the length".
//
// An argument the C layer rejects before reaching the module is neither
// exception. Leaving the operation active let a later well-formed call complete
// the operation the failed one should have ended.
func TestCDigest_ArgumentErrorTerminatesTheOperation(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	rv, _ := callC(t, C_Digest,
		cScalar(uint64(f.session)), cNull(), cScalar(32), cNull(), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_Digest(NULL, 32) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	// A second DigestInit is the observable consequence: it succeeds only if
	// the first operation is gone. While it lingered this returned
	// CKR_OPERATION_ACTIVE.
	if rv := f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("DigestInit after a refused C_Digest = %s, want CKR_OK: "+
			"the failed terminal call left its operation active", rv)
	}
}

// TestCFindObjects_RequiresADestination pins that C_FindObjects has no
// length-query form.
//
// v3.2 §5.7.8 describes phObject as "the location that receives the list of
// additional object handles" -- it is not optional. The search cursor advances
// inside the module, so handles matched for a NULL destination are consumed and
// can never be retrieved by that search again; accepting the call reported them
// as delivered under CKR_OK to a caller with nowhere to have received them.
func TestCFindObjects_RequiresADestination(t *testing.T) {
	f := newTestFixture(t)

	if rv := f.m.FindObjectsInit(f.session, nil); rv != module.CKR_OK {
		t.Fatalf("FindObjectsInit: %s", rv)
	}

	rv, _ := callC(t, C_FindObjects,
		cScalar(uint64(f.session)), cNull(), cScalar(10), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_FindObjects(phObject=NULL, max=10) = %s, want CKR_ARGUMENTS_BAD", rv)
	}

	// Asking for zero objects needs no destination and stays legal, so the
	// guard rejects a malformed call rather than every NULL pointer.
	rv, out := callC(t, C_FindObjects,
		cScalar(uint64(f.session)), cNull(), cScalar(0), cAlloc())
	if rv != module.CKR_OK {
		t.Fatalf("C_FindObjects(phObject=NULL, max=0) = %s, want CKR_OK", rv)
	}
	if got := out[3].Elem().Uint(); got != 0 {
		t.Fatalf("C_FindObjects(max=0) reported %d objects, want 0", got)
	}

	if rv := f.m.FindObjectsFinal(f.session); rv != module.CKR_OK {
		t.Fatalf("FindObjectsFinal: %s", rv)
	}
}

// TestCWaitForSlotEvent_BlockingCallIsRefused pins v3.2 §5.5.9: CKR_NO_EVENT is
// the answer to a poll, not to a wait.
//
// This module's slots are fixed at C_Initialize, so no slot event can ever
// occur. Answering CKR_NO_EVENT to a blocking call turned a slot-monitoring
// thread's wait into a spin at full CPU; the honest answer is that the library
// cannot perform the blocking form at all.
func TestCWaitForSlotEvent_BlockingCallIsRefused(t *testing.T) {
	newTestFixture(t)

	const ckfDontBlock = 1

	rv, _ := callC(t, C_WaitForSlotEvent, cScalar(0), cAlloc(), cNull())
	if rv != module.CKR_FUNCTION_NOT_SUPPORTED {
		t.Fatalf("C_WaitForSlotEvent(flags=0) = %s, want CKR_FUNCTION_NOT_SUPPORTED", rv)
	}

	rv, _ = callC(t, C_WaitForSlotEvent, cScalar(ckfDontBlock), cAlloc(), cNull())
	if rv != module.CKR_NO_EVENT {
		t.Fatalf("C_WaitForSlotEvent(CKF_DONT_BLOCK) = %s, want CKR_NO_EVENT", rv)
	}
}

// TestCSeedRandom_AppliesEntryPointPreconditions pins that the C ABI and the Go
// API answer the same call the same way.
//
// C_SeedRandom returned a constant CKR_RANDOM_SEED_NOT_SUPPORTED without
// reaching Module.SeedRandom, so it skipped the preconditions §5.19.1 requires
// of the entry point and answered even on an uninitialized library.
func TestCSeedRandom_AppliesEntryPointPreconditions(t *testing.T) {
	t.Run("an invalid session handle is reported", func(t *testing.T) {
		f := newTestFixture(t)

		rv, _ := callC(t, C_SeedRandom, cScalar(uint64(f.session)+9999), cNull(), cScalar(0))
		if rv == module.CKR_OK {
			t.Fatal("C_SeedRandom accepted a session handle that names no session")
		}
	})

	t.Run("an uninitialized library is reported", func(t *testing.T) {
		module.ResetGlobalModule()
		t.Cleanup(module.ResetGlobalModule)

		rv, _ := callC(t, C_SeedRandom, cScalar(1), cNull(), cScalar(0))
		if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
			t.Fatalf("C_SeedRandom before C_Initialize = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rv)
		}
	})
}
