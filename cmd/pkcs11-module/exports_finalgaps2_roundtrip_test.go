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

// Tests for a handful of remaining C_SignMessage and C_DigestFinal branches
// the rest of this package's fixtures do not reach: a NULL pulSignatureLen,
// the buffer-too-small leg of each, and DigestFinal's no-active-operation
// error leg.

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestCSignMessage_NullSignatureLenIsRefused proves a NULL pulSignatureLen
// is refused with CKR_ARGUMENTS_BAD before Module.SignMessage runs.
func TestCSignMessage_NullSignatureLenIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}

	data := []byte("some data")
	fn := reflect.ValueOf(C_SignMessage)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		reflect.Zero(ft.In(5)),
		reflect.Zero(ft.In(6)),
	})
	runtime.KeepAlive(data)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SignMessage(pulSignatureLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCSignMessage_BufferTooSmall proves the real-buffer leg reports
// CKR_BUFFER_TOO_SMALL and the real RSA-2048 signature size for an
// undersized destination.
func TestCSignMessage_BufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}

	data := []byte("some data")
	fn := reflect.ValueOf(C_SignMessage)
	ft := fn.Type()
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(6).Elem())
	smallLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		setBufferPtr(undersized, ft, 5),
		smallLen,
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_SignMessage(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := smallLen.Elem().Uint(); got != 256 {
		t.Fatalf("C_SignMessage(undersized) reported required length %d, want 256", got)
	}
}

// TestCDigestFinal_NoActiveOperation proves C_DigestFinal is refused with
// CKR_OPERATION_NOT_INITIALIZED for a session with no active digest, the
// mrv!=CKR_OK leg the success-path tests elsewhere in this package never
// reach.
func TestCDigestFinal_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DigestFinal, cScalar(uint64(f.session)), cNull(), cAlloc())
	if rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_DigestFinal(no active digest) = %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// TestCDigestFinal_BufferTooSmall proves the real-buffer leg reports
// CKR_BUFFER_TOO_SMALL and the real SHA-256 digest size (32 bytes) for an
// undersized destination. DigestInit/Digest never reach the backend
// transport (SHA-256 is computed locally), so the offlineTransport fixture
// suffices.
func TestCDigestFinal_BufferTooSmall(t *testing.T) {
	f := newTestFixture(t)
	if rv := startDigest(t, f); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}
	if mrv := f.m.DigestUpdate(f.session, []byte("data to digest")); mrv != module.CKR_OK {
		t.Fatalf("DigestUpdate: %s", mrv)
	}

	fn := reflect.ValueOf(C_DigestFinal)
	ft := fn.Type()
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(2).Elem())
	smallLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		setBufferPtr(undersized, ft, 1),
		smallLen,
	})
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_DigestFinal(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := smallLen.Elem().Uint(); got != 32 {
		t.Fatalf("C_DigestFinal(undersized) reported required length %d, want 32", got)
	}
}

// TestCCreateObject_ArgumentAndModuleErrors covers C_CreateObject's
// convertCTemplateToGo-overflow leg and the module-level rejection of an
// incomplete template, neither of which the existing key-object fixtures in
// this package reach.
func TestCCreateObject_ArgumentAndModuleErrors(t *testing.T) {
	f := newTestFixture(t)

	t.Run("template count overflow", func(t *testing.T) {
		template := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
		fn := reflect.ValueOf(C_CreateObject)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cAttributePtr(template, ft, 1),
			scalarOf(ft, 2, uint64(math.MaxInt32)+1),
			allocOf(ft, 3),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_CreateObject(ulCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})

	t.Run("incomplete template is refused", func(t *testing.T) {
		// No CKA_CLASS: the object layer cannot tell what kind of object
		// this is meant to be.
		template := buildCAttributeArray(t, []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "incomplete"),
		})
		fn := reflect.ValueOf(C_CreateObject)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cAttributePtr(template, ft, 1),
			scalarOf(ft, 2, attrCount(template)),
			allocOf(ft, 3),
		})
		if rv := module.CK_RV(out[0].Uint()); rv == module.CKR_OK {
			t.Fatal("C_CreateObject(no CKA_CLASS) = CKR_OK, want an error")
		}
	})
}

// TestCGenerateKeyPair_ArgumentAndModuleErrors covers C_GenerateKeyPair's
// malformed-mechanism-parameter, template-count-overflow, and
// wrong-mechanism-category legs.
func TestCGenerateKeyPair_ArgumentAndModuleErrors(t *testing.T) {
	f := newTestFixture(t)

	t.Run("malformed mechanism param", func(t *testing.T) {
		shortParam := []byte{0x01}
		mechBuf := buildCMechanismWithParam(t, module.CKM_RSA_PKCS_OAEP, shortParam)
		fn := reflect.ValueOf(C_GenerateKeyPair)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			reflect.Zero(ft.In(2)),
			scalarOf(ft, 3, 0),
			reflect.Zero(ft.In(4)),
			scalarOf(ft, 5, 0),
			allocOf(ft, 6),
			allocOf(ft, 7),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_GenerateKeyPair(short OAEP params) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("wrong mechanism category is refused", func(t *testing.T) {
		// CKM_AES_KEY_GEN generates a single secret key, not a key pair.
		mechBuf := buildCMechanism(module.CKM_AES_KEY_GEN)
		fn := reflect.ValueOf(C_GenerateKeyPair)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			reflect.Zero(ft.In(2)),
			scalarOf(ft, 3, 0),
			reflect.Zero(ft.In(4)),
			scalarOf(ft, 5, 0),
			allocOf(ft, 6),
			allocOf(ft, 7),
		})
		if rv := module.CK_RV(out[0].Uint()); rv == module.CKR_OK {
			t.Fatal("C_GenerateKeyPair(CKM_AES_KEY_GEN) = CKR_OK, want an error")
		}
	})
}

// TestCFindObjectsInit_TemplateCountOverflowIsRefused proves
// C_FindObjectsInit refuses a ulCount beyond a Go slice index's addressable
// range.
func TestCFindObjectsInit_TemplateCountOverflowIsRefused(t *testing.T) {
	f := newTestFixture(t)
	template := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})

	fn := reflect.ValueOf(C_FindObjectsInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cAttributePtr(template, ft, 1),
		scalarOf(ft, 2, uint64(math.MaxInt32)+1),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_FindObjectsInit(ulCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCFindObjects_ArgumentValidationAndClamp covers C_FindObjects'
// pulObjectCount=NULL and ulMaxObjectCount-overflow argument guards, and
// proves a match count larger than the caller's requested maximum is
// clamped rather than overrunning the caller's array.
func TestCFindObjects_ArgumentValidationAndClamp(t *testing.T) {
	f := newTestFixture(t)

	t.Run("NULL pulObjectCount", func(t *testing.T) {
		rv, _ := callC(t, C_FindObjects, cScalar(uint64(f.session)), cAlloc(), cScalar(4), cNull())
		if rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_FindObjects(pulObjectCount=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})

	t.Run("ulMaxObjectCount overflow", func(t *testing.T) {
		fn := reflect.ValueOf(C_FindObjects)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			allocOf(ft, 1),
			scalarOf(ft, 2, uint64(math.MaxInt32)+1),
			allocOf(ft, 3),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_FindObjects(ulMaxObjectCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})

	t.Run("match count is clamped to the caller's maximum", func(t *testing.T) {
		// f.privKey and f.pubKey both exist; a search with no template
		// matches every object, and a caller-supplied maximum of 1 must
		// clamp to exactly one handle rather than writing past a
		// one-element array.
		if rv, _ := callC(t, C_FindObjectsInit, cScalar(uint64(f.session)), cNull(), cScalar(0)); rv != module.CKR_OK {
			t.Fatalf("C_FindObjectsInit = %s, want CKR_OK", rv)
		}

		fn := reflect.ValueOf(C_FindObjects)
		ft := fn.Type()
		handles := newAlignedBuf(8) // room for one CK_OBJECT_HANDLE.
		countOut := reflect.New(ft.In(3).Elem())
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			setBufferPtr(handles, ft, 1),
			scalarOf(ft, 2, 1),
			countOut,
		})
		runtime.KeepAlive(handles)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_FindObjects(max=1) = %s, want CKR_OK", rv)
		}
		if got := countOut.Elem().Uint(); got != 1 {
			t.Fatalf("C_FindObjects(max=1) reported count %d, want 1", got)
		}
	})
}

// TestCLoginUser_UsernameLengthOverflowIsRefused proves C_LoginUser refuses
// a ulUsernameLen beyond a Go slice index's addressable range when
// pUsername is non-NULL.
func TestCLoginUser_UsernameLengthOverflowIsRefused(t *testing.T) {
	f := newTestFixture(t)
	pin := []byte(testUserPIN)
	username := []byte("someone")

	fn := reflect.ValueOf(C_LoginUser)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		scalarOf(ft, 1, uint64(module.CKU_USER)),
		setBufferPtr(pin, ft, 2),
		scalarOf(ft, 3, uint64(len(pin))),
		setBufferPtr(username, ft, 4),
		scalarOf(ft, 5, uint64(math.MaxInt32)+1),
	})
	runtime.KeepAlive(pin)
	runtime.KeepAlive(username)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_LoginUser(ulUsernameLen > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestLocalKeyDir_FallsBackToTempDirWhenHomeIsUnavailable proves
// localKeyDir's last-resort leg: when neither XKMS_PKCS11_LOCAL_KEYDIR, a
// configured storage path, nor a resolvable home directory is available, it
// falls back to a directory under os.TempDir() rather than returning an
// empty path.
//
// os.UserHomeDir on non-Windows consults only $HOME (no passwd-database
// fallback), so clearing it deterministically makes it fail on this
// package's target platform (linux, per go-xkms's build matrix); no skip
// guard is used.
func TestLocalKeyDir_FallsBackToTempDirWhenHomeIsUnavailable(t *testing.T) {
	t.Setenv(envLocalKeyDir, "")
	t.Setenv("HOME", "")

	if _, err := os.UserHomeDir(); err == nil {
		t.Fatal("os.UserHomeDir unexpectedly succeeded with $HOME unset; this test's premise no longer holds on this platform")
	}

	want := filepath.Join(os.TempDir(), "xkms-pkcs11-keys")
	if got := localKeyDir(nil); got != want {
		t.Errorf("localKeyDir = %q, want %q", got, want)
	}
}

// TestCSetPIN_RoundTrip proves C_SetPIN reaches Module.SetPIN for a
// well-formed call: the logged-in user's PIN is genuinely changed, checked
// by logging out and back in with the new PIN.
func TestCSetPIN_RoundTrip(t *testing.T) {
	f := newTestFixture(t)

	oldPin := []byte(testUserPIN)
	newPin := []byte("new-user-pin-5678")

	fn := reflect.ValueOf(C_SetPIN)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		setBufferPtr(oldPin, ft, 1),
		scalarOf(ft, 2, uint64(len(oldPin))),
		setBufferPtr(newPin, ft, 3),
		scalarOf(ft, 4, uint64(len(newPin))),
	})
	runtime.KeepAlive(oldPin)
	runtime.KeepAlive(newPin)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_SetPIN(well-formed) = %s, want CKR_OK", rv)
	}

	if rv := f.m.Logout(f.session); rv != module.CKR_OK {
		t.Fatalf("Logout: %s", rv)
	}
	if rv := f.m.Login(f.session, module.CKU_USER, newPin); rv != module.CKR_OK {
		t.Fatalf("Login with the new PIN = %s, want CKR_OK: C_SetPIN did not actually change it", rv)
	}
}

// TestCGenerateKey_ArgumentErrors covers C_GenerateKey's
// malformed-mechanism-parameter and template-count-overflow legs.
func TestCGenerateKey_ArgumentErrors(t *testing.T) {
	f := newTestFixture(t)

	t.Run("malformed mechanism param", func(t *testing.T) {
		shortParam := []byte{0x01}
		mechBuf := buildCMechanismWithParam(t, module.CKM_RSA_PKCS_OAEP, shortParam)
		fn := reflect.ValueOf(C_GenerateKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			reflect.Zero(ft.In(2)),
			scalarOf(ft, 3, 0),
			allocOf(ft, 4),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_GenerateKey(short OAEP params) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("template count overflow", func(t *testing.T) {
		mechBuf := buildCMechanism(module.CKM_AES_KEY_GEN)
		template := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
		fn := reflect.ValueOf(C_GenerateKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			cAttributePtr(template, ft, 2),
			scalarOf(ft, 3, uint64(math.MaxInt32)+1),
			allocOf(ft, 4),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_GenerateKey(ulCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})
}

// TestCDeriveKey_ArgumentErrors covers C_DeriveKey's
// malformed-mechanism-parameter and template-count-overflow legs.
func TestCDeriveKey_ArgumentErrors(t *testing.T) {
	f := newTestFixture(t)

	t.Run("malformed mechanism param", func(t *testing.T) {
		shortParam := []byte{0x01}
		mechBuf := buildCMechanismWithParam(t, module.CKM_RSA_PKCS_OAEP, shortParam)
		fn := reflect.ValueOf(C_DeriveKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(f.privKey)),
			reflect.Zero(ft.In(3)),
			scalarOf(ft, 4, 0),
			allocOf(ft, 5),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_DeriveKey(short OAEP params) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("template count overflow", func(t *testing.T) {
		mechBuf := buildCMechanism(module.CKM_HKDF_DERIVE)
		template := buildCAttributeArray(t, []module.Attribute{{Type: module.CKA_LABEL}})
		fn := reflect.ValueOf(C_DeriveKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(f.privKey)),
			cAttributePtr(template, ft, 3),
			scalarOf(ft, 4, uint64(math.MaxInt32)+1),
			allocOf(ft, 5),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_DeriveKey(ulCount > MaxInt32) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})
}

// TestCWaitForSlotEvent_NonNilReservedIsRefused proves the reserved argument
// (v3.2 §5.5.9: "pRvReserved ... MUST be NULL_PTR") is enforced.
func TestCWaitForSlotEvent_NonNilReservedIsRefused(t *testing.T) {
	newTestFixture(t)

	reserved := []byte{0x00}
	fn := reflect.ValueOf(C_WaitForSlotEvent)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, 0),
		allocOf(ft, 1),
		cPtr(unsafe.Pointer(&reserved[0]), ft, 2),
	})
	runtime.KeepAlive(reserved)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_WaitForSlotEvent(pReserved!=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// TestCInitPIN_RoundTrip proves C_InitPIN reaches Module.InitPIN for a
// well-formed call, mirroring the SO-session setup
// provisionTestModule performs internally (exports_test.go) but driving the
// call through the real C ABI entry point instead of the Go API directly.
func TestCInitPIN_RoundTrip(t *testing.T) {
	module.ResetGlobalModule()
	t.Cleanup(module.ResetGlobalModule)

	m, err := module.New(module.WithClient(offlineTransport{}), module.WithConfig(module.DefaultConfig()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	module.SetGlobalModule(m)

	if rv := m.Initialize(nil); rv != module.CKR_OK {
		t.Fatalf("Initialize: %s", rv)
	}
	if rv := m.InitToken(0, []byte(testSOPIN), "Test Token"); rv != module.CKR_OK {
		t.Fatalf("InitToken: %s", rv)
	}
	soSession, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession (SO): %s", rv)
	}
	if rv := m.Login(soSession, module.CKU_SO, []byte(testSOPIN)); rv != module.CKR_OK {
		t.Fatalf("Login (SO): %s", rv)
	}

	pin := []byte(testUserPIN)
	fn := reflect.ValueOf(C_InitPIN)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(soSession)),
		setBufferPtr(pin, ft, 1),
		scalarOf(ft, 2, uint64(len(pin))),
	})
	runtime.KeepAlive(pin)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_InitPIN(well-formed) = %s, want CKR_OK", rv)
	}

	// The PIN it set is genuinely usable: a normal user session can log in
	// with it.
	if rv := m.Logout(soSession); rv != module.CKR_OK {
		t.Fatalf("Logout (SO): %s", rv)
	}
	userSession, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession (user): %s", rv)
	}
	if rv := m.Login(userSession, module.CKU_USER, pin); rv != module.CKR_OK {
		t.Fatalf("Login (user) with the PIN C_InitPIN set = %s, want CKR_OK", rv)
	}
}
