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

//go:build integration && pkcs11_cabi

// Package cabi drives the built libxkms_pkcs11.so through its C ABI exactly as
// a C application does: it dlopen()s the shared object, obtains a
// CK_FUNCTION_LIST_3_2 through C_GetInterface, and dispatches every Cryptoki
// call through that list.
//
// Every other integration suite in this repository constructs Go values and
// calls pkg/pkcs11/module directly, which skips the cgo boundary in
// cmd/pkcs11-module/exports.go entirely. That boundary is where mechanism
// parameters are unmarshalled from their C structs, and it is where a whole
// family of defects has hidden: parameters that were accepted, never parsed,
// and silently replaced with defaults. A test that builds a Go
// module.RSAPSSParams cannot observe a cgo parser that never reads
// CK_RSA_PKCS_PSS_PARAMS. This package exists to close that gap.
//
// The cgo lives in non-test files on purpose. Go's module indexer rejects
// `import "C"` in any _test.go (cmd/go/internal/modindex/read.go marks such
// files bad unconditionally), so the C ABI is reached from ordinary package
// files and the _test.go files stay pure Go.
package cabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../../cmd/pkcs11-module/include
#cgo LDFLAGS: -ldl

#include "xkabi.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Cryptoki return values used by this suite. They are bound to the module's own
// headers rather than restated as literals so that a header change cannot leave
// the tests asserting stale numbers.
const (
	CKR_OK                           = uint(C.CKR_OK)
	CKR_BUFFER_TOO_SMALL             = uint(C.CKR_BUFFER_TOO_SMALL)
	CKR_MECHANISM_INVALID            = uint(C.CKR_MECHANISM_INVALID)
	CKR_MECHANISM_PARAM_INVALID      = uint(C.CKR_MECHANISM_PARAM_INVALID)
	CKR_SIGNATURE_INVALID            = uint(C.CKR_SIGNATURE_INVALID)
	CKR_ENCRYPTED_DATA_INVALID       = uint(C.CKR_ENCRYPTED_DATA_INVALID)
	CKR_FUNCTION_NOT_SUPPORTED       = uint(C.CKR_FUNCTION_NOT_SUPPORTED)
	CKR_OPERATION_NOT_INITIALIZED    = uint(C.CKR_OPERATION_NOT_INITIALIZED)
	CKR_ARGUMENTS_BAD                = uint(C.CKR_ARGUMENTS_BAD)
	CKR_KEY_HANDLE_INVALID           = uint(C.CKR_KEY_HANDLE_INVALID)
	CKR_DATA_LEN_RANGE               = uint(C.CKR_DATA_LEN_RANGE)
	CKR_CRYPTOKI_ALREADY_INITIALIZED = uint(C.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	CKR_KEY_FUNCTION_NOT_PERMITTED   = uint(C.CKR_KEY_FUNCTION_NOT_PERMITTED)
	CKR_FUNCTION_FAILED              = uint(C.CKR_FUNCTION_FAILED)
	CKR_ATTRIBUTE_VALUE_INVALID      = uint(C.CKR_ATTRIBUTE_VALUE_INVALID)
	CKR_TEMPLATE_INCONSISTENT        = uint(C.CKR_TEMPLATE_INCONSISTENT)
	CKR_SESSION_READ_ONLY            = uint(C.CKR_SESSION_READ_ONLY)
	CKR_KEY_NOT_WRAPPABLE            = uint(C.CKR_KEY_NOT_WRAPPABLE)
	CKR_ATTRIBUTE_READ_ONLY          = uint(C.CKR_ATTRIBUTE_READ_ONLY)
	CKR_OPERATION_ACTIVE             = uint(C.CKR_OPERATION_ACTIVE)

	// CKR_WRAPPING_KEY_TYPE_INCONSISTENT is what a wrapping function returns
	// for a wrapping key whose type is inconsistent with the mechanism
	// (PKCS#11 v3.2 §5.1.6).
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT = uint(C.CKR_WRAPPING_KEY_TYPE_INCONSISTENT)

	// CKR_USER_NOT_LOGGED_IN is what every key-bearing function returns on a
	// token that advertises CKF_LOGIN_REQUIRED to a session that has not
	// authenticated.
	CKR_USER_NOT_LOGGED_IN = uint(C.CKR_USER_NOT_LOGGED_IN)
)

// Mechanism types exercised by this suite.
const (
	CKM_RSA_PKCS                = uint(C.CKM_RSA_PKCS)
	CKM_RSA_PKCS_PSS            = uint(C.CKM_RSA_PKCS_PSS)
	CKM_RSA_PKCS_OAEP           = uint(C.CKM_RSA_PKCS_OAEP)
	CKM_RSA_PKCS_KEY_PAIR_GEN   = uint(C.CKM_RSA_PKCS_KEY_PAIR_GEN)
	CKM_AES_KEY_GEN             = uint(C.CKM_AES_KEY_GEN)
	CKM_AES_GCM                 = uint(C.CKM_AES_GCM)
	CKM_EC_EDWARDS_KEY_PAIR_GEN = uint(C.CKM_EC_EDWARDS_KEY_PAIR_GEN)
	CKM_EDDSA                   = uint(C.CKM_EDDSA)
	CKM_HKDF_DERIVE             = uint(C.CKM_HKDF_DERIVE)
	CKM_HKDF_KEY_GEN            = uint(C.CKM_HKDF_KEY_GEN)
	CKM_SHA256_HMAC             = uint(C.CKM_SHA256_HMAC)
	CKM_SHA_1                   = uint(C.CKM_SHA_1)
	CKM_SHA256                  = uint(C.CKM_SHA256)
	CKM_SHA384                  = uint(C.CKM_SHA384)
	CKM_SHA512                  = uint(C.CKM_SHA512)
	CKM_GENERIC_SECRET_KEY_GEN  = uint(C.CKM_GENERIC_SECRET_KEY_GEN)
	CKM_EC_KEY_PAIR_GEN         = uint(C.CKM_EC_KEY_PAIR_GEN)
	CKM_ECDH1_DERIVE            = uint(C.CKM_ECDH1_DERIVE)
	CKM_ECDH1_COFACTOR_DERIVE   = uint(C.CKM_ECDH1_COFACTOR_DERIVE)
)

// SP800-108 mechanisms and the HKDF key type. These once had to be hardcoded
// here because the shipped C headers (cmd/pkcs11-module/include/pkcs11t.h)
// declared the SP800-108 parameter structs and the CK_PRF_DATA_* segment types
// but not the CKM_SP800_108_* mechanism identifiers themselves. The headers now
// declare all of them, so the suite names them the way a C application does and
// cannot drift from the header. They are checked against C_GetMechanismList in
// TestMechanismListDeclaresTheParameterisedMechanisms.
const (
	CKM_SP800_108_COUNTER_KDF         = uint(C.CKM_SP800_108_COUNTER_KDF)
	CKM_SP800_108_FEEDBACK_KDF        = uint(C.CKM_SP800_108_FEEDBACK_KDF)
	CKM_SP800_108_DOUBLE_PIPELINE_KDF = uint(C.CKM_SP800_108_DOUBLE_PIPELINE_KDF)
	CKK_HKDF                          = uint(C.CKK_HKDF)
)

// CK_EC_KDF_TYPE values for ECDH derivation.
const (
	CKD_NULL             = uint(C.CKD_NULL)
	CKD_SHA1_KDF         = uint(C.CKD_SHA1_KDF)
	CKD_SHA256_KDF       = uint(C.CKD_SHA256_KDF)
	CKD_SHA384_KDF       = uint(C.CKD_SHA384_KDF)
	CKD_SHA512_KDF       = uint(C.CKD_SHA512_KDF)
	CKD_SHA1_KDF_SP800   = uint(C.CKD_SHA1_KDF_SP800)
	CKD_SHA256_KDF_SP800 = uint(C.CKD_SHA256_KDF_SP800)
)

// MGF identifiers for RSA PSS and OAEP.
const (
	CKG_MGF1_SHA1   = uint(C.CKG_MGF1_SHA1)
	CKG_MGF1_SHA256 = uint(C.CKG_MGF1_SHA256)
	CKG_MGF1_SHA384 = uint(C.CKG_MGF1_SHA384)
	CKG_MGF1_SHA512 = uint(C.CKG_MGF1_SHA512)
)

// OAEP source identifiers.
const (
	CKZ_DATA_SPECIFIED = uint(C.CKZ_DATA_SPECIFIED)
)

// HKDF salt types (CKF_HKDF_SALT_*).
const (
	CKF_HKDF_SALT_NULL = uint(C.CKF_HKDF_SALT_NULL)
	CKF_HKDF_SALT_DATA = uint(C.CKF_HKDF_SALT_DATA)
	CKF_HKDF_SALT_KEY  = uint(C.CKF_HKDF_SALT_KEY)
)

// SP800-108 PRF data segment types.
const (
	CK_SP800_108_ITERATION_VARIABLE = uint(C.CK_SP800_108_ITERATION_VARIABLE)
	CK_SP800_108_COUNTER            = uint(C.CK_SP800_108_COUNTER)
	CK_SP800_108_DKM_LENGTH         = uint(C.CK_SP800_108_DKM_LENGTH)
	CK_SP800_108_BYTE_ARRAY         = uint(C.CK_SP800_108_BYTE_ARRAY)
)

// Message-based AEAD IV generator selectors.
const (
	CKG_NO_GENERATE      = uint(C.CKG_NO_GENERATE)
	CKG_GENERATE         = uint(C.CKG_GENERATE)
	CKG_GENERATE_COUNTER = uint(C.CKG_GENERATE_COUNTER)
	CKG_GENERATE_RANDOM  = uint(C.CKG_GENERATE_RANDOM)
)

// Object classes, key types and attribute identifiers.
const (
	CKO_PUBLIC_KEY  = uint(C.CKO_PUBLIC_KEY)
	CKO_PRIVATE_KEY = uint(C.CKO_PRIVATE_KEY)
	CKO_SECRET_KEY  = uint(C.CKO_SECRET_KEY)

	CKK_RSA            = uint(C.CKK_RSA)
	CKK_AES            = uint(C.CKK_AES)
	CKK_EC             = uint(C.CKK_EC)
	CKK_EC_EDWARDS     = uint(C.CKK_EC_EDWARDS)
	CKK_GENERIC_SECRET = uint(C.CKK_GENERIC_SECRET)

	CKA_CLASS           = uint(C.CKA_CLASS)
	CKA_KEY_TYPE        = uint(C.CKA_KEY_TYPE)
	CKA_TOKEN           = uint(C.CKA_TOKEN)
	CKA_PRIVATE         = uint(C.CKA_PRIVATE)
	CKA_LABEL           = uint(C.CKA_LABEL)
	CKA_ID              = uint(C.CKA_ID)
	CKA_VALUE           = uint(C.CKA_VALUE)
	CKA_VALUE_LEN       = uint(C.CKA_VALUE_LEN)
	CKA_MODULUS         = uint(C.CKA_MODULUS)
	CKA_MODULUS_BITS    = uint(C.CKA_MODULUS_BITS)
	CKA_PUBLIC_EXPONENT = uint(C.CKA_PUBLIC_EXPONENT)
	CKA_EC_POINT        = uint(C.CKA_EC_POINT)
	CKA_EC_PARAMS       = uint(C.CKA_EC_PARAMS)
	CKA_ENCRYPT         = uint(C.CKA_ENCRYPT)
	CKA_DECRYPT         = uint(C.CKA_DECRYPT)
	CKA_SIGN            = uint(C.CKA_SIGN)
	CKA_VERIFY          = uint(C.CKA_VERIFY)
	CKA_WRAP            = uint(C.CKA_WRAP)
	CKA_UNWRAP          = uint(C.CKA_UNWRAP)
	CKA_DERIVE          = uint(C.CKA_DERIVE)
	CKA_SENSITIVE       = uint(C.CKA_SENSITIVE)
	CKA_EXTRACTABLE     = uint(C.CKA_EXTRACTABLE)

	// CKA_TRUSTED and CKA_WRAP_WITH_TRUSTED are the pair PKCS#11 v3.2 section
	// 4.9 uses to restrict which wrapping keys a key may be exported under.
	CKA_TRUSTED           = uint(C.CKA_TRUSTED)
	CKA_WRAP_WITH_TRUSTED = uint(C.CKA_WRAP_WITH_TRUSTED)
)

// Session flags and user types.
const (
	CKF_SERIAL_SESSION = uint(C.CKF_SERIAL_SESSION)
	CKF_RW_SESSION     = uint(C.CKF_RW_SESSION)
	CKF_END_OF_MESSAGE = uint(C.CKF_END_OF_MESSAGE)

	CKU_SO   = uint(C.CKU_SO)
	CKU_USER = uint(C.CKU_USER)
)

// CKError reports a Cryptoki function that returned other than CKR_OK.
type CKError struct {
	// Function is the C_ name of the call that failed.
	Function string
	// RV is the CK_RV the module returned.
	RV uint
}

// Error implements the error interface.
func (e *CKError) Error() string {
	return fmt.Sprintf("%s returned %s (0x%08X)", e.Function, rvName(e.RV), e.RV)
}

// LoadError reports a failure to dlopen the module or to obtain its function
// list.
type LoadError struct {
	// Path is the shared object that could not be loaded.
	Path string
	// Reason describes what went wrong.
	Reason string
}

// Error implements the error interface.
func (e *LoadError) Error() string {
	return fmt.Sprintf("loading PKCS#11 module %q: %s", e.Path, e.Reason)
}

// InterfaceError reports a function that the module's function list does not
// carry, such as a message-based function on a v2.40 list.
type InterfaceError struct {
	// Path is the module that lacks the function.
	Path string
	// Function is the C_ name that is unavailable.
	Function string
}

// Error implements the error interface.
func (e *InterfaceError) Error() string {
	return fmt.Sprintf("%s is not present on the v2.40 function list returned by %q; it requires a PKCS#11 v3.x interface",
		e.Function, e.Path)
}

// ConfigError reports a missing or malformed test environment setting.
type ConfigError struct {
	// Variable is the environment variable at fault.
	Variable string
	// Reason describes what is wrong with it.
	Reason string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("environment %s: %s", e.Variable, e.Reason)
}

// rvNames maps the CK_RV values this suite reports to their spec names, so a
// failure message names the condition rather than only its number.
var rvNames = map[uint]string{
	CKR_OK:                             "CKR_OK",
	CKR_SESSION_READ_ONLY:              "CKR_SESSION_READ_ONLY",
	CKR_KEY_NOT_WRAPPABLE:              "CKR_KEY_NOT_WRAPPABLE",
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT: "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	CKR_BUFFER_TOO_SMALL:               "CKR_BUFFER_TOO_SMALL",
	CKR_MECHANISM_INVALID:              "CKR_MECHANISM_INVALID",
	CKR_MECHANISM_PARAM_INVALID:        "CKR_MECHANISM_PARAM_INVALID",
	CKR_SIGNATURE_INVALID:              "CKR_SIGNATURE_INVALID",
	CKR_ENCRYPTED_DATA_INVALID:         "CKR_ENCRYPTED_DATA_INVALID",
	CKR_FUNCTION_NOT_SUPPORTED:         "CKR_FUNCTION_NOT_SUPPORTED",
	CKR_OPERATION_NOT_INITIALIZED:      "CKR_OPERATION_NOT_INITIALIZED",
	CKR_ARGUMENTS_BAD:                  "CKR_ARGUMENTS_BAD",
	CKR_KEY_HANDLE_INVALID:             "CKR_KEY_HANDLE_INVALID",
	CKR_DATA_LEN_RANGE:                 "CKR_DATA_LEN_RANGE",
	CKR_CRYPTOKI_ALREADY_INITIALIZED:   "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	CKR_KEY_FUNCTION_NOT_PERMITTED:     "CKR_KEY_FUNCTION_NOT_PERMITTED",
	CKR_FUNCTION_FAILED:                "CKR_FUNCTION_FAILED",
	CKR_ATTRIBUTE_VALUE_INVALID:        "CKR_ATTRIBUTE_VALUE_INVALID",
	CKR_TEMPLATE_INCONSISTENT:          "CKR_TEMPLATE_INCONSISTENT",
	CKR_USER_NOT_LOGGED_IN:             "CKR_USER_NOT_LOGGED_IN",
	CKR_ATTRIBUTE_READ_ONLY:            "CKR_ATTRIBUTE_READ_ONLY",
	CKR_OPERATION_ACTIVE:               "CKR_OPERATION_ACTIVE",
}

// rvName returns the spec name for rv, or a placeholder when it is one this
// suite does not name.
func rvName(rv uint) string {
	if name, ok := rvNames[rv]; ok {
		return name
	}
	return "CKR_<unnamed>"
}

// RV extracts the CK_RV from err. It returns CKR_OK for a nil error and
// panics-free zero-value handling is deliberate: a caller comparing against a
// specific CK_RV wants a definite answer, and any non-CKError is reported as
// CKR_FUNCTION_NOT_SUPPORTED so that it cannot silently match an expectation.
func RV(err error) uint {
	if err == nil {
		return CKR_OK
	}
	var ckErr *CKError
	if ok := asCKError(err, &ckErr); ok {
		return ckErr.RV
	}
	return CKR_FUNCTION_NOT_SUPPORTED
}

// asCKError reports whether err is a *CKError and stores it in target.
func asCKError(err error, target **CKError) bool {
	ckErr, ok := err.(*CKError)
	if !ok {
		return false
	}
	*target = ckErr
	return true
}

// check converts a raw CK_RV into an error, naming the function that produced
// it.
func check(fn string, rv C.CK_RV) error {
	if uint(rv) == CKR_OK {
		return nil
	}
	return &CKError{Function: fn, RV: uint(rv)}
}

// Module is a dlopen()ed PKCS#11 shared object addressed through its function
// list.
type Module struct {
	path   string
	handle unsafe.Pointer
	fl     C.CK_FUNCTION_LIST_3_2_PTR
	hasV3  bool
}

// Open dlopen()s the shared object at path and resolves its function list.
//
// It prefers the v3.2 interface from C_GetInterface and falls back to
// C_GetFunctionList, which can only return the v2.40 list. The fallback is
// what lets this harness drive a reference implementation such as SoftHSM2 for
// comparison, which matters because a disagreement between this module and the
// specification is easiest to establish against a second implementation.
//
// Casting the v2.40 list to CK_FUNCTION_LIST_3_2_PTR is safe for the functions
// the fallback exposes: the specification defines CK_FUNCTION_LIST_3_0 and
// CK_FUNCTION_LIST_3_2 to begin with the version followed by the v2.40 entry
// points in their original order, and appends only afterwards. HasV3 gates
// every slot beyond that shared prefix.
func Open(path string) (*Module, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		return nil, &LoadError{Path: path, Reason: C.GoString(C.dlerror())}
	}

	cName := C.CString("PKCS 11")
	defer C.free(unsafe.Pointer(cName))

	version := C.CK_VERSION{major: 3, minor: 2}
	var iface C.CK_INTERFACE_PTR
	if rv := C.xk_get_interface(handle, cName, &version, &iface); uint(rv) == CKR_OK && iface != nil {
		if list := C.xk_interface_list(iface); list != nil {
			return &Module{
				path:   path,
				handle: unsafe.Pointer(handle),
				fl:     C.CK_FUNCTION_LIST_3_2_PTR(list),
				hasV3:  true,
			}, nil
		}
	}

	var legacy C.CK_FUNCTION_LIST_PTR
	rv := C.xk_get_function_list(unsafe.Pointer(handle), &legacy)
	if uint(rv) != CKR_OK || legacy == nil {
		C.dlclose(handle)
		return nil, &LoadError{
			Path:   path,
			Reason: fmt.Sprintf("neither C_GetInterface(\"PKCS 11\", 3.2) nor C_GetFunctionList yielded a function list (C_GetFunctionList returned 0x%08X)", uint(rv)),
		}
	}

	return &Module{
		path:   path,
		handle: unsafe.Pointer(handle),
		fl:     C.CK_FUNCTION_LIST_3_2_PTR(unsafe.Pointer(legacy)),
		hasV3:  false,
	}, nil
}

// Path returns the shared object this module was loaded from.
func (m *Module) Path() string { return m.path }

// HasV3 reports whether the module handed back a PKCS#11 v3.x function list.
// The message-based functions exist only on such a list.
func (m *Module) HasV3() bool { return m.hasV3 }

// Initialize calls C_Initialize with NULL arguments. An already-initialized
// module reports CKR_CRYPTOKI_ALREADY_INITIALIZED, which callers may accept.
func (m *Module) Initialize() error {
	return check("C_Initialize", C.xk_Initialize(m.fl, nil))
}

// Finalize calls C_Finalize.
func (m *Module) Finalize() error {
	return check("C_Finalize", C.xk_Finalize(m.fl, nil))
}

// SlotList returns the slots with a token present, using the two-call
// convention to size the array.
func (m *Module) SlotList() ([]uint, error) {
	var count C.CK_ULONG
	if err := check("C_GetSlotList", C.xk_GetSlotList(m.fl, C.CK_BBOOL(1), nil, &count)); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	slots := make([]C.CK_SLOT_ID, count)
	if err := check("C_GetSlotList", C.xk_GetSlotList(m.fl, C.CK_BBOOL(1), &slots[0], &count)); err != nil {
		return nil, err
	}

	out := make([]uint, count)
	for i := range out {
		out[i] = uint(slots[i])
	}
	return out, nil
}

// MechanismList returns the mechanism types the slot advertises. A mechanism
// absent from this list must be refused by every operation that names it; the
// two facts together are what distinguishes "unsupported" from "silently
// downgraded".
func (m *Module) MechanismList(slot uint) ([]uint, error) {
	var count C.CK_ULONG
	if err := check("C_GetMechanismList", C.xk_GetMechanismList(m.fl, C.CK_SLOT_ID(slot), nil, &count)); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	list := make([]C.CK_MECHANISM_TYPE, count)
	if err := check("C_GetMechanismList", C.xk_GetMechanismList(m.fl, C.CK_SLOT_ID(slot), &list[0], &count)); err != nil {
		return nil, err
	}

	out := make([]uint, count)
	for i := range out {
		out[i] = uint(list[i])
	}
	return out, nil
}

// OpenSession opens a session on slot with the given flags and returns it.
func (m *Module) OpenSession(slot uint, flags uint) (*Session, error) {
	var handle C.CK_SESSION_HANDLE
	if err := check("C_OpenSession", C.xk_OpenSession(m.fl, C.CK_SLOT_ID(slot), C.CK_FLAGS(flags), &handle)); err != nil {
		return nil, err
	}
	return &Session{mod: m, handle: handle}, nil
}

// Session is an open PKCS#11 session.
type Session struct {
	mod    *Module
	handle C.CK_SESSION_HANDLE
}

// Close calls C_CloseSession.
func (s *Session) Close() error {
	return check("C_CloseSession", C.xk_CloseSession(s.mod.fl, s.handle))
}

// Login authenticates as userType with pin.
func (s *Session) Login(userType uint, pin string) error {
	cPin := C.CString(pin)
	defer C.free(unsafe.Pointer(cPin))
	return check("C_Login", C.xk_Login(s.mod.fl, s.handle,
		C.CK_USER_TYPE(userType), (*C.CK_UTF8CHAR)(unsafe.Pointer(cPin)), C.CK_ULONG(len(pin))))
}

// Logout calls C_Logout.
func (s *Session) Logout() error {
	return check("C_Logout", C.xk_Logout(s.mod.fl, s.handle))
}

// DestroyObject calls C_DestroyObject.
func (s *Session) DestroyObject(obj uint) error {
	return check("C_DestroyObject", C.xk_DestroyObject(s.mod.fl, s.handle, C.CK_OBJECT_HANDLE(obj)))
}
