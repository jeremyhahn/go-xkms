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

// Tests for the Cryptoki entry points in exports.go and exports_v32.go.
//
// Go 1.26 rejects `import "C"` in a _test.go file, so a test cannot name the
// cgo parameter types (C.CK_SESSION_HANDLE and friends) and cannot call an
// exported C_* function with an ordinary call expression. callInit below works
// around that with reflection: reflect.Type.In reports the cgo types, and
// reflect.New produces values of them without the test ever naming one. That
// keeps the assertions on the real C-ABI entry points instead of a Go-only
// stand-in of them.

import (
	"context"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// offlineTransport satisfies module.PKCS11Transport so a module can initialize
// without a daemon behind it. Only Connect and Close are implemented: these
// tests exercise session and operation bookkeeping, which the module performs
// locally. The embedded nil interface makes any backend-delegating call panic,
// so a test that starts depending on the backend fails loudly instead of
// silently exercising a different code path.
type offlineTransport struct {
	module.PKCS11Transport
}

func (offlineTransport) Connect(ctx context.Context) error { return nil }

func (offlineTransport) Close() error { return nil }

// testFixture is an initialized module with a provisioned, logged-in session
// and key objects for each operation category.
type testFixture struct {
	m       *module.Module
	session module.SessionHandle
	privKey module.ObjectHandle
	pubKey  module.ObjectHandle
}

const (
	testSOPIN   = "so-pin-1234"
	testUserPIN = "user-pin-1234"
)

// provisionTestModule installs an initialized module backed by client as the
// global module the C entry points resolve, provisions its token, and returns
// a read-write session with the normal user logged in. The token sets
// CKF_LOGIN_REQUIRED at creation, so every key-bearing initializer is refused
// until that happens.
//
// Shared by newTestFixture (offlineTransport, whose embedded PKCS11Transport
// is nil so any backend-delegating call panics -- the fixture for tests
// scoped to session/argument bookkeeping) and newCryptoFixture
// (pkcs11test.CryptoMockClient, real RSA/AES/HKDF crypto -- the fixture for
// tests that drive a C_* entry point through a genuine cryptographic success
// path), so the two fixtures cannot drift on how a token is provisioned.
func provisionTestModule(t *testing.T, client module.PKCS11Transport) (m *module.Module, session module.SessionHandle) {
	t.Helper()

	module.ResetGlobalModule()
	t.Cleanup(module.ResetGlobalModule)

	m, err := module.New(
		module.WithClient(client),
		module.WithConfig(module.DefaultConfig()),
	)
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
	if rv := m.InitPIN(soSession, []byte(testUserPIN)); rv != module.CKR_OK {
		t.Fatalf("InitPIN: %s", rv)
	}
	if rv := m.Logout(soSession); rv != module.CKR_OK {
		t.Fatalf("Logout: %s", rv)
	}
	if rv := m.CloseSession(soSession); rv != module.CKR_OK {
		t.Fatalf("CloseSession: %s", rv)
	}

	session, rv = m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession (user): %s", rv)
	}
	if rv := m.Login(session, module.CKU_USER, []byte(testUserPIN)); rv != module.CKR_OK {
		t.Fatalf("Login (user): %s", rv)
	}

	return m, session
}

// newTestFixture installs an initialized module as the global module the C
// entry points resolve, provisions its token, and returns a read-write session
// with the normal user logged in. The token sets CKF_LOGIN_REQUIRED at
// creation, so every key-bearing initializer is refused until that happens.
func newTestFixture(t *testing.T) *testFixture {
	t.Helper()

	m, session := provisionTestModule(t, offlineTransport{})

	f := &testFixture{m: m, session: session}
	f.privKey = f.createKey(t, module.CKO_PRIVATE_KEY, "test-private-key")
	f.pubKey = f.createKey(t, module.CKO_PUBLIC_KEY, "test-public-key")
	return f
}

// createKey creates an RSA key object with every usage attribute enabled. The
// initializers under test read the object's class and usage attributes and stop
// there; no key material is needed because no test here reaches a terminal
// operation that would use it.
func (f *testFixture) createKey(t *testing.T, class module.ObjectClass, label string) module.ObjectHandle {
	t.Helper()

	handle, rv := f.m.CreateObject(f.session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(class)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		// An RSA key object carries its modulus and public exponent when it is
		// created with C_CreateObject (v3.2 §6.1.2, Table 13 footnote 1).
		module.NewAttribute(module.CKA_MODULUS, make([]byte, 256)),
		module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
	})
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject(%s): %s", label, rv)
	}
	return handle
}

// callInit invokes a Cryptoki initializer through its real cgo signature with
// pMechanism set to NULL_PTR and every remaining argument zeroed, which is the
// cancellation call the spec describes. fn must be one of the exported C_*Init
// functions and must take the session handle first.
func callInit(t *testing.T, fn any, session module.SessionHandle) module.CK_RV {
	t.Helper()

	value := reflect.ValueOf(fn)
	fnType := value.Type()

	args := make([]reflect.Value, fnType.NumIn())
	for i := range args {
		arg := reflect.New(fnType.In(i)).Elem()
		if i == 0 {
			arg.SetUint(uint64(session))
		}
		args[i] = arg
	}

	return module.CK_RV(value.Call(args)[0].Uint())
}

// initCase pairs a Cryptoki initializer with the operation category its NULL
// pMechanism call must terminate and a way to start an operation in it.
type initCase struct {
	name   string
	fn     any
	opType module.OperationType
	start  func(t *testing.T, f *testFixture) module.CK_RV
}

func startEncrypt(t *testing.T, f *testFixture) module.CK_RV {
	t.Helper()
	return f.m.EncryptInit(f.session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, f.pubKey)
}

func startDecrypt(t *testing.T, f *testFixture) module.CK_RV {
	t.Helper()
	return f.m.DecryptInit(f.session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, f.privKey)
}

func startDigest(t *testing.T, f *testFixture) module.CK_RV {
	t.Helper()
	return f.m.DigestInit(f.session, &module.Mechanism{Type: module.CKM_SHA256})
}

func startSign(t *testing.T, f *testFixture) module.CK_RV {
	t.Helper()
	return f.m.SignInit(f.session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, f.privKey)
}

func startVerify(t *testing.T, f *testFixture) module.CK_RV {
	t.Helper()
	return f.m.VerifyInit(f.session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, f.pubKey)
}

// initCases lists every entry point that must treat a NULL pMechanism as a
// request to terminate the active operation of its category.
//
// C_VerifySignatureInit is included even though it reaches the same behaviour
// through Module.VerifySignatureInit rather than the shared shim helper: the
// contract is what these tests pin, not the layer that implements it.
func initCases() []initCase {
	return []initCase{
		{"C_EncryptInit", C_EncryptInit, module.OperationEncrypt, startEncrypt},
		{"C_MessageEncryptInit", C_MessageEncryptInit, module.OperationEncrypt, startEncrypt},
		{"C_DecryptInit", C_DecryptInit, module.OperationDecrypt, startDecrypt},
		{"C_MessageDecryptInit", C_MessageDecryptInit, module.OperationDecrypt, startDecrypt},
		{"C_DigestInit", C_DigestInit, module.OperationDigest, startDigest},
		{"C_SignInit", C_SignInit, module.OperationSign, startSign},
		{"C_SignRecoverInit", C_SignRecoverInit, module.OperationSign, startSign},
		{"C_MessageSignInit", C_MessageSignInit, module.OperationSign, startSign},
		{"C_VerifyInit", C_VerifyInit, module.OperationVerify, startVerify},
		{"C_VerifyRecoverInit", C_VerifyRecoverInit, module.OperationVerify, startVerify},
		{"C_MessageVerifyInit", C_MessageVerifyInit, module.OperationVerify, startVerify},
		{"C_VerifySignatureInit", C_VerifySignatureInit, module.OperationVerifySignature, nil},
	}
}

// TestInit_NullMechanismTerminatesActiveOperation is the success case: with an
// operation of the initializer's category running, a NULL pMechanism ends it
// and returns CKR_OK.
//
// PKCS#11 v3.2 §5.13.1: "C_SignInit can be called with pMechanism set to
// NULL_PTR to terminate an active signature operation."
//
// Termination is proved by restarting the operation afterwards. While an
// operation is active a second initializer of the same category is refused with
// CKR_OPERATION_ACTIVE, so a restart that succeeds can only mean the first
// operation is gone.
func TestInit_NullMechanismTerminatesActiveOperation(t *testing.T) {
	for _, tc := range initCases() {
		if tc.start == nil {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			f := newTestFixture(t)

			if rv := tc.start(t, f); rv != module.CKR_OK {
				t.Fatalf("starting the %s operation: %s", tc.opType, rv)
			}
			if rv := tc.start(t, f); rv != module.CKR_OPERATION_ACTIVE {
				t.Fatalf("the operation should be active: got %s, want CKR_OPERATION_ACTIVE", rv)
			}

			if rv := callInit(t, tc.fn, f.session); rv != module.CKR_OK {
				t.Fatalf("%s(NULL) = %s, want CKR_OK", tc.name, rv)
			}

			if rv := tc.start(t, f); rv != module.CKR_OK {
				t.Fatalf("the operation was not terminated: restart returned %s", rv)
			}
		})
	}
}

// TestInit_NullMechanismLeavesOtherCategoriesAlone checks that cancelling one
// category does not disturb another. Sessions run several operation categories
// concurrently — a dual-function flow signs while it encrypts — and a NULL
// pMechanism names exactly one of them.
func TestInit_NullMechanismLeavesOtherCategoriesAlone(t *testing.T) {
	f := newTestFixture(t)

	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("SignInit: %s", rv)
	}
	if rv := startDigest(t, f); rv != module.CKR_OK {
		t.Fatalf("DigestInit: %s", rv)
	}

	if rv := callInit(t, C_SignInit, f.session); rv != module.CKR_OK {
		t.Fatalf("C_SignInit(NULL) = %s, want CKR_OK", rv)
	}

	if rv := startDigest(t, f); rv != module.CKR_OPERATION_ACTIVE {
		t.Fatalf("the digest operation should have survived: got %s, want CKR_OPERATION_ACTIVE", rv)
	}
}

// TestInit_NullMechanismWithNoActiveOperation checks that cancelling nothing is
// CKR_OK.
//
// PKCS#11 v3.2 makes only the failure to cancel an error; it never says that
// cancelling an operation that was never initialized is one. C_SessionCancel
// §5.6.5 settles the reading for the whole module: a flag naming an
// uninitialized operation "will be ignored and C_SessionCancel will behave as
// if the operation flag was not set."
func TestInit_NullMechanismWithNoActiveOperation(t *testing.T) {
	for _, tc := range initCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFixture(t)

			if rv := callInit(t, tc.fn, f.session); rv != module.CKR_OK {
				t.Fatalf("%s(NULL) with nothing active = %s, want CKR_OK", tc.name, rv)
			}
		})
	}
}

// TestInit_NullMechanismInvalidSession checks that a cancellation aimed at a
// session that does not exist reports the session, not a cancellation failure.
// CKR_SESSION_HANDLE_INVALID is in every initializer's return table.
func TestInit_NullMechanismInvalidSession(t *testing.T) {
	for _, tc := range initCases() {
		t.Run(tc.name, func(t *testing.T) {
			newTestFixture(t)

			rv := callInit(t, tc.fn, module.SessionHandle(0xDEADBEEF))
			if rv != module.CKR_SESSION_HANDLE_INVALID {
				t.Fatalf("%s(NULL) on an unknown session = %s, want CKR_SESSION_HANDLE_INVALID", tc.name, rv)
			}
		})
	}
}

// TestInit_NullMechanismUninitializedLibrary checks that a cancellation before
// C_Initialize reports CKR_CRYPTOKI_NOT_INITIALIZED rather than pretending the
// cancellation succeeded.
func TestInit_NullMechanismUninitializedLibrary(t *testing.T) {
	for _, tc := range initCases() {
		t.Run(tc.name, func(t *testing.T) {
			module.ResetGlobalModule()
			t.Cleanup(module.ResetGlobalModule)

			rv := callInit(t, tc.fn, module.SessionHandle(1))
			if rv != module.CKR_CRYPTOKI_NOT_INITIALIZED {
				t.Fatalf("%s(NULL) before C_Initialize = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", tc.name, rv)
			}
		})
	}
}

// TestInit_MechanismStillInitializes guards the other half of the branch: a
// non-NULL pMechanism must still initialize an operation rather than cancel
// one. Without this, a helper that always cancelled would pass every test
// above.
func TestInit_MechanismStillInitializes(t *testing.T) {
	f := newTestFixture(t)

	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("SignInit with a real mechanism: %s", rv)
	}
	if rv := startSign(t, f); rv != module.CKR_OPERATION_ACTIVE {
		t.Fatalf("the operation should be active: got %s, want CKR_OPERATION_ACTIVE", rv)
	}
}

// TestCancelResult pins the translation from Module.FinishOperation's answer to
// the CK_RV an initializer may return, including the CKR_OPERATION_CANCEL_FAILED
// branch that PKCS#11 v3.2 requires when an initialized operation cannot be
// cancelled.
func TestCancelResult(t *testing.T) {
	cases := []struct {
		name string
		in   module.CK_RV
		want module.CK_RV
	}{
		{"terminated", module.CKR_OK, module.CKR_OK},
		{"nothing to terminate", module.CKR_OPERATION_NOT_INITIALIZED, module.CKR_OK},
		{"library not initialized", module.CKR_CRYPTOKI_NOT_INITIALIZED, module.CKR_CRYPTOKI_NOT_INITIALIZED},
		{"unknown session", module.CKR_SESSION_HANDLE_INVALID, module.CKR_SESSION_HANDLE_INVALID},
		{"closed session", module.CKR_SESSION_CLOSED, module.CKR_SESSION_CLOSED},
		{"device error", module.CKR_DEVICE_ERROR, module.CKR_OPERATION_CANCEL_FAILED},
		{"function failed", module.CKR_FUNCTION_FAILED, module.CKR_OPERATION_CANCEL_FAILED},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cancelResult(tc.in); got != tc.want {
				t.Errorf("cancelResult(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Mechanism-parameter admission (mechparam.go)
// ============================================================================

// mechanismParameterExpectation is the admission policy one mechanism's
// parameter is expected to carry.
type mechanismParameterExpectation struct {
	// required is whether the mechanism is refused without its parameter.
	required bool
	// unsupported is whether a well-formed parameter is refused because this
	// module cannot perform what it selects.
	unsupported bool
}

// parameterisedMechanisms lists every mechanism whose CK_MECHANISM parameter is
// a fixed-layout C structure this module reads, with the policy each carries.
//
// It is written out by hand rather than derived from mechanismParameterDecoders
// so the two are independent: a decoder that loses its size bound, or is added
// or changed without a deliberate decision about the absent and unsupported
// cases, shows up as a difference between this list and the map.
var parameterisedMechanisms = map[module.MechanismType]mechanismParameterExpectation{
	module.CKM_ECDH1_DERIVE:                  {},
	module.CKM_ECDH1_COFACTOR_DERIVE:         {},
	module.CKM_RSA_PKCS_PSS:                  {},
	module.CKM_SHA1_RSA_PKCS_PSS:             {},
	module.CKM_SHA256_RSA_PKCS_PSS:           {},
	module.CKM_SHA384_RSA_PKCS_PSS:           {},
	module.CKM_SHA512_RSA_PKCS_PSS:           {},
	module.CKM_RSA_PKCS_OAEP:                 {required: true},
	module.CKM_AES_GCM:                       {},
	module.CKM_HKDF_DERIVE:                   {},
	module.CKM_HKDF_DATA:                     {},
	module.CKM_SP800_108_COUNTER_KDF:         {},
	module.CKM_SP800_108_DOUBLE_PIPELINE_KDF: {},
	module.CKM_SP800_108_FEEDBACK_KDF:        {},

	// CKM_EDDSA is the one entry that refuses a well-formed parameter. Every
	// CK_EDDSA_PARAMS selects Ed25519ctx, Ed25519ph, Ed448 or Ed448ph (v3.2
	// section 6.3.14, Table 73), and no wire format this shared library speaks
	// carries phFlag or pContextData to the token, so honouring the parameter
	// is not possible and defaulting to pure Ed25519 would return a signature
	// under a scheme the caller did not ask for.
	module.CKM_EDDSA: {unsupported: true},
}

// TestMechanismParameterDecoders_CoverEveryParameterisedMechanism proves the
// decoder table is the complete and only description of the mechanisms whose
// parameter the boundary casts.
//
// Every entry must carry a non-zero StructSize, because that size is the sole
// bound on the cast its Decode makes: an entry without one would read a whole
// C structure out of whatever length the caller declared.
func TestMechanismParameterDecoders_CoverEveryParameterisedMechanism(t *testing.T) {
	for mechType, want := range parameterisedMechanisms {
		decoder, ok := mechanismParameterDecoders[mechType]
		if !ok {
			t.Errorf("mechanism 0x%08X has no decoder; its parameter would be accepted and then defaulted", uint(mechType))
			continue
		}
		if decoder.StructSize == 0 {
			t.Errorf("decoder for mechanism 0x%08X declares StructSize 0, which bounds nothing", uint(mechType))
		}
		if decoder.Decode == nil {
			t.Errorf("decoder for mechanism 0x%08X has no Decode function", uint(mechType))
		}
		if decoder.Required != want.required {
			t.Errorf("decoder for mechanism 0x%08X has Required=%v, want %v", uint(mechType), decoder.Required, want.required)
		}
		if decoder.Unsupported != want.unsupported {
			t.Errorf("decoder for mechanism 0x%08X has Unsupported=%v, want %v", uint(mechType), decoder.Unsupported, want.unsupported)
		}
	}

	for mechType := range mechanismParameterDecoders {
		if _, ok := parameterisedMechanisms[mechType]; !ok {
			t.Errorf("mechanism 0x%08X gained a decoder without a decision about an absent parameter", uint(mechType))
		}
	}
}

// TestCheckMechanismParameter_AcceptsWellFormedParameters proves a parameter
// that is at least as long as the structure it claims to be is admitted.
//
// PKCS#11 v3.2 section 5.2 states ulParameterLen as the length of the buffer,
// not as an exact struct size, so a caller passing a longer buffer -- a later
// revision of the structure, or one embedded in a larger allocation -- is
// conformant and must not be refused.
func TestCheckMechanismParameter_AcceptsWellFormedParameters(t *testing.T) {
	for mechType, want := range parameterisedMechanisms {
		if want.unsupported {
			continue
		}
		decoder := mechanismParameterDecoders[mechType]
		size := uint64(decoder.StructSize)

		for _, length := range []uint64{size, size + 1, size + 4096} {
			got := checkMechanismParameter(decoder, true, length)
			if got != module.CKR_OK {
				t.Errorf("checkMechanismParameter(0x%08X, present, %d bytes) = %s, want CKR_OK (structure is %d bytes)",
					uint(mechType), length, got, size)
			}
		}
	}
}

// TestCheckMechanismParameter_RejectsTruncatedParameters proves a parameter
// shorter than its structure is refused rather than read.
//
// This is a memory-safety property, not a validation nicety: the decoder casts
// pParameter to the whole structure, and several of those structures end in a
// pointer, so reading one out of a shorter buffer dereferences memory past the
// end of the caller's allocation. CKR_MECHANISM_PARAM_INVALID is also the only
// answer that stays visible -- treating the parameter as absent would silently
// select the mechanism's default behaviour.
func TestCheckMechanismParameter_RejectsTruncatedParameters(t *testing.T) {
	for mechType := range parameterisedMechanisms {
		decoder := mechanismParameterDecoders[mechType]
		size := uint64(decoder.StructSize)

		lengths := []uint64{1, size - 1}
		if size > 8 {
			lengths = append(lengths, 8)
		}

		for _, length := range lengths {
			got := checkMechanismParameter(decoder, true, length)
			if got != module.CKR_MECHANISM_PARAM_INVALID {
				t.Errorf("checkMechanismParameter(0x%08X, present, %d bytes) = %s, want CKR_MECHANISM_PARAM_INVALID (structure is %d bytes)",
					uint(mechType), length, got, size)
			}
		}
	}
}

// TestCheckMechanismParameter_RejectsAbsentRequiredParameter proves
// CKM_RSA_PKCS_OAEP is refused without CK_RSA_PKCS_OAEP_PARAMS.
//
// PKCS#11 v3.2 section 6.1.10 gives the mechanism a mandatory parameter
// structure carrying the digest, the mask generation function and the label.
// A module that substitutes defaults instead encrypts under a digest the
// caller never chose, and the caller cannot tell: the operation succeeds and
// the ciphertext is well formed, merely undecryptable by the intended peer.
// SoftHSM2 answers CKR_ARGUMENTS_BAD, which this module matches.
func TestCheckMechanismParameter_RejectsAbsentRequiredParameter(t *testing.T) {
	decoder := mechanismParameterDecoders[module.CKM_RSA_PKCS_OAEP]

	if got := checkMechanismParameter(decoder, false, 0); got != module.CKR_ARGUMENTS_BAD {
		t.Errorf("checkMechanismParameter(CKM_RSA_PKCS_OAEP, NULL pParameter) = %s, want CKR_ARGUMENTS_BAD", got)
	}

	// A non-NULL pointer with a zero length says the same thing and must be
	// answered the same way.
	if got := checkMechanismParameter(decoder, true, 0); got != module.CKR_ARGUMENTS_BAD {
		t.Errorf("checkMechanismParameter(CKM_RSA_PKCS_OAEP, zero ulParameterLen) = %s, want CKR_ARGUMENTS_BAD", got)
	}
}

// TestCheckMechanismParameter_AcceptsAbsentOptionalParameter proves the
// mechanisms whose parameter structure is optional still work without one.
//
// CKM_EDDSA without CK_EDDSA_PARAMS is pure Ed25519/Ed448 (RFC 8032 Table 73,
// PKCS#11 v3.2 section 6.24), and refusing it would break every caller that
// wants the pure variant. The same reasoning covers the mechanisms whose
// absent parameter the module layer rejects on its own terms.
func TestCheckMechanismParameter_AcceptsAbsentOptionalParameter(t *testing.T) {
	for mechType, want := range parameterisedMechanisms {
		if want.required {
			continue
		}
		decoder := mechanismParameterDecoders[mechType]
		if got := checkMechanismParameter(decoder, false, 0); got != module.CKR_OK {
			t.Errorf("checkMechanismParameter(0x%08X, NULL pParameter) = %s, want CKR_OK", uint(mechType), got)
		}
	}
}

// TestCheckMechanismParameter_RefusesEdDSAVariantsItCannotPerform proves a
// CK_EDDSA_PARAMS is refused rather than quietly turned into pure Ed25519.
//
// PKCS#11 v3.2 section 6.3.14, Table 73 makes every present CK_EDDSA_PARAMS a
// request for Ed25519ctx, Ed25519ph, Ed448 or Ed448ph. This module cannot
// deliver any of them: phFlag and pContextData reach the crypto layer but the
// protobuf SignRequest and VerifyRequest have no field to carry them to the
// token, so the daemon signs pure Ed25519 whatever was asked for.
//
// The two failures that produces are the reason the refusal exists. A prehash
// request answered with a pure signature is rejected by any verifier computing
// Ed25519ph, and the caller learns that only from the peer. A context request
// is worse: Ed25519 signing is deterministic, so the "context" signature is
// byte-identical to the one produced without it, and the domain separation the
// caller added is absent while every test it can run locally still passes.
func TestCheckMechanismParameter_RefusesEdDSAVariantsItCannotPerform(t *testing.T) {
	decoder := mechanismParameterDecoders[module.CKM_EDDSA]
	size := uint64(decoder.StructSize)

	for _, length := range []uint64{size, size + 64} {
		got := checkMechanismParameter(decoder, true, length)
		if got != module.CKR_MECHANISM_PARAM_INVALID {
			t.Errorf("checkMechanismParameter(CKM_EDDSA, well-formed CK_EDDSA_PARAMS of %d bytes) = %s, "+
				"want CKR_MECHANISM_PARAM_INVALID; anything else lets a caller receive a pure Ed25519 "+
				"signature for a scheme it did not ask for", length, got)
		}
	}
}

// TestCheckMechanismParameter_StillAllowsPureEdDSA proves the refusal above is
// scoped to the parameter and does not break plain CKM_EDDSA.
//
// An absent CK_EDDSA_PARAMS is exactly how RFC 8032 pure Ed25519 is requested
// (v3.2 section 6.3.14, Table 73), which is the scheme this module does
// implement; refusing it would take away working functionality rather than
// remove a silent substitution.
func TestCheckMechanismParameter_StillAllowsPureEdDSA(t *testing.T) {
	decoder := mechanismParameterDecoders[module.CKM_EDDSA]

	if got := checkMechanismParameter(decoder, false, 0); got != module.CKR_OK {
		t.Fatalf("checkMechanismParameter(CKM_EDDSA, NULL pParameter) = %s, want CKR_OK; a NULL CK_EDDSA_PARAMS is pure Ed25519", got)
	}
}

// TestCheckMechanismParameter_RejectsLengthWithoutBuffer proves a declared
// length with no buffer behind it is refused.
//
// CK_MECHANISM.pParameter and ulParameterLen are a buffer and its length
// (PKCS#11 v3.2 section 5.2). A non-zero length over a NULL pointer describes
// memory that does not exist, so there is nothing to read and nothing to
// default to; the same shape is refused with CKR_ARGUMENTS_BAD wherever else
// this module takes a buffer and a length.
func TestCheckMechanismParameter_RejectsLengthWithoutBuffer(t *testing.T) {
	decoder := mechanismParameterDecoders[module.CKM_AES_GCM]

	if got := checkMechanismParameter(decoder, false, 64); got != module.CKR_ARGUMENTS_BAD {
		t.Errorf("checkMechanismParameter(CKM_AES_GCM, NULL pParameter, 64 bytes) = %s, want CKR_ARGUMENTS_BAD", got)
	}

	// A mechanism with no parameter structure of its own is held to the same
	// rule: the malformed pair is malformed regardless of mechanism.
	if got := checkMechanismParameter(nil, false, 64); got != module.CKR_ARGUMENTS_BAD {
		t.Errorf("checkMechanismParameter(unparameterised mechanism, NULL pParameter, 64 bytes) = %s, want CKR_ARGUMENTS_BAD", got)
	}
}

// TestCheckMechanismParameter_UnparameterisedMechanismsPassThrough proves a
// mechanism the boundary does not decode is left to the module layer.
//
// CKM_AES_CBC and friends carry an IV as raw bytes rather than a structure, so
// there is no size to enforce here; inventing one would refuse conformant
// callers.
func TestCheckMechanismParameter_UnparameterisedMechanismsPassThrough(t *testing.T) {
	for _, length := range []uint64{0, 1, 16, 1 << 20} {
		if got := checkMechanismParameter(nil, true, length); got != module.CKR_OK {
			t.Errorf("checkMechanismParameter(unparameterised mechanism, %d bytes) = %s, want CKR_OK", length, got)
		}
	}
	if got := checkMechanismParameter(nil, false, 0); got != module.CKR_OK {
		t.Errorf("checkMechanismParameter(unparameterised mechanism, NULL pParameter) = %s, want CKR_OK", got)
	}
}

// callExport invokes an exported C_* function through its real cgo signature.
//
// Every argument is zeroed unless setArg supplies a value for its index, which
// keeps the assertions on the shipped entry points instead of a Go-only
// stand-in: reflect.Type.In reports the cgo parameter types and reflect.New
// produces values of them without the test ever naming one, which a _test.go
// file cannot do because Go rejects `import "C"` there.
func callExport(t *testing.T, fn any, setArg map[int]func(reflect.Value)) module.CK_RV {
	t.Helper()

	value := reflect.ValueOf(fn)
	fnType := value.Type()

	args := make([]reflect.Value, fnType.NumIn())
	for i := range args {
		arg := reflect.New(fnType.In(i)).Elem()
		if set, ok := setArg[i]; ok {
			set(arg)
		}
		args[i] = arg
	}

	return module.CK_RV(value.Call(args)[0].Uint())
}

// TestRecoverCKRV_ConvertsAPanicIntoAReturnCode proves the guard every C_*
// entry point installs turns a panic into CKR_FUNCTION_FAILED at the real
// boundary.
//
// A panic that unwound past an //export function would cross the C ABI, where
// there is no Go frame to unwind into and the calling application dies. PKCS#11
// v3.2 section 5.1 admits only a CK_RV as an answer, so CKR_FUNCTION_FAILED is
// what the caller has to see instead.
//
// The panic is a real one, not a simulated one: newTestFixture installs a
// transport whose embedded PKCS11Transport is nil, so C_Sign's delegation to
// the backend dereferences it. That is the shape a malformed input would take
// if one ever reached a dereference, and it exercises the deferred guard on
// C_Sign itself.
func TestRecoverCKRV_ConvertsAPanicIntoAReturnCode(t *testing.T) {
	f := newTestFixture(t)

	if rv := startSign(t, f); rv != module.CKR_OK {
		t.Fatalf("SignInit: %s", rv)
	}

	// C_Sign(hSession, pData=NULL, ulDataLen=0, pSignature=NULL,
	// pulSignatureLen=&len): the length query still has to reach the backend to
	// learn the signature size, and that is where the nil transport panics.
	var signatureLen reflect.Value
	rv := callExport(t, C_Sign, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		4: func(v reflect.Value) {
			signatureLen = reflect.New(v.Type().Elem())
			v.Set(signatureLen)
		},
	})

	if rv != module.CKR_FUNCTION_FAILED {
		t.Fatalf("C_Sign over a panicking backend returned %s, want CKR_FUNCTION_FAILED; "+
			"a panic that is not converted here unwinds into C and terminates the application", rv)
	}
}

// TestRecoverCKRV_LeavesASuccessfulReturnAlone proves the guard does nothing
// when no panic is in flight.
//
// It runs on the deferred path of every entry point, including the ones that
// succeed, so a guard that overwrote the return value unconditionally would
// fail every call in the library. C_SignInit with a NULL pMechanism and no
// active operation is a call that must report CKR_OK.
func TestRecoverCKRV_LeavesASuccessfulReturnAlone(t *testing.T) {
	f := newTestFixture(t)

	if rv := callInit(t, C_SignInit, f.session); rv != module.CKR_OK {
		t.Fatalf("C_SignInit with a NULL pMechanism returned %s, want CKR_OK", rv)
	}
}
