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

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
)

// unregisteredMechanism is a vendor-defined mechanism value this module does
// not implement. It exercises the CKR_MECHANISM_INVALID path of every function
// that resolves a mechanism, without depending on which standard mechanisms the
// registry happens to carry.
const unregisteredMechanism MechanismType = CKM_VENDOR_DEFINED | 0x0BADBEEF

// createAllUsagesKeyFixture provisions an initialized, authenticated module
// with one key object marked for every operation an initializer can gate on.
//
// One fixture serves all of them so that a test which varies only the
// initializer under test cannot accidentally vary the key as well: when
// C_SignInit and C_EncryptInit disagree about an error, the key is the one
// thing that is provably not the cause.
func createAllUsagesKeyFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	sessionHandle := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		// An RSA public key must carry its modulus and public exponent when it
		// is created with C_CreateObject (v3.2 §6.1.2, Table 13 footnote 1).
		NewAttribute(CKA_MODULUS, make([]byte, 256)),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		NewStringAttribute(CKA_LABEL, "init-contract-key"),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_SIGN_RECOVER, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_VERIFY_RECOVER, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_MODIFIABLE, true),
		NewBoolAttribute(CKA_COPYABLE, true),
		NewBoolAttribute(CKA_DESTROYABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, keyHandle
}

// createNoUsagesKeyFixture provisions a key that exists and is visible to the
// session but carries none of the usage attributes, so every initializer must
// refuse it.
func createNoUsagesKeyFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	sessionHandle := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		// Required at creation (v3.2 §6.1.2 footnote 1). What makes this key
		// unusable is the absence of the USAGE attributes below, not of its
		// components -- the fixture must still be a well-formed RSA public key.
		NewAttribute(CKA_MODULUS, make([]byte, 256)),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		NewStringAttribute(CKA_LABEL, "init-contract-unusable-key"),
		NewBoolAttribute(CKA_TOKEN, false),
	})
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, keyHandle
}

// initTerminationCase describes one initializer that PKCS#11 v3.2 lets an
// application call with a NULL mechanism to terminate an active operation.
type initTerminationCase struct {
	name string

	// opType is the operation category the initializer claims and terminates.
	opType OperationType

	// start begins an operation of that category.
	start func(m *Module, sessionHandle SessionHandle, keyHandle ObjectHandle) CK_RV

	// terminate calls the initializer with a nil mechanism.
	terminate func(m *Module, sessionHandle SessionHandle) CK_RV
}

// initTerminationCases lists every Go-API initializer whose C counterpart
// carries the NULL-pMechanism termination contract. The three initializers
// without one — C_GenerateKey, C_GenerateKeyPair and C_DeriveKey, plus
// C_WrapKey and C_UnwrapKey — are covered separately in
// TestInitializersWithoutTerminationContract.
func initTerminationCases() []initTerminationCase {
	rsa := &Mechanism{Type: CKM_RSA_PKCS}

	return []initTerminationCase{
		{
			name:   "C_SignInit",
			opType: OperationSign,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.SignInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.SignInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_SignRecoverInit",
			opType: OperationSign,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.SignRecoverInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.SignRecoverInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_VerifyInit",
			opType: OperationVerify,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.VerifyInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.VerifyInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_VerifyRecoverInit",
			opType: OperationVerify,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.VerifyRecoverInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.VerifyRecoverInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_EncryptInit",
			opType: OperationEncrypt,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.EncryptInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.EncryptInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_DecryptInit",
			opType: OperationDecrypt,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.DecryptInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.DecryptInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_DigestInit",
			opType: OperationDigest,
			start: func(m *Module, s SessionHandle, _ ObjectHandle) CK_RV {
				return m.DigestInit(s, &Mechanism{Type: CKM_SHA256})
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.DigestInit(s, nil)
			},
		},
		{
			name:   "C_MessageEncryptInit",
			opType: OperationEncrypt,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.MessageEncryptInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.MessageEncryptInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_MessageDecryptInit",
			opType: OperationDecrypt,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.MessageDecryptInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.MessageDecryptInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_MessageSignInit",
			opType: OperationSign,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.MessageSignInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.MessageSignInit(s, nil, ObjectHandle(0))
			},
		},
		{
			name:   "C_MessageVerifyInit",
			opType: OperationVerify,
			start: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV {
				return m.MessageVerifyInit(s, rsa, k)
			},
			terminate: func(m *Module, s SessionHandle) CK_RV {
				return m.MessageVerifyInit(s, nil, ObjectHandle(0))
			},
		},
	}
}

// TestInitNullMechanismTerminatesActiveOperation covers the success half of the
// contract PKCS#11 v3.2 §5.13.1 states for C_SignInit and repeats for every
// other initializer: "C_SignInit can be called with pMechanism set to NULL_PTR
// to terminate an active signature operation."
//
// This rule used to live only in the cgo shim, so a Go consumer of Module got
// CKR_ARGUMENTS_BAD where a C consumer got CKR_OK. It is asserted here, at the
// layer that owns it, for every initializer that has the contract.
func TestInitNullMechanismTerminatesActiveOperation(t *testing.T) {
	for _, tc := range initTerminationCases() {
		t.Run(tc.name, func(t *testing.T) {
			m, sessionHandle, keyHandle := createAllUsagesKeyFixture(t)
			defer m.Finalize()

			require.Equal(t, CKR_OK, tc.start(m, sessionHandle, keyHandle),
				"the fixture must actually start an operation, or termination proves nothing")

			assert.Equal(t, CKR_OK, tc.terminate(m, sessionHandle),
				"a NULL mechanism terminates the operation and reports success")

			// FinishOperation is the module's one way to end an operation of a
			// category, so its answer is the authority on whether one is still
			// active. CKR_OPERATION_NOT_INITIALIZED means the termination
			// really released the slot rather than merely reporting CKR_OK.
			assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED,
				m.FinishOperation(sessionHandle, tc.opType),
				"no operation of this category may remain active")
		})
	}
}

// TestInitNullMechanismWithNoActiveOperation pins the answer when the
// application cancels something that was never started.
//
// PKCS#11 v3.2 §5.6.5 settles it for C_SessionCancel — a flag naming an
// uninitialized operation "will be ignored and C_SessionCancel will behave as
// if the operation flag was not set" — and the caller's postcondition, that no
// operation of the category is active, holds either way. Answering
// CKR_OPERATION_NOT_INITIALIZED would report an error for reaching exactly the
// state the caller asked for.
func TestInitNullMechanismWithNoActiveOperation(t *testing.T) {
	for _, tc := range initTerminationCases() {
		t.Run(tc.name, func(t *testing.T) {
			m, sessionHandle, _ := createAllUsagesKeyFixture(t)
			defer m.Finalize()

			assert.Equal(t, CKR_OK, tc.terminate(m, sessionHandle),
				"cancelling an inactive operation is ignored, not an error")

			// Idempotent: a second cancellation is equally ignored.
			assert.Equal(t, CKR_OK, tc.terminate(m, sessionHandle))
		})
	}
}

// TestInitNullMechanismRejectsBadSession is the negative half of the
// termination contract.
//
// A NULL mechanism asks the module to cancel an operation on a session; when
// the session or the library cannot be resolved, there was no cancellation to
// refuse, so the failure must be reported as what it is. Answering
// CKR_OPERATION_CANCEL_FAILED would tell the application its token declined a
// cancellation that was never attempted, and CKR_OK would claim a postcondition
// on a session that does not exist.
func TestInitNullMechanismRejectsBadSession(t *testing.T) {
	const closedSession = SessionHandle(9999)

	for _, tc := range initTerminationCases() {
		t.Run(tc.name+"/invalid session", func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()

			assert.Equal(t, CKR_SESSION_HANDLE_INVALID, tc.terminate(m, closedSession))
		})

		t.Run(tc.name+"/library not initialized", func(t *testing.T) {
			m := createTestModule(t)

			assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, tc.terminate(m, closedSession))
		})
	}
}

// TestVerifySignatureInitNullMechanismRejectsBadSession covers the same
// negative path for C_VerifySignatureInit (v3.2 §5.15.7), which returns a typed
// error rather than a CK_RV and so is not in the shared table.
func TestVerifySignatureInitNullMechanismRejectsBadSession(t *testing.T) {
	t.Run("invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		err := m.VerifySignatureInit(SessionHandle(9999), nil, ObjectHandle(0), nil)
		require.Error(t, err)

		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, pkcsErr.Code)
	})

	t.Run("library not initialized", func(t *testing.T) {
		m := createTestModule(t)

		err := m.VerifySignatureInit(SessionHandle(9999), nil, ObjectHandle(0), nil)
		require.Error(t, err)

		var pkcsErr *PKCS11Error
		require.ErrorAs(t, err, &pkcsErr)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, pkcsErr.Code)
	})
}

// initOrderingCase describes one key-bearing initializer for the ordering
// tests.
type initOrderingCase struct {
	name string

	call func(m *Module, sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) CK_RV

	// usageDeniedRV is the code this function returns for a key that exists but
	// is not marked for the operation. It is CKR_KEY_FUNCTION_NOT_PERMITTED
	// for every one of them, which is what v3.2 §5.1.6 defines for "a key used
	// for a cryptographic purpose that the key's attributes are not set to
	// allow". The field remains per-function so a genuine divergence can be
	// expressed rather than assumed away.
	usageDeniedRV CK_RV

	// soundKey provisions a key this function has no complaint about, so the
	// only fault left for it to report is the mechanism.
	soundKey func(t *testing.T) (*Module, SessionHandle, ObjectHandle)
}

// initOrderingCases lists every initializer that takes both a mechanism and a
// key, which is the set over which an ordering can be inconsistent.
func initOrderingCases() []initOrderingCase {
	return []initOrderingCase{
		{
			name: "C_SignInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.SignInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_SignRecoverInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.SignRecoverInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_VerifyInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.VerifyInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_VerifyRecoverInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.VerifyRecoverInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_EncryptInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.EncryptInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_DecryptInit",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				return m.DecryptInit(s, mech, k)
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			soundKey:      createAllUsagesKeyFixture,
		},
		{
			name: "C_DeriveKey",
			call: func(m *Module, s SessionHandle, mech *Mechanism, k ObjectHandle) CK_RV {
				_, rv := m.DeriveKey(s, mech, k, nil)
				return rv
			},
			usageDeniedRV: CKR_KEY_FUNCTION_NOT_PERMITTED,
			// The shared fixture's key is a public key with no CKA_DERIVE, so
			// C_DeriveKey needs one that carries it.
			soundKey: createTestModuleWithSecretKey,
		},
	}
}

// TestInitValidatesKeyBeforeMechanism pins the ordering every key-bearing
// initializer now shares.
//
// PKCS#11 v3.2 §5.1.6 leaves the choice open — "there are in general no
// particular priorities among the errors listed below" — so no order is more
// conformant than another and the defect this pins is inconsistency, not
// direction. Before this test the module split three ways: C_SignInit,
// C_SignRecoverInit and C_VerifyRecoverInit checked the mechanism first,
// C_EncryptInit, C_DecryptInit, C_VerifyInit and C_DeriveKey checked the key
// first, and C_GenerateKey, C_GenerateKeyPair, C_WrapKey and C_UnwrapKey never
// checked the mechanism at all.
//
// Key-first is what SoftHSM does, and SoftHSM is the implementation
// applications are written and debugged against.
func TestInitValidatesKeyBeforeMechanism(t *testing.T) {
	require.Nil(t, GetMechanismDescriptor(unregisteredMechanism),
		"the fixture mechanism must be one the module does not implement")

	bogus := &Mechanism{Type: unregisteredMechanism}

	for _, tc := range initOrderingCases() {
		t.Run(tc.name+"/unresolvable key wins over invalid mechanism", func(t *testing.T) {
			m, sessionHandle, _ := createAllUsagesKeyFixture(t)
			defer m.Finalize()

			assert.Equal(t, CKR_KEY_HANDLE_INVALID,
				tc.call(m, sessionHandle, bogus, ObjectHandle(0xDEAD)),
				"both faults hold; the key is reported because the key is checked first")
		})

		t.Run(tc.name+"/unusable key wins over invalid mechanism", func(t *testing.T) {
			m, sessionHandle, keyHandle := createNoUsagesKeyFixture(t)
			defer m.Finalize()

			assert.Equal(t, tc.usageDeniedRV,
				tc.call(m, sessionHandle, bogus, keyHandle),
				"a key that exists but is not marked for the operation is still a key fault")
		})

		t.Run(tc.name+"/invalid mechanism once the key is sound", func(t *testing.T) {
			m, sessionHandle, keyHandle := tc.soundKey(t)
			defer m.Finalize()

			assert.Equal(t, CKR_MECHANISM_INVALID,
				tc.call(m, sessionHandle, bogus, keyHandle),
				"with nothing wrong with the key, the mechanism is what is left to refuse")
		})
	}
}

// TestDeriveKeyKeyUsageIsKeyFunctionNotPermitted pins the code a base key
// without CKA_DERIVE produces.
//
// The two candidates are settled by their definitions, not by C_DeriveKey's
// enumerated return values. PKCS#11 v3.2 §5.1.6 defines
// CKR_KEY_FUNCTION_NOT_PERMITTED as "an attempt has been made to use a key for
// a cryptographic purpose that the key's attributes are not set to allow it to
// do" — this condition — and CKR_KEY_TYPE_INCONSISTENT as "the specified key is
// not the correct type of key to use with the specified mechanism", which a key
// of the right type with the wrong attribute is not.
//
// §5.18.5's list omits the former, which is why the module returned the latter
// for a time. A list of what a function may return cannot make a code apply
// whose own definition excludes the condition, and §5.1.7 permits any
// applicable code where several apply. SoftHSM2 returns
// CKR_KEY_FUNCTION_NOT_PERMITTED here; the C ABI suite's
// TestReferenceDeriveKeyRefusesABaseKeyWithoutCKADerive records that probe, and
// TestECDHRequiresCKADeriveOnTheBaseKey asserts the same code at the boundary.
func TestDeriveKeyKeyUsageIsKeyFunctionNotPermitted(t *testing.T) {
	t.Run("base key without CKA_DERIVE", func(t *testing.T) {
		m, sessionHandle, keyHandle := createNoUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.DeriveKey(sessionHandle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, nil)
		assert.Equal(t, CKR_KEY_FUNCTION_NOT_PERMITTED, rv)
	})

	t.Run("base key with CKA_DERIVE gets past the usage gate", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		// The fixture key carries CKA_DERIVE, so whatever this call reports it
		// must not be the usage refusal — otherwise the negative case above
		// would pass for the wrong reason.
		_, rv := m.DeriveKey(sessionHandle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, nil)
		assert.NotEqual(t, CKR_KEY_FUNCTION_NOT_PERMITTED, rv)
	})
}

// TestInitializersWithoutTerminationContract covers the five initializers that
// PKCS#11 v3.2 gives no NULL-pMechanism contract: C_GenerateKey (§5.18.1),
// C_GenerateKeyPair (§5.18.2), C_WrapKey (§5.18.3), C_UnwrapKey (§5.18.4) and
// C_DeriveKey (§5.18.5). None of their return tables lists
// CKR_OPERATION_CANCEL_FAILED, and none of them has an operation to cancel, so
// a nil mechanism there is a malformed argument and stays CKR_ARGUMENTS_BAD.
//
// All five reached mechanism.Type without a nil guard before this change, which
// made a NULL pMechanism a panic rather than an error.
func TestInitializersWithoutTerminationContract(t *testing.T) {
	t.Run("C_GenerateKey", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(sessionHandle, nil, nil)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("C_GenerateKeyPair", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(sessionHandle, nil, nil, nil)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("C_WrapKey", func(t *testing.T) {
		m, sessionHandle, wrappingKey, targetKey := createWrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.WrapKey(sessionHandle, nil, wrappingKey, targetKey)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("C_UnwrapKey", func(t *testing.T) {
		m, sessionHandle, unwrappingKey := createUnwrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.UnwrapKey(sessionHandle, nil, unwrappingKey, []byte("wrapped"), nil)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})

	t.Run("C_DeriveKey", func(t *testing.T) {
		m, sessionHandle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		_, rv := m.DeriveKey(sessionHandle, nil, keyHandle, nil)
		assert.Equal(t, CKR_ARGUMENTS_BAD, rv)
	})
}

// TestKeyManagementValidatesMechanism covers the four functions that had no
// mechanism validation at all: C_GenerateKey, C_GenerateKeyPair, C_WrapKey and
// C_UnwrapKey. Each dispatched on mechanism.Type through its own path and never
// asked whether the module implements — or, in FIPS mode, may offer — the
// mechanism it was handed.
func TestKeyManagementValidatesMechanism(t *testing.T) {
	require.Nil(t, GetMechanismDescriptor(unregisteredMechanism),
		"the fixture mechanism must be one the module does not implement")

	bogus := &Mechanism{Type: unregisteredMechanism}

	t.Run("C_GenerateKey", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(sessionHandle, bogus, nil)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("C_GenerateKeyPair", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(sessionHandle, bogus, nil, nil)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("C_WrapKey", func(t *testing.T) {
		m, sessionHandle, wrappingKey, targetKey := createWrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.WrapKey(sessionHandle, bogus, wrappingKey, targetKey)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("C_UnwrapKey", func(t *testing.T) {
		m, sessionHandle, unwrappingKey := createUnwrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.UnwrapKey(sessionHandle, bogus, unwrappingKey, []byte("wrapped"), nil)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("a supported mechanism is not refused", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		// The negative cases above would pass for the wrong reason if the new
		// gate refused everything, so pin one call that must get through it.
		handle, rv := m.GenerateKey(sessionHandle, &Mechanism{Type: CKM_AES_KEY_GEN}, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewUint32Attribute(CKA_VALUE_LEN, 32),
			NewBoolAttribute(CKA_ENCRYPT, true),
		})
		require.Equal(t, CKR_OK, rv)
		assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	})
}

// withMechanismWithheldInFIPS makes mechType non-approved for the duration of
// the test and turns FIPS mode on.
//
// Doing it this way rather than picking a mechanism NIST currently disallows
// keeps the test about the choke point — whether the function consults
// GetMechanismDescriptor at all — instead of about which mechanisms happen to
// be approved today, which is a policy table that will keep moving.
func withMechanismWithheldInFIPS(t *testing.T, mechType MechanismType) {
	t.Helper()

	original, ok := mechanismRegistry[mechType]
	require.True(t, ok, "%v must be a registered mechanism", mechType)

	withheld := *original
	withheld.FIPSApproved = false
	mechanismRegistry[mechType] = &withheld
	t.Cleanup(func() { mechanismRegistry[mechType] = original })

	withFIPSMode(t, true)

	require.Nil(t, GetMechanismDescriptor(mechType),
		"the fixture must actually withhold the mechanism")
}

// TestFIPSFilterReachesDeriveAndWrap pins the FIPS choke point on the two
// functions that used to bypass it.
//
// GetMechanismDescriptor is where the FIPS filter lives, and C_DeriveKey and
// C_WrapKey never called it: they dispatched on mechanism.Type through their
// own switch and through mechanismToAlgorithm. Nothing withheld was reachable
// in practice, but only incidentally — the withheld derivation mechanisms
// happened to fail on their parameters instead — so a backend gaining support
// would have made them usable under FIPS with no check at all.
func TestFIPSFilterReachesDeriveAndWrap(t *testing.T) {
	t.Run("C_DeriveKey refuses a mechanism FIPS withholds", func(t *testing.T) {
		withMechanismWithheldInFIPS(t, CKM_HKDF_DERIVE)

		m, sessionHandle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		_, rv := m.DeriveKey(sessionHandle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, nil)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv,
			"a withheld mechanism must be refused as invalid, not attempted")
	})

	t.Run("C_DeriveKey accepts the same mechanism outside FIPS", func(t *testing.T) {
		withFIPSMode(t, false)

		m, sessionHandle, keyHandle := createTestModuleWithSecretKey(t)
		defer m.Finalize()

		// Whatever this call goes on to report, it must not be the refusal the
		// FIPS filter produces, or the case above would pass for the wrong
		// reason.
		_, rv := m.DeriveKey(sessionHandle, &Mechanism{Type: CKM_HKDF_DERIVE}, keyHandle, nil)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, rv)
	})

	// CKM_AES_CBC rather than CKM_AES_KEY_WRAP, and the choice is load-bearing.
	// PKCS#11 v3.2 §6.10.5 has AES-CBC wrap and unwrap secret keys, so it is a
	// legitimate wrapping mechanism, and unlike CKM_AES_KEY_WRAP it carries
	// CKF_ENCRYPT, which means C_WrapKey's fallback path accepts it and the wrap
	// proceeds. A mechanism the fallback happens to reject for its own reasons
	// would produce CKR_MECHANISM_INVALID whether or not the FIPS filter was
	// consulted, and the test would pass without proving anything — which is
	// exactly the accidental safety this change exists to replace.
	const wrapMechanism = CKM_AES_CBC

	t.Run("C_WrapKey refuses a mechanism FIPS withholds", func(t *testing.T) {
		withMechanismWithheldInFIPS(t, wrapMechanism)

		m, sessionHandle, wrappingKey, targetKey := createWrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.WrapKey(sessionHandle, &Mechanism{Type: wrapMechanism}, wrappingKey, targetKey)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv,
			"a withheld mechanism must be refused as invalid, not sent to the backend")
	})

	t.Run("C_WrapKey accepts the same mechanism outside FIPS", func(t *testing.T) {
		withFIPSMode(t, false)

		m, sessionHandle, wrappingKey, targetKey := createWrapKeyFixture(t)
		defer m.Finalize()

		// Without the filter the mechanism reaches the wrapping path, so the
		// case above is proving the filter rather than a mechanism the module
		// would have refused anyway.
		_, rv := m.WrapKey(sessionHandle, &Mechanism{Type: wrapMechanism}, wrappingKey, targetKey)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("C_UnwrapKey refuses a mechanism FIPS withholds", func(t *testing.T) {
		withMechanismWithheldInFIPS(t, wrapMechanism)

		m, sessionHandle, unwrappingKey := createUnwrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.UnwrapKey(sessionHandle, &Mechanism{Type: wrapMechanism},
			unwrappingKey, []byte("wrapped"), nil)
		assert.Equal(t, CKR_MECHANISM_INVALID, rv)
	})

	t.Run("C_UnwrapKey accepts the same mechanism outside FIPS", func(t *testing.T) {
		withFIPSMode(t, false)

		m, sessionHandle, unwrappingKey := createUnwrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.UnwrapKey(sessionHandle, &Mechanism{Type: wrapMechanism},
			unwrappingKey, []byte("wrapped"), nil)
		assert.NotEqual(t, CKR_MECHANISM_INVALID, rv)
	})
}

// createWrapKeyFixture provisions a module with a wrapping key that carries
// CKA_WRAP and an extractable target key.
func createWrapKeyFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	sessionHandle := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-fixture-wrapping-key"),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, []byte("0123456789abcdef0123456789abcdef")),
	})
	require.Equal(t, CKR_OK, rv)

	targetKey, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "wrap-fixture-target-key"),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
	})
	require.Equal(t, CKR_OK, rv)

	// The target key lives in the backend, which is what an HSM-backed key
	// actually looks like and is the path this fixture must exercise: C_WrapKey
	// wraps a backend-resident key through WrapKeyByID and mechanismToAlgorithm,
	// neither of which consults the mechanism registry. The local-value fallback
	// does resolve the mechanism, through CryptoManager.EncryptInit, so a
	// fixture whose key had no KeyID would be protected by the fallback and
	// could not tell whether C_WrapKey itself validates anything.
	targetObj, err := m.objectManager.getObjectUnchecked(targetKey)
	require.NoError(t, err)
	targetObj.KeyID = "wrap-fixture-target-key-id"
	targetObj.BackendName = "default"

	return m, sessionHandle, wrappingKey, targetKey
}

// createUnwrapKeyFixture provisions a module with an unwrapping key that
// carries CKA_UNWRAP.
func createUnwrapKeyFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	sessionHandle := loginAsNormalUser(t, m)

	unwrappingKey, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "unwrap-fixture-key"),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, []byte("0123456789abcdef0123456789abcdef")),
	})
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, unwrappingKey
}

// TestWrapUnwrapKeyUsageCodes pins the codes C_WrapKey and C_UnwrapKey produce
// when the key they were given is not marked for the job.
//
// Neither return table lists CKR_KEY_FUNCTION_NOT_PERMITTED, which is what the
// module used to return. §5.18.3 and §5.18.4 list
// CKR_WRAPPING_KEY_TYPE_INCONSISTENT and CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
// defined in §5.1 as the key's type not matching what the mechanism requires —
// which is what a key never marked for wrapping or unwrapping is.
func TestWrapUnwrapKeyUsageCodes(t *testing.T) {
	t.Run("C_WrapKey without CKA_WRAP", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle := loginAsNormalUser(t, m)

		wrappingKey, rv := m.CreateObject(sessionHandle, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "no-wrap-key"),
			NewBoolAttribute(CKA_WRAP, false),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, []byte("0123456789abcdef0123456789abcdef")),
		})
		require.Equal(t, CKR_OK, rv)

		targetKey, rv := m.CreateObject(sessionHandle, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "no-wrap-target"),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, []byte("SECRETKEYVALUE!!")),
		})
		require.Equal(t, CKR_OK, rv)

		_, rv = m.WrapKey(sessionHandle, &Mechanism{Type: CKM_AES_KEY_WRAP}, wrappingKey, targetKey)
		assert.Equal(t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_WrapKey with CKA_WRAP gets past the usage gate", func(t *testing.T) {
		m, sessionHandle, wrappingKey, targetKey := createWrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.WrapKey(sessionHandle, &Mechanism{Type: CKM_AES_KEY_WRAP}, wrappingKey, targetKey)
		assert.NotEqual(t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_UnwrapKey without CKA_UNWRAP", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		sessionHandle := loginAsNormalUser(t, m)

		unwrappingKey, rv := m.CreateObject(sessionHandle, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "no-unwrap-key"),
			NewBoolAttribute(CKA_UNWRAP, false),
			NewBoolAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, []byte("0123456789abcdef0123456789abcdef")),
		})
		require.Equal(t, CKR_OK, rv)

		_, rv = m.UnwrapKey(sessionHandle, &Mechanism{Type: CKM_AES_KEY_WRAP},
			unwrappingKey, []byte("wrapped"), nil)
		assert.Equal(t, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, rv)
	})

	t.Run("C_UnwrapKey with CKA_UNWRAP gets past the usage gate", func(t *testing.T) {
		m, sessionHandle, unwrappingKey := createUnwrapKeyFixture(t)
		defer m.Finalize()

		_, rv := m.UnwrapKey(sessionHandle, &Mechanism{Type: CKM_AES_KEY_WRAP},
			unwrappingKey, []byte("wrapped"), nil)
		assert.NotEqual(t, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, rv)
	})
}

// terminalKeyGoneCase describes one terminal function and the initializer that
// binds its key.
type terminalKeyGoneCase struct {
	name string
	init func(m *Module, sessionHandle SessionHandle, keyHandle ObjectHandle) CK_RV
	call func(m *Module, sessionHandle SessionHandle) CK_RV
}

// TestTerminalCallAfterKeyDestroyed pins what C_Sign, C_SignRecover, C_Verify,
// C_Encrypt and C_Decrypt report when the key their C_*Init bound is destroyed
// before the terminal call.
//
// These functions take no key handle argument, and PKCS#11 v3.2 accordingly
// omits CKR_KEY_HANDLE_INVALID from every one of their return tables — yet that
// is what the module returned. §5.1 requires a function to answer from its own
// table; of what these tables offer, CKR_FUNCTION_FAILED ("the requested
// function could not be performed, but detailed information about why is not
// available") describes this without asserting the false claim that the
// application never called the initializer.
func TestTerminalCallAfterKeyDestroyed(t *testing.T) {
	rsa := &Mechanism{Type: CKM_RSA_PKCS}

	cases := []terminalKeyGoneCase{
		{
			name: "C_Sign",
			init: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV { return m.SignInit(s, rsa, k) },
			call: func(m *Module, s SessionHandle) CK_RV {
				_, rv := m.Sign(s, []byte("data"))
				return rv
			},
		},
		{
			name: "C_SignRecover",
			init: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV { return m.SignRecoverInit(s, rsa, k) },
			call: func(m *Module, s SessionHandle) CK_RV {
				_, rv := m.SignRecover(s, []byte("data"))
				return rv
			},
		},
		{
			name: "C_Verify",
			init: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV { return m.VerifyInit(s, rsa, k) },
			call: func(m *Module, s SessionHandle) CK_RV {
				return m.Verify(s, []byte("data"), []byte("signature"))
			},
		},
		{
			name: "C_Encrypt",
			init: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV { return m.EncryptInit(s, rsa, k) },
			call: func(m *Module, s SessionHandle) CK_RV {
				_, rv := m.Encrypt(s, []byte("data"))
				return rv
			},
		},
		{
			name: "C_Decrypt",
			init: func(m *Module, s SessionHandle, k ObjectHandle) CK_RV { return m.DecryptInit(s, rsa, k) },
			call: func(m *Module, s SessionHandle) CK_RV {
				_, rv := m.Decrypt(s, []byte("ciphertext"))
				return rv
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/key destroyed between init and call", func(t *testing.T) {
			m, sessionHandle, keyHandle := createAllUsagesKeyFixture(t)
			defer m.Finalize()

			require.Equal(t, CKR_OK, tc.init(m, sessionHandle, keyHandle))
			require.Equal(t, CKR_OK, m.DestroyObject(sessionHandle, keyHandle))

			assert.Equal(t, CKR_FUNCTION_FAILED, tc.call(m, sessionHandle),
				"CKR_KEY_HANDLE_INVALID is not in this function's return table")
		})

		t.Run(tc.name+"/no operation initialized", func(t *testing.T) {
			m, sessionHandle, _ := createAllUsagesKeyFixture(t)
			defer m.Finalize()

			// The key-gone code must stay distinguishable from the code for
			// never having initialized at all, or an application cannot tell
			// the two situations apart.
			assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, tc.call(m, sessionHandle))
		})
	}
}

// TestTemplateErrorsSurviveObjectCreation covers the three functions that
// flattened a template failure from ObjectManager.CreateDerivedObject into
// CKR_FUNCTION_FAILED: C_EncapsulateKey, C_DecapsulateKey and
// C_UnwrapKeyAuthenticated.
//
// Object creation already decides which of CKR_TEMPLATE_INCOMPLETE,
// CKR_TEMPLATE_INCONSISTENT, CKR_ATTRIBUTE_READ_ONLY and
// CKR_ATTRIBUTE_VALUE_INVALID the caller's template earned, and all four are in
// each of these functions' return tables. Replacing that with
// CKR_FUNCTION_FAILED told an application whose template was merely malformed
// that the token itself had failed, and hid which attribute to fix.
// C_UnwrapKey in module.go always propagated it, which is what made the
// inconsistency visible.
//
// A template carrying the same attribute twice is the fault used here:
// PKCS#11 v3.2 §5.1 makes a duplicated attribute CKR_TEMPLATE_INCONSISTENT, and
// validateCreateTemplate is what detects it.
func TestTemplateErrorsSurviveObjectCreation(t *testing.T) {
	duplicated := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "first"),
		NewStringAttribute(CKA_LABEL, "second"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
	}

	sound := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "sound"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
	}

	t.Run("C_EncapsulateKey and C_DecapsulateKey", func(t *testing.T) {
		m, sessionHandle, pubHandle, privHandle := createKEMRoundTripFixture(t)
		defer m.Finalize()

		encMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
		decMech := &Mechanism{Type: CKM_VENDOR_ML_KEM_768_DECAPSULATE}

		// The sound template must succeed first: it produces the ciphertext the
		// negative decapsulation case needs, and it proves the duplicate — not
		// the fixture — is what the negative cases refuse.
		_, ciphertext, err := m.EncapsulateKey(sessionHandle, encMech, pubHandle, sound)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		_, _, err = m.EncapsulateKey(sessionHandle, encMech, pubHandle, duplicated)
		require.Error(t, err)

		var encErr *PKCS11Error
		require.ErrorAs(t, err, &encErr)
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, encErr.Code,
			"the template fault the object layer diagnosed must reach the caller")

		_, err = m.DecapsulateKey(sessionHandle, decMech, privHandle, duplicated, ciphertext)
		require.Error(t, err)

		var decErr *PKCS11Error
		require.ErrorAs(t, err, &decErr)
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, decErr.Code)
	})

	t.Run("C_UnwrapKeyAuthenticated", func(t *testing.T) {
		m, sessionHandle, wrappingKey, targetKey := createAuthWrapTestObjects(t)
		defer m.Finalize()

		mechanism := NewMechanism(CKM_AES_GCM)
		aad := []byte("associated-data")

		wrapped, err := m.WrapKeyAuthenticated(sessionHandle, mechanism, wrappingKey, targetKey, aad)
		require.NoError(t, err)

		// The sound template must succeed first, for the same reason.
		_, err = m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKey, wrapped, sound, aad)
		require.NoError(t, err)

		_, err = m.UnwrapKeyAuthenticated(sessionHandle, mechanism, wrappingKey, wrapped, duplicated, aad)
		require.Error(t, err)

		var unwrapErr *PKCS11Error
		require.ErrorAs(t, err, &unwrapErr)
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT, unwrapErr.Code)
	})
}

// createKEMRoundTripFixture provisions a module with a real ML-KEM-768 key pair
// imported as PKCS#11 objects, so encapsulation and decapsulation can be driven
// end to end rather than against planted state.
func createKEMRoundTripFixture(t *testing.T) (*Module, SessionHandle, ObjectHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	sessionHandle := loginAsNormalUser(t, m)

	kem, err := kyber768.New()
	require.NoError(t, err)
	pub, err := kem.GenerateKeyPair()
	require.NoError(t, err)
	seed := kem.ExportSecretKey()
	t.Cleanup(kem.Clean)

	pubHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "template-error-fixture-pub"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_VALUE, pub),
	})
	require.Equal(t, CKR_OK, rv)

	privHandle, rv := m.CreateObject(sessionHandle, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_ML_KEM)),
		NewStringAttribute(CKA_LABEL, "template-error-fixture-priv"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_VALUE, seed),
	})
	require.Equal(t, CKR_OK, rv)

	return m, sessionHandle, pubHandle, privHandle
}

// TestGenerateKeyPairEnforcesModulusCap closes a client-triggerable denial of
// service: C_GenerateKeyPair read CKA_MODULUS_BITS and handed it to the
// backend, which enforced a floor and no ceiling, so one call asking for a
// 16384-bit modulus made the daemon generate it and exhausted its memory.
//
// The cap is the range C_GetMechanismInfo already advertises, so what the
// module says it will generate and what it will actually attempt cannot drift
// apart. Every case here asserts a refusal — none generates an oversized key,
// because generating one is the fault being prevented.
func TestGenerateKeyPairEnforcesModulusCap(t *testing.T) {
	const rsaKeyPairGen = CKM_RSA_PKCS_KEY_PAIR_GEN

	t.Run("refuses a modulus above the advertised maximum", func(t *testing.T) {
		withFIPSMode(t, false)

		info, err := GetMechanismInfo(rsaKeyPairGen)
		require.NoError(t, err)

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(sessionHandle, &Mechanism{Type: rsaKeyPairGen},
			rsaPublicKeyTemplate(info.MaxKeySize+1), nil)
		assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv,
			"a modulus the module never advertised must be refused, not generated")
	})

	t.Run("refuses a modulus below the advertised minimum", func(t *testing.T) {
		withFIPSMode(t, false)

		info, err := GetMechanismInfo(rsaKeyPairGen)
		require.NoError(t, err)
		require.Greater(t, info.MinKeySize, uint32(0))

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, _, rv := m.GenerateKeyPair(sessionHandle, &Mechanism{Type: rsaKeyPairGen},
			rsaPublicKeyTemplate(info.MinKeySize-1), nil)
		assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv)
	})

	t.Run("accepts the advertised maximum outside FIPS", func(t *testing.T) {
		withFIPSMode(t, false)

		info, err := GetMechanismInfo(rsaKeyPairGen)
		require.NoError(t, err)

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		// The refusals above would pass for the wrong reason if the cap
		// rejected everything, so the boundary the module advertises must get
		// through it.
		_, _, rv := m.GenerateKeyPair(sessionHandle, &Mechanism{Type: rsaKeyPairGen},
			rsaPublicKeyTemplate(info.MaxKeySize), nil)
		assert.NotEqual(t, CKR_ATTRIBUTE_VALUE_INVALID, rv,
			"the largest modulus C_GetMechanismInfo advertises must remain requestable")
	})

	t.Run("FIPS mode lowers the ceiling", func(t *testing.T) {
		withFIPSMode(t, true)

		info, err := GetMechanismInfo(rsaKeyPairGen)
		require.NoError(t, err)

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		// The FIPS ceiling must be the one enforced, not merely the one
		// reported: what C_GetMechanismInfo advertises and what the module will
		// attempt have to agree in both modes.
		_, _, rv := m.GenerateKeyPair(sessionHandle, &Mechanism{Type: rsaKeyPairGen},
			rsaPublicKeyTemplate(info.MaxKeySize+1), nil)
		assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv)
	})

	t.Run("elliptic-curve generation is unaffected", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		// An EC key pair carries no CKA_MODULUS_BITS and takes its size from
		// CKA_EC_PARAMS, so the modulus check must not see a zero and refuse it.
		_, _, rv := m.GenerateKeyPair(sessionHandle, &Mechanism{Type: CKM_EC_KEY_PAIR_GEN},
			[]Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
				NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
				NewStringAttribute(CKA_LABEL, "ec-keysize-unaffected"),
				NewAttribute(CKA_EC_PARAMS, p256Params),
				NewBoolAttribute(CKA_VERIFY, true),
			}, nil)
		assert.NotEqual(t, CKR_ATTRIBUTE_VALUE_INVALID, rv)
	})
}

// rsaPublicKeyTemplate builds a minimal RSA public-key template asking for the
// given modulus size in bits.
func rsaPublicKeyTemplate(modulusBits uint32) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewStringAttribute(CKA_LABEL, "modulus-cap-fixture"),
		NewUint32Attribute(CKA_MODULUS_BITS, modulusBits),
		NewBoolAttribute(CKA_VERIFY, true),
	}
}

// TestGenerateKeyEnforcesValueLenRange is the symmetric half of the same cap,
// and pins the unit the check uses.
//
// CKA_VALUE_LEN is a byte count and CKM_AES_KEY_GEN's advertised range is in
// bytes (v3.2 §6.10.3), while C_GenerateKey separately converts the value to
// bits for the backend's request. Validating the converted bit count would
// compare 256 against 16..32 and refuse every legal AES key, so the success
// case below is what holds the two units apart.
func TestGenerateKeyEnforcesValueLenRange(t *testing.T) {
	const aesKeyGen = CKM_AES_KEY_GEN

	aesTemplate := func(valueLenBytes uint32) []Attribute {
		return []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "value-len-fixture"),
			NewUint32Attribute(CKA_VALUE_LEN, valueLenBytes),
			NewBoolAttribute(CKA_ENCRYPT, true),
		}
	}

	t.Run("accepts every AES length the module advertises", func(t *testing.T) {
		info, err := GetMechanismInfo(aesKeyGen)
		require.NoError(t, err)
		require.Equal(t, uint32(16), info.MinKeySize, "AES sizes are advertised in bytes")
		require.Equal(t, uint32(32), info.MaxKeySize, "AES sizes are advertised in bytes")

		for _, lenBytes := range []uint32{16, 24, 32} {
			m, sessionHandle, _ := createAllUsagesKeyFixture(t)

			_, rv := m.GenerateKey(sessionHandle, &Mechanism{Type: aesKeyGen}, aesTemplate(lenBytes))
			assert.Equal(t, CKR_OK, rv, "AES-%d must remain generatable", lenBytes*8)

			m.Finalize()
		}
	})

	t.Run("refuses a length above the advertised maximum", func(t *testing.T) {
		info, err := GetMechanismInfo(aesKeyGen)
		require.NoError(t, err)

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(sessionHandle, &Mechanism{Type: aesKeyGen},
			aesTemplate(info.MaxKeySize+1))
		assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv)
	})

	t.Run("refuses a length below the advertised minimum", func(t *testing.T) {
		info, err := GetMechanismInfo(aesKeyGen)
		require.NoError(t, err)

		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(sessionHandle, &Mechanism{Type: aesKeyGen},
			aesTemplate(info.MinKeySize-1))
		assert.Equal(t, CKR_ATTRIBUTE_VALUE_INVALID, rv)
	})

	t.Run("an absent CKA_VALUE_LEN leaves the size to the mechanism", func(t *testing.T) {
		m, sessionHandle, _ := createAllUsagesKeyFixture(t)
		defer m.Finalize()

		_, rv := m.GenerateKey(sessionHandle, &Mechanism{Type: aesKeyGen}, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "no-value-len"),
			NewBoolAttribute(CKA_ENCRYPT, true),
		})
		assert.Equal(t, CKR_OK, rv,
			"an unspecified length is not an assertion the module can validate")
	})
}
