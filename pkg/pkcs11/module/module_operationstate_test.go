// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package module

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin down C_GetOperationState (PKCS#11 v3.2 §5.6.6)
// and C_SetOperationState (§5.6.7).
//
// This module keeps the running state of every cryptographic operation inside
// the operation object returned by the crypto manager, and for a backend-held
// key that state lives in xkmsd or in the HSM behind it. None of it can be
// serialised into a byte string and handed to an application, which is exactly
// the case §5.6.6 covers: an attempt to save the state of a session that is
// performing an appropriate operation "but which cannot be satisfied for any
// of various reasons (certain necessary state information and/or key
// information can't leave the token, for example) should fail with the error
// CKR_STATE_UNSAVEABLE".
//
// Refusing is therefore the correct answer, but only if it is a deliberate
// refusal that holds for every savable operation category. These tests assert
// that specific return value rather than merely tolerating an error, so that a
// future change which starts emitting a state blob has to come with a real
// C_SetOperationState to consume it.

// TestModule_GetOperationState_RefusesEverySavableOperation proves that
// C_GetOperationState answers CKR_STATE_UNSAVEABLE for every operation
// category PKCS#11 v3.2 §5.6.6 calls savable — encryption, decryption,
// digesting, signing and verification.
//
// The uniformity is the point. A module that refused digesting but returned
// CKR_OK and an empty blob for encryption would look "mostly right" while
// handing applications a state string that restores nothing; this test would
// catch that, because it demands the same deliberate refusal from all five.
func TestModule_GetOperationState_RefusesEverySavableOperation(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		m, session, _ := setupTestModuleWithRSAKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
		require.Equal(t, CKR_OK, m.DigestUpdate(session, []byte("saved state")))

		state, rv := m.GetOperationStateBytes(session)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv,
			"C_GetOperationState must refuse a digest whose running state cannot leave the token (v3.2 §5.6.6)")
		assert.Empty(t, state, "a refused save must not hand back a partial state string")
	})

	t.Run("sign", func(t *testing.T) {
		m, session, keyHandle := setupTestModuleWithRSAKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.SignInit(session, &Mechanism{Type: CKM_SHA256_RSA_PKCS}, keyHandle))

		_, rv := m.GetOperationStateBytes(session)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv,
			"the signing key lives in the backend, so its state cannot be saved (v3.2 §5.6.6)")
	})

	t.Run("verify", func(t *testing.T) {
		m, session, keyHandle := setupTestModuleWithRSAKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.VerifyInit(session, &Mechanism{Type: CKM_SHA256_RSA_PKCS}, keyHandle))

		_, rv := m.GetOperationStateBytes(session)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv,
			"the verification key lives in the backend, so its state cannot be saved (v3.2 §5.6.6)")
	})

	t.Run("encrypt", func(t *testing.T) {
		m, session, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.EncryptInit(session, &Mechanism{Type: CKM_AES_ECB}, keyHandle))

		_, rv := m.GetOperationStateBytes(session)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv,
			"the cipher's chaining state cannot leave the token (v3.2 §5.6.6)")
	})

	t.Run("decrypt", func(t *testing.T) {
		m, session, keyHandle := createTestModuleWithEncryptableKey(t)
		defer m.Finalize()

		require.Equal(t, CKR_OK, m.DecryptInit(session, &Mechanism{Type: CKM_AES_ECB}, keyHandle))

		_, rv := m.GetOperationStateBytes(session)
		assert.Equal(t, CKR_STATE_UNSAVEABLE, rv,
			"the cipher's chaining state cannot leave the token (v3.2 §5.6.6)")
	})
}

// TestModule_GetOperationState_RefusalLeavesOperationUsable proves that a
// refused C_GetOperationState does not disturb the operation it refused to
// save, by finishing the digest afterwards and comparing the result against
// crypto/sha256.
//
// PKCS#11 v3.2 §5.6.6 lists no circumstance in which C_GetOperationState ends
// an operation; only the terminal call of the operation itself does that. The
// defect this catches is a save path that consumes or resets the running
// digest on its way to reporting CKR_STATE_UNSAVEABLE — the application would
// see a plausible error, keep feeding data, and end up with a digest of the
// wrong bytes. Comparing against the standard library rather than merely
// checking the length is what makes that visible.
func TestModule_GetOperationState_RefusalLeavesOperationUsable(t *testing.T) {
	m, session, _ := setupTestModuleWithRSAKey(t)
	defer m.Finalize()

	first := []byte("bytes fed before the save attempt")
	second := []byte("bytes fed after the save attempt")

	require.Equal(t, CKR_OK, m.DigestInit(session, &Mechanism{Type: CKM_SHA256}))
	require.Equal(t, CKR_OK, m.DigestUpdate(session, first))

	_, rv := m.GetOperationStateBytes(session)
	require.Equal(t, CKR_STATE_UNSAVEABLE, rv)

	require.Equal(t, CKR_OK, m.DigestUpdate(session, second),
		"a refused save must leave the digest operation active")

	got, rv := m.DigestFinal(session)
	require.Equal(t, CKR_OK, rv)

	want := sha256.Sum256(append(append([]byte{}, first...), second...))
	assert.Equal(t, want[:], got,
		"the digest must cover exactly the bytes supplied, unaffected by the refused save")

	// The Go API leaves a terminal operation active so a caller may re-read the
	// cached result under the v3.2 §5.2 two-call convention; release it here.
	require.Equal(t, CKR_OK, m.FinishOperation(session, OperationDigest))
}

// TestModule_GetOperationState_NoActiveOperation asserts the error PKCS#11
// v3.2 §5.6.6 names for a session with nothing to save: "An attempt to save
// the cryptographic operations state of a session which does not currently
// have some active savable cryptographic operation(s) ... should fail with the
// error CKR_OPERATION_NOT_INITIALIZED."
//
// The defect this catches is returning CKR_STATE_UNSAVEABLE for an idle
// session. Both are errors, but they mean opposite things to an application:
// one says "try again later on a savable operation", the other says "this
// token can never save state", and an application that trusts the second will
// stop asking.
func TestModule_GetOperationState_NoActiveOperation(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	_, rv := m.GetOperationStateBytes(session)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv)
}

// TestModule_GetOperationState_ObjectSearchIsNotSavable asserts that an active
// C_FindObjects search does not count as a savable operation.
//
// PKCS#11 v3.2 §5.6.6 enumerates the savable operations exhaustively —
// encryption, decryption, digesting, signing without message recovery,
// verification without message recovery, or a legal combination of two — and
// an object search is not among them. The defect this catches is a save path
// that reaches for whichever operation the session happens to have active:
// that would emit a "state" describing a search whose template, result set and
// cursor are not in the blob, so restoring it would silently yield a search
// that finds nothing.
func TestModule_GetOperationState_ObjectSearchIsNotSavable(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	require.Equal(t, CKR_OK, m.FindObjectsInit(session, nil))

	_, rv := m.GetOperationStateBytes(session)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, rv,
		"an object search is not one of the savable operations listed in v3.2 §5.6.6")

	require.Equal(t, CKR_OK, m.FindObjectsFinal(session))
}

// TestModule_GetOperationState_InvalidSession asserts CKR_SESSION_HANDLE_INVALID,
// which PKCS#11 v3.2 §5.6.6 lists among C_GetOperationState's return values.
//
// The session handle is validated before the operation state is consulted, so
// a handle that names no session must be reported as such rather than as an
// uninitialized operation.
func TestModule_GetOperationState_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	_, rv := m.GetOperationStateBytes(SessionHandle(0xDEAD))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
}

// TestModule_SetOperationState_RejectsUnusableBlob asserts CKR_SAVED_STATE_INVALID
// for byte strings that cannot be saved state.
//
// PKCS#11 v3.2 §5.6.7: "If C_SetOperationState is supplied with alleged saved
// cryptographic operations state which it can determine is not valid saved
// state ... it fails with the error CKR_SAVED_STATE_INVALID." A blob shorter
// than the fixed header is determinable as invalid without any further
// inspection, so it must be rejected rather than read past its end.
func TestModule_SetOperationState_RejectsUnusableBlob(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	cases := []struct {
		name  string
		state []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x05}},
		{"one byte short of the header", make([]byte, 12)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv := m.SetOperationStateBytes(session, tc.state, ObjectHandle(0), ObjectHandle(0))
			assert.Equal(t, CKR_SAVED_STATE_INVALID, rv)
		})
	}
}

// TestModule_SetOperationState_RejectsBlobNamingAnUnknownKey asserts the blob is
// refused as invalid saved state, whatever key handle it carries.
//
// The blob is application-supplied, so everything in it is untrusted input —
// including the key handle. Since this module's C_GetOperationState never
// produces saved state (§5.6.6 CKR_STATE_UNSAVEABLE), nothing handed here can
// be valid, and §5.6.7's CKR_SAVED_STATE_INVALID is the answer. That refusal
// comes before the handle is examined, which is the right order: §5.6.7's
// key-handle errors describe state that IS valid but needs a key, and no state
// reaches that point. The security property the old expectation was reaching
// for still holds, more simply — a forged blob can never install another slot's
// key as this session's operation key, because no forged blob is accepted.
func TestModule_SetOperationState_RejectsBlobNamingAnUnknownKey(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	state := operationStateBlob(OperationSign, CKM_RSA_PKCS, ObjectHandle(0xFFFFFFFF), nil)

	rv := m.SetOperationStateBytes(session, state, ObjectHandle(0), ObjectHandle(0))
	assert.Equal(t, CKR_SAVED_STATE_INVALID, rv)
}

// TestModule_SetOperationState_InvalidSession asserts CKR_SESSION_HANDLE_INVALID,
// which PKCS#11 v3.2 §5.6.7 lists among C_SetOperationState's return values.
//
// The check must come before the blob is decoded: a caller that passes both a
// dead session and a malformed blob needs to be told about the session, since
// that is the error it can act on.
func TestModule_SetOperationState_InvalidSession(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	state := operationStateBlob(OperationDigest, CKM_SHA256, ObjectHandle(0), nil)

	rv := m.SetOperationStateBytes(SessionHandle(0xDEAD), state, ObjectHandle(0), ObjectHandle(0))
	assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
}

// TestTokenInfo_RestoreKeyNotNeededReflectsKeyHandling asserts that the token
// does not advertise CKF_RESTORE_KEY_NOT_NEEDED.
//
// PKCS#11 v3.2 §5.6.7 gives the flag a precise meaning: "If this flag is true,
// then a call to C_SetOperationState never needs a key handle to be supplied
// to it." An application reads it to decide whether to bother tracking key
// handles across a save/restore. Advertising it while C_SetOperationState does
// not in fact carry key material in its state would be a promise the module
// cannot keep, so the flag stays clear until the key-handling rules of §5.6.7
// (CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED) are implemented.
func TestTokenInfo_RestoreKeyNotNeededReflectsKeyHandling(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	info, rv := m.GetTokenInfo(0)
	require.Equal(t, CKR_OK, rv)

	assert.False(t, info.Flags.Has(CKF_RESTORE_KEY_NOT_NEEDED),
		"CKF_RESTORE_KEY_NOT_NEEDED promises C_SetOperationState never needs a key handle (v3.2 §5.6.7)")
}

// operationStateBlob builds the fixed 13-byte header this module's
// C_SetOperationState decodes, followed by any accumulated data.
//
// The layout is one byte of operation type, four bytes of mechanism and eight
// bytes of key handle, all big-endian, matching GetOperationStateBytes.
func operationStateBlob(opType OperationType, mech MechanismType, key ObjectHandle, data []byte) []byte {
	blob := make([]byte, 0, 13+len(data))
	blob = append(blob, byte(opType))
	blob = append(blob, byte(mech>>24), byte(mech>>16), byte(mech>>8), byte(mech))
	blob = append(blob,
		byte(key>>56), byte(key>>48), byte(key>>40), byte(key>>32),
		byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
	return append(blob, data...)
}
