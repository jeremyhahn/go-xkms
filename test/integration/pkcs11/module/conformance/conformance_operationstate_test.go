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

//go:build integration && conformance
// +build integration,conformance

// Operation-state conformance: C_GetOperationState (PKCS#11 v3.2 §5.6.6) and
// C_SetOperationState (§5.6.7).
//
// These are the only two Cryptoki entry points no other suite reaches. OpenSSL
// never calls them, and neither does pkcs11-tool, so their behaviour against a
// live xkmsd was previously unobserved — which is precisely where a function
// that accepts its arguments and quietly does nothing survives.
//
// The state of a running operation in this module is held by the crypto
// manager, and for a backend-held key it lives in xkmsd or in the HSM behind
// it. It cannot be serialised into a byte string, which is the situation
// §5.6.6 provides CKR_STATE_UNSAVEABLE for: a session "performing an
// appropriate cryptographic operation (or two), but which cannot be satisfied
// for any of various reasons (certain necessary state information and/or key
// information can't leave the token, for example) should fail with the error
// CKR_STATE_UNSAVEABLE".
//
// Refusing is a legitimate implementation. It is only legitimate if the
// refusal is deliberate and uniform, so every test here asserts the exact
// CK_RV the specification names rather than accepting any error.
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestGetOperationState_UnsaveableForEverySavableOperation drives each of the
// five operation categories PKCS#11 v3.2 §5.6.6 calls savable against a live
// xkmsd and requires the same deliberate CKR_STATE_UNSAVEABLE from all of
// them.
//
// Running the whole set matters more than any single case. A module that
// refused one category and returned CKR_OK with a stub blob for another would
// hand applications a state string that C_SetOperationState cannot turn back
// into a working operation, and the application would only discover it after
// restoring and producing a wrong result. Demanding the same answer for all
// five is what makes such a gap visible.
// Distinct 96-bit GCM nonces, one per subtest. CryptoManager's nonce-reuse
// guard refuses a repeated (key, IV) pair, so the encrypt and decrypt cases
// must not share one even though neither reaches a terminal call.
var (
	opStateEncryptIV = []byte{0x0a, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	opStateDecryptIV = []byte{0x0a, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
)

func TestGetOperationState_UnsaveableForEverySavableOperation(t *testing.T) {
	payload := []byte("operation state conformance payload")

	cases := []struct {
		name string
		// start initializes one savable operation on the session and returns
		// the operation type so the test can release it afterwards.
		start func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType
	}{
		{
			name: "digest",
			start: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType {
				if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
					t.Fatalf("C_DigestInit returned %s", rv.String())
				}
				if rv := env.Module.DigestUpdate(session, payload); rv != module.CKR_OK {
					t.Fatalf("C_DigestUpdate returned %s", rv.String())
				}
				return module.OperationDigest
			},
		},
		{
			name: "sign",
			start: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType {
				_, priv := generateRSAKeyPair(t, env, session, "opstate-sign")
				if rv := env.Module.SignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, priv); rv != module.CKR_OK {
					t.Fatalf("C_SignInit returned %s", rv.String())
				}
				return module.OperationSign
			},
		},
		{
			name: "verify",
			start: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType {
				pub, _ := generateRSAKeyPair(t, env, session, "opstate-verify")
				if rv := env.Module.VerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, pub); rv != module.CKR_OK {
					t.Fatalf("C_VerifyInit returned %s", rv.String())
				}
				return module.OperationVerify
			},
		},
		{
			name: "encrypt",
			start: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType {
				key := generateAESKey(t, env, session, "opstate-encrypt")
				if rv := env.Module.EncryptInit(session, gcmMechanism(opStateEncryptIV), key); rv != module.CKR_OK {
					t.Fatalf("C_EncryptInit returned %s", rv.String())
				}
				return module.OperationEncrypt
			},
		},
		{
			name: "decrypt",
			start: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.OperationType {
				key := generateAESKey(t, env, session, "opstate-decrypt")
				if rv := env.Module.DecryptInit(session, gcmMechanism(opStateDecryptIV), key); rv != module.CKR_OK {
					t.Fatalf("C_DecryptInit returned %s", rv.String())
				}
				return module.OperationDecrypt
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)

			opType := tc.start(t, env, session)

			state, rv := env.Module.GetOperationState(session)
			if rv != module.CKR_STATE_UNSAVEABLE {
				t.Fatalf("C_GetOperationState returned %s, want CKR_STATE_UNSAVEABLE "+
					"(v3.2 §5.6.6: state that cannot leave the token)", rv.String())
			}
			if len(state) != 0 {
				t.Errorf("C_GetOperationState refused the save but still returned %d bytes of state; "+
					"a refusal must not hand back a partial state string", len(state))
			}

			if rv := env.Module.FinishOperation(session, opType); rv != module.CKR_OK {
				t.Fatalf("FinishOperation returned %s", rv.String())
			}
		})
	}
}

// TestGetOperationState_RefusalDoesNotDisturbTheOperation proves the refusal is
// side-effect free, by finishing the digest afterwards and comparing the
// result against the standard library.
//
// PKCS#11 v3.2 §5.6.6 describes no circumstance in which C_GetOperationState
// ends or alters the operation it was asked about; only the operation's own
// terminal call does that. The defect this catches is a save path that
// consumes or resets the running digest on its way to reporting
// CKR_STATE_UNSAVEABLE. The application would see a plausible error, carry on
// feeding data, and finish with a digest over the wrong bytes — a silent wrong
// answer that a length check on the output could never detect.
func TestGetOperationState_RefusalDoesNotDisturbTheOperation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	before := []byte("fed before the save attempt")
	after := []byte("fed after the save attempt")

	if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit returned %s", rv.String())
	}
	if rv := env.Module.DigestUpdate(session, before); rv != module.CKR_OK {
		t.Fatalf("C_DigestUpdate returned %s", rv.String())
	}

	if _, rv := env.Module.GetOperationState(session); rv != module.CKR_STATE_UNSAVEABLE {
		t.Fatalf("C_GetOperationState returned %s, want CKR_STATE_UNSAVEABLE", rv.String())
	}

	if rv := env.Module.DigestUpdate(session, after); rv != module.CKR_OK {
		t.Fatalf("C_DigestUpdate after the refused save returned %s; the refusal must leave "+
			"the operation active (v3.2 §5.6.6)", rv.String())
	}

	got, rv := env.Module.DigestFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("C_DigestFinal returned %s", rv.String())
	}

	want := sha256Sum(append(append([]byte{}, before...), after...))
	if !bytes.Equal(got, want) {
		t.Errorf("digest mismatch after a refused save\n got %x\nwant %x", got, want)
	}

	if rv := env.Module.FinishOperation(session, module.OperationDigest); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}
}

// TestGetOperationState_NoSavableOperation asserts the distinct error PKCS#11
// v3.2 §5.6.6 assigns to a session with nothing to save: "An attempt to save
// the cryptographic operations state of a session which does not currently
// have some active savable cryptographic operation(s) ... should fail with the
// error CKR_OPERATION_NOT_INITIALIZED."
//
// The two failure codes are not interchangeable. CKR_OPERATION_NOT_INITIALIZED
// tells the application to start an operation and try again;
// CKR_STATE_UNSAVEABLE tells it this token will never save state and it should
// stop asking. Returning the second for an idle session would make an
// application abandon a feature that in fact works no worse than it ever did.
//
// The subtest with an active object search pins the boundary of the savable
// set: §5.6.6 enumerates it exhaustively — encryption, decryption, digesting,
// signing without message recovery, verification without message recovery, or
// a legal combination of two — and a C_FindObjects search is not in it. A save
// path that grabbed whichever operation the session happened to have active
// would emit a "state" for the search whose template, matches and cursor are
// nowhere in the blob, so restoring it would silently produce a search that
// finds nothing.
func TestGetOperationState_NoSavableOperation(t *testing.T) {
	t.Run("idle session", func(t *testing.T) {
		env, session := testutil.SetupAuthenticatedModule(t)

		if _, rv := env.Module.GetOperationState(session); rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Fatalf("C_GetOperationState returned %s, want CKR_OPERATION_NOT_INITIALIZED", rv.String())
		}
	})

	t.Run("object search is not savable", func(t *testing.T) {
		env, session := testutil.SetupAuthenticatedModule(t)

		if rv := env.Module.FindObjectsInit(session, nil); rv != module.CKR_OK {
			t.Fatalf("C_FindObjectsInit returned %s", rv.String())
		}

		if _, rv := env.Module.GetOperationState(session); rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Fatalf("C_GetOperationState during an object search returned %s, want "+
				"CKR_OPERATION_NOT_INITIALIZED (a search is not a savable operation, v3.2 §5.6.6)", rv.String())
		}

		if rv := env.Module.FindObjectsFinal(session); rv != module.CKR_OK {
			t.Fatalf("C_FindObjectsFinal returned %s", rv.String())
		}
	})
}

// TestGetOperationState_InvalidSession asserts CKR_SESSION_HANDLE_INVALID,
// which PKCS#11 v3.2 §5.6.6 lists among C_GetOperationState's return values.
//
// The session must be resolved before the operation state is consulted, so a
// handle naming no session is reported as such rather than as an
// uninitialized operation. Conflating the two would send an application
// looking for a missing C_DigestInit when the real fault is a session it
// already closed.
func TestGetOperationState_InvalidSession(t *testing.T) {
	env, _ := testutil.SetupAuthenticatedModule(t)

	if _, rv := env.Module.GetOperationState(module.SessionHandle(0xDEAD)); rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_GetOperationState on an unknown session returned %s, want CKR_SESSION_HANDLE_INVALID", rv.String())
	}
}

// TestSetOperationState_RejectsBlobThatIsNotSavedState asserts
// CKR_SAVED_STATE_INVALID for byte strings that cannot be saved state.
//
// PKCS#11 v3.2 §5.6.7: "If C_SetOperationState is supplied with alleged saved
// cryptographic operations state which it can determine is not valid saved
// state ... it fails with the error CKR_SAVED_STATE_INVALID." A blob shorter
// than the module's fixed header is determinable as invalid on its length
// alone, so it must be refused rather than decoded past its end.
func TestSetOperationState_RejectsBlobThatIsNotSavedState(t *testing.T) {
	cases := []struct {
		name  string
		state []byte
	}{
		{"empty", nil},
		{"single byte", []byte{0x05}},
		{"one byte short of the header", make([]byte, 12)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)

			rv := env.Module.SetOperationState(session, tc.state, module.ObjectHandle(0), module.ObjectHandle(0))
			if rv != module.CKR_SAVED_STATE_INVALID {
				t.Fatalf("C_SetOperationState returned %s, want CKR_SAVED_STATE_INVALID (v3.2 §5.6.7)", rv.String())
			}
		})
	}
}

// TestSetOperationState_RejectsKeyHandleNotVisibleToTheSession asserts
// CKR_SAVED_STATE_INVALID when handed a forged blob, whatever key it names
// no object the restoring session may see.
//
// The blob is application-supplied and §5.6.7 explicitly allows it to have
// come from a different session, so the key handle inside it is untrusted
// input. Resolving it through the destination session's access context is what
// stops a forged blob from installing an object the session has no right to —
// another token's key, or a private key while the session is not logged in —
// as that session's active operation key. Accepting the handle unchecked would
// be a privilege escalation reachable from an application argument.
func TestSetOperationState_RejectsKeyHandleNotVisibleToTheSession(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	state := makeOperationStateBlob(module.OperationSign, module.CKM_RSA_PKCS, module.ObjectHandle(0xFFFFFFFF))

	rv := env.Module.SetOperationState(session, state, module.ObjectHandle(0), module.ObjectHandle(0))
	if rv != module.CKR_SAVED_STATE_INVALID {
		t.Fatalf("C_SetOperationState with a forged blob returned %s, want CKR_SAVED_STATE_INVALID", rv.String())
	}
}

// TestSetOperationState_InvalidSession asserts CKR_SESSION_HANDLE_INVALID,
// which PKCS#11 v3.2 §5.6.7 lists among C_SetOperationState's return values.
//
// The session check must precede any use of the blob: a caller that passes
// both a dead session and a well-formed blob needs to hear about the session,
// which is the fault it can act on.
func TestSetOperationState_InvalidSession(t *testing.T) {
	env, _ := testutil.SetupAuthenticatedModule(t)

	state := makeOperationStateBlob(module.OperationDigest, module.CKM_SHA256, module.ObjectHandle(0))

	rv := env.Module.SetOperationState(module.SessionHandle(0xDEAD), state, module.ObjectHandle(0), module.ObjectHandle(0))
	if rv != module.CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("C_SetOperationState on an unknown session returned %s, want CKR_SESSION_HANDLE_INVALID", rv.String())
	}
}

// TestTokenInfo_RestoreKeyNotNeededIsNotAdvertised asserts that the token does
// not claim CKF_RESTORE_KEY_NOT_NEEDED.
//
// PKCS#11 v3.2 §5.6.7 gives the flag an exact meaning: "If this flag is true,
// then a call to C_SetOperationState never needs a key handle to be supplied
// to it." Applications read it to decide whether to track key handles across a
// save and restore. Advertising it while the module's saved state carries no
// key material would be a promise it cannot keep, and an application that
// believed it would drop the handles and then be unable to restore anything.
// The flag therefore stays clear until the §5.6.7 key rules — CKR_KEY_NEEDED,
// CKR_KEY_NOT_NEEDED and CKR_KEY_CHANGED — are implemented.
func TestTokenInfo_RestoreKeyNotNeededIsNotAdvertised(t *testing.T) {
	env, _ := testutil.SetupAuthenticatedModule(t)

	info, rv := env.Module.GetTokenInfo(0)
	if rv != module.CKR_OK {
		t.Fatalf("C_GetTokenInfo returned %s", rv.String())
	}

	if info.Flags.Has(module.CKF_RESTORE_KEY_NOT_NEEDED) {
		t.Error("token advertises CKF_RESTORE_KEY_NOT_NEEDED, but C_SetOperationState does not " +
			"carry key material in its saved state (v3.2 §5.6.7)")
	}
}

// makeOperationStateBlob builds the fixed 13-byte header this module's
// C_SetOperationState decodes: one byte of operation type, four bytes of
// mechanism and eight bytes of key handle, all big-endian.
func makeOperationStateBlob(opType module.OperationType, mech module.MechanismType, key module.ObjectHandle) []byte {
	return []byte{
		byte(opType),
		byte(mech >> 24), byte(mech >> 16), byte(mech >> 8), byte(mech),
		byte(key >> 56), byte(key >> 48), byte(key >> 40), byte(key >> 32),
		byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key),
	}
}
