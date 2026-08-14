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

// Package conformance enforces the rule that a single-part cryptographic
// function may not terminate a multiple-part operation.
//
// PKCS#11 v3.2 states this separately for six functions — C_Sign (§5.14.3),
// C_Verify (§5.14.6), C_Encrypt (§5.9.2), C_Decrypt (§5.10.2), C_Digest
// (§5.12.2) and C_VerifySignature (§5.15.8) — in the same words each time: the
// function "cannot be used to terminate a multi-part operation, and MUST be
// called after [its Init] without intervening [Update] calls."
//
// The failure this prevents is silent. Each single-part function starts a fresh
// backend operation over its own argument, so accepting it after an Update
// discards every buffered part and returns a perfectly well-formed digest or
// signature — of the wrong message. Nothing in the return value tells the
// caller, and the wrongness only surfaces at a remote verifier.
//
// The tests are table-driven over all five operations that have both forms in
// the Go-facing API, because the guard is per-function: fixing one says nothing
// about the other four, and that is exactly how the original defect survived.
//
// Build tags: integration,conformance
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// aesIV is a fixed IV for the CBC cases. A conformance test asserts a control
// rule, not confidentiality, and a fixed value keeps the failure deterministic.
var aesIV = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
}

// generateAESKey creates a session-scoped 256-bit AES key usable for both
// directions of a symmetric operation.
func generateAESKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()

	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, label),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey CKM_AES_KEY_GEN returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// generateRSAKeyPair creates a session-scoped 2048-bit RSA key pair usable for
// signing and verification.
func generateRSAKeyPair(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) (pub, priv module.ObjectHandle) {
	t.Helper()

	pub, priv, rv := env.Module.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, label+"-pub"),
			module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_VERIFY, true),
		},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, label+"-priv"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_PRIVATE, true),
			module.NewBoolAttribute(module.CKA_SIGN, true),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair CKM_RSA_PKCS_KEY_PAIR_GEN returned %s", rv.String())
	}
	t.Cleanup(func() {
		env.Module.DestroyObject(session, pub)
		env.Module.DestroyObject(session, priv)
	})
	return pub, priv
}

// singlePartCase describes one operation's Init / Update / single-part triple.
type singlePartCase struct {
	// name identifies the single-part function under test.
	name string

	// section is the spec section stating the rule, quoted in failures so the
	// reader does not have to go looking for it.
	section string

	// setUp initializes the operation and returns the return value of Init.
	setUp func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV

	// update feeds one part into the operation.
	update func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV

	// singlePart invokes the single-part function that must now be refused.
	singlePart func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV

	// wantWithoutUpdate is what singlePart must return on the legitimate path,
	// with no Update call before it.
	//
	// Asserting the exact value rather than merely "not CKR_OPERATION_ACTIVE"
	// matters: the weaker form reports PASS even when the operation is failing
	// outright underneath, which is exactly how an unimplemented mechanism hid
	// behind this control test.
	wantWithoutUpdate module.CK_RV
}

// singlePartCases covers every operation exposing both a single-part function
// and an Update.
func singlePartCases() []singlePartCase {
	part := []byte("buffered part")
	whole := []byte("a different single-part argument")

	return []singlePartCase{
		{
			name:              "C_Sign",
			wantWithoutUpdate: module.CKR_OK,
			section:           "v3.2 §5.14.3",
			setUp: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, priv := generateRSAKeyPair(t, env, session, "multipart-sign")
				return env.Module.SignInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, priv)
			},
			update: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				return env.Module.SignUpdate(session, part)
			},
			singlePart: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.Sign(session, whole)
				return rv
			},
		},
		{
			name:              "C_Verify",
			wantWithoutUpdate: module.CKR_SIGNATURE_INVALID,
			section:           "v3.2 §5.14.6",
			setUp: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				pub, _ := generateRSAKeyPair(t, env, session, "multipart-verify")
				return env.Module.VerifyInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, pub)
			},
			update: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				return env.Module.VerifyUpdate(session, part)
			},
			singlePart: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				return env.Module.Verify(session, whole, make([]byte, 256))
			},
		},
		{
			name:              "C_Encrypt",
			wantWithoutUpdate: module.CKR_OK,
			section:           "v3.2 §5.9.2",
			setUp: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				key := generateAESKey(t, env, session, "multipart-encrypt")
				return env.Module.EncryptInit(session,
					&module.Mechanism{Type: module.CKM_AES_CBC, Parameter: aesIV}, key)
			},
			update: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.EncryptUpdate(session, make([]byte, 16))
				return rv
			},
			singlePart: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.Encrypt(session, make([]byte, 16))
				return rv
			},
		},
		{
			name:              "C_Decrypt",
			wantWithoutUpdate: module.CKR_OK,
			section:           "v3.2 §5.10.2",
			setUp: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				key := generateAESKey(t, env, session, "multipart-decrypt")
				return env.Module.DecryptInit(session,
					&module.Mechanism{Type: module.CKM_AES_CBC, Parameter: aesIV}, key)
			},
			update: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.DecryptUpdate(session, make([]byte, 16))
				return rv
			},
			singlePart: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.Decrypt(session, make([]byte, 16))
				return rv
			},
		},
		{
			name:              "C_Digest",
			wantWithoutUpdate: module.CKR_OK,
			section:           "v3.2 §5.12.2",
			setUp: func(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				return env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256})
			},
			update: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				return env.Module.DigestUpdate(session, part)
			},
			singlePart: func(env *testutil.TestEnvironment, session module.SessionHandle) module.CK_RV {
				_, rv := env.Module.Digest(session, whole)
				return rv
			},
		},
	}
}

// TestSinglePart_AfterUpdateIsRefused proves each single-part function refuses
// to run once a part has been supplied.
//
// CKR_OPERATION_ACTIVE is the code required here: it is the one the spec lists
// among each function's return values for this situation, and it tells the
// caller the operation is still the multiple-part one it started.
func TestSinglePart_AfterUpdateIsRefused(t *testing.T) {
	for _, tc := range singlePartCases() {
		t.Run(tc.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)

			if rv := tc.setUp(t, env, session); rv != module.CKR_OK {
				t.Fatalf("initializing the operation returned %s", rv.String())
			}
			if rv := tc.update(env, session); rv != module.CKR_OK {
				t.Fatalf("feeding a part returned %s", rv.String())
			}

			rv := tc.singlePart(env, session)
			if rv == module.CKR_OK {
				t.Fatalf("%s succeeded after an Update call. It cannot have included "+
					"the buffered part, so it returned a well-formed result over the "+
					"wrong data (%s forbids using it to terminate a multiple-part "+
					"operation)", tc.name, tc.section)
			}
			if rv != module.CKR_OPERATION_ACTIVE {
				t.Errorf("%s after an Update returned %s, want CKR_OPERATION_ACTIVE (%s)",
					tc.name, rv.String(), tc.section)
			}
		})
	}
}

// TestSinglePart_WithoutUpdateStillWorks is the control for the test above.
//
// A guard that refuses the legitimate single-part call is just as broken as one
// that permits the illegitimate one, and a rule stated only in the negative can
// be satisfied by a function that always fails. This asserts the same five
// functions still succeed on the path the spec requires them to accept.
func TestSinglePart_WithoutUpdateStillWorks(t *testing.T) {
	for _, tc := range singlePartCases() {
		t.Run(tc.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)

			if rv := tc.setUp(t, env, session); rv != module.CKR_OK {
				t.Fatalf("initializing the operation returned %s", rv.String())
			}

			// Each case declares the exact value it must return. C_Verify is
			// handed a zero-filled signature, so its correct answer is
			// CKR_SIGNATURE_INVALID — it must reach the verification to say so
			// rather than refuse on the multiple-part guard.
			rv := tc.singlePart(env, session)
			if rv == module.CKR_OPERATION_ACTIVE {
				t.Fatalf("%s was refused with CKR_OPERATION_ACTIVE with no intervening "+
					"Update call; the multiple-part guard is firing on the path the "+
					"spec requires it to accept", tc.name)
			}
			if rv != tc.wantWithoutUpdate {
				t.Errorf("%s returned %s, want %s. The operation is failing on the path "+
					"the spec requires it to accept, which means the mechanism is not "+
					"actually working — a check for merely \"not CKR_OPERATION_ACTIVE\" "+
					"would have reported this as a pass", tc.name, rv.String(),
					tc.wantWithoutUpdate.String())
			}
		})
	}
}

// TestDigestKey_MakesTheOperationMultiPart proves C_DigestKey counts as a part.
//
// PKCS#11 v3.2 §5.12.3 permits C_DigestUpdate and C_DigestKey to be
// interspersed in any order, which makes them equivalent as sources of buffered
// input. A module that tracks only C_DigestUpdate would let C_Digest silently
// discard a digested key — the same defect through a different door.
func TestDigestKey_MakesTheOperationMultiPart(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	key := generateAESKey(t, env, session, "multipart-digestkey")

	if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit returned %s", rv.String())
	}

	// A key whose material never leaves the backend is legitimately
	// indigestible (v3.2 §5.12.4 defines CKR_KEY_INDIGESTIBLE for exactly
	// that). Both outcomes are asserted rather than skipped: a consumed key
	// must arm the guard, and a refused one must leave the operation
	// untouched — silently half-consuming a key would be the real defect.
	digestKeyRV := env.Module.DigestKey(session, key)

	switch digestKeyRV {
	case module.CKR_OK:
		if _, rv := env.Module.Digest(session, []byte("single part")); rv != module.CKR_OPERATION_ACTIVE {
			t.Errorf("C_Digest after C_DigestKey returned %s, want CKR_OPERATION_ACTIVE; "+
				"a digested key is a buffered part exactly as C_DigestUpdate's data is "+
				"(v3.2 §5.12.2, §5.12.3)", rv.String())
		}
	case module.CKR_KEY_INDIGESTIBLE:
		if _, rv := env.Module.Digest(session, []byte("single part")); rv != module.CKR_OK {
			t.Errorf("C_DigestKey refused the key with CKR_KEY_INDIGESTIBLE but the "+
				"digest operation was left unusable (C_Digest returned %s). A refused "+
				"C_DigestKey must consume nothing and leave the operation intact "+
				"(v3.2 §5.12.4)", rv.String())
		}
	default:
		t.Fatalf("C_DigestKey returned %s, want CKR_OK or CKR_KEY_INDIGESTIBLE",
			digestKeyRV.String())
	}
}
