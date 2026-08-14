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

package cabi

import (
	"crypto"
	"crypto/sha256"
	"os"
	"testing"
)

// referenceModulePathEnv names the environment variable holding a second,
// independent PKCS#11 module to compare against. The Makefile target points it
// at SoftHSM2.
const referenceModulePathEnv = "REFERENCE_PKCS11_MODULE"

// referencePINEnv names the user PIN for the reference token.
const referencePINEnv = "REFERENCE_PKCS11_PIN"

// newReferenceFixture opens a logged-in session on the reference module.
//
// The reference is loaded through the same harness as the module under test,
// so any difference the comparison turns up is a difference between the two
// implementations rather than between two test paths. SoftHSM2 offers only a
// v2.40 function list, which is why Open falls back to C_GetFunctionList.
func newReferenceFixture(t *testing.T) *Fixture {
	t.Helper()

	path := os.Getenv(referenceModulePathEnv)
	if path == "" {
		t.Fatalf("%s is not set; it must point at a reference PKCS#11 module such as /usr/lib/softhsm/libsofthsm2.so",
			referenceModulePathEnv)
	}

	mod, err := Open(path)
	if err != nil {
		t.Fatalf("loading the reference module: %v", err)
	}
	if err := mod.Initialize(); err != nil && RV(err) != CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Fatalf("C_Initialize on the reference module: %v", err)
	}

	slots, err := mod.SlotList()
	if err != nil {
		t.Fatalf("C_GetSlotList on the reference module: %v", err)
	}
	if len(slots) == 0 {
		t.Fatalf("the reference module at %s reports no slot with a token present; initialize one first", path)
	}

	session, err := mod.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession on the reference module: %v", err)
	}

	pin := os.Getenv(referencePINEnv)
	if pin == "" {
		pin = defaultUserPIN
	}
	if err := session.Login(CKU_USER, pin); err != nil {
		if cerr := session.Close(); cerr != nil {
			t.Errorf("C_CloseSession on the reference module: %v", cerr)
		}
		t.Fatalf("C_Login on the reference module: %v", err)
	}

	f := &Fixture{Module: mod, Slot: slots[0], Session: session, t: t}
	t.Cleanup(f.teardown)
	return f
}

// TestReferenceRSAPSSSignsTheSuppliedDigest establishes, against an
// independent implementation, what CKM_RSA_PKCS_PSS is supposed to do with its
// input.
//
// It is the evidence behind TestRSAPSSInputIsTheCallerSuppliedDigest. Without
// it, a claim that the module under test double-hashes could be answered with
// "the specification is ambiguous"; with it, the two implementations
// demonstrably disagree and only one of them matches the text of PKCS#11 v3.2
// section 6.1.9.
func TestReferenceRSAPSSSignsTheSuppliedDigest(t *testing.T) {
	f := newReferenceFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("reference PSS input convention"))
	params := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: 32}
	sig := signPSS(t, f, priv, params, digest[:])

	if got := verifyPSS(pubKey, crypto.SHA256, digest[:], sig, 32); got != pssInputIsDigest {
		t.Fatalf("the reference module did not sign the caller-supplied digest as the digest (%s); "+
			"the comparison this suite draws against it is no longer valid", got)
	}
}

// TestReferenceRSAOAEPRequiresParameters establishes that a conforming module
// refuses CKM_RSA_PKCS_OAEP without CK_RSA_PKCS_OAEP_PARAMS.
//
// It is the evidence behind TestRSAOAEPRejectsMissingParameters. PKCS#11 v3.2
// section 6.1.10 gives the mechanism a mandatory parameter structure, and a
// module that substitutes a default digest instead of refusing produces
// ciphertext under a digest the caller never chose.
func TestReferenceRSAOAEPRequiresParameters(t *testing.T) {
	f := newReferenceFixture(t)
	_, priv := generateRSAKeyPair(t, f, 2048)

	err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, nil, priv)
	if err == nil {
		t.Fatal("the reference module accepted CKM_RSA_PKCS_OAEP with a NULL pParameter; " +
			"the comparison this suite draws against it is no longer valid")
	}
	t.Logf("reference module refuses a NULL CK_RSA_PKCS_OAEP_PARAMS with %s (0x%08X)", rvName(RV(err)), RV(err))
}

// TestReferenceDeriveKeyRefusesABaseKeyWithoutCKADerive establishes which
// return value a conforming module gives when C_DeriveKey is called on a base
// key whose CKA_DERIVE is CK_FALSE.
//
// It is the evidence behind TestECDHRequiresCKADeriveOnTheBaseKey, and it
// exists because the specification can be read two ways. PKCS#11 v3.2 §5.1.6
// defines CKR_KEY_FUNCTION_NOT_PERMITTED as "an attempt has been made to use a
// key for a cryptographic purpose that the key's attributes are not set to
// allow it to do", which is exactly this condition, and defines
// CKR_KEY_TYPE_INCONSISTENT as "the specified key is not the correct type of
// key to use with the specified mechanism", which is not — the key here is an
// EC key and the mechanism is CKM_ECDH1_DERIVE. But §5.18.5's enumerated
// return values for C_DeriveKey list CKR_KEY_TYPE_INCONSISTENT and omit
// CKR_KEY_FUNCTION_NOT_PERMITTED, while C_SignInit and C_EncryptInit — the
// other two functions gated on a usage attribute — list both.
//
// An independent implementation is what settles it. The value is logged rather
// than asserted against a hard-coded expectation: this test's job is to report
// what conforming behaviour is, not to restate the answer the module under
// test already gives.
func TestReferenceDeriveKeyRefusesABaseKeyWithoutCKADerive(t *testing.T) {
	f := newReferenceFixture(t)
	pub, priv := generateECKeyPair(t, f, false)
	tokenPub := readECDHPublicKey(t, f, pub)
	_ = tokenPub

	peer, peerPoint := newECDHPeer(t)
	_ = peer

	params := ECDH1DeriveParams{KDF: CKD_NULL, PublicData: peerPoint}

	key, err := deriveECDHSecret(t, f, priv, params, 32)
	if err == nil {
		f.Track(key)
		t.Fatal("the reference module derived from a base key whose CKA_DERIVE is CK_FALSE; " +
			"PKCS#11 v3.2 section 4.9 defaults the attribute to CK_FALSE and section 5.18.5 requires it to be CK_TRUE, " +
			"so the comparison this suite draws against it is no longer valid")
	}
	t.Logf("reference module refuses a base key without CKA_DERIVE with %s (0x%08X)", rvName(RV(err)), RV(err))
}
