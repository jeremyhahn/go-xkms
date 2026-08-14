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

// Package conformance validates C_DeriveKey, which previously had zero
// integration coverage.
//
// Two independent derivation families are exercised, each against its own
// oracle:
//
//   - CKM_HKDF_DERIVE is checked against golang.org/x/crypto/hkdf, the
//     standard-library-adjacent RFC 5869 implementation. This is a byte-exact
//     oracle: the module either produces exactly the bytes RFC 5869 defines
//     for the given IKM/salt/info, or it does not.
//   - CKM_ECDH1_DERIVE is checked the way ECDH key agreement is checked in
//     practice: two independently generated key pairs derive from each
//     other's public point, and the two results must be byte-identical. A
//     mismatch here — swapped coordinate order, a wrong KDF counter, an
//     asymmetric use of SharedData — cannot be caught by checking CKR_OK
//     alone, since a broken derivation still returns a well-formed key on
//     each side; it is simply the wrong key on one or both.
//
// Reference: OASIS PKCS#11 v3.2 §5.20.1 (C_DeriveKey), §6.62.2 (HKDF), §6.20
// (ECDH1), RFC 5869 (HKDF), ANSI X9.63 (concatenation KDF).
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
	"golang.org/x/crypto/hkdf"
)

// createDeriveBaseKey imports a session-scoped generic secret key with known
// key material, so the derivation oracle can be computed independently of
// whatever the backend would have generated.
func createDeriveBaseKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, ikm []byte, canDerive bool) module.ObjectHandle {
	t.Helper()

	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
		module.NewStringAttribute(module.CKA_LABEL, "derive-base-key"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_DERIVE, canDerive),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewAttribute(module.CKA_VALUE, ikm),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the derive base key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// extractableDerivedTemplate is the attribute template every derive test uses
// for the resulting key, so the derived CKA_VALUE can be read back and
// compared to the oracle. Without CKA_EXTRACTABLE/CKA_SENSITIVE set this way,
// C_DeriveKey's documented default (v3.2 CKA_SENSITIVE=TRUE) would make the
// result unreadable and the test could only check CKR_OK.
func extractableDerivedTemplate(label string, keyLen uint32) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, keyLen),
	}
}

// TestDeriveKey_HKDFMatchesStandardLibrary proves CKM_HKDF_DERIVE produces
// exactly the bytes RFC 5869 defines for the given inputs.
//
// A module that ran an extract-only or expand-only step, mixed up the salt
// and info arguments, or used the wrong hash would still return CKR_OK with a
// key of the requested length; only comparing the actual bytes against a
// known-correct HKDF implementation catches that.
//
// Reference: PKCS#11 v3.2 §6.62.2 (CKM_HKDF_DERIVE); RFC 5869.
func TestDeriveKey_HKDFMatchesStandardLibrary(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	ikm := []byte("conformance HKDF input key material, 32+ bytes long")
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	info := []byte("conformance-hkdf-info")
	const keyLen = 42 // deliberately not a multiple of SHA-256's block size

	baseKey := createDeriveBaseKey(t, env, session, ikm, true)

	mech := &module.Mechanism{
		Type: module.CKM_HKDF_DERIVE,
		TypedParameter: &module.HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: module.CKM_SHA256,
			SaltType:    module.CKF_HKDF_SALT_DATA,
			Salt:        salt,
			Info:        info,
		},
	}

	derivedHandle, rv := env.Module.DeriveKey(session, mech, baseKey, extractableDerivedTemplate("hkdf-derived", keyLen))
	if rv != module.CKR_OK {
		t.Fatalf("C_DeriveKey CKM_HKDF_DERIVE returned %s", rv.String())
	}

	got := readAttribute(t, env, session, derivedHandle, module.CKA_VALUE)

	oracle := make([]byte, keyLen)
	kdf := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := kdf.Read(oracle); err != nil {
		t.Fatalf("computing the RFC 5869 oracle failed: %v", err)
	}

	if !bytes.Equal(got, oracle) {
		t.Errorf("CKM_HKDF_DERIVE output does not match RFC 5869\n got %x\nwant %x", got, oracle)
	}
}

// TestDeriveKey_HKDFRequiresStructuredParameters proves C_DeriveKey refuses
// CKM_HKDF_DERIVE when the caller supplies raw mechanism parameter bytes
// instead of a parsed CK_HKDF_PARAMS.
//
// v3.2 §6.62.2 defines CK_HKDF_PARAMS as the sole carrier of the salt, info
// and PRF hash; a module that derived under fabricated defaults instead of
// refusing would silently hand back key material the caller never asked for,
// under CKR_OK.
func TestDeriveKey_HKDFRequiresStructuredParameters(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	baseKey := createDeriveBaseKey(t, env, session, []byte("some input key material"), true)

	mech := &module.Mechanism{
		Type:      module.CKM_HKDF_DERIVE,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	_, rv := env.Module.DeriveKey(session, mech, baseKey, extractableDerivedTemplate("hkdf-no-params", 32))
	if rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("C_DeriveKey with unstructured HKDF parameters returned %s, want CKR_MECHANISM_PARAM_INVALID",
			rv.String())
	}
}

// TestDeriveKey_RejectsKeyWithoutDeriveAttribute proves a base key whose
// CKA_DERIVE is CK_FALSE cannot be used to derive.
//
// Reference: PKCS#11 v3.2 §5.18.5 gates C_DeriveKey on CKA_DERIVE; an absent
// or false attribute is not permission.
func TestDeriveKey_RejectsKeyWithoutDeriveAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	baseKey := createDeriveBaseKey(t, env, session, []byte("input key material"), false)

	mech := &module.Mechanism{
		Type: module.CKM_HKDF_DERIVE,
		TypedParameter: &module.HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: module.CKM_SHA256,
			SaltType:    module.CKF_HKDF_SALT_NULL,
		},
	}

	_, rv := env.Module.DeriveKey(session, mech, baseKey, extractableDerivedTemplate("should-not-derive", 32))
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_DeriveKey with a non-CKA_DERIVE base key returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED",
			rv.String())
	}
}

// TestDeriveKey_RejectsUnsupportedMechanism proves C_DeriveKey refuses a
// mechanism that is not a derivation mechanism at all.
//
// Reference: PKCS#11 v3.2 return values for C_DeriveKey include
// CKR_MECHANISM_INVALID.
func TestDeriveKey_RejectsUnsupportedMechanism(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	baseKey := createDeriveBaseKey(t, env, session, []byte("input key material"), true)

	mech := &module.Mechanism{Type: module.CKM_SHA256}
	_, rv := env.Module.DeriveKey(session, mech, baseKey, extractableDerivedTemplate("wrong-mechanism", 32))
	if rv != module.CKR_MECHANISM_INVALID {
		t.Errorf("C_DeriveKey with CKM_SHA256 (not a derive mechanism) returned %s, want CKR_MECHANISM_INVALID",
			rv.String())
	}
}

// TestDeriveKey_ReadOnlySessionIsRefused proves C_DeriveKey, which creates a
// new key object, refuses to run on a read-only session.
//
// Reference: CKR_SESSION_READ_ONLY is a documented return value for
// C_DeriveKey (v3.2 §5.20.1 return-values list).
func TestDeriveKey_ReadOnlySessionIsRefused(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	baseKey := createDeriveBaseKey(t, env, session, []byte("input key material"), true)

	// The token's login state is shared across every session on it, so a
	// second session opened while the first is still logged in is already
	// authenticated; logging in again would return CKR_USER_ALREADY_LOGGED_IN.
	roSession := env.MustOpenROSession(t)

	mech := &module.Mechanism{
		Type: module.CKM_HKDF_DERIVE,
		TypedParameter: &module.HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: module.CKM_SHA256,
			SaltType:    module.CKF_HKDF_SALT_NULL,
		},
	}

	_, rv := env.Module.DeriveKey(roSession, mech, baseKey, extractableDerivedTemplate("ro-session", 32))
	if rv != module.CKR_SESSION_READ_ONLY {
		t.Errorf("C_DeriveKey on a read-only session returned %s, want CKR_SESSION_READ_ONLY", rv.String())
	}
}

// generateECDHKeyPair generates a P-256 key pair whose private key carries
// CKA_DERIVE, the attribute CKM_ECDH1_DERIVE requires.
func generateECDHKeyPair(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) (pub, priv module.ObjectHandle) {
	t.Helper()

	c := ecCurveCases[0] // P-256
	pubTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		mustMarshalECParams(t, c),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	}
	privTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
	}

	mech := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}
	pub, priv, rv := env.Module.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair for ECDH returned %s", rv.String())
	}
	t.Cleanup(func() {
		env.Module.DestroyObject(session, pub)
		env.Module.DestroyObject(session, priv)
	})
	return pub, priv
}

// mustMarshalECParams builds the CKA_EC_PARAMS attribute for curve c.
func mustMarshalECParams(t *testing.T, c ecCurveCase) module.Attribute {
	t.Helper()
	ecParams, err := asn1.Marshal(c.oid)
	if err != nil {
		t.Fatalf("marshalling curve OID failed: %v", err)
	}
	return module.NewAttribute(module.CKA_EC_PARAMS, ecParams)
}

// rawECPoint strips the CKA_EC_POINT OCTET STRING wrapper and returns the raw
// SEC 1 uncompressed point (0x04 || X || Y), which is what CKM_ECDH1_DERIVE's
// CK_ECDH1_DERIVE_PARAMS.pPublicData carries per v3.2 §6.20.2.
func rawECPoint(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, pub module.ObjectHandle) []byte {
	t.Helper()
	wrapped := readAttribute(t, env, session, pub, module.CKA_EC_POINT)
	var raw []byte
	if _, err := asn1.Unmarshal(wrapped, &raw); err != nil {
		t.Fatalf("CKA_EC_POINT is not a DER OCTET STRING: %v", err)
	}
	return raw
}

// TestDeriveKey_ECDH1BothPartiesAgree proves that two independently generated
// EC key pairs, each deriving from the other's public point with
// CKM_ECDH1_DERIVE, produce byte-identical shared secrets.
//
// This is the correctness property ECDH key agreement exists to provide: it
// would fail if the module used the wrong coordinate, negated the point, or
// applied the concatenation KDF's counter/SharedInfo ordering
// asymmetrically. C_GetAttributeValue returning CKR_OK for both derived keys
// says nothing about whether they are the SAME key, which is the only thing
// that makes ECDH useful.
//
// Reference: PKCS#11 v3.2 §6.20.2 (CKM_ECDH1_DERIVE); ANSI X9.63
// concatenation KDF (CKD_SHA256_KDF).
func TestDeriveKey_ECDH1BothPartiesAgree(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	alicePub, alicePriv := generateECDHKeyPair(t, env, session, "ecdh-alice")
	bobPub, bobPriv := generateECDHKeyPair(t, env, session, "ecdh-bob")

	alicePoint := rawECPoint(t, env, session, alicePub)
	bobPoint := rawECPoint(t, env, session, bobPub)

	sharedInfo := []byte("conformance-ecdh-shared-info")

	deriveWith := func(base module.ObjectHandle, peerPoint []byte, label string) []byte {
		mech := &module.Mechanism{
			Type: module.CKM_ECDH1_DERIVE,
			TypedParameter: &module.ECDHParams{
				KDF:        module.CKD_SHA256_KDF,
				SharedData: sharedInfo,
				PublicData: peerPoint,
			},
		}
		handle, rv := env.Module.DeriveKey(session, mech, base, extractableDerivedTemplate(label, 32))
		if rv != module.CKR_OK {
			t.Fatalf("C_DeriveKey CKM_ECDH1_DERIVE (%s) returned %s", label, rv.String())
		}
		return readAttribute(t, env, session, handle, module.CKA_VALUE)
	}

	aliceSecret := deriveWith(alicePriv, bobPoint, "alice-derived")
	bobSecret := deriveWith(bobPriv, alicePoint, "bob-derived")

	if len(aliceSecret) == 0 {
		t.Fatal("Alice's derived secret is empty")
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Errorf("Alice and Bob derived different secrets from the same ECDH exchange\n"+
			"Alice: %x\nBob:   %x", aliceSecret, bobSecret)
	}
}

// TestDeriveKey_ECDH1RejectsUnsupportedKDF proves CKD_NULL, which this
// module deliberately does not implement (it would have to hand back the raw
// shared secret with no KDF applied), is refused rather than silently
// answered with a substitute KDF's output.
//
// Reference: v3.2 §6.20.2; CKR_MECHANISM_PARAM_INVALID for an unsupported
// CK_EC_KDF_TYPE.
func TestDeriveKey_ECDH1RejectsUnsupportedKDF(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	_, alicePriv := generateECDHKeyPair(t, env, session, "ecdh-null-kdf-alice")
	bobPub, _ := generateECDHKeyPair(t, env, session, "ecdh-null-kdf-bob")
	bobPoint := rawECPoint(t, env, session, bobPub)

	mech := &module.Mechanism{
		Type: module.CKM_ECDH1_DERIVE,
		TypedParameter: &module.ECDHParams{
			KDF:        module.CKD_NULL,
			PublicData: bobPoint,
		},
	}
	_, rv := env.Module.DeriveKey(session, mech, alicePriv, extractableDerivedTemplate("null-kdf", 32))
	if rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("C_DeriveKey CKM_ECDH1_DERIVE with CKD_NULL returned %s, want CKR_MECHANISM_PARAM_INVALID",
			rv.String())
	}
}
