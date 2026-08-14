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

// Package conformance validates C_EncapsulateKey and C_DecapsulateKey (the
// PKCS#11 v3.2 KEM functions), which previously had zero integration
// coverage.
//
// module_kem.go dispatches both operations entirely inside this process
// (crypto_quantum.go's encapsulateMLKEM768/decapsulateMLKEM768), using the
// reference pkg/quantum/kyber768 implementation with no backend round trip.
// That means a key pair generated with kyber768 directly and imported via
// C_CreateObject is exactly the kind of key the module operates on in
// production — not a substitute for one a real C_GenerateKeyPair call would
// produce.
//
// The oracle is two-layered:
//  1. C_EncapsulateKey's ciphertext, decapsulated independently with
//     kyber768.Decapsulate using the same private key, must yield the exact
//     shared secret C_EncapsulateKey returned. This is the FIPS 203
//     correctness property KEMs exist to provide, checked against the
//     reference implementation rather than the module's own idea of
//     "matches".
//  2. C_DecapsulateKey, given that same ciphertext, must recover the
//     identical shared secret — proving the module's own decapsulation path
//     (not just the reference library's) agrees.
//
// Reference: OASIS PKCS#11 v3.2 §5.18.8 (C_EncapsulateKey), §5.18.9
// (C_DecapsulateKey), §6.68 (CKM_ML_KEM); NIST FIPS 203.
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/quantum/kyber768"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// mlKEM768KeyPair holds a reference-implementation ML-KEM-768 key pair.
type mlKEM768KeyPair struct {
	kem       *kyber768.Kyber768
	publicKey []byte
	seed      []byte
}

// generateMLKEM768Oracle generates an ML-KEM-768 key pair with the reference
// kyber768 implementation, independent of the module under test.
func generateMLKEM768Oracle(t *testing.T) *mlKEM768KeyPair {
	t.Helper()
	kem, err := kyber768.New()
	if err != nil {
		t.Fatalf("kyber768.New failed: %v", err)
	}
	pub, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("kyber768 GenerateKeyPair failed: %v", err)
	}
	seed := kem.ExportSecretKey()
	t.Cleanup(kem.Clean)
	return &mlKEM768KeyPair{kem: kem, publicKey: pub, seed: seed}
}

// importMLKEM768PublicKey imports the oracle's public key as an
// encapsulation-capable public key object.
func importMLKEM768PublicKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, kp *mlKEM768KeyPair, label string) module.ObjectHandle {
	t.Helper()
	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_ENCAPSULATE, true),
		module.NewAttribute(module.CKA_VALUE, kp.publicKey),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the imported ML-KEM-768 public key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// importMLKEM768PrivateKey imports the oracle's seed as a
// decapsulation-capable private key object. crypto_quantum.go's
// decapsulateMLKEM768 reconstructs the decapsulation key from this seed via
// kyber768.Create, so CKA_VALUE here must be the 64-byte seed, not a
// derived public key or any other encoding.
func importMLKEM768PrivateKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, kp *mlKEM768KeyPair, label string) module.ObjectHandle {
	t.Helper()
	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_DECAPSULATE, true),
		module.NewAttribute(module.CKA_VALUE, kp.seed),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the imported ML-KEM-768 private key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// extractableSecretTemplate is the CKO_SECRET_KEY template every KEM test
// uses for the resulting shared-secret object, so its CKA_VALUE can be read
// back and compared against the oracle.
func extractableSecretTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
	}
}

// TestEncapsulateKey_CiphertextDecapsulatesToTheReturnedSecretUnderTheReferenceImplementation
// proves C_EncapsulateKey's ciphertext and returned shared secret are a
// genuine FIPS 203 pair: decapsulating the ciphertext independently with
// kyber768, using the same private key, must recover exactly the shared
// secret C_EncapsulateKey handed back.
//
// This is the property that makes a KEM useful. Checking only that
// C_EncapsulateKey returned CKR_OK with a non-empty ciphertext and a key
// handle would pass even if the "shared secret" object held unrelated random
// bytes.
func TestEncapsulateKey_CiphertextDecapsulatesToTheReturnedSecretUnderTheReferenceImplementation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLKEM768Oracle(t)
	pubHandle := importMLKEM768PublicKey(t, env, session, kp, "encap-oracle-pub")

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	secretHandle, ciphertext, err := env.Module.EncapsulateKey(session, mech, pubHandle, extractableSecretTemplate("encap-oracle-secret"))
	if err != nil {
		t.Fatalf("C_EncapsulateKey returned %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("C_EncapsulateKey returned CKR_OK with an empty ciphertext")
	}

	secretAttrs, rv := env.Module.GetAttributeValue(session, secretHandle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("reading back the encapsulated shared secret returned %s", rv.String())
	}
	moduleSecret := secretAttrs[0].Value

	oracleSecret, err := kp.kem.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("the reference kyber768 implementation could not decapsulate the module's "+
			"ciphertext: %v", err)
	}

	if !bytes.Equal(moduleSecret, oracleSecret) {
		t.Errorf("C_EncapsulateKey's returned shared secret does not match what the reference "+
			"ML-KEM-768 implementation recovers from its own ciphertext\n"+
			"module  %x\noracle  %x", moduleSecret, oracleSecret)
	}
}

// TestEncapsulateKey_DecapsulateKeyRoundtripAgree proves that C_DecapsulateKey,
// given the ciphertext from C_EncapsulateKey and the matching private key,
// recovers the same shared secret C_EncapsulateKey produced.
//
// This exercises the module's own decapsulation path end to end (as opposed
// to the previous test, which only checks the reference library's view of
// the ciphertext), and is the round trip a real ML-KEM key exchange performs.
func TestEncapsulateKey_DecapsulateKeyRoundtripAgree(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLKEM768Oracle(t)
	pubHandle := importMLKEM768PublicKey(t, env, session, kp, "roundtrip-pub")
	privHandle := importMLKEM768PrivateKey(t, env, session, kp, "roundtrip-priv")

	encMech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	encSecretHandle, ciphertext, err := env.Module.EncapsulateKey(session, encMech, pubHandle, extractableSecretTemplate("roundtrip-enc-secret"))
	if err != nil {
		t.Fatalf("C_EncapsulateKey returned %v", err)
	}

	decMech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_DECAPSULATE}
	decSecretHandle, err := env.Module.DecapsulateKey(session, decMech, privHandle, extractableSecretTemplate("roundtrip-dec-secret"), ciphertext)
	if err != nil {
		t.Fatalf("C_DecapsulateKey returned %v", err)
	}

	encAttrs, rv := env.Module.GetAttributeValue(session, encSecretHandle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("reading back the encapsulated secret returned %s", rv.String())
	}
	decAttrs, rv := env.Module.GetAttributeValue(session, decSecretHandle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("reading back the decapsulated secret returned %s", rv.String())
	}

	if len(encAttrs[0].Value) == 0 {
		t.Fatal("the encapsulated shared secret is empty")
	}
	if !bytes.Equal(encAttrs[0].Value, decAttrs[0].Value) {
		t.Errorf("C_EncapsulateKey and C_DecapsulateKey disagree on the shared secret\n"+
			"encapsulated %x\ndecapsulated %x", encAttrs[0].Value, decAttrs[0].Value)
	}
}

// TestDecapsulateKey_RejectsTamperedCiphertext proves C_DecapsulateKey does
// not silently manufacture a "shared secret" from ciphertext that was
// corrupted after encapsulation.
//
// FIPS 203 (implicit rejection) means a decapsulation over a corrupted
// ciphertext still returns SOME 32-byte value rather than an explicit
// failure. What this test proves is the plumbing property that actually
// matters here: the value derived from corrupted ciphertext must not equal
// the value derived from the real ciphertext, so a corrupted transport
// cannot silently produce an agreeing key.
func TestDecapsulateKey_RejectsTamperedCiphertext(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLKEM768Oracle(t)
	pubHandle := importMLKEM768PublicKey(t, env, session, kp, "tamper-pub")
	privHandle := importMLKEM768PrivateKey(t, env, session, kp, "tamper-priv")

	encMech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	encSecretHandle, ciphertext, err := env.Module.EncapsulateKey(session, encMech, pubHandle, extractableSecretTemplate("tamper-enc-secret"))
	if err != nil {
		t.Fatalf("C_EncapsulateKey returned %v", err)
	}
	encAttrs, rv := env.Module.GetAttributeValue(session, encSecretHandle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("reading back the encapsulated secret returned %s", rv.String())
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xff

	decMech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_DECAPSULATE}
	decSecretHandle, err := env.Module.DecapsulateKey(session, decMech, privHandle, extractableSecretTemplate("tamper-dec-secret"), tampered)
	if err != nil {
		// An explicit failure also satisfies the property under test.
		return
	}
	decAttrs, rv := env.Module.GetAttributeValue(session, decSecretHandle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("reading back the decapsulated secret returned %s", rv.String())
	}
	if bytes.Equal(encAttrs[0].Value, decAttrs[0].Value) {
		t.Error("C_DecapsulateKey recovered the same shared secret from a tampered ciphertext " +
			"as from the real one")
	}
}

// TestEncapsulateKey_RejectsKeyWithoutEncapsulateAttribute proves the gating
// attribute is CKA_ENCAPSULATE.
//
// Reference: v3.2 §5.18.8: "the CKA_ENCAPSULATE attribute of the public key
// ... MUST be CK_TRUE".
func TestEncapsulateKey_RejectsKeyWithoutEncapsulateAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLKEM768Oracle(t)
	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewStringAttribute(module.CKA_LABEL, "no-encapsulate-pub"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_ENCAPSULATE, false),
		module.NewAttribute(module.CKA_VALUE, kp.publicKey),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	_, _, err := env.Module.EncapsulateKey(session, mech, handle, extractableSecretTemplate("should-not-encap"))
	if err == nil {
		t.Fatal("C_EncapsulateKey succeeded with a CKA_ENCAPSULATE=false key")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED", pkcsErr.Code.String())
	}
}

// TestDecapsulateKey_RejectsKeyWithoutDecapsulateAttribute proves the gating
// attribute is CKA_DECAPSULATE.
//
// The ciphertext argument is a correctly-sized (but not genuinely
// encapsulated) placeholder rather than a real C_EncapsulateKey output:
// module.go's DecapsulateKey checks CKA_DECAPSULATE before it ever attempts
// to decapsulate the ciphertext, so this test does not need a real one.
//
// Reference: v3.2 §5.18.9: "the CKA_DECAPSULATE attribute of the private key
// ... MUST be CK_TRUE".
func TestDecapsulateKey_RejectsKeyWithoutDecapsulateAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	kp := generateMLKEM768Oracle(t)

	privHandle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewStringAttribute(module.CKA_LABEL, "no-decap-priv"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_DECAPSULATE, false),
		module.NewAttribute(module.CKA_VALUE, kp.seed),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, privHandle) })

	placeholderCiphertext := make([]byte, kyber768.CiphertextSize)
	decMech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_DECAPSULATE}
	_, err := env.Module.DecapsulateKey(session, decMech, privHandle, extractableSecretTemplate("no-decap-dec"), placeholderCiphertext)
	if err == nil {
		t.Fatal("C_DecapsulateKey succeeded with a CKA_DECAPSULATE=false key")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED", pkcsErr.Code.String())
	}
}

// TestEncapsulateKey_RejectsSecretKeyClass proves C_EncapsulateKey refuses a
// key handle that is not a CKO_PUBLIC_KEY, e.g. one that names a secret key.
//
// Reference: v3.2 §5.18.8's hPublicKey parameter must reference a public key
// object; CKR_KEY_HANDLE_INVALID covers a handle of the wrong class.
func TestEncapsulateKey_RejectsSecretKeyClass(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	secretHandle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "not-a-public-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, secretHandle) })

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	_, _, err := env.Module.EncapsulateKey(session, mech, secretHandle, extractableSecretTemplate("wrong-class"))
	if err == nil {
		t.Fatal("C_EncapsulateKey succeeded against a secret-key handle")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_KEY_HANDLE_INVALID {
		t.Errorf("returned %s, want CKR_KEY_HANDLE_INVALID", pkcsErr.Code.String())
	}
}

// TestEncapsulateKey_RejectsReadOnlySession proves C_EncapsulateKey, which
// creates a new key object, refuses to run on a read-only session.
//
// Reference: creating an object requires a R/W session unless the object is
// explicitly a token object requested on... in this module's implementation
// the check is unconditional (module_kem.go: session.IsReadWrite()),
// matching the same defensive posture as C_DeriveKey.
func TestEncapsulateKey_RejectsReadOnlySession(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	kp := generateMLKEM768Oracle(t)
	pubHandle := importMLKEM768PublicKey(t, env, session, kp, "ro-session-pub")

	// The token's login state is shared across every session on it, so a
	// second session opened while the first is still logged in is already
	// authenticated; logging in again would return CKR_USER_ALREADY_LOGGED_IN.
	roSession := env.MustOpenROSession(t)

	mech := &module.Mechanism{Type: module.CKM_VENDOR_ML_KEM_768_ENCAPSULATE}
	_, _, err := env.Module.EncapsulateKey(roSession, mech, pubHandle, extractableSecretTemplate("ro-session-secret"))
	if err == nil {
		t.Fatal("C_EncapsulateKey succeeded on a read-only session")
	}
	pkcsErr, ok := err.(*module.PKCS11Error)
	if !ok {
		t.Fatalf("expected a *module.PKCS11Error, got %T: %v", err, err)
	}
	if pkcsErr.Code != module.CKR_SESSION_READ_ONLY {
		t.Errorf("returned %s, want CKR_SESSION_READ_ONLY", pkcsErr.Code.String())
	}
}
