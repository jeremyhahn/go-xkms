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

// Package conformance extends C_WrapKey coverage beyond the plain
// CKM_AES_KEY_WRAP round trip and adds the C_UnwrapKey negative paths that no
// existing test reaches.
//
// module.go's C_WrapKey has two dispatch paths: when the key being wrapped
// was created locally (module.CreateObject, so it has no backend KeyID), it
// wraps via CryptoManager.EncryptInit/Encrypt against the wrapping key's
// backend key; when the target key has a real backend KeyID (as every key
// C_GenerateKey/C_GenerateKeyPair produces does), it instead calls
// CryptoManager.WrapKeyByID, which wraps directly under the caller's own
// designated wrapping key via XKMSService.WrapKeyByID/wrapKeyMaterial
// (pkg/xkms/servicer_wrapkey.go) — deliberately independent of
// backend.ImportExportBackend.GetImportParameters/WrapKey, which serve the
// unrelated key-*import ceremony* (an ephemeral wrapping key pair generated
// for bringing externally generated material into a backend, not for
// wrapping under an existing key). C_UnwrapKey has only the second path —
// it always calls CryptoManager.UnwrapKeyByID, which unwraps the same way
// via unwrapKeyMaterial.
//
// Test helpers here import the target/source key material with a known
// plaintext value via C_CreateObject (so C_WrapKey exercises its local
// Encrypt-based path and the plaintext is known for comparison).
//
// Reference: OASIS PKCS#11 v3.2 §5.18.3 (C_WrapKey), §5.18.6 (C_UnwrapKey),
// §6.6 (RSA), §6.6.5 (CKM_RSA_PKCS_OAEP), §6.13 (CKM_AES_GCM).
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// rsaOAEPEncrypt encrypts plaintext with RSA-OAEP-SHA-256 under pub,
// independent of anything the module does. Used only to construct a
// well-formed wrapped blob for TestUnwrapKey_RecoversTheWrappedKey,
// which fails before ever attempting to decrypt it.
func rsaOAEPEncrypt(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	if err != nil {
		t.Fatalf("rsa.EncryptOAEP failed: %v", err)
	}
	return ciphertext
}

// generateAESWrappingKey generates a real (backend-held) AES key usable as
// an AES-GCM wrapping/unwrapping key.
func generateAESWrappingKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()

	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, label),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_WRAP, true),
			module.NewBoolAttribute(module.CKA_UNWRAP, true),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey (wrapping key) returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle
}

// generateOAEPWrappingKeyPair generates a real (backend-held) RSA key pair,
// used by TestWrapKey_RSAWrappingKeyRoundTrips and
// TestUnwrapKey_RecoversTheWrappedKey to exercise C_WrapKey/C_UnwrapKey with
// an RSA wrapping key.
func generateOAEPWrappingKeyPair(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) (pub, priv module.ObjectHandle) {
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
			module.NewBoolAttribute(module.CKA_WRAP, true),
		},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, label+"-priv"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_UNWRAP, true),
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

// importWrappableAESKey imports a 16-byte AES key with a known plaintext
// value via C_CreateObject. Because this creates the object without a
// backend KeyID, C_WrapKey takes its local Encrypt-based fallback path
// rather than CryptoManager.WrapKeyByID.
func importWrappableAESKey(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) (handle module.ObjectHandle, keyBytes []byte) {
	t.Helper()

	keyBytes = make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generating random key material failed: %v", err)
	}

	handle, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewAttribute(module.CKA_VALUE, keyBytes),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the target AES key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, handle) })
	return handle, keyBytes
}

// TestWrapKey_AESGCMRoundtripRecoversOriginalKeyMaterial proves that
// C_WrapKey's output, decrypted independently with C_Decrypt under the same
// wrapping key and IV, recovers exactly the original (known) target key
// bytes.
//
// This cannot go through C_UnwrapKey — see
// TestUnwrapKey_RecoversTheWrappedKey — so C_Decrypt stands in as
// the oracle for what C_WrapKey actually produced: a wrap that silently
// corrupted, truncated, or encrypted the wrong bytes would still return
// CKR_OK with a plausible-length blob; only decrypting it back to the exact
// original bytes catches that.
func TestWrapKey_AESGCMRoundtripRecoversOriginalKeyMaterial(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	wrapKeyHandle := generateAESWrappingKey(t, env, session, "wrap-gcm")
	target, original := importWrappableAESKey(t, env, session, "gcm-target")

	iv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	mech := gcmMechanism(iv)

	wrapped, rv := env.Module.WrapKey(session, mech, wrapKeyHandle, target)
	if rv != module.CKR_OK {
		t.Fatalf("C_WrapKey CKM_AES_GCM returned %s", rv.String())
	}
	if len(wrapped) == 0 {
		t.Fatal("C_WrapKey returned CKR_OK with an empty wrapped blob")
	}
	if bytes.Contains(wrapped, original) {
		t.Error("C_WrapKey's output contains the plaintext key bytes verbatim")
	}

	if rv := env.Module.DecryptInit(session, mech, wrapKeyHandle); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit returned %s", rv.String())
	}
	recovered, rv := env.Module.Decrypt(session, wrapped)
	if rv != module.CKR_OK {
		t.Fatalf("C_Decrypt of the wrapped blob returned %s", rv.String())
	}
	if !bytes.Equal(recovered, original) {
		t.Errorf("C_WrapKey did not produce a genuine encryption of the target key\n"+
			"original  %x\nrecovered %x", original, recovered)
	}
}

// TestWrapKey_RejectsKeyWithoutWrapAttribute proves C_WrapKey refuses a
// wrapping key whose CKA_WRAP is CK_FALSE.
//
// Reference: PKCS#11 v3.2 §5.18.3: CKA_WRAP MUST be CK_TRUE on the wrapping
// key. An absent attribute is not permission.
func TestWrapKey_RejectsKeyWithoutWrapAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	noWrapKey, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "no-wrap-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			// Deliberately no CKA_WRAP.
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, noWrapKey) })

	target, _ := importWrappableAESKey(t, env, session, "no-wrap-target")

	iv := make([]byte, 12)
	_, rv = env.Module.WrapKey(session, gcmMechanism(iv), noWrapKey, target)
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_WrapKey with a non-CKA_WRAP key returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED", rv.String())
	}
}

// TestWrapKey_RejectsNonExtractableTargetKey proves C_WrapKey refuses to wrap
// a key whose CKA_EXTRACTABLE is CK_FALSE.
//
// Reference: PKCS#11 v3.2 §5.18.3 / CKA_EXTRACTABLE semantics (v3.2 §4.9):
// wrapping is an export path, so a key never marked extractable must not
// leave the token in any form.
func TestWrapKey_RejectsNonExtractableTargetKey(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	wrapKeyHandle := generateAESWrappingKey(t, env, session, "wrap-nonextractable")

	target, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "nonextractable-target"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
		module.NewAttribute(module.CKA_VALUE, make([]byte, 16)),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, target) })

	iv := make([]byte, 12)
	_, rv = env.Module.WrapKey(session, gcmMechanism(iv), wrapKeyHandle, target)
	if rv != module.CKR_KEY_UNEXTRACTABLE {
		t.Errorf("C_WrapKey of a non-extractable key returned %s, want CKR_KEY_UNEXTRACTABLE", rv.String())
	}
}

// TestWrapKey_RejectsInvalidWrappingKeyHandle proves C_WrapKey returns the
// function-specific handle error, not a generic one, for a bad wrapping key
// handle.
//
// Reference: v3.2 defines CKR_WRAPPING_KEY_HANDLE_INVALID specifically for
// this parameter, distinct from CKR_KEY_HANDLE_INVALID used for the key being
// wrapped.
func TestWrapKey_RejectsInvalidWrappingKeyHandle(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	target, _ := importWrappableAESKey(t, env, session, "bad-wrapkey-target")

	const bogusHandle = module.ObjectHandle(0x7fffffff)
	iv := make([]byte, 12)
	_, rv := env.Module.WrapKey(session, gcmMechanism(iv), bogusHandle, target)
	if rv != module.CKR_WRAPPING_KEY_HANDLE_INVALID {
		t.Errorf("C_WrapKey with an invalid wrapping key handle returned %s, want CKR_WRAPPING_KEY_HANDLE_INVALID",
			rv.String())
	}
}

// TestUnwrapKey_RejectsKeyWithoutUnwrapAttribute proves C_UnwrapKey refuses
// an unwrapping key whose CKA_UNWRAP is CK_FALSE, and does so before it ever
// reaches the backend dispatch exercised by TestUnwrapKey_RecoversTheWrappedKey:
// module.go's UnwrapKey checks CKA_UNWRAP immediately after resolving the
// key handle, ahead of the CryptoManager.UnwrapKeyByID call.
//
// Reference: PKCS#11 v3.2 §5.18.6: CKA_UNWRAP MUST be CK_TRUE on the
// unwrapping key.
func TestUnwrapKey_RejectsKeyWithoutUnwrapAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	wrapKeyHandle := generateAESWrappingKey(t, env, session, "unwrap-attr-wrapkey")
	noUnwrapKey, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "no-unwrap-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			// Deliberately no CKA_UNWRAP.
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, noUnwrapKey) })

	target, _ := importWrappableAESKey(t, env, session, "no-unwrap-target")
	iv := make([]byte, 12)
	mech := gcmMechanism(iv)
	wrapped, rv := env.Module.WrapKey(session, mech, wrapKeyHandle, target)
	if rv != module.CKR_OK {
		t.Fatalf("C_WrapKey (setup) returned %s", rv.String())
	}

	unwrapTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	}
	_, rv = env.Module.UnwrapKey(session, mech, noUnwrapKey, wrapped, unwrapTemplate)
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_UnwrapKey with a non-CKA_UNWRAP key returned %s, want CKR_KEY_FUNCTION_NOT_PERMITTED",
			rv.String())
	}
}

// TestUnwrapKey_RejectsInvalidUnwrappingKeyHandle proves C_UnwrapKey returns
// the function-specific handle error for a bad unwrapping key handle. This
// check also runs ahead of the CryptoManager.UnwrapKeyByID backend dispatch.
//
// Reference: v3.2 defines CKR_UNWRAPPING_KEY_HANDLE_INVALID specifically for
// this parameter.
func TestUnwrapKey_RejectsInvalidUnwrappingKeyHandle(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	unwrapTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	}
	const bogusHandle = module.ObjectHandle(0x7ffffffe)
	iv := make([]byte, 12)
	_, rv := env.Module.UnwrapKey(session, gcmMechanism(iv),
		bogusHandle, []byte("not a real wrapped blob but not empty either"), unwrapTemplate)
	if rv != module.CKR_UNWRAPPING_KEY_HANDLE_INVALID {
		t.Errorf("C_UnwrapKey with an invalid unwrapping key handle returned %s, want CKR_UNWRAPPING_KEY_HANDLE_INVALID",
			rv.String())
	}
}

// TestWrapKey_RSAWrappingKeyRoundTrips proves C_WrapKey succeeds when the
// wrapping key is RSA, for a fully permitted key pair and a locally-imported
// (empty-KeyID) target that takes the local Encrypt-based dispatch path,
// consistent with CKM_RSA_PKCS_OAEP being advertised with CKF_WRAP (v3.2
// §6.6.5).
//
// C_WrapKey's local fallback calls CryptoManager.Encrypt, which reaches
// XKMSService.Encrypt on the wire (pkg/xkms/servicer_crypto.go); that
// handler falls back to asymmetric RSA encryption when the backend does not
// implement types.SymmetricKeyProvider, which is what lets an RSA wrapping
// key work through this path.
func TestWrapKey_RSAWrappingKeyRoundTrips(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	pub, _ := generateOAEPWrappingKeyPair(t, env, session, "rsa-unusable")
	target, _ := importWrappableAESKey(t, env, session, "rsa-unusable-target")

	_, rv := env.Module.WrapKey(session, &module.Mechanism{Type: module.CKM_RSA_PKCS_OAEP}, pub, target)
	if rv != module.CKR_OK {
		t.Errorf("C_WrapKey CKM_RSA_PKCS_OAEP returned %s, want CKR_OK; the mechanism is "+
			"advertised with CKF_WRAP (v3.2 §6.6.5), so a fully-permitted RSA wrapping key and "+
			"a locally-imported target key must succeed", rv.String())
	}
}

// TestUnwrapKey_RecoversTheWrappedKey proves C_UnwrapKey recovers exactly
// the original plaintext from a well-formed CKM_RSA_PKCS_OAEP-wrapped blob,
// given a fully permitted unwrapping key, consistent with
// C_GetMechanismList/C_GetMechanismInfo advertising CKF_UNWRAP for that
// mechanism (mechanism.go's CKM_RSA_PKCS_OAEP descriptor sets CKF_UNWRAP).
//
// module.go's UnwrapKey has no local decrypt-based fallback — it always
// calls CryptoManager.UnwrapKeyByID → XKMSService.UnwrapKeyByID →
// unwrapKeyMaterial (pkg/xkms/servicer_wrapkey.go), which unwraps directly
// under the caller's own designated unwrapping key rather than routing
// through the unrelated RSA import-ceremony primitives
// (SoftwareBackend.GetImportParameters). module.go's own wrapAlgorithmNames
// must map each mechanism it advertises (CKM_RSA_PKCS_OAEP to "rsa-oaep",
// CKM_AES_KEY_WRAP to "aes-kw", and so on) to the exact algorithm names
// unwrapKeyMaterial's dispatch switch recognizes for this call to succeed.
//
// The "well-formed wrapped blob" here is produced independently, with
// crypto/rsa directly (RSA-OAEP-SHA-256 under the module's own public key,
// read back via CKA_MODULUS/CKA_PUBLIC_EXPONENT) rather than via C_WrapKey:
// the reference implementation is the oracle for what a genuine
// RSA-OAEP-wrapped blob looks like, independent of anything C_WrapKey does.
func TestUnwrapKey_RecoversTheWrappedKey(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	pub, priv := generateOAEPWrappingKeyPair(t, env, session, "ceremony-defect")
	modulus := readAttribute(t, env, session, pub, module.CKA_MODULUS)
	exponent := readAttribute(t, env, session, pub, module.CKA_PUBLIC_EXPONENT)
	expBig := new(big.Int).SetBytes(exponent)
	oraclePub := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(expBig.Int64())}

	plaintext := make([]byte, 16)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generating random plaintext failed: %v", err)
	}
	wrapped := rsaOAEPEncrypt(t, oraclePub, plaintext)

	unwrapTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
	}
	_, rv := env.Module.UnwrapKey(session, &module.Mechanism{Type: module.CKM_RSA_PKCS_OAEP}, priv, wrapped, unwrapTemplate)
	if rv != module.CKR_OK {
		t.Errorf("C_UnwrapKey CKM_RSA_PKCS_OAEP returned %s, want CKR_OK; C_GetMechanismList "+
			"advertises CKF_UNWRAP for this mechanism (v3.2 §5.18.6), so a well-formed wrapped "+
			"blob and a fully-permitted unwrapping key must recover the original plaintext",
			rv.String())
	}
}
