// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Round-trip tests for the cryptographic success paths of the C_* entry
// points: C_GenerateKey, C_GenerateKeyPair, C_Sign/C_Verify, C_Encrypt/
// C_Decrypt, C_WrapKey/C_UnwrapKey, C_DeriveKey and C_WrapKeyAuthenticated/
// C_UnwrapKeyAuthenticated.
//
// Every other test in this package drives the cgo boundary over
// offlineTransport (exports_test.go), whose embedded PKCS11Transport is nil,
// so any call that reaches the backend panics and the test is confined to the
// argument-marshalling and no-active-operation branches. That leaves the
// genuine cryptographic branches of these functions -- the memcpy of a real
// ciphertext or signature into the caller's buffer, the FinishOperation call
// on success -- uncovered.
//
// This file swaps in pkcs11test.CryptoMockClient, the real-crypto
// module.PKCS11Transport pkg/pkcs11/module's own suite already uses
// (module_suite_test.go), so a key generated, wrapped or derived here is
// backed by genuine RSA/AES/HKDF operations and a round trip proves the C ABI
// boundary carries real bytes rather than an internally-consistent stub.
//
// CKM_RSA_PKCS_OAEP is not exercised: CryptoMockClient.EncryptAsym backs the
// OAEP encrypt half, but CryptoMockClient.Decrypt (the RPC
// CryptoManager.Decrypt sends every decrypt through, OAEP included) only
// implements AES-GCM -- it has no Padding/Hash/Label-aware RSA branch -- so an
// OAEP decrypt against this fixture does not decrypt the ciphertext, it runs
// AES-GCM against a freshly lazily-generated symmetric key under the RSA
// key's id and fails. That is a real gap in the shared test double, reported
// rather than worked around here per this batch's instructions. The
// CKM_AES_GCM Encrypt/Decrypt round trip below exercises the identical
// C_EncryptInit/C_Encrypt/C_DecryptInit/C_Decrypt code paths, which do not
// vary by key type.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"
)

// newCryptoFixture provisions a module backed by a real-crypto
// CryptoMockClient and returns a logged-in read-write session.
func newCryptoFixture(t *testing.T) (m *module.Module, session module.SessionHandle) {
	t.Helper()
	return provisionTestModule(t, pkcs11test.NewCryptoMockClient())
}

// buildCMechanismWithParam lays out a CK_MECHANISM selecting mechType whose
// pParameter points at paramBuf, the parameterised sibling of
// exports_keymgmt2_test.go's buildCMechanism. paramBuf's backing storage is
// pinned for the rest of t by putPtr (exports_mechdecode_test.go).
func buildCMechanismWithParam(t testing.TB, mechType module.MechanismType, paramBuf []byte) []byte {
	buf := newAlignedBuf(cMechanismSize)
	putULong(buf, 0, uint64(mechType))
	putPtr(t, buf, 8, bytePtr(paramBuf))
	putULong(buf, 16, uint64(len(paramBuf)))
	return buf
}

// handleOf reads the CK_OBJECT_HANDLE an allocOf argument was written through
// after the call it was passed to returns.
func handleOf(v reflect.Value) module.ObjectHandle {
	return module.ObjectHandle(v.Elem().Uint())
}

// attrCount reports how many CK_ATTRIBUTE records a buildCAttributeArray
// buffer holds, for the ulCount/ulAttributeCount argument beside it.
func attrCount(buf []byte) uint64 {
	return uint64(len(buf) / cAttributeSize)
}

// generateRSAKeyPairViaC drives C_GenerateKeyPair with a real CKM_RSA_PKCS_KEY_PAIR_GEN
// mechanism and returns the public and private handles it produced.
func generateRSAKeyPairViaC(t *testing.T, session module.SessionHandle) (pub, priv module.ObjectHandle) {
	t.Helper()

	mechBuf := buildCMechanism(module.CKM_RSA_PKCS_KEY_PAIR_GEN)
	pubTemplate := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-rsa-pub"),
		module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})
	privTemplate := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-rsa-priv"),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})

	fn := reflect.ValueOf(C_GenerateKeyPair)
	ft := fn.Type()
	args := []reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		cAttributePtr(pubTemplate, ft, 2),
		scalarOf(ft, 3, attrCount(pubTemplate)),
		cAttributePtr(privTemplate, ft, 4),
		scalarOf(ft, 5, attrCount(privTemplate)),
		allocOf(ft, 6),
		allocOf(ft, 7),
	}
	out := fn.Call(args)

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair = %s, want CKR_OK", rv)
	}
	return handleOf(args[6]), handleOf(args[7])
}

// generateAESKeyViaC drives C_GenerateKey with a real CKM_AES_KEY_GEN
// mechanism and returns the handle it produced. The key is marked
// CKA_SENSITIVE=false/CKA_EXTRACTABLE=true so tests can read CKA_VALUE back
// as their own oracle (PKCS#11 v3.2 §4.9 footnote 7 is the one combination
// whose value a token may reveal).
func generateAESKeyViaC(t *testing.T, session module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()

	mechBuf := buildCMechanism(module.CKM_AES_KEY_GEN)
	template := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})

	fn := reflect.ValueOf(C_GenerateKey)
	ft := fn.Type()
	args := []reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		cAttributePtr(template, ft, 2),
		scalarOf(ft, 3, attrCount(template)),
		allocOf(ft, 4),
	}
	out := fn.Call(args)

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_GenerateKey(%s) = %s, want CKR_OK", label, rv)
	}
	return handleOf(args[4])
}

// signInitViaC drives C_SignInit with a parameterless mechanism.
func signInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechType module.MechanismType) module.CK_RV {
	t.Helper()

	mechBuf := buildCMechanism(mechType)
	fn := reflect.ValueOf(C_SignInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	return module.CK_RV(out[0].Uint())
}

// verifyInitViaC drives C_VerifyInit with a parameterless mechanism.
func verifyInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechType module.MechanismType) module.CK_RV {
	t.Helper()

	mechBuf := buildCMechanism(mechType)
	fn := reflect.ValueOf(C_VerifyInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	return module.CK_RV(out[0].Uint())
}

// signViaC drives C_Sign's two-call idiom: a NULL pSignature length query
// followed by a call with a buffer sized from the query's answer, pinning
// PKCS#11 v3.2 §5.11.2's length-then-fill contract on a real signature rather
// than on the NULL/argument-error branches exports_crypto_test.go covers.
func signViaC(t *testing.T, session module.SessionHandle, data []byte) []byte {
	t.Helper()

	fn := reflect.ValueOf(C_Sign)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(4).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		reflect.Zero(ft.In(3)),
		queryLen,
	})
	runtime.KeepAlive(data)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_Sign(pSignature=NULL) = %s, want CKR_OK", rv)
	}

	sigBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(sigBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		setBufferPtr(sigBuf, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(sigBuf)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_Sign(full buffer) = %s, want CKR_OK", rv)
	}
	return sigBuf[:fillLen.Elem().Uint()]
}

// verifyViaC drives C_Verify with a real signature, a single call per v3.2
// §5.12.2 (C_Verify has no length-query form: the caller already knows its
// own signature's length).
func verifyViaC(t *testing.T, session module.SessionHandle, data, signature []byte) module.CK_RV {
	t.Helper()

	fn := reflect.ValueOf(C_Verify)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		setBufferPtr(signature, ft, 3),
		scalarOf(ft, 4, uint64(len(signature))),
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(signature)
	return module.CK_RV(out[0].Uint())
}

// setBufferPtr is setBufferArg (exports_random_test.go) adapted to return the
// reflect.Value directly, for the direct fn.Call sequences in this file.
func setBufferPtr(buf []byte, fnType reflect.Type, argIdx int) reflect.Value {
	v := reflect.New(fnType.In(argIdx)).Elem()
	if len(buf) == 0 {
		return v
	}
	setBufferArg(buf)(v)
	return v
}

// encryptInitViaC drives C_EncryptInit, with or without a mechanism
// parameter.
func encryptInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechBuf []byte) module.CK_RV {
	t.Helper()

	fn := reflect.ValueOf(C_EncryptInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	return module.CK_RV(out[0].Uint())
}

// decryptInitViaC drives C_DecryptInit, with or without a mechanism
// parameter.
func decryptInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechBuf []byte) module.CK_RV {
	t.Helper()

	fn := reflect.ValueOf(C_DecryptInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	return module.CK_RV(out[0].Uint())
}

// encryptViaC drives C_Encrypt's two-call idiom (length query, then fill),
// returning the ciphertext and the CK_RV of the filling call.
func encryptViaC(t *testing.T, session module.SessionHandle, plaintext []byte) ([]byte, module.CK_RV) {
	t.Helper()

	fn := reflect.ValueOf(C_Encrypt)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(4).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(plaintext, ft, 1),
		scalarOf(ft, 2, uint64(len(plaintext))),
		reflect.Zero(ft.In(3)),
		queryLen,
	})
	runtime.KeepAlive(plaintext)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_Encrypt(pEncryptedData=NULL) = %s, want CKR_OK", rv)
	}

	ctBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(ctBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(plaintext, ft, 1),
		scalarOf(ft, 2, uint64(len(plaintext))),
		setBufferPtr(ctBuf, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ctBuf)
	return ctBuf[:fillLen.Elem().Uint()], module.CK_RV(out[0].Uint())
}

// decryptViaC drives C_Decrypt in a single call sized generously for the
// plaintext (never larger than the ciphertext), returning the plaintext and
// the call's CK_RV.
func decryptViaC(t *testing.T, session module.SessionHandle, ciphertext []byte) ([]byte, module.CK_RV) {
	t.Helper()

	fn := reflect.ValueOf(C_Decrypt)
	ft := fn.Type()

	ptBuf := make([]byte, len(ciphertext))
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(ptBuf)))
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(ciphertext, ft, 1),
		scalarOf(ft, 2, uint64(len(ciphertext))),
		setBufferPtr(ptBuf, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(ptBuf)
	return ptBuf[:fillLen.Elem().Uint()], module.CK_RV(out[0].Uint())
}

// ============================================================================
// RSA: C_GenerateKeyPair + C_SignInit/C_Sign/C_VerifyInit/C_Verify
// ============================================================================

// TestRSAGenerateSignVerify_RoundTrip proves the cgo boundary carries a real
// RSA-2048 key pair and a real PKCS#1 v1.5 signature: a key C_GenerateKeyPair
// produced signs through C_Sign, the same public key accepts it through
// C_Verify, and a one-byte tamper to either the message or the signature is
// rejected with CKR_SIGNATURE_INVALID rather than silently accepted.
func TestRSAGenerateSignVerify_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)

	data := []byte("the quick brown fox jumps over the lazy dog")

	if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
	}
	signature := signViaC(t, session, data)
	if len(signature) == 0 {
		t.Fatal("C_Sign produced an empty signature")
	}

	if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
	}
	if rv := verifyViaC(t, session, data, signature); rv != module.CKR_OK {
		t.Fatalf("C_Verify(genuine signature) = %s, want CKR_OK", rv)
	}

	t.Run("tampered data is rejected", func(t *testing.T) {
		if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
		}
		tampered := append([]byte(nil), data...)
		tampered[0] ^= 0xFF
		if rv := verifyViaC(t, session, tampered, signature); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_Verify(tampered data) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})

	t.Run("tampered signature is rejected", func(t *testing.T) {
		if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
		}
		tampered := append([]byte(nil), signature...)
		tampered[0] ^= 0xFF
		if rv := verifyViaC(t, session, data, tampered); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_Verify(tampered signature) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})
}

// ============================================================================
// AES-GCM: C_GenerateKey + C_EncryptInit/C_Encrypt/C_DecryptInit/C_Decrypt
// ============================================================================

// gcmRoundTripIV is the fixed 12-byte AES-GCM IV this file's Encrypt/Decrypt
// round trips use; CKM_AES_GCM requires one in CK_GCM_PARAMS (v3.2 §6.13.7)
// and decryption cannot proceed without it.
var gcmRoundTripIV = []byte("roundtrip-iv")

// TestAESGenerateEncryptDecrypt_RoundTrip proves C_Encrypt/C_Decrypt carry a
// real AES-256-GCM ciphertext across the cgo boundary: a key C_GenerateKey
// produced encrypts through C_Encrypt's two-call length-then-fill idiom,
// C_Decrypt recovers the exact plaintext, and a tampered ciphertext byte is
// rejected with CKR_ENCRYPTED_DATA_INVALID (PKCS#11 v3.2 §3.2/§5.10.2) rather
// than decrypting to corrupt plaintext under CKR_OK.
func TestAESGenerateEncryptDecrypt_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "roundtrip-aes-encrypt")

	plaintext := []byte("a secret message encrypted end to end through the cgo boundary")
	gcmParams := buildGCMParams(t, gcmRoundTripIV, 96, nil, 128)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, gcmParams)

	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}
	ciphertext, rv := encryptViaC(t, session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt(full buffer) = %s, want CKR_OK", rv)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("C_Encrypt returned the plaintext unchanged")
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext is %d bytes, want %d (plaintext + 16-byte GCM tag)", len(ciphertext), len(plaintext)+16)
	}

	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	recovered, rv := decryptViaC(t, session, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Decrypt(genuine ciphertext) = %s, want CKR_OK", rv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt = %q, want %q", recovered, plaintext)
	}

	t.Run("tampered ciphertext is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0xFF

		tamperMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
		if rv := decryptInitViaC(t, session, key, tamperMechBuf); rv != module.CKR_OK {
			t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
		}
		if _, rv := decryptViaC(t, session, tampered); rv != module.CKR_ENCRYPTED_DATA_INVALID {
			t.Fatalf("C_Decrypt(tampered ciphertext) = %s, want CKR_ENCRYPTED_DATA_INVALID", rv)
		}
	})
}

// ============================================================================
// AES-GCM: C_GenerateKey + C_WrapKey/C_UnwrapKey
// ============================================================================

// encryptOnceViaC opens a fresh CKM_AES_GCM encrypt operation under key with
// the given IV and returns the ciphertext, for use as an independent identity
// oracle: two keys holding the same material produce the same ciphertext for
// the same (plaintext, IV) pair, and only that pair.
func encryptOnceViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, iv, plaintext []byte) []byte {
	t.Helper()

	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, iv, 96, nil, 128))
	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit: %s", rv)
	}
	ciphertext, rv := encryptViaC(t, session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_Encrypt: %s", rv)
	}
	return ciphertext
}

// TestAESWrapUnwrapKey_RoundTrip proves C_WrapKey/C_UnwrapKey carry a real
// AES key across the cgo boundary rather than a length-shaped stand-in: the
// unwrapped key is checked against the target key by encrypting the same
// probe plaintext under the same fixed IV with each (AES-GCM is deterministic
// in (key, IV, plaintext), so identical ciphertext can only mean identical
// key material -- pkg/testing/pkcs11test/keymgmt.go's module-level suite uses
// the same oracle). A handle that merely looks non-zero would pass a weaker
// check; this would not, because CryptoMockClient.WrapKeyByID/UnwrapKeyByID
// perform genuine AES-GCM wrap/unwrap keyed by backend key id.
func TestAESWrapUnwrapKey_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	wrappingKey := generateAESKeyViaC(t, session, "roundtrip-wrapping-key")
	targetKey := generateAESKeyViaC(t, session, "roundtrip-target-key")

	wrapMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	fn := reflect.ValueOf(C_WrapKey)
	ft := fn.Type()

	// A single call with a generously sized buffer, not the length-query-then-
	// fill idiom: unlike C_Encrypt/C_Sign (which cache their result so a
	// repeated call after a length query replays it, see module.go's Encrypt),
	// C_WrapKey calls Module.WrapKey fresh on every invocation, and this
	// mechanism's IV is claimed by the process-wide AES-GCM reuse guard on
	// each real wrap (module_authwrap.go's guardGCMNonce doc explains the same
	// guard covers C_WrapKey). A query call under this fixed IV followed by a
	// real call under the same IV would burn it twice and the second call
	// would be refused as a nonce reuse.
	wrappedBuf := make([]byte, 4096)
	fillLen := reflect.New(ft.In(5).Elem())
	fillLen.Elem().SetUint(uint64(len(wrappedBuf)))
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(wrapMechBuf, ft, 1),
		scalarOf(ft, 2, uint64(wrappingKey)),
		scalarOf(ft, 3, uint64(targetKey)),
		setBufferPtr(wrappedBuf, ft, 4),
		fillLen,
	})
	runtime.KeepAlive(wrappedBuf)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_WrapKey(full buffer) = %s, want CKR_OK", rv)
	}
	wrappedKey := wrappedBuf[:fillLen.Elem().Uint()]
	if len(wrappedKey) == 0 {
		t.Fatal("C_WrapKey produced an empty wrapped key")
	}

	unwrapTemplate := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-unwrapped-key"),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})
	unwrapMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))

	unwrapFn := reflect.ValueOf(C_UnwrapKey)
	uft := unwrapFn.Type()
	uargs := []reflect.Value{
		scalarOf(uft, 0, uint64(session)),
		cMechanismPtr(unwrapMechBuf, uft, 1),
		scalarOf(uft, 2, uint64(wrappingKey)),
		setBufferPtr(wrappedKey, uft, 3),
		scalarOf(uft, 4, uint64(len(wrappedKey))),
		cAttributePtr(unwrapTemplate, uft, 5),
		scalarOf(uft, 6, attrCount(unwrapTemplate)),
		allocOf(uft, 7),
	}
	uout := unwrapFn.Call(uargs)
	runtime.KeepAlive(wrappedKey)
	if rv := module.CK_RV(uout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_UnwrapKey = %s, want CKR_OK", rv)
	}
	unwrappedKey := handleOf(uargs[7])
	if unwrappedKey == 0 {
		t.Fatal("C_UnwrapKey returned a zero object handle")
	}

	probe := []byte("wrap-unwrap-identity-probe-plaintext!!")
	fromTarget := encryptOnceViaC(t, session, targetKey, gcmRoundTripIV, probe)
	fromUnwrapped := encryptOnceViaC(t, session, unwrappedKey, gcmRoundTripIV, probe)
	if !bytes.Equal(fromTarget, fromUnwrapped) {
		t.Fatalf("the unwrapped key is not the key that was wrapped: the same plaintext under the "+
			"same IV encrypts to\n %x under the target key and\n %x under the unwrapped key",
			fromTarget, fromUnwrapped)
	}
}

// ============================================================================
// C_CreateObject + C_DeriveKey (CKM_HKDF_DERIVE)
// ============================================================================

// createSecretKeyObjectViaC drives C_CreateObject to import value as an AES
// CKA_VALUE secret key object, for tests that need a base key whose material
// is known exactly (an imported key gets no backend id, so CKM_HKDF_DERIVE's
// local computation is the only path that can consume it).
func createSecretKeyObjectViaC(t *testing.T, session module.SessionHandle, value []byte) module.ObjectHandle {
	t.Helper()

	template := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-hkdf-base-key"),
		module.NewAttribute(module.CKA_VALUE, value),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})

	fn := reflect.ValueOf(C_CreateObject)
	ft := fn.Type()
	args := []reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cAttributePtr(template, ft, 1),
		scalarOf(ft, 2, attrCount(template)),
		allocOf(ft, 3),
	}
	out := fn.Call(args)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_CreateObject(secret key) = %s, want CKR_OK", rv)
	}
	return handleOf(args[3])
}

// TestDeriveKeyHKDF_RoundTrip proves C_DeriveKey carries a real CK_HKDF_PARAMS
// across the cgo boundary and performs genuine RFC 5869 HKDF-SHA256: a base
// key imported through C_CreateObject derives a key whose CKA_VALUE is
// checked against an independent golang.org/x/crypto/hkdf computation, not
// merely against a non-zero object handle.
func TestDeriveKeyHKDF_RoundTrip(t *testing.T) {
	m, session := newCryptoFixture(t)

	ikm := []byte("0123456789ABCDEF0123456789ABCDEF")
	salt := []byte("roundtrip-hkdf-salt")
	info := []byte("roundtrip-hkdf-info")
	baseKey := createSecretKeyObjectViaC(t, session, ikm)

	hkdfParams := buildHKDFParams(t, true, true, module.CKM_SHA256, module.CKF_HKDF_SALT_DATA, salt, 0, info)
	mechBuf := buildCMechanismWithParam(t, module.CKM_HKDF_DERIVE, hkdfParams)
	derivedTemplate := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-derived-key"),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})

	fn := reflect.ValueOf(C_DeriveKey)
	ft := fn.Type()
	args := []reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(baseKey)),
		cAttributePtr(derivedTemplate, ft, 3),
		scalarOf(ft, 4, attrCount(derivedTemplate)),
		allocOf(ft, 5),
	}
	out := fn.Call(args)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_DeriveKey = %s, want CKR_OK", rv)
	}
	derivedKey := handleOf(args[5])
	if derivedKey == 0 {
		t.Fatal("C_DeriveKey returned a zero object handle")
	}

	attrs, rv := m.GetAttributeValue(session, derivedKey, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(derived CKA_VALUE) = %s, want CKR_OK", rv)
	}
	derived := attrs[0].Value

	expected := make([]byte, len(derived))
	reader := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(reader, expected); err != nil {
		t.Fatalf("building the HKDF oracle failed: %v", err)
	}
	if !bytes.Equal(derived, expected) {
		t.Fatalf("C_DeriveKey disagrees with RFC 5869 HKDF-SHA256\n got %x\nwant %x", derived, expected)
	}
}

// ============================================================================
// C_CreateObject + C_WrapKeyAuthenticated/C_UnwrapKeyAuthenticated
// ============================================================================

// TestWrapUnwrapKeyAuthenticated_RoundTrip proves C_WrapKeyAuthenticated/
// C_UnwrapKeyAuthenticated carry real AES-GCM AEAD ciphertext across the cgo
// boundary. Both keys are imported with C_CreateObject: module_authwrap.go
// performs the AES-GCM itself from each key's own CKA_VALUE rather than
// through the backend transport (see that file's package comment), so this is
// the one round trip in this file that needs no CryptoMockClient support at
// all. A tampered wrapped blob is rejected with CKR_AEAD_DECRYPT_FAILED
// (module_authwrap.go's UnwrapKeyAuthenticated) rather than unwrapping to
// corrupt key material under CKR_OK.
func TestWrapUnwrapKeyAuthenticated_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)

	// A fresh AES-256 key and IV per run: the module's GCM nonce guard is
	// process-wide, so a fixed pair would be refused as a reuse the second
	// time this test runs in one process (go test -count=N).
	wrappingMaterial := make([]byte, 32)
	if _, err := rand.Read(wrappingMaterial); err != nil {
		t.Fatalf("rand.Read(wrapping key): %v", err)
	}
	wrappingKey := createSecretKeyObjectViaC(t, session, wrappingMaterial)
	// CKA_WRAP and CKA_UNWRAP must both be set (v3.2 §5.18.6/§5.18.7):
	// this test wraps and unwraps under the same key object, so it needs
	// permission for both directions. createSecretKeyObjectViaC sets
	// neither, so they are added by reaching the object directly.
	setAuthWrapAttributes(t, session, wrappingKey, true, true)

	targetValue := []byte("the-target-key-material-16b!")[:16]
	targetKey := createSecretKeyObjectViaC(t, session, targetValue)
	setAuthWrapAttributes(t, session, targetKey, false, true)

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand.Read(iv): %v", err)
	}
	gcmMsgParams := buildGCMMessageParams(t, iv, 0, module.CKG_NO_GENERATE, nil, 0)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, gcmMsgParams)

	wrapFn := reflect.ValueOf(C_WrapKeyAuthenticated)
	wft := wrapFn.Type()

	wQueryLen := reflect.New(wft.In(7).Elem())
	wout := wrapFn.Call([]reflect.Value{
		scalarOf(wft, 0, uint64(session)),
		cMechanismPtr(mechBuf, wft, 1),
		scalarOf(wft, 2, uint64(wrappingKey)),
		scalarOf(wft, 3, uint64(targetKey)),
		reflect.Zero(wft.In(4)),
		scalarOf(wft, 5, 0),
		reflect.Zero(wft.In(6)),
		wQueryLen,
	})
	if rv := module.CK_RV(wout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_WrapKeyAuthenticated(pWrappedKey=NULL) = %s, want CKR_OK", rv)
	}

	wrappedBuf := make([]byte, wQueryLen.Elem().Uint())
	wFillLen := reflect.New(wft.In(7).Elem())
	wFillLen.Elem().SetUint(uint64(len(wrappedBuf)))
	wout = wrapFn.Call([]reflect.Value{
		scalarOf(wft, 0, uint64(session)),
		cMechanismPtr(mechBuf, wft, 1),
		scalarOf(wft, 2, uint64(wrappingKey)),
		scalarOf(wft, 3, uint64(targetKey)),
		reflect.Zero(wft.In(4)),
		scalarOf(wft, 5, 0),
		setBufferPtr(wrappedBuf, wft, 6),
		wFillLen,
	})
	runtime.KeepAlive(wrappedBuf)
	if rv := module.CK_RV(wout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_WrapKeyAuthenticated(full buffer) = %s, want CKR_OK", rv)
	}
	wrappedKey := wrappedBuf[:wFillLen.Elem().Uint()]
	if len(wrappedKey) != len(targetValue)+16 {
		t.Fatalf("wrapped key is %d bytes, want %d (16-byte target + 16-byte GCM tag)", len(wrappedKey), len(targetValue)+16)
	}

	unwrapTemplate := buildCAttributeArray(t, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "roundtrip-authunwrapped-key"),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	})
	unwrapMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, iv, 0, module.CKG_NO_GENERATE, nil, 0))

	unwrapFn := reflect.ValueOf(C_UnwrapKeyAuthenticated)
	uft := unwrapFn.Type()
	uargs := []reflect.Value{
		scalarOf(uft, 0, uint64(session)),
		cMechanismPtr(unwrapMechBuf, uft, 1),
		scalarOf(uft, 2, uint64(wrappingKey)),
		setBufferPtr(wrappedKey, uft, 3),
		scalarOf(uft, 4, uint64(len(wrappedKey))),
		cAttributePtr(unwrapTemplate, uft, 5),
		scalarOf(uft, 6, attrCount(unwrapTemplate)),
		reflect.Zero(uft.In(7)),
		scalarOf(uft, 8, 0),
		allocOf(uft, 9),
	}
	uout := unwrapFn.Call(uargs)
	runtime.KeepAlive(wrappedKey)
	if rv := module.CK_RV(uout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_UnwrapKeyAuthenticated(genuine blob) = %s, want CKR_OK", rv)
	}
	unwrappedKey := handleOf(uargs[9])

	m := module.GetGlobalModule()
	attrs, rv := m.GetAttributeValue(session, unwrappedKey, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(unwrapped CKA_VALUE) = %s, want CKR_OK", rv)
	}
	if !bytes.Equal(attrs[0].Value, targetValue) {
		t.Fatalf("C_UnwrapKeyAuthenticated recovered %x, want %x", attrs[0].Value, targetValue)
	}

	t.Run("tampered wrapped blob is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), wrappedKey...)
		tampered[0] ^= 0xFF

		tamperMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMMessageParams(t, iv, 0, module.CKG_NO_GENERATE, nil, 0))
		targs := []reflect.Value{
			scalarOf(uft, 0, uint64(session)),
			cMechanismPtr(tamperMechBuf, uft, 1),
			scalarOf(uft, 2, uint64(wrappingKey)),
			setBufferPtr(tampered, uft, 3),
			scalarOf(uft, 4, uint64(len(tampered))),
			cAttributePtr(unwrapTemplate, uft, 5),
			scalarOf(uft, 6, attrCount(unwrapTemplate)),
			reflect.Zero(uft.In(7)),
			scalarOf(uft, 8, 0),
			allocOf(uft, 9),
		}
		tout := unwrapFn.Call(targs)
		runtime.KeepAlive(tampered)
		if rv := module.CK_RV(tout[0].Uint()); rv != module.CKR_AEAD_DECRYPT_FAILED {
			t.Fatalf("C_UnwrapKeyAuthenticated(tampered blob) = %s, want CKR_AEAD_DECRYPT_FAILED", rv)
		}
	})
}

// setAuthWrapAttributes sets CKA_WRAP and CKA_UNWRAP directly on a key object
// through the module's Go API. C_CreateObject's raw CK_ATTRIBUTE array could
// carry these too, but every other boolean attribute this file's templates
// need is already expressed that way; reaching the two authenticated-wrap
// gating flags is the one place this suite drops to the Go API rather than
// adding two more raw CK_ATTRIBUTE records for a single call site.
func setAuthWrapAttributes(t *testing.T, session module.SessionHandle, key module.ObjectHandle, wrap, unwrap bool) {
	t.Helper()
	m := module.GetGlobalModule()
	rv := m.SetAttributeValue(session, key, []module.Attribute{
		module.NewBoolAttribute(module.CKA_WRAP, wrap),
		module.NewBoolAttribute(module.CKA_UNWRAP, unwrap),
	})
	if rv != module.CKR_OK {
		t.Fatalf("SetAttributeValue(CKA_WRAP=%v, CKA_UNWRAP=%v) = %s, want CKR_OK", wrap, unwrap, rv)
	}
}
