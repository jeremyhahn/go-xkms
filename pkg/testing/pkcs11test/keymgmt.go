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

package pkcs11test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// decryptUnderKey runs a single-part decryption of ciphertext under key with
// mechanism and returns the plaintext and C_Decrypt's return value.
//
// Two AES keys hold the same material if and only if a CKM_AES_GCM ciphertext
// sealed under one opens under the other: the GCM tag fails under any other
// key. That equivalence is what proves a C_UnwrapKey actually reconstructed the
// wrapped key rather than inventing a fresh one, and it works even when neither
// key's value may be read back.
func decryptUnderKey(t *testing.T, m *module.Module, sh module.SessionHandle,
	key module.ObjectHandle, mechanism *module.Mechanism, ciphertext []byte) ([]byte, module.CK_RV) {
	t.Helper()

	requireRV(t, module.CKR_OK, m.DecryptInit(sh, mechanism, key), "DecryptInit failed")
	plaintext, rv := m.Decrypt(sh, ciphertext)
	if rv == module.CKR_OK {
		requireRV(t, module.CKR_OK, m.FinishOperation(sh, module.OperationDecrypt),
			"FinishOperation should terminate the decryption operation")
	}
	return plaintext, rv
}

// RunKeyManagementTests verifies Section 5.14 Key Management Functions of the
// PKCS#11 v3.0 spec. It exercises C_GenerateKey, C_GenerateKeyPair, C_WrapKey,
// C_UnwrapKey, and C_DeriveKey.
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.14
func (s *Suite) RunKeyManagementTests(t *testing.T) {
	t.Run("C_GenerateKey", s.testGenerateKey)
	t.Run("C_GenerateKeyPair", s.testGenerateKeyPair)
	t.Run("C_WrapKey", s.testWrapKey)
	t.Run("C_UnwrapKey", s.testUnwrapKey)
	t.Run("C_DeriveKey", s.testDeriveKey)
}

// testGenerateKey verifies C_GenerateKey behavior per PKCS#11 v3.0 Section 5.14.1.
func (s *Suite) testGenerateKey(t *testing.T) {

	t.Run("Happy_GenerateAESKeyReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "gen-aes-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		keyHandle, rv := m.GenerateKey(sh, mechanism, template)
		requireRV(t, module.CKR_OK, rv, "GenerateKey with valid AES template should return CKR_OK")

		if keyHandle == 0 {
			t.Fatal("GenerateKey should return a non-zero object handle")
		}
	})

	t.Run("Error_GenerateKeyWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "gen-aes-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.GenerateKey(invalidSession, mechanism, template)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GenerateKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_GenerateKeyWithNilMechanismReturnsArgumentsBad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "gen-aes-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.GenerateKey(sh, nil, template)
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"GenerateKey with nil mechanism should return CKR_ARGUMENTS_BAD")
	})
}

// testGenerateKeyPair verifies C_GenerateKeyPair behavior per PKCS#11 v3.0 Section 5.14.2.
func (s *Suite) testGenerateKeyPair(t *testing.T) {

	t.Run("Happy_GenerateRSAKeyPairReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}
		publicTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, "gen-rsa-pub"),
			module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			module.NewBoolAttribute(module.CKA_VERIFY, true),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}
		privateTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, "gen-rsa-priv"),
			module.NewBoolAttribute(module.CKA_SIGN, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		pubHandle, privHandle, rv := m.GenerateKeyPair(sh, mechanism, publicTemplate, privateTemplate)
		requireRV(t, module.CKR_OK, rv, "GenerateKeyPair with valid RSA templates should return CKR_OK")

		if pubHandle == 0 {
			t.Fatal("GenerateKeyPair should return a non-zero public key handle")
		}
		if privHandle == 0 {
			t.Fatal("GenerateKeyPair should return a non-zero private key handle")
		}
	})

	t.Run("Error_GenerateKeyPairWithInvalidSessionReturnsSessionHandleInvalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}
		publicTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			module.NewBoolAttribute(module.CKA_VERIFY, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}
		privateTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewBoolAttribute(module.CKA_SIGN, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, _, rv := m.GenerateKeyPair(invalidSession, mechanism, publicTemplate, privateTemplate)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GenerateKeyPair with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testWrapKey verifies C_WrapKey behavior per PKCS#11 v3.0 Section 5.14.3.
func (s *Suite) testWrapKey(t *testing.T) {

	t.Run("Happy_WrapKeyWithValidParamsReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		// Both keys are real backend keys so the wrap and unwrap both run
		// inside the backend and round-trip. Wrapping a purely local object
		// (one with CKA_VALUE but no backend key) produces the mechanism's
		// own ciphertext format, which the backend unwrap path does not read.
		wrappingKey := generateSecretKey(t, m, sh)
		targetKey := generateSecretKey(t, m, sh)

		// The target's own material, read while the object still permits it,
		// is the reference the wrapped blob is checked against.
		targetKeyValue := attributeValue(t, m, sh, targetKey, module.CKA_VALUE)

		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		wrappedKey, rv := m.WrapKey(sh, mechanism, wrappingKey, targetKey)
		requireRV(t, module.CKR_OK, rv, "WrapKey with valid parameters should return CKR_OK")

		// C_WrapKey encrypts the key (v3.2 §5.18.3). A len != 0 check reports
		// green for an implementation that hands back the target's plaintext
		// CKA_VALUE -- key exfiltration through the wrapping API. The wrapped
		// blob must not contain the key material anywhere, and under an AEAD
		// wrapping mechanism it must be at least the key plus a 128-bit
		// authentication tag.
		if bytes.Contains(wrappedKey, targetKeyValue) {
			t.Fatalf("the wrapped key contains the target key's plaintext CKA_VALUE; "+
				"C_WrapKey exported %d bytes of key material in the clear",
				len(targetKeyValue))
		}
		if len(wrappedKey) < len(targetKeyValue)+gcmTagLen {
			t.Fatalf("the wrapped key is %d bytes, too short to be %d bytes of key "+
				"material plus a %d-byte AES-GCM tag",
				len(wrappedKey), len(targetKeyValue), gcmTagLen)
		}
	})

	t.Run("Error_WrapKeyWithInvalidSessionFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		_, rv := m.WrapKey(invalidSession, mechanism, module.ObjectHandle(1), module.ObjectHandle(2))
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"WrapKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_WrapKeyWithInvalidWrappingKeyHandleFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		targetKey := generateSecretKey(t, m, sh)

		invalidWrappingKey := module.ObjectHandle(0xBADF00D)
		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))

		_, rv := m.WrapKey(sh, mechanism, invalidWrappingKey, targetKey)
		requireRV(t, module.CKR_WRAPPING_KEY_HANDLE_INVALID, rv,
			"WrapKey with invalid wrapping key handle should return CKR_WRAPPING_KEY_HANDLE_INVALID")
	})
}

// testUnwrapKey verifies C_UnwrapKey behavior per PKCS#11 v3.0 Section 5.14.4.
func (s *Suite) testUnwrapKey(t *testing.T) {

	t.Run("Happy_UnwrapKeyWithWrappedBytesReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		// Both keys are real backend keys so the wrap and unwrap both run
		// inside the backend and round-trip. Wrapping a purely local object
		// (one with CKA_VALUE but no backend key) produces the mechanism's
		// own ciphertext format, which the backend unwrap path does not read.
		wrappingKey := generateSecretKey(t, m, sh)
		targetKey := generateSecretKey(t, m, sh)

		wrapMech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		wrappedKeyBytes, rv := m.WrapKey(sh, wrapMech, wrappingKey, targetKey)
		requireRV(t, module.CKR_OK, rv, "WrapKey should succeed before UnwrapKey test")

		// Unwrap using the same wrapping key.
		unwrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "unwrapped-aes-key"),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		unwrapMech := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		unwrappedHandle, rv := m.UnwrapKey(sh, unwrapMech, wrappingKey, wrappedKeyBytes, unwrapTemplate)
		requireRV(t, module.CKR_OK, rv, "UnwrapKey with valid wrapped bytes should return CKR_OK")

		if unwrappedHandle == 0 {
			t.Fatal("UnwrapKey should return a non-zero object handle")
		}

		// A non-zero handle proves nothing about what is behind it: an
		// implementation that ignored wrappedKeyBytes and generated a fresh
		// random key would return one too, and the caller would silently be
		// using a different key than the one it unwrapped.
		//
		// Sealing a probe under the unwrapped key and opening it under the
		// target settles it, because the GCM tag only verifies under the key
		// that sealed it. The probe is sealed under an IV the token generates
		// (CKG_GENERATE_RANDOM, v3.2 §6.13.7), the form fips140=only permits.
		probe := []byte("unwrap-identity-probe-plaintext!")
		sealed, decryptMech := s.sealTestData(t, m, sh, unwrappedHandle, probe)
		recovered, rv := decryptUnderKey(t, m, sh, targetKey, decryptMech, sealed)
		if rv != module.CKR_OK {
			t.Fatalf("the unwrapped key is not the key that was wrapped: a probe sealed "+
				"under it does not open under the target key (%v)", rv)
		}
		if !bytes.Equal(recovered, probe) {
			t.Fatalf("the target key opened the probe sealed under the unwrapped key to %q, want %q",
				recovered, probe)
		}
	})

	t.Run("Error_UnwrapKeyWithInvalidSessionFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := module.NewMechanismWithTypedParams(module.CKM_AES_GCM, module.NewAESGCMParams(suiteGCMIV(), 128))
		unwrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.UnwrapKey(invalidSession, mechanism, module.ObjectHandle(1), []byte("fake-wrapped-data"), unwrapTemplate)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"UnwrapKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testDeriveKey verifies C_DeriveKey behavior per PKCS#11 v3.0 Section 5.14.5.
func (s *Suite) testDeriveKey(t *testing.T) {

	// suiteHKDFSalt and suiteHKDFInfo are the fixed CK_HKDF_PARAMS inputs the
	// derivation tests use. With a fixed base key they make CKM_HKDF_DERIVE
	// fully deterministic, which is what allows the derived material to be
	// compared against RFC 5869 rather than merely inspected for a handle.
	suiteHKDFSalt := []byte("conformance-suite-salt")
	suiteHKDFInfo := []byte("conformance-suite-info")

	// hkdfMechanism builds CKM_HKDF_DERIVE with the suite's fixed parameters
	// and the given info. CK_HKDF_PARAMS is required for this mechanism
	// (v3.2 §6.62.2), so the mechanism always carries a real one.
	hkdfMechanism := func(info []byte) *module.Mechanism {
		return &module.Mechanism{
			Type: module.CKM_HKDF_DERIVE,
			TypedParameter: &module.HKDFParams{
				Extract:     true,
				Expand:      true,
				PRFHashMech: module.CKM_SHA256,
				SaltType:    module.CKF_HKDF_SALT_DATA,
				Salt:        suiteHKDFSalt,
				Info:        info,
			},
		}
	}

	// derivedKeyTemplate asks for a 16-byte AES key whose value may be read
	// back. C_DeriveKey defaults a derived key to sensitive and
	// non-extractable, and a key whose material can never be seen cannot be
	// checked against a KDF.
	derivedKeyTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "derived-aes-key"),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	}

	t.Run("Happy_DeriveKeyMatchesRFC5869", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)

		// The base key is a local object whose CKA_VALUE the suite planted, so
		// the input keying material the token derives from is known exactly.
		baseKey := createSecretKeyObject(t, m, sh)

		derivedHandle, rv := m.DeriveKey(sh, hkdfMechanism(suiteHKDFInfo), baseKey, derivedKeyTemplate)
		requireRV(t, module.CKR_OK, rv, "DeriveKey with valid parameters should return CKR_OK")

		if derivedHandle == 0 {
			t.Fatal("DeriveKey should return a non-zero object handle")
		}

		// CKM_HKDF_DERIVE with bExtract and bExpand set is RFC 5869
		// extract-then-expand (v3.2 §6.62.2), which is deterministic in
		// (IKM, salt, info, L). Comparing against golang.org/x/crypto/hkdf
		// catches a derivation that returns random bytes, one that ignores the
		// salt or info, and one that quietly uses a different PRF -- none of
		// which a non-zero handle check can see.
		derived := attributeValue(t, m, sh, derivedHandle, module.CKA_VALUE)

		expected := make([]byte, len(derived))
		reader := hkdf.New(sha256.New, suiteSecretKeyValue, suiteHKDFSalt, suiteHKDFInfo)
		if _, err := io.ReadFull(reader, expected); err != nil {
			t.Fatalf("building the HKDF oracle failed: %v", err)
		}

		if !bytes.Equal(derived, expected) {
			t.Fatalf("the derived key disagrees with RFC 5869 HKDF-SHA256\n got %x\nwant %x",
				derived, expected)
		}
	})

	t.Run("Happy_DeriveKeyWithDifferentInfoProducesDifferentMaterial", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openAuthenticatedRWSession(t, m)
		baseKey := createSecretKeyObject(t, m, sh)

		firstHandle, rv := m.DeriveKey(sh, hkdfMechanism(suiteHKDFInfo), baseKey, derivedKeyTemplate)
		requireRV(t, module.CKR_OK, rv, "first DeriveKey should succeed")

		secondHandle, rv := m.DeriveKey(sh, hkdfMechanism([]byte("a-different-info-string")),
			baseKey, derivedKeyTemplate)
		requireRV(t, module.CKR_OK, rv, "second DeriveKey should succeed")

		// CK_HKDF_PARAMS.pInfo is domain separation: two derivations from one
		// base key that differ only in info MUST NOT yield the same key. A
		// token that dropped pInfo on the floor produces identical material
		// here while both derivations still look successful.
		first := attributeValue(t, m, sh, firstHandle, module.CKA_VALUE)
		second := attributeValue(t, m, sh, secondHandle, module.CKA_VALUE)

		if bytes.Equal(first, second) {
			t.Fatalf("changing CK_HKDF_PARAMS.pInfo did not change the derived key; "+
				"both derivations produced %x", first)
		}
	})

	t.Run("Error_DeriveKeyWithInvalidSessionFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_HKDF_DERIVE}
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.DeriveKey(invalidSession, mechanism, module.ObjectHandle(1), template)
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DeriveKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}
