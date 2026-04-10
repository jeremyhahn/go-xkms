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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

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

		sh := openRWSession(t, m)

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
		if s.skipIfUnsupported(t, rv) {
			return
		}
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
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GenerateKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_GenerateKeyWithNilMechanismReturnsArgumentsBad", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

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
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_ARGUMENTS_BAD, rv,
			"GenerateKey with nil mechanism should return CKR_ARGUMENTS_BAD")
	})
}

// testGenerateKeyPair verifies C_GenerateKeyPair behavior per PKCS#11 v3.0 Section 5.14.2.
func (s *Suite) testGenerateKeyPair(t *testing.T) {

	t.Run("Happy_GenerateRSAKeyPairReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

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
		if s.skipIfUnsupported(t, rv) {
			return
		}
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
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GenerateKeyPair with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testWrapKey verifies C_WrapKey behavior per PKCS#11 v3.0 Section 5.14.3.
func (s *Suite) testWrapKey(t *testing.T) {

	t.Run("Happy_WrapKeyWithValidParamsReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		// Create wrapping key (real backend key for encryption) and target
		// key to wrap (needs CKA_VALUE for WrapKey to read key material).
		wrappingKey := generateSecretKey(t, m, sh)
		targetKey := createSecretKeyObject(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		wrappedKey, rv := m.WrapKey(sh, mechanism, wrappingKey, targetKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "WrapKey with valid parameters should return CKR_OK")

		if len(wrappedKey) == 0 {
			t.Fatal("WrapKey should return non-empty wrapped key bytes")
		}
	})

	t.Run("Error_WrapKeyWithInvalidSessionFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}

		_, rv := m.WrapKey(invalidSession, mechanism, module.ObjectHandle(1), module.ObjectHandle(2))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"WrapKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})

	t.Run("Error_WrapKeyWithInvalidWrappingKeyHandleFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		targetKey := generateSecretKey(t, m, sh)

		invalidWrappingKey := module.ObjectHandle(0xBADF00D)
		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}

		_, rv := m.WrapKey(sh, mechanism, invalidWrappingKey, targetKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_WRAPPING_KEY_HANDLE_INVALID, rv,
			"WrapKey with invalid wrapping key handle should return CKR_WRAPPING_KEY_HANDLE_INVALID")
	})
}

// testUnwrapKey verifies C_UnwrapKey behavior per PKCS#11 v3.0 Section 5.14.4.
func (s *Suite) testUnwrapKey(t *testing.T) {

	t.Run("Happy_UnwrapKeyWithWrappedBytesReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		// Create wrapping key (real backend key for encryption) and target
		// key to wrap (needs CKA_VALUE for WrapKey to read key material).
		wrappingKey := generateSecretKey(t, m, sh)
		targetKey := createSecretKeyObject(t, m, sh)

		wrapMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		wrappedKeyBytes, rv := m.WrapKey(sh, wrapMech, wrappingKey, targetKey)
		if s.skipIfUnsupported(t, rv) {
			return
		}
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

		unwrapMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		unwrappedHandle, rv := m.UnwrapKey(sh, unwrapMech, wrappingKey, wrappedKeyBytes, unwrapTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "UnwrapKey with valid wrapped bytes should return CKR_OK")

		if unwrappedHandle == 0 {
			t.Fatal("UnwrapKey should return a non-zero object handle")
		}
	})

	t.Run("Error_UnwrapKeyWithInvalidSessionFails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		mechanism := &module.Mechanism{Type: module.CKM_AES_GCM}
		unwrapTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.UnwrapKey(invalidSession, mechanism, module.ObjectHandle(1), []byte("fake-wrapped-data"), unwrapTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"UnwrapKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testDeriveKey verifies C_DeriveKey behavior per PKCS#11 v3.0 Section 5.14.5.
func (s *Suite) testDeriveKey(t *testing.T) {

	t.Run("Happy_DeriveKeyWithValidParamsReturnsOK", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		// Use an existing secret key as the base key for derivation.
		baseKey := generateSecretKey(t, m, sh)

		mechanism := &module.Mechanism{Type: module.CKM_HKDF_DERIVE}
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "derived-aes-key"),
			module.NewUint32Attribute(module.CKA_VALUE_LEN, 16),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewBoolAttribute(module.CKA_DERIVE, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		derivedHandle, rv := m.DeriveKey(sh, mechanism, baseKey, template)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DeriveKey with valid parameters should return CKR_OK")

		if derivedHandle == 0 {
			t.Fatal("DeriveKey should return a non-zero object handle")
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
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"DeriveKey with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}
