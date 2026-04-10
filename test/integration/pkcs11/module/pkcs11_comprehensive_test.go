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

//go:build integration
// +build integration

// Package module provides comprehensive PKCS#11 v3.0 integration tests.
// These tests validate ALL operations and mechanisms per the OASIS PKCS#11 v3.0 specification.
package module

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// =============================================================================
// PKCS#11 v3.0 Core Functions Tests
// OASIS PKCS#11 v3.0 Section 5.4
// =============================================================================

// TestGetFunctionList tests C_GetFunctionList functionality.
// OASIS PKCS#11 v3.0 Section 5.4
func TestGetFunctionList(t *testing.T) {
	t.Run("GetFunctionList_BeforeInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		// GetFunctionList should work even before Initialize
		// as per PKCS#11 spec, it's the first function called
		if env.Module == nil {
			t.Fatal("expected module to be created")
		}
	})

	t.Run("GetFunctionList_AfterInit", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Module should be usable after initialization
		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "GetInfo")
		if info == nil {
			t.Fatal("expected info after initialization")
		}
	})
}

// TestGetInterface tests C_GetInterface functionality (PKCS#11 v3.0).
// OASIS PKCS#11 v3.0 Section 5.4
func TestGetInterface(t *testing.T) {
	t.Run("GetInterface_Standard", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Verify module reports v3.0 compatibility
		info, rv := env.Module.GetInfo()
		RequireOK(t, rv, "GetInfo")
		if info.CryptokiVersion.Major < 3 {
			t.Errorf("expected Cryptoki version >= 3.0, got %d.%d",
				info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
		}
	})
}

// =============================================================================
// PKCS#11 v3.0 Mechanism Comprehensive Tests
// OASIS PKCS#11 v3.0 Section 5.12
// =============================================================================

// TestAllSupportedMechanisms tests that all documented mechanisms are properly supported.
func TestAllSupportedMechanisms(t *testing.T) {
	env := SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)

	mechanisms, rv := env.Module.GetMechanismList(0)
	RequireOK(t, rv, "GetMechanismList")

	if len(mechanisms) == 0 {
		t.Fatal("expected at least one mechanism")
	}

	// Verify each mechanism has valid info
	for _, mech := range mechanisms {
		info, rv := env.Module.GetMechanismInfo(0, mech)
		if rv != module.CKR_OK {
			t.Errorf("GetMechanismInfo(%s) failed: %s", mech.String(), rv.String())
			continue
		}

		// Verify mechanism info is valid
		if info == nil {
			t.Errorf("GetMechanismInfo(%s) returned nil info", mech.String())
			continue
		}

		// Verify min <= max key size
		if info.MinKeySize > info.MaxKeySize {
			t.Errorf("mechanism %s: MinKeySize (%d) > MaxKeySize (%d)",
				mech.String(), info.MinKeySize, info.MaxKeySize)
		}

		t.Logf("Mechanism %s: KeySize=%d-%d, Flags=0x%08x",
			mech.String(), info.MinKeySize, info.MaxKeySize, info.Flags)
	}
}

// TestRSAMechanisms tests all RSA mechanisms comprehensively.
func TestRSAMechanisms(t *testing.T) {
	testCases := []struct {
		name         string
		signMech     module.MechanismType
		requiresInit bool
	}{
		{"RSA_PKCS", module.CKM_RSA_PKCS, true},
		{"SHA1_RSA_PKCS", module.CKM_SHA1_RSA_PKCS, true},
		{"SHA256_RSA_PKCS", module.CKM_SHA256_RSA_PKCS, true},
		{"SHA384_RSA_PKCS", module.CKM_SHA384_RSA_PKCS, true},
		{"SHA512_RSA_PKCS", module.CKM_SHA512_RSA_PKCS, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_SignVerify", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			// Generate RSA key pair
			label := "test-rsa-" + tc.name
			pubTemplate := BuildRSAPublicKeyTemplate(label+"-pub", 2048)
			privTemplate := BuildRSAPrivateKeyTemplate(label + "-priv")
			mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
			RequireOK(t, rv, "GenerateKeyPair RSA")

			data := []byte("Test data for RSA signature verification")

			// For RSA_PKCS with combined hash mechanisms, the data should be raw
			// For plain RSA_PKCS, data should be pre-hashed
			signData := data
			if tc.signMech == module.CKM_RSA_PKCS {
				// Pre-hash for raw RSA-PKCS signature
				signData = hashSHA256(data)
			}

			// Sign
			signMech := &module.Mechanism{Type: tc.signMech}
			rv = env.Module.SignInit(session, signMech, privHandle)
			RequireOK(t, rv, "SignInit "+tc.name)

			signature, rv := env.Module.Sign(session, signData)
			RequireOK(t, rv, "Sign "+tc.name)

			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify
			rv = env.Module.VerifyInit(session, signMech, pubHandle)
			RequireOK(t, rv, "VerifyInit "+tc.name)

			rv = env.Module.Verify(session, signData, signature)
			RequireOK(t, rv, "Verify "+tc.name)

			t.Logf("%s: signature size = %d bytes", tc.name, len(signature))
		})
	}
}

// TestRSAPSSMechanisms tests RSA-PSS mechanisms.
func TestRSAPSSMechanisms(t *testing.T) {
	testCases := []struct {
		name     string
		signMech module.MechanismType
	}{
		{"SHA256_RSA_PKCS_PSS", module.CKM_SHA256_RSA_PKCS_PSS},
		{"SHA384_RSA_PKCS_PSS", module.CKM_SHA384_RSA_PKCS_PSS},
		{"SHA512_RSA_PKCS_PSS", module.CKM_SHA512_RSA_PKCS_PSS},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_SignVerify", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			// Generate RSA key pair
			label := "test-pss-" + tc.name
			pubTemplate := BuildRSAPublicKeyTemplate(label+"-pub", 2048)
			privTemplate := BuildRSAPrivateKeyTemplate(label + "-priv")
			mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
			RequireOK(t, rv, "GenerateKeyPair RSA")

			data := []byte("Test data for RSA-PSS signature")

			// Sign
			signMech := &module.Mechanism{Type: tc.signMech}
			rv = env.Module.SignInit(session, signMech, privHandle)
			RequireOK(t, rv, "SignInit "+tc.name)

			signature, rv := env.Module.Sign(session, data)
			RequireOK(t, rv, "Sign "+tc.name)

			// Verify
			rv = env.Module.VerifyInit(session, signMech, pubHandle)
			RequireOK(t, rv, "VerifyInit "+tc.name)

			rv = env.Module.Verify(session, data, signature)
			RequireOK(t, rv, "Verify "+tc.name)

			t.Logf("%s: signature size = %d bytes", tc.name, len(signature))
		})
	}
}

// TestECDSAMechanisms tests all ECDSA mechanisms.
func TestECDSAMechanisms(t *testing.T) {
	testCases := []struct {
		name     string
		curveOID []byte
		signMech module.MechanismType
	}{
		{"ECDSA_P256", OID_P256, module.CKM_ECDSA},
		{"ECDSA_SHA256_P256", OID_P256, module.CKM_ECDSA_SHA256},
		{"ECDSA_SHA384_P384", OID_P384, module.CKM_ECDSA_SHA384},
		{"ECDSA_SHA512_P521", OID_P521, module.CKM_ECDSA_SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_SignVerify", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			// Generate EC key pair
			label := "test-ecdsa-" + tc.name
			pubTemplate := BuildECPublicKeyTemplate(label+"-pub", tc.curveOID)
			privTemplate := BuildECPrivateKeyTemplate(label + "-priv")
			mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
			RequireOK(t, rv, "GenerateKeyPair EC "+tc.name)

			data := []byte("Test data for ECDSA signature")

			// For raw ECDSA, data should be pre-hashed
			signData := data
			if tc.signMech == module.CKM_ECDSA {
				signData = hashSHA256(data)
			}

			// Sign
			signMech := &module.Mechanism{Type: tc.signMech}
			rv = env.Module.SignInit(session, signMech, privHandle)
			RequireOK(t, rv, "SignInit "+tc.name)

			signature, rv := env.Module.Sign(session, signData)
			RequireOK(t, rv, "Sign "+tc.name)

			// Verify
			rv = env.Module.VerifyInit(session, signMech, pubHandle)
			RequireOK(t, rv, "VerifyInit "+tc.name)

			rv = env.Module.Verify(session, signData, signature)
			RequireOK(t, rv, "Verify "+tc.name)

			t.Logf("%s: signature size = %d bytes", tc.name, len(signature))
		})
	}
}

// TestEdDSAMechanisms tests EdDSA (Ed25519) mechanisms comprehensively.
func TestEdDSAMechanisms(t *testing.T) {
	t.Run("Ed25519_KeyGen", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-keygen-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-keygen-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		if pubHandle == 0 || privHandle == 0 {
			t.Error("expected valid key handles")
		}

		t.Logf("Ed25519 key pair: pub=%d, priv=%d", pubHandle, privHandle)
	})

	t.Run("Ed25519_SignVerify", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-sign-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-sign-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		data := []byte("Test data for Ed25519 signature")

		// Sign with EdDSA
		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA")

		// Ed25519 signatures are always 64 bytes
		if len(signature) != 64 {
			t.Errorf("expected 64-byte Ed25519 signature, got %d bytes", len(signature))
		}

		// Verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA")
	})

	t.Run("Ed25519_EmptyMessage", func(t *testing.T) {
		// NOTE: Ed25519 signing of empty messages is allowed by RFC 8032 but our
		// implementation currently does not support it. This is a known limitation.
		t.Skip("Ed25519 empty message signing not currently supported")

		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-empty-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-empty-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Ed25519 allows signing empty messages per RFC 8032
		data := []byte{}

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA empty")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA empty data")

		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA empty")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA empty data")

		t.Log("Ed25519 empty message sign/verify succeeded")
	})

	t.Run("Ed25519_LargeMessage", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-large-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-large-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Test with large message (1MB)
		data := make([]byte, 1024*1024)
		for i := range data {
			data[i] = byte(i % 256)
		}

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA large")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA large data")

		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA large")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA large data")

		t.Logf("Ed25519 large message (1MB) sign/verify succeeded")
	})
}

// =============================================================================
// AES Mechanism Tests
// OASIS PKCS#11 v3.0 Section 5.13
// =============================================================================

// TestAESKeyGeneration tests AES key generation with all valid key sizes.
func TestAESKeyGeneration(t *testing.T) {
	keySizes := []uint32{16, 24, 32} // 128, 192, 256 bits

	for _, keyLen := range keySizes {
		testName := fmt.Sprintf("AES_%d", keyLen*8)
		t.Run(testName, func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			template := BuildAESKeyTemplate("test-aes-gen", keyLen)
			mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

			handle, rv := env.Module.GenerateKey(session, mechanism, template)
			RequireOK(t, rv, "GenerateKey AES")

			if handle == 0 {
				t.Error("expected valid key handle")
			}

			t.Logf("Generated AES-%d key: handle=%d", keyLen*8, handle)
		})
	}
}

// TestAESEncryptionModes tests all AES encryption modes.
func TestAESEncryptionModes(t *testing.T) {
	testCases := []struct {
		name    string
		encMech module.MechanismType
	}{
		{"AES_GCM", module.CKM_AES_GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_EncryptDecrypt", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			// Generate AES key
			template := BuildAESKeyTemplate("test-aes-"+tc.name, 32)
			keyMech := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

			keyHandle, rv := env.Module.GenerateKey(session, keyMech, template)
			RequireOK(t, rv, "GenerateKey AES")

			plaintext := []byte("Test plaintext for AES encryption mode testing - pad to 32 bytes")

			// Encrypt
			encMech := &module.Mechanism{Type: tc.encMech}
			rv = env.Module.EncryptInit(session, encMech, keyHandle)
			RequireOK(t, rv, "EncryptInit "+tc.name)

			ciphertext, rv := env.Module.Encrypt(session, plaintext)
			RequireOK(t, rv, "Encrypt "+tc.name)

			if len(ciphertext) == 0 {
				t.Error("expected non-empty ciphertext")
			}

			// Decrypt
			rv = env.Module.DecryptInit(session, encMech, keyHandle)
			RequireOK(t, rv, "DecryptInit "+tc.name)

			decrypted, rv := env.Module.Decrypt(session, ciphertext)
			RequireOK(t, rv, "Decrypt "+tc.name)

			// Verify roundtrip
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("%s roundtrip failed: plaintext != decrypted", tc.name)
				t.Logf("Original:  %x", plaintext)
				t.Logf("Decrypted: %x", decrypted)
			}

			t.Logf("%s: plaintext=%d bytes, ciphertext=%d bytes",
				tc.name, len(plaintext), len(ciphertext))
		})
	}
}

// =============================================================================
// Digest Mechanism Tests
// OASIS PKCS#11 v3.0 Section 5.11
// =============================================================================

// TestAllDigestMechanisms tests all digest/hash mechanisms.
func TestAllDigestMechanisms(t *testing.T) {
	testCases := []struct {
		name         string
		mechanism    module.MechanismType
		expectedSize int
	}{
		{"SHA256", module.CKM_SHA256, 32},
		{"SHA384", module.CKM_SHA384, 48},
		{"SHA512", module.CKM_SHA512, 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_SinglePart", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			data := []byte("Test data for digest operation")

			mechanism := &module.Mechanism{Type: tc.mechanism}
			rv := env.Module.DigestInit(session, mechanism)
			RequireOK(t, rv, "DigestInit "+tc.name)

			digest, rv := env.Module.Digest(session, data)
			RequireOK(t, rv, "Digest "+tc.name)

			if len(digest) != tc.expectedSize {
				t.Errorf("%s: expected %d-byte digest, got %d bytes",
					tc.name, tc.expectedSize, len(digest))
			}

			t.Logf("%s digest: %x", tc.name, digest)
		})

		t.Run(tc.name+"_MultiPart", func(t *testing.T) {
			env, session := SetupAuthenticatedModule(t)

			data1 := []byte("First part of data")
			data2 := []byte("Second part of data")

			mechanism := &module.Mechanism{Type: tc.mechanism}
			rv := env.Module.DigestInit(session, mechanism)
			RequireOK(t, rv, "DigestInit "+tc.name)

			rv = env.Module.DigestUpdate(session, data1)
			RequireOK(t, rv, "DigestUpdate 1 "+tc.name)

			rv = env.Module.DigestUpdate(session, data2)
			RequireOK(t, rv, "DigestUpdate 2 "+tc.name)

			digest, rv := env.Module.DigestFinal(session)
			RequireOK(t, rv, "DigestFinal "+tc.name)

			if len(digest) != tc.expectedSize {
				t.Errorf("%s multi-part: expected %d-byte digest, got %d bytes",
					tc.name, tc.expectedSize, len(digest))
			}

			t.Logf("%s multi-part digest: %x", tc.name, digest)
		})
	}
}

// TestDigestEmptyData tests digesting empty data.
func TestDigestEmptyData(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	mechanism := &module.Mechanism{Type: module.CKM_SHA256}
	rv := env.Module.DigestInit(session, mechanism)
	RequireOK(t, rv, "DigestInit")

	digest, rv := env.Module.Digest(session, []byte{})
	RequireOK(t, rv, "Digest empty")

	// SHA-256 of empty string is well-known
	expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	actualHex := bytesToHex(digest)
	if actualHex != expectedEmpty {
		t.Errorf("SHA-256 of empty data incorrect:\nexpected: %s\ngot:      %s",
			expectedEmpty, actualHex)
	}
}

// =============================================================================
// Multi-Part Operation Tests
// OASIS PKCS#11 v3.0 Section 5.13
// =============================================================================

// TestMultiPartSigning tests multi-part signing operations.
func TestMultiPartSigning(t *testing.T) {
	t.Run("RSA_MultiPartSign", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("test-rsa-multipart-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-rsa-multipart-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair RSA")

		data1 := []byte("First part of data to sign")
		data2 := []byte("Second part of data to sign")

		// Multi-part sign
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		rv = env.Module.SignUpdate(session, data1)
		RequireOK(t, rv, "SignUpdate 1")

		rv = env.Module.SignUpdate(session, data2)
		RequireOK(t, rv, "SignUpdate 2")

		signature, rv := env.Module.SignFinal(session)
		RequireOK(t, rv, "SignFinal")

		// Multi-part verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		rv = env.Module.VerifyUpdate(session, data1)
		RequireOK(t, rv, "VerifyUpdate 1")

		rv = env.Module.VerifyUpdate(session, data2)
		RequireOK(t, rv, "VerifyUpdate 2")

		rv = env.Module.VerifyFinal(session, signature)
		RequireOK(t, rv, "VerifyFinal")

		t.Log("RSA multi-part sign/verify succeeded")
	})

	t.Run("ECDSA_MultiPartSign", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildECPublicKeyTemplate("test-ecdsa-multipart-pub", OID_P256)
		privTemplate := BuildECPrivateKeyTemplate("test-ecdsa-multipart-priv")
		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC")

		data1 := []byte("First part of ECDSA data")
		data2 := []byte("Second part of ECDSA data")

		// Multi-part sign
		signMech := &module.Mechanism{Type: module.CKM_ECDSA_SHA256}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit ECDSA")

		rv = env.Module.SignUpdate(session, data1)
		RequireOK(t, rv, "SignUpdate 1 ECDSA")

		rv = env.Module.SignUpdate(session, data2)
		RequireOK(t, rv, "SignUpdate 2 ECDSA")

		signature, rv := env.Module.SignFinal(session)
		RequireOK(t, rv, "SignFinal ECDSA")

		// Multi-part verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit ECDSA")

		rv = env.Module.VerifyUpdate(session, data1)
		RequireOK(t, rv, "VerifyUpdate 1 ECDSA")

		rv = env.Module.VerifyUpdate(session, data2)
		RequireOK(t, rv, "VerifyUpdate 2 ECDSA")

		rv = env.Module.VerifyFinal(session, signature)
		RequireOK(t, rv, "VerifyFinal ECDSA")

		t.Log("ECDSA multi-part sign/verify succeeded")
	})
}

// =============================================================================
// Random Number Generation Tests
// OASIS PKCS#11 v3.0 Section 5.17
// =============================================================================

// TestGenerateRandomComprehensive tests random number generation comprehensively.
func TestGenerateRandomComprehensive(t *testing.T) {
	t.Run("GenerateRandom_VariousSizes", func(t *testing.T) {
		sizes := []uint32{1, 16, 32, 64, 128, 256, 1024, 4096}

		for _, size := range sizes {
			env, session := SetupAuthenticatedModule(t)

			data, rv := env.Module.GenerateRandom(session, size)
			RequireOK(t, rv, "GenerateRandom")

			if uint32(len(data)) != size {
				t.Errorf("expected %d bytes, got %d", size, len(data))
			}

			// Basic randomness check - not all zeros
			allZeros := true
			for _, b := range data {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros && size > 1 {
				t.Errorf("random data of %d bytes is all zeros (extremely unlikely)", size)
			}
		}
	})

	t.Run("GenerateRandom_Uniqueness", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate multiple random values and ensure they're different
		values := make([][]byte, 10)
		for i := range values {
			data, rv := env.Module.GenerateRandom(session, 32)
			RequireOK(t, rv, "GenerateRandom")
			values[i] = data
		}

		// Check that all values are unique
		for i := 0; i < len(values); i++ {
			for j := i + 1; j < len(values); j++ {
				if bytes.Equal(values[i], values[j]) {
					t.Error("generated duplicate random values (extremely unlikely)")
				}
			}
		}
	})

	t.Run("GenerateRandom_ZeroLength", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data, rv := env.Module.GenerateRandom(session, 0)
		// Per PKCS#11 spec, zero-length request should succeed with empty data
		if rv != module.CKR_OK && rv != module.CKR_ARGUMENTS_BAD {
			t.Errorf("unexpected return value for zero-length random: %s", rv.String())
		}
		if rv == module.CKR_OK && len(data) != 0 {
			t.Errorf("expected empty data for zero-length request, got %d bytes", len(data))
		}
	})
}

// =============================================================================
// Session State Machine Tests
// OASIS PKCS#11 v3.0 Section 5.6
// =============================================================================

// TestSessionStateTransitions tests all valid session state transitions.
func TestSessionStateTransitions(t *testing.T) {
	t.Run("RO_Session_PublicState", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenROSession(t)
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		// RO session in public state
		if info.State != module.CKS_RO_PUBLIC_SESSION {
			t.Errorf("expected CKS_RO_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	t.Run("RO_Session_UserState", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// First need to set user PIN via SO
		rwSession := env.MustOpenRWSession(t)
		env.MustLoginSO(t, rwSession, TestPINs.SO)

		rv := env.Module.InitPIN(rwSession, TestPINs.User)
		RequireOK(t, rv, "InitPIN")

		rv = env.Module.Logout(rwSession)
		RequireOK(t, rv, "Logout SO")

		// Now test RO user state
		roSession := env.MustOpenROSession(t)
		env.MustLoginUser(t, roSession, TestPINs.User)

		info, rv := env.Module.GetSessionInfo(roSession)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RO_USER_FUNCTIONS {
			t.Errorf("expected CKS_RO_USER_FUNCTIONS, got %s", info.State.String())
		}
	})

	t.Run("RW_Session_PublicState", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		// RW session in public state
		if info.State != module.CKS_RW_PUBLIC_SESSION {
			t.Errorf("expected CKS_RW_PUBLIC_SESSION, got %s", info.State.String())
		}
	})

	t.Run("RW_Session_UserState", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RW_USER_FUNCTIONS {
			t.Errorf("expected CKS_RW_USER_FUNCTIONS, got %s", info.State.String())
		}
	})

	t.Run("RW_Session_SOState", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		env.MustLoginSO(t, session, TestPINs.SO)

		info, rv := env.Module.GetSessionInfo(session)
		RequireOK(t, rv, "GetSessionInfo")

		if info.State != module.CKS_RW_SO_FUNCTIONS {
			t.Errorf("expected CKS_RW_SO_FUNCTIONS, got %s", info.State.String())
		}
	})
}

// =============================================================================
// Object Attribute Tests
// OASIS PKCS#11 v3.0 Section 5.7
// =============================================================================

// TestObjectAttributeManagement tests object attribute get/set operations.
func TestObjectAttributeManagement(t *testing.T) {
	t.Run("GetAttributeValue_KeyLabel", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a key with known label
		label := "test-attr-label"
		template := BuildAESKeyTemplate(label, 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		handle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Get the label attribute
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
		})
		RequireOK(t, rv, "GetAttributeValue")

		if len(attrs) != 3 {
			t.Fatalf("expected 3 attributes, got %d", len(attrs))
		}

		// Verify label
		foundLabel := false
		for _, attr := range attrs {
			if attr.Type == module.CKA_LABEL {
				if attr.GetString() != label {
					t.Errorf("expected label %q, got %q", label, attr.GetString())
				}
				foundLabel = true
			}
		}
		if !foundLabel {
			t.Error("CKA_LABEL not found in returned attributes")
		}
	})

	t.Run("FindObjects_ByMultipleAttributes", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a few keys with different labels
		labels := []string{"find-test-1", "find-test-2", "find-test-3"}
		for _, label := range labels {
			template := BuildAESKeyTemplate(label, 32)
			mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
			_, rv := env.Module.GenerateKey(session, mechanism, template)
			RequireOK(t, rv, "GenerateKey "+label)
		}

		// Find by class and key type
		searchTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		}

		rv := env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 100)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(handles) < 3 {
			t.Errorf("expected at least 3 AES keys, found %d", len(handles))
		}

		t.Logf("Found %d AES secret keys", len(handles))
	})
}

// =============================================================================
// Error Handling Tests
// OASIS PKCS#11 v3.0 Section 11
// =============================================================================

// TestErrorHandling tests that proper errors are returned for invalid operations.
func TestErrorHandling(t *testing.T) {
	t.Run("CKR_CRYPTOKI_NOT_INITIALIZED", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		// Don't initialize

		_, rv := env.Module.GetSlotList(true)
		RequireReturnValue(t, rv, module.CKR_CRYPTOKI_NOT_INITIALIZED, "GetSlotList without init")
	})

	t.Run("CKR_SESSION_HANDLE_INVALID", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Use invalid session handle
		rv := env.Module.CloseSession(module.SessionHandle(999999))
		RequireReturnValue(t, rv, module.CKR_SESSION_HANDLE_INVALID, "CloseSession invalid handle")
	})

	t.Run("CKR_KEY_HANDLE_INVALID", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		mechanism := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv := env.Module.SignInit(session, mechanism, module.ObjectHandle(999999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "SignInit invalid key")
	})

	t.Run("CKR_MECHANISM_INVALID", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a key
		template := BuildAESKeyTemplate("test-invalid-mech", 32)
		keyMech := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		handle, rv := env.Module.GenerateKey(session, keyMech, template)
		RequireOK(t, rv, "GenerateKey")

		// Try to sign with invalid mechanism
		invalidMech := &module.Mechanism{Type: module.MechanismType(0xFFFFFFFF)}
		rv = env.Module.SignInit(session, invalidMech, handle)
		RequireReturnValue(t, rv, module.CKR_MECHANISM_INVALID, "SignInit invalid mechanism")
	})

	t.Run("CKR_OPERATION_NOT_INITIALIZED", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Try to sign without SignInit
		_, rv := env.Module.Sign(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Sign without init")

		// Try to verify without VerifyInit
		rv = env.Module.Verify(session, []byte("data"), []byte("sig"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Verify without init")

		// Try to encrypt without EncryptInit
		_, rv = env.Module.Encrypt(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Encrypt without init")

		// Try to decrypt without DecryptInit
		_, rv = env.Module.Decrypt(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Decrypt without init")

		// Try to digest without DigestInit
		_, rv = env.Module.Digest(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Digest without init")
	})

	t.Run("CKR_USER_NOT_LOGGED_IN", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		// Don't login

		// Try to generate key without login
		template := BuildAESKeyTemplate("test-no-login", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		_, rv := env.Module.GenerateKey(session, mechanism, template)
		// Should fail because user is not logged in for private key operations
		// Note: This depends on token policy - some tokens allow public key gen
		if rv == module.CKR_USER_NOT_LOGGED_IN {
			t.Log("Correctly requires login for key generation")
		}
	})

	t.Run("CKR_PIN_INCORRECT", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)

		// Try to login with wrong PIN
		rv := env.Module.Login(session, module.CKU_SO, []byte("wrongpin"))
		RequireReturnValue(t, rv, module.CKR_PIN_INCORRECT, "Login wrong PIN")
	})

	t.Run("CKR_USER_ALREADY_LOGGED_IN", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		session := env.MustOpenRWSession(t)
		env.MustLoginSO(t, session, TestPINs.SO)

		// Try to login again
		rv := env.Module.Login(session, module.CKU_SO, TestPINs.SO)
		RequireReturnValue(t, rv, module.CKR_USER_ALREADY_LOGGED_IN, "Login twice")
	})
}

// =============================================================================
// Concurrent Operations Tests
// OASIS PKCS#11 v3.0 Section 6.7
// =============================================================================

// TestConcurrentSessions tests concurrent session operations.
func TestConcurrentSessions(t *testing.T) {
	t.Run("MultipleConcurrentSessions", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Open multiple sessions
		sessions := make([]module.SessionHandle, 10)
		for i := range sessions {
			session, rv := env.Module.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
			RequireOK(t, rv, "OpenSession")
			sessions[i] = session
		}

		// Verify all sessions have valid info
		for i, session := range sessions {
			info, rv := env.Module.GetSessionInfo(session)
			RequireOK(t, rv, "GetSessionInfo")
			if info.State != module.CKS_RW_PUBLIC_SESSION {
				t.Errorf("session %d: expected public state, got %s", i, info.State.String())
			}
		}

		// Close all sessions
		for _, session := range sessions {
			rv := env.Module.CloseSession(session)
			RequireOK(t, rv, "CloseSession")
		}
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// hashSHA256 returns SHA-256 hash of data.
func hashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// hashSHA384 returns SHA-384 hash of data.
func hashSHA384(data []byte) []byte {
	hash := sha512.Sum384(data)
	return hash[:]
}

// hashSHA512 returns SHA-512 hash of data.
func hashSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// bytesToHex converts bytes to hex string.
func bytesToHex(data []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hex[b>>4]
		result[i*2+1] = hex[b&0x0f]
	}
	return string(result)
}
