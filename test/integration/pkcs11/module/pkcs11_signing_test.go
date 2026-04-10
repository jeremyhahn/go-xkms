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

package module

import (
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestRSASign tests RSA PKCS#1 v1.5 signing via C_SignInit and C_Sign.
func TestRSASign(t *testing.T) {
	t.Run("RSA_PKCS_Sign", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-sign-rsa-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-sign-rsa-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Data to sign (pre-hashed for RSA PKCS#1 v1.5)
		data := []byte("Test data to be signed")
		hash := sha256.Sum256(data)

		// Initialize signing
		signMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		// Sign the hash
		signature, rv := env.Module.Sign(session, hash[:])
		RequireOK(t, rv, "Sign")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		// RSA-2048 signature should be 256 bytes
		expectedSigLen := 256
		if len(signature) != expectedSigLen {
			t.Errorf("expected signature length %d, got %d", expectedSigLen, len(signature))
		}

		t.Logf("Generated RSA signature of %d bytes", len(signature))
	})

	t.Run("RSA_SHA256_Sign", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-sign-sha256-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-sign-sha256-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Data to sign (mechanism handles hashing)
		data := []byte("Test data for SHA256 RSA signing")

		// Initialize signing with SHA256_RSA_PKCS
		signMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit SHA256_RSA_PKCS")

		// Sign the data
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		t.Logf("Generated SHA256-RSA signature of %d bytes", len(signature))
	})

	t.Run("SignWithInvalidKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		signMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv := env.Module.SignInit(session, signMech, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "SignInit with invalid key")
	})

	t.Run("SignWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data := []byte("test data")
		_, rv := env.Module.Sign(session, data)
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Sign without SignInit")
	})

	t.Run("DoubleSignInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-double-init-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-double-init-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		signMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// First SignInit
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "first SignInit")

		// Second SignInit should fail
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireReturnValue(t, rv, module.CKR_OPERATION_ACTIVE, "second SignInit")

		// Complete the first operation to clean up
		hash := sha256.Sum256([]byte("test"))
		_, _ = env.Module.Sign(session, hash[:])
	})
}

// TestRSAPSSSign tests RSA-PSS signing.
func TestRSAPSSSign(t *testing.T) {
	t.Run("RSA_PSS_SHA256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-pss-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-pss-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Data to sign
		data := []byte("Test data for RSA-PSS signing")

		// Initialize PSS signing
		pssMech := &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS_PSS}
		rv = env.Module.SignInit(session, pssMech, privHandle)
		RequireOK(t, rv, "SignInit RSA-PSS")

		// Sign
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign RSA-PSS")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		t.Logf("Generated RSA-PSS signature of %d bytes", len(signature))
	})
}

// TestECDSASign tests ECDSA signing.
func TestECDSASign(t *testing.T) {
	t.Run("ECDSA_P256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate EC P-256 key pair
		pubTemplate := BuildECPublicKeyTemplate("test-ecdsa-pub", OID_P256)
		privTemplate := BuildECPrivateKeyTemplate("test-ecdsa-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC")

		// Hash data (ECDSA signs hashes)
		data := []byte("Test data for ECDSA signing")
		hash := sha256.Sum256(data)

		// Initialize ECDSA signing
		ecdsaMech := &module.Mechanism{Type: module.CKM_ECDSA}
		rv = env.Module.SignInit(session, ecdsaMech, privHandle)
		RequireOK(t, rv, "SignInit ECDSA")

		// Sign
		signature, rv := env.Module.Sign(session, hash[:])
		RequireOK(t, rv, "Sign ECDSA")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		// P-256 ECDSA signature is ~64 bytes (two 32-byte integers)
		// But DER encoding can vary, so just check it's reasonable
		if len(signature) < 64 || len(signature) > 72 {
			t.Logf("ECDSA signature length: %d (expected ~64-72)", len(signature))
		}

		t.Logf("Generated ECDSA signature of %d bytes", len(signature))
	})

	t.Run("ECDSA_SHA256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate EC P-256 key pair
		pubTemplate := BuildECPublicKeyTemplate("test-ecdsa-sha256-pub", OID_P256)
		privTemplate := BuildECPrivateKeyTemplate("test-ecdsa-sha256-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC")

		// Data to sign (mechanism handles hashing)
		data := []byte("Test data for ECDSA SHA256 signing")

		// Initialize ECDSA_SHA256 signing
		ecdsaMech := &module.Mechanism{Type: module.CKM_ECDSA_SHA256}
		rv = env.Module.SignInit(session, ecdsaMech, privHandle)
		RequireOK(t, rv, "SignInit ECDSA_SHA256")

		// Sign
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign ECDSA_SHA256")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		t.Logf("Generated ECDSA-SHA256 signature of %d bytes", len(signature))
	})
}

// TestSignVerifyRoundtrip tests signing and then verifying.
func TestSignVerifyRoundtrip(t *testing.T) {
	t.Run("RSA_SignVerify", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-roundtrip-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-roundtrip-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Data to sign
		data := []byte("Test data for sign/verify roundtrip")
		hash := sha256.Sum256(data)

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit")

		signature, rv := env.Module.Sign(session, hash[:])
		RequireOK(t, rv, "Sign")

		// Verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		rv = env.Module.Verify(session, hash[:], signature)
		RequireOK(t, rv, "Verify")

		t.Log("RSA sign/verify roundtrip succeeded")
	})

	t.Run("RSA_VerifyInvalidSignature", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-invalid-sig-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-invalid-sig-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Try to verify an invalid signature
		data := []byte("Test data")
		hash := sha256.Sum256(data)
		invalidSig := make([]byte, 256) // All zeros - invalid signature

		verifyMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv = env.Module.VerifyInit(session, verifyMech, pubHandle)
		RequireOK(t, rv, "VerifyInit")

		rv = env.Module.Verify(session, hash[:], invalidSig)
		RequireReturnValue(t, rv, module.CKR_SIGNATURE_INVALID, "Verify invalid signature")
	})

	t.Run("ECDSA_SignVerify", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate EC P-256 key pair
		pubTemplate := BuildECPublicKeyTemplate("test-ecdsa-roundtrip-pub", OID_P256)
		privTemplate := BuildECPrivateKeyTemplate("test-ecdsa-roundtrip-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC")

		// Data to sign
		data := []byte("Test data for ECDSA sign/verify roundtrip")
		hash := sha256.Sum256(data)

		// Sign
		ecdsaMech := &module.Mechanism{Type: module.CKM_ECDSA}
		rv = env.Module.SignInit(session, ecdsaMech, privHandle)
		RequireOK(t, rv, "SignInit ECDSA")

		signature, rv := env.Module.Sign(session, hash[:])
		RequireOK(t, rv, "Sign ECDSA")

		// Verify
		rv = env.Module.VerifyInit(session, ecdsaMech, pubHandle)
		RequireOK(t, rv, "VerifyInit ECDSA")

		rv = env.Module.Verify(session, hash[:], signature)
		RequireOK(t, rv, "Verify ECDSA")

		t.Log("ECDSA sign/verify roundtrip succeeded")
	})

	t.Run("VerifyWithWrongKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate two RSA key pairs
		pubTemplate1 := BuildRSAPublicKeyTemplate("test-wrong-key-1-pub", 2048)
		privTemplate1 := BuildRSAPrivateKeyTemplate("test-wrong-key-1-priv")

		pubTemplate2 := BuildRSAPublicKeyTemplate("test-wrong-key-2-pub", 2048)
		privTemplate2 := BuildRSAPrivateKeyTemplate("test-wrong-key-2-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, privHandle1, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate1, privTemplate1)
		RequireOK(t, rv, "GenerateKeyPair 1")

		pubHandle2, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate2, privTemplate2)
		RequireOK(t, rv, "GenerateKeyPair 2")

		// Sign with key 1
		data := []byte("Test data")
		hash := sha256.Sum256(data)

		signMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv = env.Module.SignInit(session, signMech, privHandle1)
		RequireOK(t, rv, "SignInit")

		signature, rv := env.Module.Sign(session, hash[:])
		RequireOK(t, rv, "Sign")

		// Verify with key 2 - should fail
		rv = env.Module.VerifyInit(session, signMech, pubHandle2)
		RequireOK(t, rv, "VerifyInit")

		rv = env.Module.Verify(session, hash[:], signature)
		RequireReturnValue(t, rv, module.CKR_SIGNATURE_INVALID, "Verify with wrong key")
	})
}

// TestVerifyOperations tests C_VerifyInit and C_Verify.
func TestVerifyOperations(t *testing.T) {
	t.Run("VerifyWithInvalidKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		verifyMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}
		rv := env.Module.VerifyInit(session, verifyMech, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "VerifyInit invalid key")
	})

	t.Run("VerifyWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.Verify(session, []byte("data"), []byte("sig"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Verify without init")
	})

	t.Run("DoubleVerifyInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-double-verify-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-double-verify-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		verifyMech := &module.Mechanism{Type: module.CKM_RSA_PKCS}

		// First VerifyInit
		rv = env.Module.VerifyInit(session, verifyMech, pubHandle)
		RequireOK(t, rv, "first VerifyInit")

		// Second VerifyInit should fail
		rv = env.Module.VerifyInit(session, verifyMech, pubHandle)
		RequireReturnValue(t, rv, module.CKR_OPERATION_ACTIVE, "second VerifyInit")

		// Complete operation to clean up
		_ = env.Module.Verify(session, []byte("data"), make([]byte, 256))
	})
}

// TestDigestOperations tests C_DigestInit and C_Digest.
func TestDigestOperations(t *testing.T) {
	t.Run("SHA256_Digest", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data := []byte("Test data for SHA-256 digest")

		// Initialize digest
		digestMech := &module.Mechanism{Type: module.CKM_SHA256}
		rv := env.Module.DigestInit(session, digestMech)
		RequireOK(t, rv, "DigestInit SHA256")

		// Compute digest
		digest, rv := env.Module.Digest(session, data)
		RequireOK(t, rv, "Digest")

		// SHA-256 produces 32-byte digest
		if len(digest) != 32 {
			t.Errorf("expected 32-byte digest, got %d", len(digest))
		}

		// Verify against Go's crypto/sha256
		expected := sha256.Sum256(data)
		for i, b := range digest {
			if b != expected[i] {
				t.Errorf("digest mismatch at byte %d", i)
				break
			}
		}

		t.Logf("SHA-256 digest computed successfully")
	})

	t.Run("SHA384_Digest", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data := []byte("Test data for SHA-384 digest")

		digestMech := &module.Mechanism{Type: module.CKM_SHA384}
		rv := env.Module.DigestInit(session, digestMech)
		RequireOK(t, rv, "DigestInit SHA384")

		digest, rv := env.Module.Digest(session, data)
		RequireOK(t, rv, "Digest")

		// SHA-384 produces 48-byte digest
		if len(digest) != 48 {
			t.Errorf("expected 48-byte digest, got %d", len(digest))
		}

		t.Logf("SHA-384 digest computed successfully")
	})

	t.Run("SHA512_Digest", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data := []byte("Test data for SHA-512 digest")

		digestMech := &module.Mechanism{Type: module.CKM_SHA512}
		rv := env.Module.DigestInit(session, digestMech)
		RequireOK(t, rv, "DigestInit SHA512")

		digest, rv := env.Module.Digest(session, data)
		RequireOK(t, rv, "Digest")

		// SHA-512 produces 64-byte digest
		if len(digest) != 64 {
			t.Errorf("expected 64-byte digest, got %d", len(digest))
		}

		t.Logf("SHA-512 digest computed successfully")
	})

	t.Run("DigestWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		_, rv := env.Module.Digest(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Digest without init")
	})

	t.Run("DoubleDigestInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		digestMech := &module.Mechanism{Type: module.CKM_SHA256}

		rv := env.Module.DigestInit(session, digestMech)
		RequireOK(t, rv, "first DigestInit")

		rv = env.Module.DigestInit(session, digestMech)
		RequireReturnValue(t, rv, module.CKR_OPERATION_ACTIVE, "second DigestInit")

		// Clean up
		_, _ = env.Module.Digest(session, []byte("cleanup"))
	})
}

// TestEncryptDecryptOperations tests encryption and decryption.
func TestEncryptDecryptOperations(t *testing.T) {
	t.Run("AES_GCM_EncryptDecrypt", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate AES key
		keyTemplate := BuildAESKeyTemplate("test-aes-enc", 32)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		keyHandle, rv := env.Module.GenerateKey(session, mechanism, keyTemplate)
		RequireOK(t, rv, "GenerateKey AES")

		plaintext := []byte("Test plaintext for AES-GCM encryption")

		// Encrypt
		encMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv = env.Module.EncryptInit(session, encMech, keyHandle)
		RequireOK(t, rv, "EncryptInit")

		ciphertext, rv := env.Module.Encrypt(session, plaintext)
		RequireOK(t, rv, "Encrypt")

		if len(ciphertext) == 0 {
			t.Error("expected non-empty ciphertext")
		}

		// Ciphertext should be longer due to IV and auth tag
		if len(ciphertext) <= len(plaintext) {
			t.Logf("Warning: ciphertext length (%d) is not longer than plaintext (%d)",
				len(ciphertext), len(plaintext))
		}

		// Decrypt
		rv = env.Module.DecryptInit(session, encMech, keyHandle)
		RequireOK(t, rv, "DecryptInit")

		decrypted, rv := env.Module.Decrypt(session, ciphertext)
		RequireOK(t, rv, "Decrypt")

		// Verify decrypted matches original
		if string(decrypted) != string(plaintext) {
			t.Errorf("decrypted text does not match original")
			t.Logf("Original:  %s", string(plaintext))
			t.Logf("Decrypted: %s", string(decrypted))
		}

		t.Log("AES-GCM encrypt/decrypt roundtrip succeeded")
	})

	t.Run("EncryptWithInvalidKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		encMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := env.Module.EncryptInit(session, encMech, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "EncryptInit invalid key")
	})

	t.Run("EncryptWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		_, rv := env.Module.Encrypt(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Encrypt without init")
	})

	t.Run("DecryptWithInvalidKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		decMech := &module.Mechanism{Type: module.CKM_AES_GCM}
		rv := env.Module.DecryptInit(session, decMech, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "DecryptInit invalid key")
	})

	t.Run("DecryptWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		_, rv := env.Module.Decrypt(session, []byte("data"))
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Decrypt without init")
	})
}
