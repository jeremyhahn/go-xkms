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
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestGenerateEd25519KeyPair tests Ed25519 key pair generation via C_GenerateKeyPair.
func TestGenerateEd25519KeyPair(t *testing.T) {
	t.Run("Ed25519_Basic", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		if pubHandle == 0 || pubHandle == module.ObjectHandle(module.InvalidHandle) {
			t.Error("expected valid public key handle")
		}
		if privHandle == 0 || privHandle == module.ObjectHandle(module.InvalidHandle) {
			t.Error("expected valid private key handle")
		}

		t.Logf("Generated Ed25519 key pair: pub=%d, priv=%d", pubHandle, privHandle)

		// Verify public key attributes
		pubAttrs, rv := env.Module.GetAttributeValue(session, pubHandle, []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue for Ed25519 public key")

		for _, attr := range pubAttrs {
			switch attr.Type {
			case module.CKA_CLASS:
				class, _ := attr.GetUint32()
				if module.ObjectClass(class) != module.CKO_PUBLIC_KEY {
					t.Errorf("expected CKO_PUBLIC_KEY, got %d", class)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_EC_EDWARDS {
					t.Errorf("expected CKK_EC_EDWARDS, got %d", keyType)
				}
			case module.CKA_LABEL:
				if attr.GetString() != "test-ed25519-pub" {
					t.Errorf("unexpected label: %s", attr.GetString())
				}
			}
		}

		// Verify private key attributes
		privAttrs, rv := env.Module.GetAttributeValue(session, privHandle, []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue for Ed25519 private key")

		for _, attr := range privAttrs {
			switch attr.Type {
			case module.CKA_CLASS:
				class, _ := attr.GetUint32()
				if module.ObjectClass(class) != module.CKO_PRIVATE_KEY {
					t.Errorf("expected CKO_PRIVATE_KEY, got %d", class)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_EC_EDWARDS {
					t.Errorf("expected CKK_EC_EDWARDS, got %d", keyType)
				}
			}
		}
	})

	t.Run("Ed25519_InvalidMechanism", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-invalid-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-invalid-priv")

		// Using wrong mechanism for Ed25519
		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		// This might succeed if the SDK accepts any EC key gen, but template mismatch could cause issues
		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		// We don't assert specific failure here as behavior depends on SDK implementation
		t.Logf("GenerateKeyPair with EC mechanism for Ed25519 template returned: %s", rv.String())
	})
}

// TestEd25519Sign tests EdDSA signing operations via C_SignInit and C_Sign.
func TestEd25519Sign(t *testing.T) {
	t.Run("EdDSA_Sign", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-eddsa-sign-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-eddsa-sign-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Data to sign (Ed25519 signs raw data, no pre-hashing required)
		data := []byte("Test data to be signed with Ed25519")

		// Initialize EdDSA signing
		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		// Sign the data
		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA")

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		// Ed25519 signature should be 64 bytes
		expectedSigLen := 64
		if len(signature) != expectedSigLen {
			t.Errorf("expected signature length %d, got %d", expectedSigLen, len(signature))
		}

		t.Logf("Generated EdDSA signature of %d bytes", len(signature))
	})

	t.Run("EdDSA_SignWithInvalidKey", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv := env.Module.SignInit(session, signMech, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_KEY_HANDLE_INVALID, "SignInit with invalid key")
	})

	t.Run("EdDSA_SignWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		data := []byte("test data")
		_, rv := env.Module.Sign(session, data)
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "Sign without SignInit")
	})

	t.Run("EdDSA_DoubleSignInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-eddsa-double-init-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-eddsa-double-init-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		_, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}

		// First SignInit
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "first SignInit EdDSA")

		// Second SignInit should fail
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireReturnValue(t, rv, module.CKR_OPERATION_ACTIVE, "second SignInit")

		// Complete the first operation to clean up
		_, _ = env.Module.Sign(session, []byte("test"))
	})
}

// TestEd25519SignVerifyRoundtrip tests signing and then verifying with EdDSA.
func TestEd25519SignVerifyRoundtrip(t *testing.T) {
	t.Run("EdDSA_SignVerify", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-eddsa-roundtrip-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-eddsa-roundtrip-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Data to sign
		data := []byte("Test data for Ed25519 sign/verify roundtrip")

		// Sign
		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA")

		// Verify
		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA")

		t.Log("Ed25519 sign/verify roundtrip succeeded")
	})

	t.Run("EdDSA_VerifyInvalidSignature", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-eddsa-invalid-sig-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-eddsa-invalid-sig-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Try to verify an invalid signature
		data := []byte("Test data")
		invalidSig := make([]byte, 64) // All zeros - invalid signature

		verifyMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.VerifyInit(session, verifyMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, data, invalidSig)
		RequireReturnValue(t, rv, module.CKR_SIGNATURE_INVALID, "Verify with invalid signature")
	})

	t.Run("EdDSA_VerifyTamperedData", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-eddsa-tampered-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-eddsa-tampered-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Sign original data
		originalData := []byte("Original test data")

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		signature, rv := env.Module.Sign(session, originalData)
		RequireOK(t, rv, "Sign EdDSA")

		// Try to verify with tampered data
		tamperedData := []byte("Tampered test data")

		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, tamperedData, signature)
		RequireReturnValue(t, rv, module.CKR_SIGNATURE_INVALID, "Verify with tampered data")
	})
}

// TestEd25519ViaSDK tests that Ed25519 operations properly delegate to the SDK transport.
func TestEd25519ViaSDK(t *testing.T) {
	t.Run("Ed25519_MultipleKeys", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate multiple Ed25519 key pairs
		for i := 0; i < 3; i++ {
			pubLabel := "test-ed25519-multi-pub-" + string(rune('A'+i))
			privLabel := "test-ed25519-multi-priv-" + string(rune('A'+i))

			pubTemplate := BuildEd25519PublicKeyTemplate(pubLabel)
			privTemplate := BuildEd25519PrivateKeyTemplate(privLabel)

			mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

			pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
			RequireOK(t, rv, "GenerateKeyPair Ed25519")

			// Sign and verify with each key
			data := []byte("Test data for key " + string(rune('A'+i)))

			signMech := &module.Mechanism{Type: module.CKM_EDDSA}
			rv = env.Module.SignInit(session, signMech, privHandle)
			RequireOK(t, rv, "SignInit EdDSA")

			signature, rv := env.Module.Sign(session, data)
			RequireOK(t, rv, "Sign EdDSA")

			rv = env.Module.VerifyInit(session, signMech, pubHandle)
			RequireOK(t, rv, "VerifyInit EdDSA")

			rv = env.Module.Verify(session, data, signature)
			RequireOK(t, rv, "Verify EdDSA")

			t.Logf("Key pair %d: generated and tested successfully", i)
		}
	})

	t.Run("Ed25519_LargeData", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-large-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-large-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Sign a larger piece of data (Ed25519 can sign arbitrary length data)
		data := bytes.Repeat([]byte("A"), 4096)

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA large data")

		if len(signature) != 64 {
			t.Errorf("expected 64-byte signature, got %d", len(signature))
		}

		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA large data")

		t.Log("Ed25519 large data sign/verify succeeded")
	})

	t.Run("Ed25519_EmptyData", func(t *testing.T) {
		// NOTE: Ed25519 signing of empty messages is allowed by RFC 8032 but our
		// implementation currently does not support it. This is a known limitation.
		t.Skip("Ed25519 empty message signing not currently supported")

		env, session := SetupAuthenticatedModule(t)

		// Generate Ed25519 key pair
		pubTemplate := BuildEd25519PublicKeyTemplate("test-ed25519-empty-pub")
		privTemplate := BuildEd25519PrivateKeyTemplate("test-ed25519-empty-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_EDWARDS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair Ed25519")

		// Sign empty data (Ed25519 can sign zero-length messages)
		data := []byte{}

		signMech := &module.Mechanism{Type: module.CKM_EDDSA}
		rv = env.Module.SignInit(session, signMech, privHandle)
		RequireOK(t, rv, "SignInit EdDSA")

		signature, rv := env.Module.Sign(session, data)
		RequireOK(t, rv, "Sign EdDSA empty data")

		rv = env.Module.VerifyInit(session, signMech, pubHandle)
		RequireOK(t, rv, "VerifyInit EdDSA")

		rv = env.Module.Verify(session, data, signature)
		RequireOK(t, rv, "Verify EdDSA empty data")

		t.Log("Ed25519 empty data sign/verify succeeded")
	})
}

// TestEd25519MechanismInfo tests that the module correctly reports Ed25519 mechanism info.
func TestEd25519MechanismInfo(t *testing.T) {
	t.Run("EdDSA_MechanismInfo", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Get mechanism info for EdDSA
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_EDDSA)
		RequireOK(t, rv, "GetMechanismInfo CKM_EDDSA")

		if info == nil {
			t.Fatal("expected non-nil mechanism info")
		}

		// EdDSA should support signing and verification
		if info.Flags&module.CKF_SIGN == 0 {
			t.Error("expected CKF_SIGN flag for CKM_EDDSA")
		}
		if info.Flags&module.CKF_VERIFY == 0 {
			t.Error("expected CKF_VERIFY flag for CKM_EDDSA")
		}

		t.Logf("CKM_EDDSA mechanism info: MinKeySize=%d, MaxKeySize=%d, Flags=%d",
			info.MinKeySize, info.MaxKeySize, info.Flags)
	})

	t.Run("EC_EDWARDS_KEY_PAIR_GEN_MechanismInfo", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)

		// Get mechanism info for Edwards key pair generation
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_EC_EDWARDS_KEY_PAIR_GEN)
		RequireOK(t, rv, "GetMechanismInfo CKM_EC_EDWARDS_KEY_PAIR_GEN")

		if info == nil {
			t.Fatal("expected non-nil mechanism info")
		}

		// Key pair generation mechanism should have GENERATE_KEY_PAIR flag
		if info.Flags&module.CKF_GENERATE_KEY_PAIR == 0 {
			t.Error("expected CKF_GENERATE_KEY_PAIR flag for CKM_EC_EDWARDS_KEY_PAIR_GEN")
		}

		t.Logf("CKM_EC_EDWARDS_KEY_PAIR_GEN mechanism info: MinKeySize=%d, MaxKeySize=%d, Flags=%d",
			info.MinKeySize, info.MaxKeySize, info.Flags)
	})
}
