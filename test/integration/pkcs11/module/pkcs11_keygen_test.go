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
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// uniqueLabel generates a unique label for tests to avoid conflicts with previous runs.
func uniqueLabel(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// TestGenerateRSAKeyPair tests RSA key pair generation via C_GenerateKeyPair.
func TestGenerateRSAKeyPair(t *testing.T) {
	t.Run("RSA2048", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("test-rsa-2048-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-rsa-2048-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair RSA-2048")

		if pubHandle == 0 || pubHandle == module.ObjectHandle(module.InvalidHandle) {
			t.Error("expected valid public key handle")
		}
		if privHandle == 0 || privHandle == module.ObjectHandle(module.InvalidHandle) {
			t.Error("expected valid private key handle")
		}

		t.Logf("Generated RSA-2048 key pair: pub=%d, priv=%d", pubHandle, privHandle)

		// Verify public key attributes
		pubAttrs, rv := env.Module.GetAttributeValue(session, pubHandle, []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue for public key")

		for _, attr := range pubAttrs {
			switch attr.Type {
			case module.CKA_CLASS:
				class, _ := attr.GetUint32()
				if module.ObjectClass(class) != module.CKO_PUBLIC_KEY {
					t.Errorf("expected CKO_PUBLIC_KEY, got %d", class)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_RSA {
					t.Errorf("expected CKK_RSA, got %d", keyType)
				}
			case module.CKA_LABEL:
				if attr.GetString() != "test-rsa-2048-pub" {
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
		RequireOK(t, rv, "GetAttributeValue for private key")

		for _, attr := range privAttrs {
			switch attr.Type {
			case module.CKA_CLASS:
				class, _ := attr.GetUint32()
				if module.ObjectClass(class) != module.CKO_PRIVATE_KEY {
					t.Errorf("expected CKO_PRIVATE_KEY, got %d", class)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_RSA {
					t.Errorf("expected CKK_RSA, got %d", keyType)
				}
			}
		}
	})

	t.Run("RSA4096", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildRSAPublicKeyTemplate("test-rsa-4096-pub", 4096)
		privTemplate := BuildRSAPrivateKeyTemplate("test-rsa-4096-priv")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair RSA-4096")

		t.Logf("Generated RSA-4096 key pair: pub=%d, priv=%d", pubHandle, privHandle)
	})

	t.Run("GenerateKeyPairWithoutRWSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Setup user PIN first
		rwSession := env.MustOpenRWSession(t)
		env.MustLoginSO(t, rwSession, TestPINs.SO)
		rv := env.Module.InitPIN(rwSession, TestPINs.User)
		RequireOK(t, rv, "InitPIN")
		rv = env.Module.Logout(rwSession)
		RequireOK(t, rv, "Logout SO")
		env.Module.CloseSession(rwSession)

		// Open RO session
		roSession := env.MustOpenROSession(t)
		env.MustLoginUser(t, roSession, TestPINs.User)

		pubTemplate := BuildRSAPublicKeyTemplate("test-rsa-ro", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-rsa-ro")

		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, _, rv = env.Module.GenerateKeyPair(roSession, mechanism, pubTemplate, privTemplate)
		RequireReturnValue(t, rv, module.CKR_SESSION_READ_ONLY, "GenerateKeyPair on RO session")
	})
}

// TestGenerateECKeyPair tests elliptic curve key pair generation.
func TestGenerateECKeyPair(t *testing.T) {
	t.Run("P256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildECPublicKeyTemplate("test-ec-p256-pub", OID_P256)
		privTemplate := BuildECPrivateKeyTemplate("test-ec-p256-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC P-256")

		t.Logf("Generated EC P-256 key pair: pub=%d, priv=%d", pubHandle, privHandle)

		// Verify key type is EC
		attrs, rv := env.Module.GetAttributeValue(session, pubHandle, []module.Attribute{
			{Type: module.CKA_KEY_TYPE},
		})
		RequireOK(t, rv, "GetAttributeValue for EC public key")

		for _, attr := range attrs {
			if attr.Type == module.CKA_KEY_TYPE {
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_EC {
					t.Errorf("expected CKK_EC, got %d", keyType)
				}
			}
		}
	})

	t.Run("P384", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildECPublicKeyTemplate("test-ec-p384-pub", OID_P384)
		privTemplate := BuildECPrivateKeyTemplate("test-ec-p384-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC P-384")

		t.Logf("Generated EC P-384 key pair: pub=%d, priv=%d", pubHandle, privHandle)
	})

	t.Run("P521", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		pubTemplate := BuildECPublicKeyTemplate("test-ec-p521-pub", OID_P521)
		privTemplate := BuildECPrivateKeyTemplate("test-ec-p521-priv")

		mechanism := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}

		pubHandle, privHandle, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair EC P-521")

		t.Logf("Generated EC P-521 key pair: pub=%d, priv=%d", pubHandle, privHandle)
	})
}

// TestGenerateAESKey tests AES symmetric key generation via C_GenerateKey.
func TestGenerateAESKey(t *testing.T) {
	t.Run("AES128", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := BuildAESKeyTemplate("test-aes-128", 16) // 16 bytes = 128 bits

		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		handle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey AES-128")

		if handle == 0 || handle == module.ObjectHandle(module.InvalidHandle) {
			t.Error("expected valid key handle")
		}

		t.Logf("Generated AES-128 key: %d", handle)

		// Verify key attributes
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_CLASS},
			{Type: module.CKA_KEY_TYPE},
			{Type: module.CKA_VALUE_LEN},
		})
		RequireOK(t, rv, "GetAttributeValue for AES key")

		for _, attr := range attrs {
			switch attr.Type {
			case module.CKA_CLASS:
				class, _ := attr.GetUint32()
				if module.ObjectClass(class) != module.CKO_SECRET_KEY {
					t.Errorf("expected CKO_SECRET_KEY, got %d", class)
				}
			case module.CKA_KEY_TYPE:
				keyType, _ := attr.GetUint32()
				if module.KeyType(keyType) != module.CKK_AES {
					t.Errorf("expected CKK_AES, got %d", keyType)
				}
			case module.CKA_VALUE_LEN:
				keyLen, _ := attr.GetUint32()
				if keyLen != 16 {
					t.Errorf("expected key length 16, got %d", keyLen)
				}
			}
		}
	})

	t.Run("AES256", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := BuildAESKeyTemplate("test-aes-256", 32) // 32 bytes = 256 bits

		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		handle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey AES-256")

		t.Logf("Generated AES-256 key: %d", handle)
	})

	t.Run("GenerateKeyWithoutRWSession", func(t *testing.T) {
		env := SetupTestEnvironment(t, nil)
		env.MustInitializeModule(t)
		env.MustInitializeToken(t, TestPINs.SO, TestLabels.Token)

		// Setup user PIN
		rwSession := env.MustOpenRWSession(t)
		env.MustLoginSO(t, rwSession, TestPINs.SO)
		rv := env.Module.InitPIN(rwSession, TestPINs.User)
		RequireOK(t, rv, "InitPIN")
		rv = env.Module.Logout(rwSession)
		RequireOK(t, rv, "Logout SO")
		env.Module.CloseSession(rwSession)

		// Open RO session
		roSession := env.MustOpenROSession(t)
		env.MustLoginUser(t, roSession, TestPINs.User)

		template := BuildAESKeyTemplate("test-aes-ro", 16)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		_, rv = env.Module.GenerateKey(roSession, mechanism, template)
		RequireReturnValue(t, rv, module.CKR_SESSION_READ_ONLY, "GenerateKey on RO session")
	})
}

// TestFindGeneratedKeys tests C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal.
func TestFindGeneratedKeys(t *testing.T) {
	t.Run("FindByLabel", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate a key with a unique label to avoid conflicts with previous test runs
		label := uniqueLabel("unique-test-key")
		template := BuildAESKeyTemplate(label, 16)
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}

		keyHandle, rv := env.Module.GenerateKey(session, mechanism, template)
		RequireOK(t, rv, "GenerateKey")

		// Find the key by label
		searchTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, label),
		}

		rv = env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 10)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(handles) != 1 {
			t.Errorf("expected 1 key, found %d", len(handles))
		}

		if len(handles) > 0 && handles[0] != keyHandle {
			t.Errorf("expected handle %d, got %d", keyHandle, handles[0])
		}
	})

	t.Run("FindByClass", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair
		pubTemplate := BuildRSAPublicKeyTemplate("test-find-class-pub", 2048)
		privTemplate := BuildRSAPrivateKeyTemplate("test-find-class-priv")
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		_, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Find all public keys
		searchTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		}

		rv = env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 100)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(handles) == 0 {
			t.Error("expected to find at least one public key")
		}

		t.Logf("Found %d public key(s)", len(handles))
	})

	t.Run("FindWithMultipleCriteria", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate RSA key pair with unique label to avoid conflicts
		label := uniqueLabel("multi-criteria-test")
		pubTemplate := BuildRSAPublicKeyTemplate(label, 2048)
		privTemplate := BuildRSAPrivateKeyTemplate(label)
		mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}

		pubHandle, _, rv := env.Module.GenerateKeyPair(session, mechanism, pubTemplate, privTemplate)
		RequireOK(t, rv, "GenerateKeyPair")

		// Find by class AND label
		searchTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewStringAttribute(module.CKA_LABEL, label),
		}

		rv = env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 10)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(handles) != 1 {
			t.Errorf("expected 1 key, found %d", len(handles))
		}

		if len(handles) > 0 && handles[0] != pubHandle {
			t.Errorf("expected handle %d, got %d", pubHandle, handles[0])
		}
	})

	t.Run("FindEmptyResult", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Search for non-existent key
		searchTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "non-existent-key-12345"),
		}

		rv := env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		handles, rv := env.Module.FindObjects(session, 10)
		RequireOK(t, rv, "FindObjects")

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(handles) != 0 {
			t.Errorf("expected 0 keys, found %d", len(handles))
		}
	})

	t.Run("FindObjectsWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Try to find without init
		_, rv := env.Module.FindObjects(session, 10)
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "FindObjects without init")
	})

	t.Run("DoubleFindObjectsInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := []module.Attribute{}

		rv := env.Module.FindObjectsInit(session, template)
		RequireOK(t, rv, "first FindObjectsInit")

		// Second init should fail
		rv = env.Module.FindObjectsInit(session, template)
		RequireReturnValue(t, rv, module.CKR_OPERATION_ACTIVE, "second FindObjectsInit")

		// Clean up
		env.Module.FindObjectsFinal(session)
	})

	t.Run("FindObjectsFinalWithoutInit", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.FindObjectsFinal(session)
		RequireReturnValue(t, rv, module.CKR_OPERATION_NOT_INITIALIZED, "FindObjectsFinal without init")
	})

	t.Run("PaginatedFindObjects", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate multiple keys with unique label to avoid conflicts
		label := uniqueLabel("paginated-test")
		mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
		for i := 0; i < 5; i++ {
			template := BuildAESKeyTemplate(label, 16)
			_, rv := env.Module.GenerateKey(session, mechanism, template)
			RequireOK(t, rv, "GenerateKey")
		}

		// Find all with pagination
		searchTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, label),
		}

		rv := env.Module.FindObjectsInit(session, searchTemplate)
		RequireOK(t, rv, "FindObjectsInit")

		// Get 2 at a time
		var allHandles []module.ObjectHandle
		for {
			handles, rv := env.Module.FindObjects(session, 2)
			RequireOK(t, rv, "FindObjects")
			if len(handles) == 0 {
				break
			}
			allHandles = append(allHandles, handles...)
		}

		rv = env.Module.FindObjectsFinal(session)
		RequireOK(t, rv, "FindObjectsFinal")

		if len(allHandles) != 5 {
			t.Errorf("expected 5 keys through pagination, found %d", len(allHandles))
		}
	})
}

// TestGenerateRandom tests C_GenerateRandom functionality.
func TestGenerateRandom(t *testing.T) {
	t.Run("GenerateRandomData", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate 32 bytes of random data
		randomData, rv := env.Module.GenerateRandom(session, 32)
		RequireOK(t, rv, "GenerateRandom")

		if len(randomData) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(randomData))
		}

		// Verify data is not all zeros (extremely unlikely for random data)
		allZeros := true
		for _, b := range randomData {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("random data appears to be all zeros")
		}

		t.Logf("Generated %d random bytes", len(randomData))
	})

	t.Run("GenerateRandomMultipleCalls", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Generate random data twice - should be different
		random1, rv := env.Module.GenerateRandom(session, 16)
		RequireOK(t, rv, "GenerateRandom 1")

		random2, rv := env.Module.GenerateRandom(session, 16)
		RequireOK(t, rv, "GenerateRandom 2")

		// While theoretically possible to be equal, it's astronomically unlikely
		equal := true
		for i := range random1 {
			if random1[i] != random2[i] {
				equal = false
				break
			}
		}
		if equal {
			t.Error("two random generations should not produce identical results")
		}
	})

	t.Run("GenerateRandomZeroLength", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		randomData, rv := env.Module.GenerateRandom(session, 0)
		RequireOK(t, rv, "GenerateRandom with 0 length")

		if len(randomData) != 0 {
			t.Errorf("expected 0 bytes, got %d", len(randomData))
		}
	})
}

// TestObjectManagement tests C_CreateObject, C_CopyObject, C_DestroyObject.
func TestObjectManagement(t *testing.T) {
	t.Run("CreateDataObject", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "test-data-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewAttribute(module.CKA_VALUE, []byte("test data content")),
		}

		handle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "CreateObject")

		if handle == 0 {
			t.Error("expected valid object handle")
		}

		// Verify object attributes
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
			{Type: module.CKA_VALUE},
		})
		RequireOK(t, rv, "GetAttributeValue")

		for _, attr := range attrs {
			switch attr.Type {
			case module.CKA_LABEL:
				if attr.GetString() != "test-data-object" {
					t.Errorf("unexpected label: %s", attr.GetString())
				}
			case module.CKA_VALUE:
				if string(attr.Value) != "test data content" {
					t.Errorf("unexpected value: %s", string(attr.Value))
				}
			}
		}
	})

	t.Run("CopyObject", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create original object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "original-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewBoolAttribute(module.CKA_COPYABLE, true),
			module.NewAttribute(module.CKA_VALUE, []byte("original content")),
		}

		origHandle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "CreateObject original")

		// Copy with modified label
		copyTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "copied-object"),
		}

		copyHandle, rv := env.Module.CopyObject(session, origHandle, copyTemplate)
		RequireOK(t, rv, "CopyObject")

		if copyHandle == origHandle {
			t.Error("copy should have different handle")
		}

		// Verify copy has new label
		attrs, rv := env.Module.GetAttributeValue(session, copyHandle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue for copy")

		for _, attr := range attrs {
			if attr.Type == module.CKA_LABEL {
				if attr.GetString() != "copied-object" {
					t.Errorf("copy should have new label, got: %s", attr.GetString())
				}
			}
		}
	})

	t.Run("DestroyObject", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "to-be-destroyed"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewAttribute(module.CKA_VALUE, []byte("temp content")),
		}

		handle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "CreateObject")

		// Destroy the object
		rv = env.Module.DestroyObject(session, handle)
		RequireOK(t, rv, "DestroyObject")

		// Verify object is destroyed
		_, rv = env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireReturnValue(t, rv, module.CKR_OBJECT_HANDLE_INVALID, "GetAttributeValue after destroy")
	})

	t.Run("DestroyInvalidHandle", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		rv := env.Module.DestroyObject(session, module.ObjectHandle(99999))
		RequireReturnValue(t, rv, module.CKR_OBJECT_HANDLE_INVALID, "DestroyObject invalid handle")
	})

	t.Run("SetAttributeValue", func(t *testing.T) {
		env, session := SetupAuthenticatedModule(t)

		// Create object
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "modifiable-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, true),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
			module.NewAttribute(module.CKA_VALUE, []byte("initial")),
		}

		handle, rv := env.Module.CreateObject(session, template)
		RequireOK(t, rv, "CreateObject")

		// Modify the label
		newAttrs := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "modified-label"),
		}

		rv = env.Module.SetAttributeValue(session, handle, newAttrs)
		RequireOK(t, rv, "SetAttributeValue")

		// Verify modification
		attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{
			{Type: module.CKA_LABEL},
		})
		RequireOK(t, rv, "GetAttributeValue after modify")

		for _, attr := range attrs {
			if attr.Type == module.CKA_LABEL {
				if attr.GetString() != "modified-label" {
					t.Errorf("expected modified-label, got: %s", attr.GetString())
				}
			}
		}
	})
}
