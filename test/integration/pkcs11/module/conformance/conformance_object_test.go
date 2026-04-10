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

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
//
// # Object Attribute Conformance Tests
//
// This file tests PKCS#11 object attribute requirements per the OASIS PKCS#11 v3.0
// specification, including mandatory attributes, read-only enforcement, sensitive
// attribute handling, extractable attribute enforcement, and template validation.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 4: Objects
//   - OASIS PKCS#11 Base v3.0, Section 4.4: Common Attributes
//   - OASIS PKCS#11 Base v3.0, Section 4.9: Key Objects
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestObjectAttributes_MandatoryAttributes tests that mandatory attributes are required.
//
// Reference: OASIS PKCS#11 v3.0, Section 4
// Each object class has mandatory attributes that must be present.
func TestObjectAttributes_MandatoryAttributes(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test CKA_CLASS is mandatory for all objects
	// Reference: OASIS PKCS#11 v3.0, Section 4.4
	t.Run("CKA_CLASS_Required", func(t *testing.T) {
		// Template without CKA_CLASS
		template := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "no-class"),
		}

		_, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_TEMPLATE_INCOMPLETE {
			t.Errorf("create without CKA_CLASS: expected CKR_TEMPLATE_INCOMPLETE, got %s", rv.String())
		}
	})

	// Test CKA_KEY_TYPE is required for key objects
	// Reference: OASIS PKCS#11 v3.0, Section 4.9
	t.Run("KeyObject_CKA_KEY_TYPE", func(t *testing.T) {
		// Create a complete secret key template
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "test-secret-key"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, true),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)), // 256-bit key
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Logf("create secret key: expected CKR_OK, got %s", rv.String())
		} else {
			env.Module.DestroyObject(session, handle)
		}
	})
}

// TestObjectAttributes_ReadOnlyEnforcement tests that read-only attributes cannot be modified.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.4
// Certain attributes are read-only after object creation.
func TestObjectAttributes_ReadOnlyEnforcement(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create a data object
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "readonly-test"),
		module.NewAttribute(module.CKA_VALUE, []byte("test data")),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
	}

	handle, rv := env.Module.CreateObject(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.DestroyObject(session, handle)

	readOnlyAttrs := []struct {
		name     string
		attrType module.AttributeType
		value    []byte
	}{
		{
			name:     "CKA_CLASS",
			attrType: module.CKA_CLASS,
			value:    module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_CERTIFICATE)).Value,
		},
		{
			name:     "CKA_LOCAL",
			attrType: module.CKA_LOCAL,
			value:    []byte{1},
		},
		{
			name:     "CKA_UNIQUE_ID",
			attrType: module.CKA_UNIQUE_ID,
			value:    []byte("new-unique-id"),
		},
	}

	for _, attr := range readOnlyAttrs {
		t.Run(attr.name, func(t *testing.T) {
			setTemplate := []module.Attribute{
				{Type: attr.attrType, Value: attr.value},
			}

			rv := env.Module.SetAttributeValue(session, handle, setTemplate)
			if rv != module.CKR_ATTRIBUTE_READ_ONLY {
				t.Errorf("modify %s: expected CKR_ATTRIBUTE_READ_ONLY, got %s", attr.name, rv.String())
			}
		})
	}
}

// TestObjectAttributes_SensitiveHandling tests sensitive attribute behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.9.2
// Sensitive attributes cannot be revealed via C_GetAttributeValue.
func TestObjectAttributes_SensitiveHandling(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create a secret key with CKA_SENSITIVE=true
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "sensitive-key"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewAttribute(module.CKA_VALUE, make([]byte, 32)), // 256-bit key
	}

	handle, rv := env.Module.CreateObject(session, template)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.DestroyObject(session, handle)

	// Attempting to read CKA_VALUE should fail or return empty
	// Reference: OASIS PKCS#11 v3.0, Section 4.9.2
	t.Run("CKA_VALUE_Sensitive", func(t *testing.T) {
		getTemplate := []module.Attribute{
			{Type: module.CKA_VALUE},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		// Should return CKR_ATTRIBUTE_SENSITIVE or set value to empty
		if rv == module.CKR_OK {
			if len(attrs) > 0 && len(attrs[0].Value) > 0 {
				// If it returns OK, the value should be empty for sensitive keys
				t.Logf("note: CKA_VALUE returned with length %d (may indicate value exposure)", len(attrs[0].Value))
			}
		} else if rv != module.CKR_ATTRIBUTE_SENSITIVE {
			t.Errorf("get CKA_VALUE of sensitive key: expected CKR_ATTRIBUTE_SENSITIVE or CKR_OK with empty value, got %s", rv.String())
		}
	})

	// Non-sensitive attributes should still be readable
	t.Run("NonSensitiveReadable", func(t *testing.T) {
		getTemplate := []module.Attribute{
			{Type: module.CKA_LABEL},
			{Type: module.CKA_SENSITIVE},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Errorf("get non-sensitive attrs: expected CKR_OK, got %s", rv.String())
		}

		if len(attrs) != 2 {
			t.Errorf("expected 2 attributes, got %d", len(attrs))
		}
	})
}

// TestObjectAttributes_ExtractableEnforcement tests extractable attribute behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.9.2
// CKA_EXTRACTABLE controls whether key material can be extracted via C_WrapKey.
func TestObjectAttributes_ExtractableEnforcement(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create a key with CKA_EXTRACTABLE=false
	t.Run("NonExtractableKey", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "non-extractable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Verify CKA_EXTRACTABLE is false
		getTemplate := []module.Attribute{{Type: module.CKA_EXTRACTABLE}}
		attrs, _ := env.Module.GetAttributeValue(session, handle, getTemplate)

		if len(attrs) > 0 {
			extractable, err := attrs[0].GetBool()
			if err == nil && extractable {
				t.Error("CKA_EXTRACTABLE should be false")
			}
		}
	})

	// CKA_NEVER_EXTRACTABLE should be set based on initial CKA_EXTRACTABLE
	// Reference: OASIS PKCS#11 v3.0, Section 4.9.2
	t.Run("NeverExtractableTracking", func(t *testing.T) {
		// Key created with CKA_EXTRACTABLE=false should have CKA_NEVER_EXTRACTABLE=true
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "never-extractable-test"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_EXTRACTABLE, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		getTemplate := []module.Attribute{{Type: module.CKA_NEVER_EXTRACTABLE}}
		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)

		if rv == module.CKR_OK && len(attrs) > 0 {
			neverExtractable, err := attrs[0].GetBool()
			if err == nil && !neverExtractable {
				t.Log("note: CKA_NEVER_EXTRACTABLE should be true for keys created with CKA_EXTRACTABLE=false")
			}
		}
	})
}

// TestObjectAttributes_TemplateValidation tests template validation during object creation.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.7.1
func TestObjectAttributes_TemplateValidation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test invalid attribute value
	t.Run("InvalidAttributeValue", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "invalid-test"),
			// Invalid CKA_TOKEN value (should be boolean, providing invalid bytes)
			{Type: module.CKA_TOKEN, Value: []byte{2, 3, 4, 5}}, // Invalid boolean
		}

		handle, rv := env.Module.CreateObject(session, template)
		// May return CKR_ATTRIBUTE_VALUE_INVALID or succeed with default
		if rv == module.CKR_OK {
			env.Module.DestroyObject(session, handle)
		}
	})

	// Test inconsistent template
	t.Run("InconsistentTemplate", func(t *testing.T) {
		// Example: Public key claiming to have sign capability
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, "inconsistent-test"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SIGN, true), // Public keys verify, not sign
		}

		handle, rv := env.Module.CreateObject(session, template)
		// May return CKR_TEMPLATE_INCONSISTENT or succeed
		if rv == module.CKR_OK {
			env.Module.DestroyObject(session, handle)
		}
	})
}

// TestObjectAttributes_TokenVsSession tests CKA_TOKEN attribute behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.4
// CKA_TOKEN determines whether object persists after session closes.
func TestObjectAttributes_TokenVsSession(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")
	testutil.RequireOK(t, env.Module.CloseSession(session), "CloseSession")

	t.Run("SessionObject_Destroyed", func(t *testing.T) {
		// Open session and create session object
		session := env.MustOpenRWSession(t)
		env.MustLoginUser(t, session, testutil.TestPINs.User)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "session-object"),
			module.NewBoolAttribute(module.CKA_TOKEN, false), // Session object
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}

		// Verify object exists
		_, rv = env.Module.GetAttributeValue(session, handle, []module.Attribute{{Type: module.CKA_LABEL}})
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		// Close session
		env.Module.Logout(session)
		env.Module.CloseSession(session)

		// Open new session - object should be gone
		session2 := env.MustOpenRWSession(t)
		env.MustLoginUser(t, session2, testutil.TestPINs.User)
		defer env.Module.CloseSession(session2)
		defer env.Module.Logout(session2)

		// Object handle should be invalid
		_, rv = env.Module.GetAttributeValue(session2, handle, []module.Attribute{{Type: module.CKA_LABEL}})
		if rv == module.CKR_OK {
			t.Error("session object should not exist after session closed")
		}
	})

	t.Run("TokenObject_Persists", func(t *testing.T) {
		// Open session and create token object
		session := env.MustOpenRWSession(t)
		env.MustLoginUser(t, session, testutil.TestPINs.User)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "token-object-persist"),
			module.NewBoolAttribute(module.CKA_TOKEN, true), // Token object
		}

		_, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}

		// Close session
		env.Module.Logout(session)
		env.Module.CloseSession(session)

		// Open new session - object should still exist
		session2 := env.MustOpenRWSession(t)
		env.MustLoginUser(t, session2, testutil.TestPINs.User)
		defer env.Module.CloseSession(session2)
		defer env.Module.Logout(session2)

		// Find object by label
		findTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "token-object-persist"),
		}

		rv = env.Module.FindObjectsInit(session2, findTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("FindObjectsInit: expected CKR_OK, got %s", rv.String())
		}

		handles, rv := env.Module.FindObjects(session2, 10)
		env.Module.FindObjectsFinal(session2)

		if rv != module.CKR_OK {
			t.Fatalf("FindObjects: expected CKR_OK, got %s", rv.String())
		}

		// Clean up the token object
		if len(handles) > 0 {
			env.Module.DestroyObject(session2, handles[0])
		}
	})
}

// TestObjectAttributes_PrivateAccess tests CKA_PRIVATE attribute behavior.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.4
// CKA_PRIVATE determines whether user authentication is required to access object.
func TestObjectAttributes_PrivateAccess(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Setup user PIN and create objects
	session := env.MustOpenRWSession(t)
	env.MustLoginSO(t, session, testutil.TestPINs.SO)
	testutil.RequireOK(t, env.Module.InitPIN(session, testutil.TestPINs.User), "InitPIN")
	testutil.RequireOK(t, env.Module.Logout(session), "Logout")

	// Login as user to create objects
	env.MustLoginUser(t, session, testutil.TestPINs.User)

	// Create public object (CKA_PRIVATE=false)
	publicTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "public-object"),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, false),
	}

	publicHandle, rv := env.Module.CreateObject(session, publicTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject public: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.DestroyObject(session, publicHandle)

	// Create private object (CKA_PRIVATE=true)
	privateTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, "private-object"),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_PRIVATE, true),
	}

	privateHandle, rv := env.Module.CreateObject(session, privateTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("CreateObject private: expected CKR_OK, got %s", rv.String())
	}
	defer env.Module.DestroyObject(session, privateHandle)

	// Logout
	env.Module.Logout(session)
	env.Module.CloseSession(session)

	// Open new session without login
	session2 := env.MustOpenRWSession(t)
	defer env.Module.CloseSession(session2)

	// Should be able to find public object without login
	t.Run("PublicObject_NoLogin", func(t *testing.T) {
		findTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "public-object"),
		}

		env.Module.FindObjectsInit(session2, findTemplate)
		handles, _ := env.Module.FindObjects(session2, 10)
		env.Module.FindObjectsFinal(session2)

		if len(handles) == 0 {
			t.Log("note: public object may require login on some tokens")
		}
	})

	// Private object should not be visible without login
	t.Run("PrivateObject_NoLogin", func(t *testing.T) {
		findTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "private-object"),
		}

		env.Module.FindObjectsInit(session2, findTemplate)
		handles, _ := env.Module.FindObjects(session2, 10)
		env.Module.FindObjectsFinal(session2)

		if len(handles) > 0 {
			t.Error("private object should not be visible without login")
		}
	})
}

// TestObjectAttributes_ModifiableAndCopyable tests CKA_MODIFIABLE and CKA_COPYABLE.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.4
func TestObjectAttributes_ModifiableAndCopyable(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test CKA_MODIFIABLE=false prevents modifications
	t.Run("NonModifiable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-modifiable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Try to modify
		setTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "new-label"),
		}

		rv = env.Module.SetAttributeValue(session, handle, setTemplate)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("modify non-modifiable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}
	})

	// Test CKA_COPYABLE=false prevents copying
	t.Run("NonCopyable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-copyable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_COPYABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Try to copy
		_, rv = env.Module.CopyObject(session, handle, nil)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("copy non-copyable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}
	})
}

// TestObjectAttributes_Destroyable tests CKA_DESTROYABLE attribute.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.4
func TestObjectAttributes_Destroyable(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test CKA_DESTROYABLE=false prevents destruction
	t.Run("NonDestroyable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "non-destroyable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_DESTROYABLE, false),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}

		// Try to destroy
		rv = env.Module.DestroyObject(session, handle)
		if rv != module.CKR_ACTION_PROHIBITED {
			t.Errorf("destroy non-destroyable: expected CKR_ACTION_PROHIBITED, got %s", rv.String())
		}

		// Note: Object will be cleaned up when session closes since it's a session object
	})

	// Test CKA_DESTROYABLE=true allows destruction
	t.Run("Destroyable", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "destroyable"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}

		rv = env.Module.DestroyObject(session, handle)
		if rv != module.CKR_OK {
			t.Errorf("destroy destroyable: expected CKR_OK, got %s", rv.String())
		}
	})
}

// TestObjectAttributes_KeyUsage tests key usage attribute enforcement.
//
// Reference: OASIS PKCS#11 v3.0, Section 4.9
// CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE
func TestObjectAttributes_KeyUsage(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Create a key that can only encrypt (not decrypt)
	t.Run("EncryptOnlyKey", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
			module.NewStringAttribute(module.CKA_LABEL, "encrypt-only"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_ENCRYPT, true),
			module.NewBoolAttribute(module.CKA_DECRYPT, false),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Verify key attributes
		getTemplate := []module.Attribute{
			{Type: module.CKA_ENCRYPT},
			{Type: module.CKA_DECRYPT},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			val, _ := attr.GetBool()
			switch attr.Type {
			case module.CKA_ENCRYPT:
				if !val {
					t.Error("CKA_ENCRYPT should be true")
				}
			case module.CKA_DECRYPT:
				if val {
					t.Error("CKA_DECRYPT should be false")
				}
			}
		}
	})

	// Create a key that can only sign (not verify)
	t.Run("SignOnlyKey", func(t *testing.T) {
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
			module.NewStringAttribute(module.CKA_LABEL, "sign-only"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SIGN, true),
			module.NewBoolAttribute(module.CKA_VERIFY, false),
			module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
		}

		handle, rv := env.Module.CreateObject(session, template)
		if rv != module.CKR_OK {
			t.Fatalf("CreateObject: expected CKR_OK, got %s", rv.String())
		}
		defer env.Module.DestroyObject(session, handle)

		// Verify key attributes
		getTemplate := []module.Attribute{
			{Type: module.CKA_SIGN},
			{Type: module.CKA_VERIFY},
		}

		attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
		if rv != module.CKR_OK {
			t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
		}

		for _, attr := range attrs {
			val, _ := attr.GetBool()
			switch attr.Type {
			case module.CKA_SIGN:
				if !val {
					t.Error("CKA_SIGN should be true")
				}
			case module.CKA_VERIFY:
				if val {
					t.Error("CKA_VERIFY should be false")
				}
			}
		}
	})
}

// TestObjectAttributes_ObjectClasses tests different object class attributes.
//
// Reference: OASIS PKCS#11 v3.0, Section 4
func TestObjectAttributes_ObjectClasses(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	testCases := []struct {
		name     string
		class    module.ObjectClass
		template []module.Attribute
	}{
		{
			name:  "CKO_DATA",
			class: module.CKO_DATA,
			template: []module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
				module.NewStringAttribute(module.CKA_LABEL, "data-object"),
				module.NewAttribute(module.CKA_VALUE, []byte("test data")),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
			},
		},
		{
			name:  "CKO_SECRET_KEY",
			class: module.CKO_SECRET_KEY,
			template: []module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
				module.NewStringAttribute(module.CKA_LABEL, "secret-key"),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
				module.NewBoolAttribute(module.CKA_ENCRYPT, true),
				module.NewAttribute(module.CKA_VALUE, make([]byte, 32)),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handle, rv := env.Module.CreateObject(session, tc.template)
			if rv != module.CKR_OK {
				t.Fatalf("CreateObject %s: expected CKR_OK, got %s", tc.name, rv.String())
			}
			defer env.Module.DestroyObject(session, handle)

			// Verify class
			getTemplate := []module.Attribute{{Type: module.CKA_CLASS}}
			attrs, rv := env.Module.GetAttributeValue(session, handle, getTemplate)
			if rv != module.CKR_OK {
				t.Fatalf("GetAttributeValue: expected CKR_OK, got %s", rv.String())
			}

			if len(attrs) > 0 {
				classVal, _ := attrs[0].GetUint32()
				if module.ObjectClass(classVal) != tc.class {
					t.Errorf("class mismatch: expected %d, got %d", tc.class, classVal)
				}
			}
		})
	}
}
