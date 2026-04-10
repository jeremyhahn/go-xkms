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

package module

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestObjectClass_String(t *testing.T) {
	tests := []struct {
		name     string
		class    ObjectClass
		expected string
	}{
		{"CKO_DATA", CKO_DATA, "CKO_DATA"},
		{"CKO_CERTIFICATE", CKO_CERTIFICATE, "CKO_CERTIFICATE"},
		{"CKO_PUBLIC_KEY", CKO_PUBLIC_KEY, "CKO_PUBLIC_KEY"},
		{"CKO_PRIVATE_KEY", CKO_PRIVATE_KEY, "CKO_PRIVATE_KEY"},
		{"CKO_SECRET_KEY", CKO_SECRET_KEY, "CKO_SECRET_KEY"},
		{"CKO_HW_FEATURE", CKO_HW_FEATURE, "CKO_HW_FEATURE"},
		{"CKO_DOMAIN_PARAMETERS", CKO_DOMAIN_PARAMETERS, "CKO_DOMAIN_PARAMETERS"},
		{"CKO_MECHANISM", CKO_MECHANISM, "CKO_MECHANISM"},
		{"CKO_OTP_KEY", CKO_OTP_KEY, "CKO_OTP_KEY"},
		{"CKO_PROFILE", CKO_PROFILE, "CKO_PROFILE"},
		{"CKO_VALIDATION", CKO_VALIDATION, "CKO_VALIDATION"},
		{"CKO_TRUST", CKO_TRUST, "CKO_TRUST"},
		{"CKO_VENDOR_DEFINED", CKO_VENDOR_DEFINED, "CKO_VENDOR_DEFINED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.class.String()
			if result != tt.expected {
				t.Errorf("ObjectClass.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestObjectClass_String_Unknown(t *testing.T) {
	unknownClass := ObjectClass(0x12345678)
	result := unknownClass.String()
	if result != "CKO_UNKNOWN(0x12345678)" {
		t.Errorf("unexpected unknown class string: %s", result)
	}
}

func TestObjectClass_String_VendorDefined(t *testing.T) {
	vendorClass := CKO_VENDOR_DEFINED + 0x100
	result := vendorClass.String()
	if result != "CKO_VENDOR_DEFINED+0x100" {
		t.Errorf("unexpected vendor defined class string: %s", result)
	}
}

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected string
	}{
		{"CKK_RSA", CKK_RSA, "CKK_RSA"},
		{"CKK_EC", CKK_EC, "CKK_EC"},
		{"CKK_AES", CKK_AES, "CKK_AES"},
		{"CKK_GENERIC_SECRET", CKK_GENERIC_SECRET, "CKK_GENERIC_SECRET"},
		{"CKK_EC_EDWARDS", CKK_EC_EDWARDS, "CKK_EC_EDWARDS"},
		{"CKK_DES3", CKK_DES3, "CKK_DES3"},
		{"CKK_ML_KEM", CKK_ML_KEM, "CKK_ML_KEM"},
		{"CKK_ML_DSA", CKK_ML_DSA, "CKK_ML_DSA"},
		{"CKK_SLH_DSA", CKK_SLH_DSA, "CKK_SLH_DSA"},
		{"CKK_HKDF", CKK_HKDF, "CKK_HKDF"},
		{"CKK_SHA3_256_HMAC", CKK_SHA3_256_HMAC, "CKK_SHA3_256_HMAC"},
		{"CKK_SHA3_384_HMAC", CKK_SHA3_384_HMAC, "CKK_SHA3_384_HMAC"},
		{"CKK_SHA3_512_HMAC", CKK_SHA3_512_HMAC, "CKK_SHA3_512_HMAC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.keyType.String()
			if result != tt.expected {
				t.Errorf("KeyType.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestKeyType_String_Unknown(t *testing.T) {
	unknownType := KeyType(0x7FFFFFFF)
	result := unknownType.String()
	if result != "CKK_UNKNOWN(0x7FFFFFFF)" {
		t.Errorf("unexpected unknown key type string: %s", result)
	}
}

func TestKeyType_String_VendorDefined(t *testing.T) {
	vendorType := CKK_VENDOR_DEFINED + 0x200
	result := vendorType.String()
	if result != "CKK_VENDOR_DEFINED+0x200" {
		t.Errorf("unexpected vendor defined key type string: %s", result)
	}
}

func TestAttributeType_String(t *testing.T) {
	tests := []struct {
		name     string
		attrType AttributeType
		expected string
	}{
		{"CKA_CLASS", CKA_CLASS, "CKA_CLASS"},
		{"CKA_TOKEN", CKA_TOKEN, "CKA_TOKEN"},
		{"CKA_PRIVATE", CKA_PRIVATE, "CKA_PRIVATE"},
		{"CKA_LABEL", CKA_LABEL, "CKA_LABEL"},
		{"CKA_ID", CKA_ID, "CKA_ID"},
		{"CKA_VALUE", CKA_VALUE, "CKA_VALUE"},
		{"CKA_KEY_TYPE", CKA_KEY_TYPE, "CKA_KEY_TYPE"},
		{"CKA_MODULUS", CKA_MODULUS, "CKA_MODULUS"},
		{"CKA_PUBLIC_EXPONENT", CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT"},
		{"CKA_EC_PARAMS", CKA_EC_PARAMS, "CKA_EC_PARAMS"},
		{"CKA_EC_POINT", CKA_EC_POINT, "CKA_EC_POINT"},
		{"CKA_ENCRYPT", CKA_ENCRYPT, "CKA_ENCRYPT"},
		{"CKA_DECRYPT", CKA_DECRYPT, "CKA_DECRYPT"},
		{"CKA_SIGN", CKA_SIGN, "CKA_SIGN"},
		{"CKA_VERIFY", CKA_VERIFY, "CKA_VERIFY"},
		{"CKA_WRAP", CKA_WRAP, "CKA_WRAP"},
		{"CKA_UNWRAP", CKA_UNWRAP, "CKA_UNWRAP"},
		{"CKA_EXTRACTABLE", CKA_EXTRACTABLE, "CKA_EXTRACTABLE"},
		{"CKA_SENSITIVE", CKA_SENSITIVE, "CKA_SENSITIVE"},
		{"CKA_ENCAPSULATE", CKA_ENCAPSULATE, "CKA_ENCAPSULATE"},
		{"CKA_DECAPSULATE", CKA_DECAPSULATE, "CKA_DECAPSULATE"},
		{"CKA_OBJECT_VALIDATION_FLAGS", CKA_OBJECT_VALIDATION_FLAGS, "CKA_OBJECT_VALIDATION_FLAGS"},
		{"CKA_VALIDATION_TYPE", CKA_VALIDATION_TYPE, "CKA_VALIDATION_TYPE"},
		{"CKA_VALIDATION_VERSION", CKA_VALIDATION_VERSION, "CKA_VALIDATION_VERSION"},
		{"CKA_VALIDATION_LEVEL", CKA_VALIDATION_LEVEL, "CKA_VALIDATION_LEVEL"},
		{"CKA_VALIDATION_MODULE_ID", CKA_VALIDATION_MODULE_ID, "CKA_VALIDATION_MODULE_ID"},
		{"CKA_VALIDATION_FLAG", CKA_VALIDATION_FLAG, "CKA_VALIDATION_FLAG"},
		{"CKA_VALIDATION_AUTHORITY_TYPE", CKA_VALIDATION_AUTHORITY_TYPE, "CKA_VALIDATION_AUTHORITY_TYPE"},
		{"CKA_VALIDATION_COUNTRY", CKA_VALIDATION_COUNTRY, "CKA_VALIDATION_COUNTRY"},
		{"CKA_VALIDATION_CERTIFICATE_IDENTIFIER", CKA_VALIDATION_CERTIFICATE_IDENTIFIER, "CKA_VALIDATION_CERTIFICATE_IDENTIFIER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrType.String()
			if result != tt.expected {
				t.Errorf("AttributeType.String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestAttributeType_String_Unknown(t *testing.T) {
	unknownType := AttributeType(0x7FFFFFFF)
	result := unknownType.String()
	if result != "CKA_UNKNOWN(0x7FFFFFFF)" {
		t.Errorf("unexpected unknown attribute type string: %s", result)
	}
}

func TestAttributeType_String_VendorDefined(t *testing.T) {
	vendorType := CKA_VENDOR_DEFINED + 0x300
	result := vendorType.String()
	if result != "CKA_VENDOR_DEFINED+0x300" {
		t.Errorf("unexpected vendor defined attribute type string: %s", result)
	}
}

func TestIsSensitiveAttribute(t *testing.T) {
	sensitiveTypes := []AttributeType{
		CKA_VALUE,
		CKA_PRIVATE_EXPONENT,
		CKA_PRIME_1,
		CKA_PRIME_2,
		CKA_EXPONENT_1,
		CKA_EXPONENT_2,
		CKA_COEFFICIENT,
	}

	for _, attr := range sensitiveTypes {
		if !IsSensitiveAttribute(attr) {
			t.Errorf("expected %s to be sensitive", attr.String())
		}
	}

	nonSensitiveTypes := []AttributeType{
		CKA_CLASS,
		CKA_LABEL,
		CKA_MODULUS,
		CKA_PUBLIC_EXPONENT,
	}

	for _, attr := range nonSensitiveTypes {
		if IsSensitiveAttribute(attr) {
			t.Errorf("expected %s to NOT be sensitive", attr.String())
		}
	}
}

func TestIsReadOnlyAttribute(t *testing.T) {
	readOnlyTypes := []AttributeType{
		CKA_CLASS,
		CKA_KEY_TYPE,
		CKA_LOCAL,
		CKA_NEVER_EXTRACTABLE,
		CKA_ALWAYS_SENSITIVE,
		CKA_KEY_GEN_MECHANISM,
		CKA_MODULUS,
		CKA_PUBLIC_EXPONENT,
		CKA_EC_PARAMS,
		CKA_EC_POINT,
		CKA_UNIQUE_ID,
	}

	for _, attr := range readOnlyTypes {
		if !IsReadOnlyAttribute(attr) {
			t.Errorf("expected %s to be read-only", attr.String())
		}
	}

	writableTypes := []AttributeType{
		CKA_LABEL,
		CKA_ID,
		CKA_ENCRYPT,
		CKA_DECRYPT,
	}

	for _, attr := range writableTypes {
		if IsReadOnlyAttribute(attr) {
			t.Errorf("expected %s to NOT be read-only", attr.String())
		}
	}
}

func TestNewAttribute(t *testing.T) {
	value := []byte{1, 2, 3, 4}
	attr := NewAttribute(CKA_VALUE, value)

	if attr.Type != CKA_VALUE {
		t.Errorf("expected type CKA_VALUE, got %v", attr.Type)
	}
	if !bytes.Equal(attr.Value, value) {
		t.Errorf("expected value %v, got %v", value, attr.Value)
	}

	// Verify copy (modifying original doesn't affect attribute)
	value[0] = 99
	if attr.Value[0] == 99 {
		t.Error("attribute value should be a copy")
	}
}

func TestNewAttribute_Nil(t *testing.T) {
	attr := NewAttribute(CKA_VALUE, nil)
	if attr.Value != nil {
		t.Errorf("expected nil value, got %v", attr.Value)
	}
}

func TestNewBoolAttribute(t *testing.T) {
	trueAttr := NewBoolAttribute(CKA_TOKEN, true)
	if len(trueAttr.Value) != 1 || trueAttr.Value[0] != 1 {
		t.Errorf("expected true attribute value [1], got %v", trueAttr.Value)
	}

	falseAttr := NewBoolAttribute(CKA_TOKEN, false)
	if len(falseAttr.Value) != 1 || falseAttr.Value[0] != 0 {
		t.Errorf("expected false attribute value [0], got %v", falseAttr.Value)
	}
}

func TestNewUint32Attribute(t *testing.T) {
	attr := NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY))

	if attr.Type != CKA_CLASS {
		t.Errorf("expected type CKA_CLASS, got %v", attr.Type)
	}

	val, err := attr.GetUint32()
	if err != nil {
		t.Fatalf("GetUint32 failed: %v", err)
	}
	if val != uint32(CKO_SECRET_KEY) {
		t.Errorf("expected %d, got %d", CKO_SECRET_KEY, val)
	}
}

func TestNewUint64Attribute(t *testing.T) {
	attr := NewUint64Attribute(CKA_VALUE_LEN, 0xDEADBEEFCAFEBABE)

	val, err := attr.GetUint64()
	if err != nil {
		t.Fatalf("GetUint64 failed: %v", err)
	}
	if val != 0xDEADBEEFCAFEBABE {
		t.Errorf("expected 0xDEADBEEFCAFEBABE, got 0x%X", val)
	}
}

func TestNewStringAttribute(t *testing.T) {
	attr := NewStringAttribute(CKA_LABEL, "my-key")

	if attr.Type != CKA_LABEL {
		t.Errorf("expected type CKA_LABEL, got %v", attr.Type)
	}
	if attr.GetString() != "my-key" {
		t.Errorf("expected 'my-key', got %s", attr.GetString())
	}
}

func TestAttribute_GetBool(t *testing.T) {
	t.Run("true value", func(t *testing.T) {
		attr := Attribute{Type: CKA_TOKEN, Value: []byte{1}}
		val, err := attr.GetBool()
		if err != nil {
			t.Fatalf("GetBool failed: %v", err)
		}
		if !val {
			t.Error("expected true")
		}
	})

	t.Run("false value", func(t *testing.T) {
		attr := Attribute{Type: CKA_TOKEN, Value: []byte{0}}
		val, err := attr.GetBool()
		if err != nil {
			t.Fatalf("GetBool failed: %v", err)
		}
		if val {
			t.Error("expected false")
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		attr := Attribute{Type: CKA_TOKEN, Value: []byte{1, 2}}
		_, err := attr.GetBool()
		if err == nil {
			t.Error("expected error for invalid length")
		}
		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_VALUE_INVALID {
			t.Errorf("expected CKR_ATTRIBUTE_VALUE_INVALID, got %v", err)
		}
	})
}

func TestAttribute_GetUint32_Error(t *testing.T) {
	attr := Attribute{Type: CKA_CLASS, Value: []byte{1, 2}} // Too short
	_, err := attr.GetUint32()
	if err == nil {
		t.Error("expected error for short value")
	}
}

func TestAttribute_GetUint64_Error(t *testing.T) {
	attr := Attribute{Type: CKA_VALUE_LEN, Value: []byte{1, 2, 3, 4}} // Too short
	_, err := attr.GetUint64()
	if err == nil {
		t.Error("expected error for short value")
	}
}

func TestNewObject(t *testing.T) {
	obj := NewObject(CKO_DATA)

	if obj.Class != CKO_DATA {
		t.Errorf("expected class CKO_DATA, got %v", obj.Class)
	}
	if obj.Attributes == nil {
		t.Error("expected non-nil attributes map")
	}
	if !obj.IsModifiable {
		t.Error("expected IsModifiable to be true by default")
	}
	if !obj.IsCopyable {
		t.Error("expected IsCopyable to be true by default")
	}
	if !obj.IsDestroyable {
		t.Error("expected IsDestroyable to be true by default")
	}
}

func TestNewKeyObject(t *testing.T) {
	obj := NewKeyObject(CKO_SECRET_KEY, CKK_AES)

	if obj.Class != CKO_SECRET_KEY {
		t.Errorf("expected class CKO_SECRET_KEY, got %v", obj.Class)
	}
	if obj.KeyType != CKK_AES {
		t.Errorf("expected key type CKK_AES, got %v", obj.KeyType)
	}

	// Verify CKA_KEY_TYPE attribute is set
	if !obj.HasAttribute(CKA_KEY_TYPE) {
		t.Error("expected CKA_KEY_TYPE attribute to be set")
	}
}

func TestObject_SetAttribute(t *testing.T) {
	obj := NewObject(CKO_DATA)

	// Set label
	obj.SetAttribute(CKA_LABEL, []byte("test-label"))
	if obj.GetLabel() != "test-label" {
		t.Errorf("expected label 'test-label', got %s", obj.GetLabel())
	}

	// Set token attribute (updates IsToken)
	obj.SetAttribute(CKA_TOKEN, []byte{1})
	if !obj.IsToken {
		t.Error("expected IsToken to be true")
	}

	// Set private attribute (updates IsPrivate)
	obj.SetAttribute(CKA_PRIVATE, []byte{1})
	if !obj.IsPrivate {
		t.Error("expected IsPrivate to be true")
	}

	// Set sensitive attribute (updates IsSensitive)
	obj.SetAttribute(CKA_SENSITIVE, []byte{1})
	if !obj.IsSensitive {
		t.Error("expected IsSensitive to be true")
	}

	// Set extractable attribute (updates IsExtractable)
	obj.SetAttribute(CKA_EXTRACTABLE, []byte{1})
	if !obj.IsExtractable {
		t.Error("expected IsExtractable to be true")
	}
}

func TestObject_SetAttribute_Class(t *testing.T) {
	obj := NewObject(CKO_DATA)
	obj.SetAttribute(CKA_CLASS, NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)).Value)

	if obj.Class != CKO_SECRET_KEY {
		t.Errorf("expected class CKO_SECRET_KEY, got %v", obj.Class)
	}
}

func TestObject_SetAttribute_KeyType(t *testing.T) {
	obj := NewObject(CKO_SECRET_KEY)
	obj.SetAttribute(CKA_KEY_TYPE, NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)).Value)

	if obj.KeyType != CKK_AES {
		t.Errorf("expected key type CKK_AES, got %v", obj.KeyType)
	}
}

func TestObject_GetAttribute(t *testing.T) {
	obj := NewObject(CKO_DATA)
	obj.SetAttribute(CKA_LABEL, []byte("test"))

	value := obj.GetAttribute(CKA_LABEL)
	if !bytes.Equal(value, []byte("test")) {
		t.Errorf("expected 'test', got %s", value)
	}

	// Non-existent attribute
	value = obj.GetAttribute(CKA_ID)
	if value != nil {
		t.Errorf("expected nil for non-existent attribute, got %v", value)
	}
}

func TestObject_HasAttribute(t *testing.T) {
	obj := NewObject(CKO_DATA)
	obj.SetAttribute(CKA_LABEL, []byte("test"))

	if !obj.HasAttribute(CKA_LABEL) {
		t.Error("expected HasAttribute to return true for CKA_LABEL")
	}
	if obj.HasAttribute(CKA_ID) {
		t.Error("expected HasAttribute to return false for CKA_ID")
	}
}

func TestObject_GetID(t *testing.T) {
	obj := NewObject(CKO_DATA)
	id := []byte{0x01, 0x02, 0x03}
	obj.SetAttribute(CKA_ID, id)

	if !bytes.Equal(obj.GetID(), id) {
		t.Errorf("expected ID %v, got %v", id, obj.GetID())
	}
}

func TestObject_MatchesTemplate(t *testing.T) {
	obj := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
	obj.SetAttribute(CKA_LABEL, []byte("aes-key"))
	obj.SetAttribute(CKA_ID, []byte{1})

	// Matching template
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "aes-key"),
	}
	if !obj.MatchesTemplate(template) {
		t.Error("expected object to match template")
	}

	// Non-matching template (wrong label)
	template = []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewStringAttribute(CKA_LABEL, "rsa-key"),
	}
	if obj.MatchesTemplate(template) {
		t.Error("expected object to NOT match template")
	}

	// Non-matching template (missing attribute)
	template = []Attribute{
		NewAttribute(CKA_VALUE, []byte{1, 2, 3}),
	}
	if obj.MatchesTemplate(template) {
		t.Error("expected object to NOT match template (missing attribute)")
	}

	// Empty template matches everything
	template = []Attribute{}
	if !obj.MatchesTemplate(template) {
		t.Error("expected object to match empty template")
	}
}

func TestObject_Clone(t *testing.T) {
	obj := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
	obj.Handle = 1
	obj.SetAttribute(CKA_LABEL, []byte("original"))
	obj.SetAttribute(CKA_ID, []byte{1, 2, 3})
	obj.KeyID = "backend-key-1"
	obj.BackendName = "softhsm"
	obj.IsToken = true
	obj.IsSensitive = true

	clone := obj.Clone()

	// Verify clone has new handle (0)
	if clone.Handle != 0 {
		t.Errorf("expected clone handle 0, got %d", clone.Handle)
	}

	// Verify attributes are copied
	if clone.Class != obj.Class {
		t.Error("class not copied")
	}
	if clone.KeyType != obj.KeyType {
		t.Error("key type not copied")
	}
	if clone.KeyID != obj.KeyID {
		t.Error("key ID not copied")
	}
	if clone.BackendName != obj.BackendName {
		t.Error("backend name not copied")
	}
	if clone.IsToken != obj.IsToken {
		t.Error("IsToken not copied")
	}
	if clone.IsSensitive != obj.IsSensitive {
		t.Error("IsSensitive not copied")
	}

	// Verify attributes are independent
	clone.SetAttribute(CKA_LABEL, []byte("cloned"))
	if obj.GetLabel() == "cloned" {
		t.Error("modifying clone should not affect original")
	}
}

func TestNewObjectManager(t *testing.T) {
	om := NewObjectManager()

	if om == nil {
		t.Fatal("NewObjectManager returned nil")
	}
	if om.objects == nil {
		t.Error("objects table not initialized")
	}
	if om.sessionObjects == nil {
		t.Error("sessionObjects map not initialized")
	}
	if om.findState == nil {
		t.Error("findState map not initialized")
	}
	if om.Size() != 0 {
		t.Errorf("expected size 0, got %d", om.Size())
	}
}

func TestObjectManager_CreateObject_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "test-data"),
		NewAttribute(CKA_VALUE, []byte{1, 2, 3}),
	}

	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}
	if handle == ObjectHandle(InvalidHandle) {
		t.Error("CreateObject returned invalid handle")
	}

	// Verify object was created
	obj, err := om.GetObject(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.Class != CKO_DATA {
		t.Errorf("expected class CKO_DATA, got %v", obj.Class)
	}
	if obj.GetLabel() != "test-data" {
		t.Errorf("expected label 'test-data', got %s", obj.GetLabel())
	}
}

func TestObjectManager_CreateObject_KeyObject(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "aes-key"),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
	}

	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	obj, err := om.GetObject(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.KeyType != CKK_AES {
		t.Errorf("expected key type CKK_AES, got %v", obj.KeyType)
	}
}

func TestObjectManager_CreateObject_MissingClass(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewStringAttribute(CKA_LABEL, "no-class"),
	}

	_, err := om.CreateObject(session, template)
	if err == nil {
		t.Error("expected error for missing CKA_CLASS")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_TEMPLATE_INCOMPLETE {
		t.Errorf("expected CKR_TEMPLATE_INCOMPLETE, got %v", err)
	}
}

func TestObjectManager_CreateObject_InvalidClassValue(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		{Type: CKA_CLASS, Value: []byte{1}}, // Too short
	}

	_, err := om.CreateObject(session, template)
	if err == nil {
		t.Error("expected error for invalid CKA_CLASS value")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_VALUE_INVALID {
		t.Errorf("expected CKR_ATTRIBUTE_VALUE_INVALID, got %v", err)
	}
}

func TestObjectManager_CreateObject_SessionObject(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create session object (CKA_TOKEN = false by default)
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	_, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	if om.SessionObjectCount() != 1 {
		t.Errorf("expected 1 session object, got %d", om.SessionObjectCount())
	}
}

func TestObjectManager_CreateObject_TokenObject(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
	}

	_, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Token objects should not be tracked as session objects
	if om.SessionObjectCount() != 0 {
		t.Errorf("expected 0 session objects, got %d", om.SessionObjectCount())
	}
}

func TestObjectManager_CopyObject_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create original object
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "original"),
	}
	origHandle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Copy with modifications
	copyTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "copied"),
	}
	copyHandle, err := om.CopyObject(session, origHandle, copyTemplate)
	if err != nil {
		t.Fatalf("CopyObject failed: %v", err)
	}

	// Verify copy
	copyObj, err := om.GetObject(copyHandle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if copyObj.GetLabel() != "copied" {
		t.Errorf("expected label 'copied', got %s", copyObj.GetLabel())
	}

	// Verify original unchanged
	origObj, err := om.GetObject(origHandle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if origObj.GetLabel() != "original" {
		t.Errorf("expected original label 'original', got %s", origObj.GetLabel())
	}
}

func TestObjectManager_CopyObject_InvalidHandle(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	_, err := om.CopyObject(session, ObjectHandle(999), nil)
	if err == nil {
		t.Error("expected error for invalid handle")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID, got %v", err)
	}
}

func TestObjectManager_CopyObject_NotCopyable(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_COPYABLE, false),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	_, err = om.CopyObject(session, handle, nil)
	if err == nil {
		t.Error("expected error for non-copyable object")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ACTION_PROHIBITED {
		t.Errorf("expected CKR_ACTION_PROHIBITED, got %v", err)
	}
}

func TestObjectManager_CopyObject_ReadOnlyAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to modify read-only attribute
	copyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
	}
	_, err = om.CopyObject(session, handle, copyTemplate)
	if err == nil {
		t.Error("expected error for modifying read-only attribute")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY, got %v", err)
	}
}

func TestObjectManager_DestroyObject_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	if om.Size() != 1 {
		t.Errorf("expected size 1, got %d", om.Size())
	}

	err = om.DestroyObject(session, handle)
	if err != nil {
		t.Fatalf("DestroyObject failed: %v", err)
	}

	if om.Size() != 0 {
		t.Errorf("expected size 0 after destroy, got %d", om.Size())
	}

	// Verify object is gone
	_, err = om.GetObject(handle)
	if err == nil {
		t.Error("expected error for destroyed object")
	}
}

func TestObjectManager_DestroyObject_InvalidHandle(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	err := om.DestroyObject(session, ObjectHandle(999))
	if err == nil {
		t.Error("expected error for invalid handle")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID, got %v", err)
	}
}

func TestObjectManager_DestroyObject_NotDestroyable(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_DESTROYABLE, false),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	err = om.DestroyObject(session, handle)
	if err == nil {
		t.Error("expected error for non-destroyable object")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ACTION_PROHIBITED {
		t.Errorf("expected CKR_ACTION_PROHIBITED, got %v", err)
	}
}

func TestObjectManager_GetAttributeValue_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "test"),
		NewAttribute(CKA_ID, []byte{1, 2, 3}),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Get attributes
	queryTemplate := []Attribute{
		{Type: CKA_LABEL},
		{Type: CKA_ID},
	}
	result, err := om.GetAttributeValue(session, handle, queryTemplate)
	if err != nil {
		t.Fatalf("GetAttributeValue failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
	if string(result[0].Value) != "test" {
		t.Errorf("expected label 'test', got %s", result[0].Value)
	}
	if !bytes.Equal(result[1].Value, []byte{1, 2, 3}) {
		t.Errorf("expected ID [1,2,3], got %v", result[1].Value)
	}
}

func TestObjectManager_GetAttributeValue_InvalidHandle(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	_, err := om.GetAttributeValue(session, ObjectHandle(999), nil)
	if err == nil {
		t.Error("expected error for invalid handle")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID, got %v", err)
	}
}

func TestObjectManager_GetAttributeValue_SensitiveAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_VALUE, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to get sensitive attribute
	queryTemplate := []Attribute{{Type: CKA_VALUE}}
	result, err := om.GetAttributeValue(session, handle, queryTemplate)

	// Should return CKR_ATTRIBUTE_SENSITIVE
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_SENSITIVE {
		t.Errorf("expected CKR_ATTRIBUTE_SENSITIVE, got %v", err)
	}

	// Result should have nil value
	if len(result) != 1 || result[0].Value != nil {
		t.Error("expected nil value for sensitive attribute")
	}
}

func TestObjectManager_GetAttributeValue_InvalidAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to get non-existent attribute
	queryTemplate := []Attribute{{Type: CKA_MODULUS}}
	result, err := om.GetAttributeValue(session, handle, queryTemplate)

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_TYPE_INVALID {
		t.Errorf("expected CKR_ATTRIBUTE_TYPE_INVALID, got %v", err)
	}

	if len(result) != 1 || result[0].Value != nil {
		t.Error("expected nil value for invalid attribute")
	}
}

func TestObjectManager_SetAttributeValue_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "original"),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Modify attribute
	modTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "modified"),
	}
	err = om.SetAttributeValue(session, handle, modTemplate)
	if err != nil {
		t.Fatalf("SetAttributeValue failed: %v", err)
	}

	// Verify modification
	obj, err := om.GetObject(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.GetLabel() != "modified" {
		t.Errorf("expected label 'modified', got %s", obj.GetLabel())
	}
}

func TestObjectManager_SetAttributeValue_InvalidHandle(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	err := om.SetAttributeValue(session, ObjectHandle(999), nil)
	if err == nil {
		t.Error("expected error for invalid handle")
	}
}

func TestObjectManager_SetAttributeValue_NotModifiable(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_MODIFIABLE, false),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	modTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "new-label"),
	}
	err = om.SetAttributeValue(session, handle, modTemplate)
	if err == nil {
		t.Error("expected error for non-modifiable object")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ACTION_PROHIBITED {
		t.Errorf("expected CKR_ACTION_PROHIBITED, got %v", err)
	}
}

func TestObjectManager_SetAttributeValue_ReadOnlyAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	handle, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to modify read-only attribute
	modTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
	}
	err = om.SetAttributeValue(session, handle, modTemplate)
	if err == nil {
		t.Error("expected error for read-only attribute")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY, got %v", err)
	}
}

func TestObjectManager_FindObjects_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create multiple objects
	for i := 0; i < 5; i++ {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "test-object"),
		}
		_, err := om.CreateObject(session, template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Create one object with different class
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
	}
	_, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Search for data objects
	searchTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	err = om.FindObjectsInit(session, searchTemplate)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	// Get all matches
	handles, err := om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(handles) != 5 {
		t.Errorf("expected 5 matches, got %d", len(handles))
	}

	err = om.FindObjectsFinal(session)
	if err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}
}

func TestObjectManager_FindObjects_EmptyTemplate(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create objects
	for i := 0; i < 3; i++ {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		}
		_, err := om.CreateObject(session, template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Empty template matches all
	err := om.FindObjectsInit(session, nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	handles, err := om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(handles) != 3 {
		t.Errorf("expected 3 matches, got %d", len(handles))
	}

	err = om.FindObjectsFinal(session)
	if err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}
}

func TestObjectManager_FindObjects_Batched(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create 10 objects
	for i := 0; i < 10; i++ {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		}
		_, err := om.CreateObject(session, template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	err := om.FindObjectsInit(session, nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	// Get first batch
	batch1, err := om.FindObjects(session, 3)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(batch1) != 3 {
		t.Errorf("expected 3 in batch1, got %d", len(batch1))
	}

	// Get second batch
	batch2, err := om.FindObjects(session, 3)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(batch2) != 3 {
		t.Errorf("expected 3 in batch2, got %d", len(batch2))
	}

	// Get remaining
	batch3, err := om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(batch3) != 4 {
		t.Errorf("expected 4 in batch3, got %d", len(batch3))
	}

	// No more
	batch4, err := om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(batch4) != 0 {
		t.Errorf("expected 0 in batch4, got %d", len(batch4))
	}

	err = om.FindObjectsFinal(session)
	if err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}
}

func TestObjectManager_FindObjectsInit_OperationActive(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	err := om.FindObjectsInit(session, nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	// Try to init again without finishing
	err = om.FindObjectsInit(session, nil)
	if err == nil {
		t.Error("expected error for active operation")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OPERATION_ACTIVE {
		t.Errorf("expected CKR_OPERATION_ACTIVE, got %v", err)
	}

	err = om.FindObjectsFinal(session)
	if err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}
}

func TestObjectManager_FindObjects_NotInitialized(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	_, err := om.FindObjects(session, 10)
	if err == nil {
		t.Error("expected error for uninitialized operation")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %v", err)
	}
}

func TestObjectManager_FindObjectsFinal_NotInitialized(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	err := om.FindObjectsFinal(session)
	if err == nil {
		t.Error("expected error for uninitialized operation")
	}

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %v", err)
	}
}

func TestObjectManager_DestroySessionObjects(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create session objects
	for i := 0; i < 3; i++ {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewBoolAttribute(CKA_TOKEN, false),
		}
		_, err := om.CreateObject(session, template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Create token object
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
	}
	_, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	if om.Size() != 4 {
		t.Errorf("expected 4 objects, got %d", om.Size())
	}
	if om.SessionObjectCount() != 3 {
		t.Errorf("expected 3 session objects, got %d", om.SessionObjectCount())
	}

	// Start a find operation
	err = om.FindObjectsInit(session, nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	// Destroy session objects
	om.DestroySessionObjects(session)

	// Session objects should be gone
	if om.SessionObjectCount() != 0 {
		t.Errorf("expected 0 session objects, got %d", om.SessionObjectCount())
	}

	// Find state should be cleaned up
	if om.HasFindOperation(session) {
		t.Error("expected find operation to be cleaned up")
	}
}

func TestObjectManager_HasFindOperation(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	if om.HasFindOperation(session) {
		t.Error("expected no find operation initially")
	}

	err := om.FindObjectsInit(session, nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	if !om.HasFindOperation(session) {
		t.Error("expected find operation to be active")
	}

	err = om.FindObjectsFinal(session)
	if err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}

	if om.HasFindOperation(session) {
		t.Error("expected no find operation after final")
	}
}

func TestObjectManager_AddObject_WithHandle(t *testing.T) {
	// Test adding an object with a pre-assigned handle (restoration scenario)
	om := NewObjectManager()

	// Create an object with a specific handle (simulating restored object)
	obj := NewObject(CKO_PRIVATE_KEY)
	obj.Handle = ObjectHandle(42)
	obj.KeyType = CKK_RSA
	obj.IsToken = true
	obj.SetAttribute(CKA_ID, []byte{0x20})
	obj.SetAttribute(CKA_LABEL, []byte("restored-key"))

	err := om.AddObject(obj)
	if err != nil {
		t.Fatalf("AddObject failed: %v", err)
	}

	// Verify object is stored at the original handle
	retrieved, getErr := om.GetObject(ObjectHandle(42))
	if getErr != nil {
		t.Fatalf("GetObject failed: %v", getErr)
	}

	if retrieved.Handle != ObjectHandle(42) {
		t.Errorf("Handle mismatch: got %d, want 42", retrieved.Handle)
	}

	// Verify attributes are preserved
	ckaID := retrieved.GetAttribute(CKA_ID)
	if len(ckaID) != 1 || ckaID[0] != 0x20 {
		t.Errorf("CKA_ID mismatch: got %v, want [0x20]", ckaID)
	}

	label := retrieved.GetAttribute(CKA_LABEL)
	if string(label) != "restored-key" {
		t.Errorf("CKA_LABEL mismatch: got %s, want restored-key", label)
	}
}

func TestObjectManager_AddObject_WithoutHandle(t *testing.T) {
	// Test adding an object without a handle (new object scenario)
	om := NewObjectManager()

	obj := NewObject(CKO_PRIVATE_KEY)
	obj.KeyType = CKK_RSA
	obj.SetAttribute(CKA_LABEL, []byte("new-key"))

	err := om.AddObject(obj)
	if err != nil {
		t.Fatalf("AddObject failed: %v", err)
	}

	// Verify a handle was allocated
	if obj.Handle == ObjectHandle(InvalidHandle) {
		t.Error("Expected handle to be allocated")
	}

	// Verify object can be retrieved
	retrieved, getErr := om.GetObject(obj.Handle)
	if getErr != nil {
		t.Fatalf("GetObject failed: %v", getErr)
	}

	label := retrieved.GetAttribute(CKA_LABEL)
	if string(label) != "new-key" {
		t.Errorf("CKA_LABEL mismatch: got %s, want new-key", label)
	}
}

func TestObjectManager_AddObject_FindByTemplate(t *testing.T) {
	// Test that restored objects can be found by CKA_ID template
	om := NewObjectManager()
	session := SessionHandle(1)

	// Create and add a restored object with specific CKA_ID
	obj := NewObject(CKO_PRIVATE_KEY)
	obj.Handle = ObjectHandle(100)
	obj.KeyType = CKK_RSA
	obj.IsToken = true
	obj.SetAttribute(CKA_ID, []byte{0x20})
	obj.SetAttribute(CKA_CLASS, NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)).Value)

	err := om.AddObject(obj)
	if err != nil {
		t.Fatalf("AddObject failed: %v", err)
	}

	// Search by CKA_ID template (simulates pkcs11-tool --id 20)
	template := []Attribute{
		{Type: CKA_ID, Value: []byte{0x20}},
		{Type: CKA_CLASS, Value: NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)).Value},
	}

	findErr := om.FindObjectsInit(session, template)
	if findErr != nil {
		t.Fatalf("FindObjectsInit failed: %v", findErr)
	}

	handles, findNextErr := om.FindObjects(session, 10)
	if findNextErr != nil {
		t.Fatalf("FindObjects failed: %v", findNextErr)
	}

	if len(handles) != 1 {
		t.Fatalf("Expected 1 object, got %d", len(handles))
	}

	if handles[0] != ObjectHandle(100) {
		t.Errorf("Expected handle 100, got %d", handles[0])
	}

	_ = om.FindObjectsFinal(session)
}

func TestObjectManager_SetNextHandle_Persistence(t *testing.T) {
	// This test simulates the persistence/restoration scenario where:
	// 1. Objects are restored with specific handles using AddObject
	// 2. SetNextHandle is called to set the counter past the max restored handle
	// 3. New objects are created via CreateObject
	// 4. The new handles should not conflict with restored handles

	om := NewObjectManager()
	session := SessionHandle(1)

	// Simulate restoring objects from persistence
	// These objects have specific handles that were persisted
	restoredObj1 := NewObject(CKO_PUBLIC_KEY)
	restoredObj1.Handle = ObjectHandle(5)
	restoredObj1.SetAttribute(CKA_ID, []byte("key1"))
	if err := om.AddObject(restoredObj1); err != nil {
		t.Fatalf("Failed to add restored object 1: %v", err)
	}

	restoredObj2 := NewObject(CKO_PRIVATE_KEY)
	restoredObj2.Handle = ObjectHandle(6)
	restoredObj2.SetAttribute(CKA_ID, []byte("key1"))
	if err := om.AddObject(restoredObj2); err != nil {
		t.Fatalf("Failed to add restored object 2: %v", err)
	}

	restoredObj3 := NewObject(CKO_PUBLIC_KEY)
	restoredObj3.Handle = ObjectHandle(10)
	restoredObj3.SetAttribute(CKA_ID, []byte("key2"))
	if err := om.AddObject(restoredObj3); err != nil {
		t.Fatalf("Failed to add restored object 3: %v", err)
	}

	// Set the next handle to be after the maximum restored handle (10 + 1 = 11)
	om.SetNextHandle(ObjectHandle(11))

	// Now create new objects - they should get handles 11, 12, etc. not 1, 2, etc.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "new-object-1"),
	}

	handle1, err := om.CreateObject(session, template)
	if err != nil {
		t.Fatalf("Failed to create new object 1: %v", err)
	}

	// The new handle should be greater than 10 (the max restored handle)
	if handle1 <= ObjectHandle(10) {
		t.Errorf("New object got handle %d, expected > 10 to avoid conflicts", handle1)
	}

	template2 := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "new-object-2"),
	}

	handle2, err := om.CreateObject(session, template2)
	if err != nil {
		t.Fatalf("Failed to create new object 2: %v", err)
	}

	// The second new handle should be after the first
	if handle2 <= handle1 {
		t.Errorf("Second object handle %d should be > first handle %d", handle2, handle1)
	}

	// Verify all objects are accessible
	if _, err := om.GetObject(ObjectHandle(5)); err != nil {
		t.Errorf("Restored object at handle 5 not found: %v", err)
	}
	if _, err := om.GetObject(ObjectHandle(6)); err != nil {
		t.Errorf("Restored object at handle 6 not found: %v", err)
	}
	if _, err := om.GetObject(ObjectHandle(10)); err != nil {
		t.Errorf("Restored object at handle 10 not found: %v", err)
	}
	if _, err := om.GetObject(handle1); err != nil {
		t.Errorf("New object at handle %d not found: %v", handle1, err)
	}
	if _, err := om.GetObject(handle2); err != nil {
		t.Errorf("New object at handle %d not found: %v", handle2, err)
	}

	// Total objects should be 5 (3 restored + 2 new)
	if om.Size() != 5 {
		t.Errorf("Expected 5 objects, got %d", om.Size())
	}
}

func TestObjectManager_Concurrent(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent object creation
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			template := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
				NewStringAttribute(CKA_LABEL, "concurrent-test"),
			}
			_, err := om.CreateObject(session, template)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}

	if om.Size() != 50 {
		t.Errorf("expected 50 objects, got %d", om.Size())
	}
}

func TestUitoaHex(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{15, "F"},
		{16, "10"},
		{255, "FF"},
		{256, "100"},
		{0xDEADBEEF, "DEADBEEF"},
		{0x12345678, "12345678"},
	}

	for _, tt := range tests {
		result := uitoaHex(tt.input)
		if result != tt.expected {
			t.Errorf("uitoaHex(%d) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}
