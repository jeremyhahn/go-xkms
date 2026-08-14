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
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fullAccessCtx returns an AccessContext for an authenticated normal user on a
// read/write session. It is the access level every test written before
// AccessContext existed implicitly assumed, so migrated tests use it to
// preserve their original intent unless the test is specifically exercising
// one of the new access-policy rules.
func fullAccessCtx(session SessionHandle) AccessContext {
	return AccessContext{Session: session, LoggedIn: true, ReadWrite: true}
}

// publicCtx returns an AccessContext for an unauthenticated, read-only
// session — the minimal-privilege caller used to exercise the private-object
// visibility and read-only-session rules.
func publicCtx(session SessionHandle) AccessContext {
	return AccessContext{Session: session}
}

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

	// Matching template. This is a SEARCH template, not a creation template:
	// every attribute named here must match the object, so an attribute the
	// object does not carry makes the match fail.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "aes-key"),
	}
	if !obj.MatchesTemplate(template) {
		t.Error("expected object to match template")
	}

	// Non-matching template (wrong label)
	template = []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
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

	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}
	if handle == ObjectHandle(InvalidHandle) {
		t.Error("CreateObject returned invalid handle")
	}

	// Verify object was created
	obj, err := om.getObjectUnchecked(handle)
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
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}

	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	obj, err := om.getObjectUnchecked(handle)
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

	_, err := om.CreateObject(fullAccessCtx(session), template)
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

	_, err := om.CreateObject(fullAccessCtx(session), template)
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

	_, err := om.CreateObject(fullAccessCtx(session), template)
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

	_, err := om.CreateObject(fullAccessCtx(session), template)
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
	origHandle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Copy with modifications
	copyTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "copied"),
	}
	copyHandle, err := om.CopyObject(fullAccessCtx(session), origHandle, copyTemplate)
	if err != nil {
		t.Fatalf("CopyObject failed: %v", err)
	}

	// Verify copy
	copyObj, err := om.getObjectUnchecked(copyHandle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if copyObj.GetLabel() != "copied" {
		t.Errorf("expected label 'copied', got %s", copyObj.GetLabel())
	}

	// Verify original unchanged
	origObj, err := om.getObjectUnchecked(origHandle)
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

	_, err := om.CopyObject(fullAccessCtx(session), ObjectHandle(999), nil)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	_, err = om.CopyObject(fullAccessCtx(session), handle, nil)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to modify read-only attribute
	copyTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
	}
	_, err = om.CopyObject(fullAccessCtx(session), handle, copyTemplate)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	if om.Size() != 1 {
		t.Errorf("expected size 1, got %d", om.Size())
	}

	err = om.DestroyObject(fullAccessCtx(session), handle)
	if err != nil {
		t.Fatalf("DestroyObject failed: %v", err)
	}

	if om.Size() != 0 {
		t.Errorf("expected size 0 after destroy, got %d", om.Size())
	}

	// Verify object is gone
	_, err = om.getObjectUnchecked(handle)
	if err == nil {
		t.Error("expected error for destroyed object")
	}
}

func TestObjectManager_DestroyObject_InvalidHandle(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	err := om.DestroyObject(fullAccessCtx(session), ObjectHandle(999))
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	err = om.DestroyObject(fullAccessCtx(session), handle)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Get attributes
	queryTemplate := []Attribute{
		{Type: CKA_LABEL},
		{Type: CKA_ID},
	}
	result, err := om.GetAttributeValue(fullAccessCtx(session), handle, queryTemplate)
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

	_, err := om.GetAttributeValue(fullAccessCtx(session), ObjectHandle(999), nil)
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
	ctx := fullAccessCtx(session)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_VALUE, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to get sensitive attribute
	queryTemplate := []Attribute{{Type: CKA_VALUE}}
	result, err := om.GetAttributeValue(ctx, handle, queryTemplate)

	// Should return CKR_ATTRIBUTE_SENSITIVE
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_SENSITIVE {
		t.Errorf("expected CKR_ATTRIBUTE_SENSITIVE, got %v", err)
	}

	// Result should have nil value and be marked Unavailable
	if len(result) != 1 || result[0].Value != nil || !result[0].Unavailable {
		t.Error("expected nil value and Unavailable=true for sensitive attribute")
	}
}

// TestObjectManager_GetAttributeValue_UnextractableHidesSensitive verifies
// that an unextractable-but-not-sensitive object still hides sensitive
// attributes: CKA_SENSITIVE=FALSE alone is not enough to reveal CKA_VALUE if
// CKA_EXTRACTABLE=FALSE.
func TestObjectManager_GetAttributeValue_UnextractableHidesSensitive(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, false),
		NewAttribute(CKA_VALUE, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	queryTemplate := []Attribute{{Type: CKA_VALUE}}
	result, err := om.GetAttributeValue(ctx, handle, queryTemplate)

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_SENSITIVE {
		t.Errorf("expected CKR_ATTRIBUTE_SENSITIVE for unextractable object, got %v", err)
	}
	if len(result) != 1 || result[0].Value != nil || !result[0].Unavailable {
		t.Error("expected nil value and Unavailable=true for unextractable attribute")
	}
}

// TestObjectManager_GetAttributeValue_PartialFailureReturnsAllResults
// verifies that GetAttributeValue processes every template entry even after
// one fails, returning a fully-populated result slice alongside the error so
// the caller can still write back the attributes it is entitled to.
func TestObjectManager_GetAttributeValue_PartialFailureReturnsAllResults(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewStringAttribute(CKA_LABEL, "aes-key"),
		NewAttribute(CKA_VALUE, []byte{1, 2, 3, 4}),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	queryTemplate := []Attribute{
		{Type: CKA_LABEL},
		{Type: CKA_VALUE},
	}
	result, err := om.GetAttributeValue(ctx, handle, queryTemplate)

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_SENSITIVE {
		t.Errorf("expected CKR_ATTRIBUTE_SENSITIVE, got %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
	if result[0].Unavailable || string(result[0].Value) != "aes-key" {
		t.Errorf("expected CKA_LABEL to be readable, got value=%q unavailable=%v", result[0].Value, result[0].Unavailable)
	}
	if !result[1].Unavailable || result[1].Value != nil {
		t.Errorf("expected CKA_VALUE to be Unavailable with nil value, got value=%v unavailable=%v", result[1].Value, result[1].Unavailable)
	}
}

func TestObjectManager_GetAttributeValue_InvalidAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to get non-existent attribute
	queryTemplate := []Attribute{{Type: CKA_MODULUS}}
	result, err := om.GetAttributeValue(fullAccessCtx(session), handle, queryTemplate)

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_TYPE_INVALID {
		t.Errorf("expected CKR_ATTRIBUTE_TYPE_INVALID, got %v", err)
	}

	if len(result) != 1 || result[0].Value != nil || !result[0].Unavailable {
		t.Error("expected nil value and Unavailable=true for invalid attribute")
	}
}

func TestObjectManager_SetAttributeValue_Success(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "original"),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Modify attribute
	modTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "modified"),
	}
	err = om.SetAttributeValue(fullAccessCtx(session), handle, modTemplate)
	if err != nil {
		t.Fatalf("SetAttributeValue failed: %v", err)
	}

	// Verify modification
	obj, err := om.getObjectUnchecked(handle)
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

	err := om.SetAttributeValue(fullAccessCtx(session), ObjectHandle(999), nil)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	modTemplate := []Attribute{
		NewStringAttribute(CKA_LABEL, "new-label"),
	}
	err = om.SetAttributeValue(fullAccessCtx(session), handle, modTemplate)
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
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Try to modify read-only attribute
	modTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
	}
	err = om.SetAttributeValue(fullAccessCtx(session), handle, modTemplate)
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
		_, err := om.CreateObject(fullAccessCtx(session), template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Create one object with different class
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
		NewUint32Attribute(CKA_CERTIFICATE_TYPE, CKC_X_509),
		NewAttribute(CKA_VALUE, []byte{0x30, 0x00}),
		// Required at creation for an X.509 certificate (v3.2 §4.6.3 footnote 1).
		NewAttribute(CKA_SUBJECT, []byte{0x30, 0x00}),
	}
	_, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Search for data objects
	searchTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	err = om.FindObjectsInit(fullAccessCtx(session), searchTemplate)
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
		_, err := om.CreateObject(fullAccessCtx(session), template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Empty template matches all
	err := om.FindObjectsInit(fullAccessCtx(session), nil)
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
		_, err := om.CreateObject(fullAccessCtx(session), template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	err := om.FindObjectsInit(fullAccessCtx(session), nil)
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

	err := om.FindObjectsInit(fullAccessCtx(session), nil)
	if err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}

	// Try to init again without finishing
	err = om.FindObjectsInit(fullAccessCtx(session), nil)
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
		_, err := om.CreateObject(fullAccessCtx(session), template)
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}
	}

	// Create token object
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
	}
	_, err := om.CreateObject(fullAccessCtx(session), template)
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
	err = om.FindObjectsInit(fullAccessCtx(session), nil)
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

	err := om.FindObjectsInit(fullAccessCtx(session), nil)
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
	retrieved, getErr := om.getObjectUnchecked(ObjectHandle(42))
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
	retrieved, getErr := om.getObjectUnchecked(obj.Handle)
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

	findErr := om.FindObjectsInit(fullAccessCtx(session), template)
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

	handle1, err := om.CreateObject(fullAccessCtx(session), template)
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

	handle2, err := om.CreateObject(fullAccessCtx(session), template2)
	if err != nil {
		t.Fatalf("Failed to create new object 2: %v", err)
	}

	// The second new handle should be after the first
	if handle2 <= handle1 {
		t.Errorf("Second object handle %d should be > first handle %d", handle2, handle1)
	}

	// Verify all objects are accessible
	if _, err := om.getObjectUnchecked(ObjectHandle(5)); err != nil {
		t.Errorf("Restored object at handle 5 not found: %v", err)
	}
	if _, err := om.getObjectUnchecked(ObjectHandle(6)); err != nil {
		t.Errorf("Restored object at handle 6 not found: %v", err)
	}
	if _, err := om.getObjectUnchecked(ObjectHandle(10)); err != nil {
		t.Errorf("Restored object at handle 10 not found: %v", err)
	}
	if _, err := om.getObjectUnchecked(handle1); err != nil {
		t.Errorf("New object at handle %d not found: %v", handle1, err)
	}
	if _, err := om.getObjectUnchecked(handle2); err != nil {
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
			_, err := om.CreateObject(fullAccessCtx(session), template)
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

// --- AccessContext regression tests ---
//
// The following tests cover the security-hardening rules the object layer
// now enforces through AccessContext: private-object invisibility to public
// sessions, the read/write-session requirement for token objects, the
// login requirement for private-object creation, the one-way attribute
// transition rules, the expanded read-only attribute set, creation template
// validation, per-class attribute defaults, and per-session object scoping.

// privateSecretKeyTemplate returns a creation template for a private,
// sensitive secret key session object, used to exercise the private-object
// visibility rules.
func privateSecretKeyTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		// Required at creation for an AES secret key (v3.2 §6.10.1 footnote 1).
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}
}

// TestObjectManager_FindObjectsInit_HidesPrivateObjectFromPublicSession
// verifies that a search from an unauthenticated session never surfaces a
// private object, per PKCS#11 v3.2 §5.7.7.
func TestObjectManager_FindObjectsInit_HidesPrivateObjectFromPublicSession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	// CKO_SECRET_KEY defaults to CKA_PRIVATE=TRUE, so creating it requires a
	// logged-in session.
	_, err := om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	searchTemplate := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY))}

	// A public (unauthenticated) session must not find the private object.
	if err := om.FindObjectsInit(publicCtx(session), searchTemplate); err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}
	handles, err := om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("expected 0 matches for public session, got %d", len(handles))
	}
	if err := om.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}

	// A logged-in session must find it.
	if err := om.FindObjectsInit(fullAccessCtx(session), searchTemplate); err != nil {
		t.Fatalf("FindObjectsInit failed: %v", err)
	}
	handles, err = om.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects failed: %v", err)
	}
	if len(handles) != 1 {
		t.Errorf("expected 1 match for logged-in session, got %d", len(handles))
	}
	if err := om.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal failed: %v", err)
	}
}

// TestObjectManager_GetObjectFor_PrivateObjectHiddenFromPublicSession
// verifies that GetObjectFor reports a private object as CKR_OBJECT_HANDLE_INVALID
// to an unauthenticated session, indistinguishable from a nonexistent handle.
func TestObjectManager_GetObjectFor_PrivateObjectHiddenFromPublicSession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	handle, err := om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	_, err = om.GetObjectFor(publicCtx(session), handle)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID for public session, got %v", err)
	}

	obj, err := om.GetObjectFor(fullAccessCtx(session), handle)
	if err != nil {
		t.Fatalf("expected logged-in session to access private object, got %v", err)
	}
	if obj.Handle != handle {
		t.Errorf("expected handle %d, got %d", handle, obj.Handle)
	}
}

// TestObjectManager_GetAttributeValue_PrivateObjectHiddenFromPublicSession
// verifies that GetAttributeValue rejects a public session with
// CKR_OBJECT_HANDLE_INVALID and returns no result, rather than leaking the
// object's existence through CKR_ATTRIBUTE_SENSITIVE or similar.
func TestObjectManager_GetAttributeValue_PrivateObjectHiddenFromPublicSession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	handle, err := om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	result, err := om.GetAttributeValue(publicCtx(session), handle, []Attribute{{Type: CKA_LABEL}})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID for public session, got %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for hidden private object, got %v", result)
	}
}

// TestObjectManager_CopyObject_PrivateObjectHiddenFromPublicSession verifies
// that CopyObject rejects a public session with CKR_OBJECT_HANDLE_INVALID.
func TestObjectManager_CopyObject_PrivateObjectHiddenFromPublicSession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	handle, err := om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	_, err = om.CopyObject(publicCtx(session), handle, nil)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID for public session, got %v", err)
	}
}

// TestObjectManager_DestroyObject_PrivateObjectHiddenFromPublicSession
// verifies that DestroyObject rejects a public session with
// CKR_OBJECT_HANDLE_INVALID and leaves the object intact.
func TestObjectManager_DestroyObject_PrivateObjectHiddenFromPublicSession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	handle, err := om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	err = om.DestroyObject(publicCtx(session), handle)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_OBJECT_HANDLE_INVALID {
		t.Errorf("expected CKR_OBJECT_HANDLE_INVALID for public session, got %v", err)
	}
	if om.Size() != 1 {
		t.Errorf("expected object to survive a rejected destroy, got size %d", om.Size())
	}
}

// TestObjectManager_CreateObject_PrivateObjectRequiresLogin verifies that
// creating a private object without an authenticated normal user fails with
// CKR_USER_NOT_LOGGED_IN, and succeeds once logged in.
func TestObjectManager_CreateObject_PrivateObjectRequiresLogin(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	_, err := om.CreateObject(publicCtx(session), privateSecretKeyTemplate("secret"))
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_USER_NOT_LOGGED_IN {
		t.Errorf("expected CKR_USER_NOT_LOGGED_IN, got %v", err)
	}

	_, err = om.CreateObject(fullAccessCtx(session), privateSecretKeyTemplate("secret"))
	if err != nil {
		t.Fatalf("expected logged-in session to create private object, got %v", err)
	}
}

// TestObjectManager_CreateObject_TokenObjectRequiresReadWrite verifies that
// creating a token object during a read-only session fails with
// CKR_SESSION_READ_ONLY, and succeeds on a read/write session.
func TestObjectManager_CreateObject_TokenObjectRequiresReadWrite(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
	}

	roCtx := AccessContext{Session: session, LoggedIn: true, ReadWrite: false}
	_, err := om.CreateObject(roCtx, template)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_SESSION_READ_ONLY {
		t.Errorf("expected CKR_SESSION_READ_ONLY, got %v", err)
	}

	_, err = om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("expected read/write session to create token object, got %v", err)
	}
}

// TestObjectManager_SetAttributeValue_TokenObjectRequiresReadWrite verifies
// that modifying a token object during a read-only session fails with
// CKR_SESSION_READ_ONLY, and succeeds once the session is read/write.
func TestObjectManager_SetAttributeValue_TokenObjectRequiresReadWrite(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
		NewStringAttribute(CKA_LABEL, "original"),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	modTemplate := []Attribute{NewStringAttribute(CKA_LABEL, "modified")}
	roCtx := AccessContext{Session: session, LoggedIn: true, ReadWrite: false}
	err = om.SetAttributeValue(roCtx, handle, modTemplate)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_SESSION_READ_ONLY {
		t.Errorf("expected CKR_SESSION_READ_ONLY, got %v", err)
	}

	if err := om.SetAttributeValue(fullAccessCtx(session), handle, modTemplate); err != nil {
		t.Fatalf("expected read/write session to modify token object, got %v", err)
	}
}

// TestObjectManager_DestroyObject_TokenObjectRequiresReadWrite verifies that
// destroying a token object during a read-only session fails with
// CKR_SESSION_READ_ONLY, leaving the object intact, and succeeds once the
// session is read/write.
func TestObjectManager_DestroyObject_TokenObjectRequiresReadWrite(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	roCtx := AccessContext{Session: session, LoggedIn: true, ReadWrite: false}
	err = om.DestroyObject(roCtx, handle)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_SESSION_READ_ONLY {
		t.Errorf("expected CKR_SESSION_READ_ONLY, got %v", err)
	}
	if om.Size() != 1 {
		t.Errorf("expected token object to survive a rejected destroy, got size %d", om.Size())
	}

	if err := om.DestroyObject(fullAccessCtx(session), handle); err != nil {
		t.Fatalf("expected read/write session to destroy token object, got %v", err)
	}
}

// TestObjectManager_SetAttributeValue_SessionObjectModifiableFromReadOnlySession
// verifies that a session (non-token) object may be modified during a
// read-only session — the read/write requirement applies only to token
// objects, per PKCS#11 v3.2 §5.7.4.
func TestObjectManager_SetAttributeValue_SessionObjectModifiableFromReadOnlySession(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	roCtx := AccessContext{Session: session, LoggedIn: false, ReadWrite: false}

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "original"),
	}
	handle, err := om.CreateObject(roCtx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	modTemplate := []Attribute{NewStringAttribute(CKA_LABEL, "modified")}
	if err := om.SetAttributeValue(roCtx, handle, modTemplate); err != nil {
		t.Fatalf("expected session object to be modifiable from a read-only session, got %v", err)
	}

	obj, err := om.getObjectUnchecked(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.GetLabel() != "modified" {
		t.Errorf("expected label 'modified', got %q", obj.GetLabel())
	}
}

// TestObjectManager_SetAttributeValue_SensitiveOneWay verifies that
// CKA_SENSITIVE may transition CK_FALSE→CK_TRUE but never back, per
// PKCS#11 v3.2 §4.1.1.
func TestObjectManager_SetAttributeValue_SensitiveOneWay(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	// CKO_SECRET_KEY defaults CKA_SENSITIVE to CK_FALSE.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		// Required at creation (v3.2 §6.10.1 footnote 1).
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// FALSE -> TRUE is permitted.
	if err := om.SetAttributeValue(ctx, handle, []Attribute{NewBoolAttribute(CKA_SENSITIVE, true)}); err != nil {
		t.Fatalf("expected CKA_SENSITIVE FALSE->TRUE to succeed, got %v", err)
	}

	// TRUE -> FALSE must be rejected.
	err = om.SetAttributeValue(ctx, handle, []Attribute{NewBoolAttribute(CKA_SENSITIVE, false)})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for CKA_SENSITIVE TRUE->FALSE, got %v", err)
	}
}

// TestObjectManager_SetAttributeValue_ExtractableOneWay verifies that
// CKA_EXTRACTABLE may transition CK_TRUE→CK_FALSE but never back, per
// PKCS#11 v3.2 §4.1.1.
func TestObjectManager_SetAttributeValue_ExtractableOneWay(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	// CKO_SECRET_KEY defaults CKA_EXTRACTABLE to CK_TRUE.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		// Required at creation (v3.2 §6.10.1 footnote 1).
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// TRUE -> FALSE is permitted.
	if err := om.SetAttributeValue(ctx, handle, []Attribute{NewBoolAttribute(CKA_EXTRACTABLE, false)}); err != nil {
		t.Fatalf("expected CKA_EXTRACTABLE TRUE->FALSE to succeed, got %v", err)
	}

	// FALSE -> TRUE must be rejected.
	err = om.SetAttributeValue(ctx, handle, []Attribute{NewBoolAttribute(CKA_EXTRACTABLE, true)})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for CKA_EXTRACTABLE FALSE->TRUE, got %v", err)
	}
}

// TestObjectManager_CopyObject_SensitiveOneWay verifies that CopyObject
// enforces the same CKA_SENSITIVE one-way rule as SetAttributeValue, so a
// copy cannot be used to launder protection off a key.
func TestObjectManager_CopyObject_SensitiveOneWay(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	// CKO_PRIVATE_KEY defaults CKA_SENSITIVE to CK_TRUE.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	_, err = om.CopyObject(ctx, handle, []Attribute{NewBoolAttribute(CKA_SENSITIVE, false)})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for CKA_SENSITIVE TRUE->FALSE via copy, got %v", err)
	}
}

// TestObjectManager_CopyObject_ExtractableOneWay verifies that CopyObject
// enforces the same CKA_EXTRACTABLE one-way rule as SetAttributeValue.
func TestObjectManager_CopyObject_ExtractableOneWay(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	// CKO_SECRET_KEY defaults CKA_EXTRACTABLE to CK_TRUE.
	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		// Required at creation (v3.2 §6.10.1 footnote 1).
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// TRUE -> FALSE is permitted via copy.
	copyHandle, err := om.CopyObject(ctx, handle, []Attribute{NewBoolAttribute(CKA_EXTRACTABLE, false)})
	if err != nil {
		t.Fatalf("expected CKA_EXTRACTABLE TRUE->FALSE via copy to succeed, got %v", err)
	}
	copyObj, err := om.getObjectUnchecked(copyHandle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if copyObj.IsExtractable {
		t.Error("expected copy to have IsExtractable=false")
	}

	// FALSE -> TRUE must be rejected, including via a further copy.
	_, err = om.CopyObject(ctx, copyHandle, []Attribute{NewBoolAttribute(CKA_EXTRACTABLE, true)})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
		t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for CKA_EXTRACTABLE FALSE->TRUE via copy, got %v", err)
	}
}

// TestObjectManager_SetAttributeValue_RejectsCopyOnlyAttributes verifies that
// CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE and CKA_DESTROYABLE — changeable
// only through C_CopyObject per PKCS#11 v3.2 §4.1.1 — are rejected by
// SetAttributeValue.
func TestObjectManager_SetAttributeValue_RejectsCopyOnlyAttributes(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	copyOnly := []Attribute{
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, true),
		NewBoolAttribute(CKA_MODIFIABLE, false),
		NewBoolAttribute(CKA_DESTROYABLE, false),
	}

	for _, attr := range copyOnly {
		t.Run(attr.Type.String(), func(t *testing.T) {
			template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
			handle, err := om.CreateObject(ctx, template)
			if err != nil {
				t.Fatalf("CreateObject failed: %v", err)
			}

			err = om.SetAttributeValue(ctx, handle, []Attribute{attr})
			var pkcsErr *PKCS11Error
			if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
				t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for %s via SetAttributeValue, got %v", attr.Type, err)
			}
		})
	}
}

// TestObjectManager_CopyObject_AllowsCopyOnlyAttributes verifies that
// CopyObject — unlike SetAttributeValue — may change CKA_TOKEN, CKA_PRIVATE,
// CKA_MODIFIABLE and CKA_DESTROYABLE, since the copy is a new object rather
// than a mutation of the original (PKCS#11 v3.2 §4.1.1).
func TestObjectManager_CopyObject_AllowsCopyOnlyAttributes(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
	handle, err := om.CreateObject(ctx, template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	copyTemplate := []Attribute{
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, true),
		NewBoolAttribute(CKA_MODIFIABLE, false),
		NewBoolAttribute(CKA_DESTROYABLE, false),
	}
	copyHandle, err := om.CopyObject(ctx, handle, copyTemplate)
	if err != nil {
		t.Fatalf("expected CopyObject to allow changing token/private/modifiable/destroyable, got %v", err)
	}

	copyObj, err := om.getObjectUnchecked(copyHandle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if !copyObj.IsToken || !copyObj.IsPrivate || copyObj.IsModifiable || copyObj.IsDestroyable {
		t.Errorf("expected copy to reflect changed attributes, got IsToken=%v IsPrivate=%v IsModifiable=%v IsDestroyable=%v",
			copyObj.IsToken, copyObj.IsPrivate, copyObj.IsModifiable, copyObj.IsDestroyable)
	}
}

// TestObjectManager_CreateObject_KeyClassRequiresKeyType verifies that key
// classes (public, private, secret) require CKA_KEY_TYPE in the creation
// template.
func TestObjectManager_CreateObject_KeyClassRequiresKeyType(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY))}
	_, err := om.CreateObject(ctx, template)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_TEMPLATE_INCOMPLETE {
		t.Errorf("expected CKR_TEMPLATE_INCOMPLETE for missing CKA_KEY_TYPE, got %v", err)
	}
}

// TestObjectManager_CreateObject_CertificateRequiresTypeAndValue verifies
// that CKO_CERTIFICATE requires both CKA_CERTIFICATE_TYPE and CKA_VALUE.
func TestObjectManager_CreateObject_CertificateRequiresTypeAndValue(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	// Missing both.
	_, err := om.CreateObject(ctx, []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE))})
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_TEMPLATE_INCOMPLETE {
		t.Errorf("expected CKR_TEMPLATE_INCOMPLETE for missing certificate attributes, got %v", err)
	}

	// Missing CKA_VALUE only.
	_, err = om.CreateObject(ctx, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
		NewUint32Attribute(CKA_CERTIFICATE_TYPE, CKC_X_509),
	})
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_TEMPLATE_INCOMPLETE {
		t.Errorf("expected CKR_TEMPLATE_INCOMPLETE for missing CKA_VALUE, got %v", err)
	}

	// Both present succeeds.
	_, err = om.CreateObject(ctx, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_CERTIFICATE)),
		NewUint32Attribute(CKA_CERTIFICATE_TYPE, CKC_X_509),
		NewAttribute(CKA_VALUE, []byte{0x30, 0x00}),
		// Required at creation for an X.509 certificate (v3.2 §4.6.3 footnote 1).
		NewAttribute(CKA_SUBJECT, []byte{0x30, 0x00}),
	})
	if err != nil {
		t.Fatalf("expected certificate with all required attributes to succeed, got %v", err)
	}
}

// TestObjectManager_CreateObject_DuplicateAttribute verifies that a
// creation template with the same attribute type twice is rejected with
// CKR_TEMPLATE_INCONSISTENT.
func TestObjectManager_CreateObject_DuplicateAttribute(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
	}
	_, err := om.CreateObject(fullAccessCtx(session), template)
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_TEMPLATE_INCONSISTENT {
		t.Errorf("expected CKR_TEMPLATE_INCONSISTENT for duplicate attribute, got %v", err)
	}
}

// TestObjectManager_CreateObject_RejectsComputedAttributes verifies that a
// caller cannot forge token-computed provenance attributes (CKA_LOCAL,
// CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM,
// CKA_UNIQUE_ID) through a creation template.
func TestObjectManager_CreateObject_RejectsComputedAttributes(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)
	ctx := fullAccessCtx(session)

	computed := []Attribute{
		NewBoolAttribute(CKA_LOCAL, true),
		NewBoolAttribute(CKA_ALWAYS_SENSITIVE, true),
		NewBoolAttribute(CKA_NEVER_EXTRACTABLE, true),
		NewUint32Attribute(CKA_KEY_GEN_MECHANISM, 1),
		NewAttribute(CKA_UNIQUE_ID, []byte{1, 2, 3}),
	}

	for _, attr := range computed {
		t.Run(attr.Type.String(), func(t *testing.T) {
			template := []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
				attr,
			}
			_, err := om.CreateObject(ctx, template)
			var pkcsErr *PKCS11Error
			if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_READ_ONLY {
				t.Errorf("expected CKR_ATTRIBUTE_READ_ONLY for caller-supplied %s, got %v", attr.Type, err)
			}
		})
	}
}

// TestObjectManager_ClassDefaults_PrivateKey verifies that CKO_PRIVATE_KEY
// defaults to CKA_PRIVATE=TRUE, CKA_SENSITIVE=TRUE and CKA_EXTRACTABLE=TRUE
// when the caller's template omits them.
func TestObjectManager_ClassDefaults_PrivateKey(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	obj, err := om.getObjectUnchecked(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if !obj.IsPrivate || !obj.IsSensitive || !obj.IsExtractable {
		t.Errorf("expected private key defaults IsPrivate=true IsSensitive=true IsExtractable=true, got IsPrivate=%v IsSensitive=%v IsExtractable=%v",
			obj.IsPrivate, obj.IsSensitive, obj.IsExtractable)
	}
}

// TestObjectManager_ClassDefaults_SecretKey verifies that CKO_SECRET_KEY
// defaults to CKA_PRIVATE=TRUE and CKA_EXTRACTABLE=TRUE, but CKA_SENSITIVE
// defaults to FALSE (unlike private keys).
func TestObjectManager_ClassDefaults_SecretKey(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		// Required at creation (v3.2 §6.10.1 footnote 1).
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	}
	handle, err := om.CreateObject(fullAccessCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	obj, err := om.getObjectUnchecked(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if !obj.IsPrivate || obj.IsSensitive || !obj.IsExtractable {
		t.Errorf("expected secret key defaults IsPrivate=true IsSensitive=false IsExtractable=true, got IsPrivate=%v IsSensitive=%v IsExtractable=%v",
			obj.IsPrivate, obj.IsSensitive, obj.IsExtractable)
	}
}

// TestObjectManager_ClassDefaults_DataObjectNotPrivate verifies that
// non-key classes such as CKO_DATA default to CKA_PRIVATE=FALSE.
func TestObjectManager_ClassDefaults_DataObjectNotPrivate(t *testing.T) {
	om := NewObjectManager()
	session := SessionHandle(1)

	template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
	// A public session must be able to create it, proving the object is not
	// private by default.
	handle, err := om.CreateObject(publicCtx(session), template)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	obj, err := om.getObjectUnchecked(handle)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.IsPrivate {
		t.Error("expected CKO_DATA object to default to IsPrivate=false")
	}
}

// TestObjectManager_DestroySessionObjects_ScopedToOwningSession verifies
// that DestroySessionObjects destroys only the objects created through the
// given session's AccessContext, leaving another session's objects intact
// (PKCS#11 v3.2 §5.6.2).
func TestObjectManager_DestroySessionObjects_ScopedToOwningSession(t *testing.T) {
	om := NewObjectManager()
	sessionA := SessionHandle(1)
	sessionB := SessionHandle(2)

	var aHandles, bHandles []ObjectHandle
	for i := 0; i < 2; i++ {
		template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
		h, err := om.CreateObject(fullAccessCtx(sessionA), template)
		if err != nil {
			t.Fatalf("CreateObject (session A) failed: %v", err)
		}
		aHandles = append(aHandles, h)
	}
	for i := 0; i < 2; i++ {
		template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
		h, err := om.CreateObject(fullAccessCtx(sessionB), template)
		if err != nil {
			t.Fatalf("CreateObject (session B) failed: %v", err)
		}
		bHandles = append(bHandles, h)
	}

	if om.Size() != 4 {
		t.Fatalf("expected 4 objects before destroy, got %d", om.Size())
	}

	om.DestroySessionObjects(sessionA)

	if om.Size() != 2 {
		t.Errorf("expected 2 objects to survive, got %d", om.Size())
	}
	for _, h := range aHandles {
		if _, err := om.getObjectUnchecked(h); err == nil {
			t.Errorf("expected session A object %d to be destroyed", h)
		}
	}
	for _, h := range bHandles {
		if _, err := om.getObjectUnchecked(h); err != nil {
			t.Errorf("expected session B object %d to survive, got %v", h, err)
		}
	}
	if om.SessionObjectCount() != 2 {
		t.Errorf("expected 2 session objects remaining (session B's), got %d", om.SessionObjectCount())
	}
}

// TestObject_GetAttribute_ReturnsCopy verifies that GetAttribute returns a
// copy of the stored value, so a caller that zeroizes key material after use
// cannot corrupt the object's stored state.
func TestObject_GetAttribute_ReturnsCopy(t *testing.T) {
	obj := NewObject(CKO_DATA)
	obj.SetAttribute(CKA_LABEL, []byte("original"))

	value := obj.GetAttribute(CKA_LABEL)
	for i := range value {
		value[i] = 'X'
	}

	value2 := obj.GetAttribute(CKA_LABEL)
	if string(value2) != "original" {
		t.Errorf("expected stored attribute to be unaffected by mutating the returned copy, got %q", value2)
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

// TestMatchesTemplate_ULongWidthIndependence proves a CK_ULONG-valued attribute
// matches regardless of the width it was encoded at.
//
// The same value legitimately arrives in two widths: a C application sends a
// native CK_ULONG through the cgo boundary, which is 8 bytes on a 64-bit
// platform, while an object created through the Go API's NewUint32Attribute
// holds 4. Comparing the raw bytes reported those as different, so
// C_FindObjects could not find any Go-created object by CKA_CLASS or
// CKA_KEY_TYPE. The symptom was maddening precisely because it was partial:
// pkcs11-tool listed such a key without complaint, then said "Private key not
// found" the moment it searched for one to sign with.
func TestMatchesTemplate_ULongWidthIndependence(t *testing.T) {
	uint64Attr := func(attrType AttributeType, v uint64) Attribute {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, v)
		return Attribute{Type: attrType, Value: buf}
	}

	t.Run("a 4-byte stored class matches an 8-byte search", func(t *testing.T) {
		obj := &Object{Attributes: map[AttributeType][]byte{
			CKA_CLASS:    NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)).Value,
			CKA_KEY_TYPE: NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)).Value,
			CKA_LABEL:    []byte("signing-key"),
		}}

		assert.True(t, obj.MatchesTemplate([]Attribute{
			uint64Attr(CKA_CLASS, uint64(CKO_PRIVATE_KEY)),
			uint64Attr(CKA_KEY_TYPE, uint64(CKK_RSA)),
			{Type: CKA_LABEL, Value: []byte("signing-key")},
		}), "a C caller's 8-byte CK_ULONG must match the stored 4-byte value")
	})

	t.Run("an 8-byte stored class matches a 4-byte search", func(t *testing.T) {
		obj := &Object{Attributes: map[AttributeType][]byte{
			CKA_CLASS: uint64Attr(CKA_CLASS, uint64(CKO_SECRET_KEY)).Value,
		}}

		assert.True(t, obj.MatchesTemplate([]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		}), "the comparison must be symmetric in the two widths")
	})

	t.Run("different values still do not match", func(t *testing.T) {
		// Width tolerance must not become value blindness.
		obj := &Object{Attributes: map[AttributeType][]byte{
			CKA_CLASS: NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)).Value,
		}}

		assert.False(t, obj.MatchesTemplate([]Attribute{
			uint64Attr(CKA_CLASS, uint64(CKO_PUBLIC_KEY)),
		}), "a private key must not match a search for a public key")
	})

	t.Run("byte-array attributes still compare exactly", func(t *testing.T) {
		// CKA_ID and CKA_LABEL are byte arrays, not CK_ULONGs, so a
		// four-byte-versus-eight-byte difference there is a real difference.
		obj := &Object{Attributes: map[AttributeType][]byte{
			CKA_ID: {0x01, 0x00, 0x00, 0x00},
		}}

		assert.True(t, obj.MatchesTemplate([]Attribute{
			{Type: CKA_ID, Value: []byte{0x01, 0x00, 0x00, 0x00}},
		}))
		assert.False(t, obj.MatchesTemplate([]Attribute{
			{Type: CKA_ID, Value: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		}), "a byte array must not be padded to a CK_ULONG width")
	})
}

// TestKEMTemplateAttributesRoundTrip covers the two KEM template attributes
// through C_SetAttributeValue and C_GetAttributeValue. OASIS defines
// CKA_ENCAPSULATE_TEMPLATE and CKA_DECAPSULATE_TEMPLATE without the
// CKF_ARRAY_ATTRIBUTE bit that every other *_TEMPLATE attribute carries, so
// this module's values were corrected to match. Attribute storage is keyed on
// the numeric type and never inspects the array bit, so the correction must
// leave the round trip intact; this test is what says so.
func TestKEMTemplateAttributesRoundTrip(t *testing.T) {
	kemTemplateAttrs := []struct {
		name string
		attr AttributeType
		want uint32
	}{
		{"CKA_ENCAPSULATE_TEMPLATE", CKA_ENCAPSULATE_TEMPLATE, 0x0000062A},
		{"CKA_DECAPSULATE_TEMPLATE", CKA_DECAPSULATE_TEMPLATE, 0x0000062B},
	}

	for _, tc := range kemTemplateAttrs {
		t.Run(tc.name+" carries the OASIS value", func(t *testing.T) {
			assert.Equal(t, tc.want, uint32(tc.attr))
			assert.Zero(t, uint32(tc.attr)&0x40000000,
				"OASIS defines %s without CKF_ARRAY_ATTRIBUTE", tc.name)
		})

		t.Run(tc.name+" survives set and get", func(t *testing.T) {
			om := NewObjectManager()
			session := SessionHandle(1)
			ctx := fullAccessCtx(session)

			handle, err := om.CreateObject(ctx, []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			})
			if err != nil {
				t.Fatalf("CreateObject failed: %v", err)
			}

			// A template attribute's value is an encoded attribute array. The
			// object layer parses it rather than storing it opaquely, because
			// a constraint the token cannot read is a constraint it cannot
			// apply, so the round trip is exercised with a real array.
			encoded := EncodeAttributeArray([]Attribute{
				NewBoolAttribute(CKA_EXTRACTABLE, false),
			})
			if err := om.SetAttributeValue(ctx, handle, []Attribute{
				NewAttribute(tc.attr, encoded),
			}); err != nil {
				t.Fatalf("SetAttributeValue(%s) failed: %v", tc.name, err)
			}

			got, err := om.GetAttributeValue(ctx, handle, []Attribute{{Type: tc.attr}})
			if err != nil {
				t.Fatalf("GetAttributeValue(%s) failed: %v", tc.name, err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 attribute back, got %d", len(got))
			}
			assert.Equal(t, tc.attr, got[0].Type)
			assert.Equal(t, encoded, got[0].Value)
			assert.False(t, got[0].Unavailable)
		})

		t.Run(tc.name+" is reported missing when never set", func(t *testing.T) {
			om := NewObjectManager()
			session := SessionHandle(1)
			ctx := fullAccessCtx(session)

			handle, err := om.CreateObject(ctx, []Attribute{
				NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			})
			if err != nil {
				t.Fatalf("CreateObject failed: %v", err)
			}

			got, err := om.GetAttributeValue(ctx, handle, []Attribute{{Type: tc.attr}})
			var pkcsErr *PKCS11Error
			if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_ATTRIBUTE_TYPE_INVALID {
				t.Fatalf("expected CKR_ATTRIBUTE_TYPE_INVALID, got %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected the template entry back, got %d", len(got))
			}
			assert.True(t, got[0].Unavailable,
				"an absent attribute must be marked unavailable per v3.2 §5.7.5")
			assert.Nil(t, got[0].Value)
		})
	}

	// The correction must not have collided with a neighbour: 0x629 and 0x62C
	// are occupied by unrelated attributes, and Cryptoki dispatches on value.
	t.Run("KEM template values do not collide with their neighbours", func(t *testing.T) {
		assert.NotEqual(t, CKA_VALIDATION_PROFILE, CKA_ENCAPSULATE_TEMPLATE)
		assert.NotEqual(t, CKA_TRUST_SERVER_AUTH, CKA_DECAPSULATE_TEMPLATE)
		assert.NotEqual(t, CKA_ENCAPSULATE_TEMPLATE, CKA_DECAPSULATE_TEMPLATE)
	})
}

// TestNewULongAttribute_EncodesTheNativeWidth proves the canonical CK_ULONG
// constructor writes a whole CK_ULONG and loses no part of the value.
//
// PKCS#11 v3.2 §3.2 defines CK_ULONG as the platform's unsigned long, which is
// eight bytes on every platform this module builds for; ckULongSize says so.
func TestNewULongAttribute_EncodesTheNativeWidth(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value uint64
	}{
		{name: "zero", value: 0},
		{name: "object class", value: uint64(CKO_PUBLIC_KEY)},
		{name: "whole low half", value: 0xFFFFFFFF},
		{name: "value above the 32-bit range", value: 0x0000000100000000},
		{name: "largest CK_ULONG", value: ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attr := NewULongAttribute(CKA_CLASS, tc.value)

			assert.Equal(t, CKA_CLASS, attr.Type)
			assert.Len(t, attr.Value, ckULongSize,
				"a CK_ULONG attribute must be exactly one CK_ULONG wide")
			assert.Equal(t, tc.value, binary.LittleEndian.Uint64(attr.Value),
				"the value must survive encoding without truncation")
		})
	}
}

// TestNewUint32Attribute_WidensOnlyCKULONGAttributes proves the 32-bit
// constructor cannot produce a short CK_ULONG, and equally that it does not
// widen an attribute that is not one.
//
// The first half is the defect: CKA_CLASS and CKA_KEY_TYPE written four bytes
// wide made pkcs11-provider read a generated key's class as
// 0xFFFFFFFF00000002 and abandon the object. The second half is the reason the
// widening is keyed on the attribute type rather than applied to every value:
// CKA_ID and CKA_VALUE are byte arrays whose length is part of what they say,
// and appending four zero bytes to a caller's four-byte CKA_ID would change
// which key it identifies.
func TestNewUint32Attribute_WidensOnlyCKULONGAttributes(t *testing.T) {
	t.Run("every CK_ULONG-typed attribute is stored at the native width", func(t *testing.T) {
		for attrType := range ulongAttributes {
			attr := NewUint32Attribute(attrType, 0x00000002)

			assert.Lenf(t, attr.Value, ckULongSize,
				"%s is a CK_ULONG and must be encoded as one", attrType.String())
			assert.Equalf(t, uint64(0x00000002), binary.LittleEndian.Uint64(attr.Value),
				"%s must keep its value when widened", attrType.String())
		}
	})

	t.Run("a byte-array attribute keeps the width it was given", func(t *testing.T) {
		for _, attrType := range []AttributeType{CKA_ID, CKA_VALUE, CKA_LABEL, CKA_SUBJECT} {
			attr := NewUint32Attribute(attrType, 0x04030201)

			assert.Lenf(t, attr.Value, 4,
				"%s is a byte array, not a CK_ULONG, and must not be widened", attrType.String())
			assert.Equalf(t, []byte{0x01, 0x02, 0x03, 0x04}, attr.Value,
				"%s must be encoded exactly as given", attrType.String())
		}
	})
}

// TestNormalizeULongWidth proves the rule the token stores by: a CK_ULONG
// attribute is held at the native width whatever width it arrived in, and
// nothing else is touched.
func TestNormalizeULongWidth(t *testing.T) {
	t.Run("a four-byte CK_ULONG is widened without changing its value", func(t *testing.T) {
		got := normalizeULongWidth(CKA_CLASS, []byte{0x02, 0x00, 0x00, 0x00})

		assert.Len(t, got, ckULongSize)
		assert.Equal(t, uint64(CKO_PUBLIC_KEY), binary.LittleEndian.Uint64(got))
	})

	t.Run("a native-width CK_ULONG is returned unchanged", func(t *testing.T) {
		value := []byte{0x03, 0, 0, 0, 0, 0, 0, 0}
		got := normalizeULongWidth(CKA_KEY_TYPE, value)

		assert.Equal(t, value, got)
	})

	t.Run("a byte-array attribute is returned unchanged", func(t *testing.T) {
		value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		got := normalizeULongWidth(CKA_ID, value)

		assert.Equal(t, value, got, "CKA_ID is not a CK_ULONG and must not be re-encoded")
	})

	t.Run("a width that is no CK_ULONG is returned unchanged", func(t *testing.T) {
		// Inventing the missing bytes would put a number into the object that
		// the caller never supplied. The value is left for the validators and
		// the operations that read it to reject on its own terms.
		for _, value := range [][]byte{nil, {}, {0x01}, {0x01, 0x02, 0x03}, make([]byte, 16)} {
			got := normalizeULongWidth(CKA_CLASS, value)

			assert.Equalf(t, value, got,
				"a %d-byte value is not a CK_ULONG and must not be re-encoded", len(value))
		}
	})
}

// TestObject_StoresCKULONGAttributesAtNativeWidth proves the constructors that
// build an object from Go constants store whole CK_ULONGs, and that
// SetAttribute normalises whatever any other caller hands it.
func TestObject_StoresCKULONGAttributesAtNativeWidth(t *testing.T) {
	t.Run("NewObject stores a native-width CKA_CLASS", func(t *testing.T) {
		obj := NewObject(CKO_PRIVATE_KEY)

		assert.Len(t, obj.Attributes[CKA_CLASS], ckULongSize)
		assert.Equal(t, uint64(CKO_PRIVATE_KEY),
			binary.LittleEndian.Uint64(obj.Attributes[CKA_CLASS]))
	})

	t.Run("NewKeyObject stores a native-width CKA_KEY_TYPE", func(t *testing.T) {
		obj := NewKeyObject(CKO_PUBLIC_KEY, CKK_EC)

		assert.Len(t, obj.Attributes[CKA_KEY_TYPE], ckULongSize)
		assert.Equal(t, uint64(CKK_EC),
			binary.LittleEndian.Uint64(obj.Attributes[CKA_KEY_TYPE]))
		assert.Equal(t, CKK_EC, obj.KeyType,
			"the convenience field must still be decoded from the widened value")
	})

	t.Run("SetAttribute widens a short CK_ULONG", func(t *testing.T) {
		obj := NewObject(CKO_SECRET_KEY)
		obj.SetAttribute(CKA_VALUE_LEN, []byte{0x20, 0x00, 0x00, 0x00})

		assert.Len(t, obj.Attributes[CKA_VALUE_LEN], ckULongSize)
		assert.Equal(t, uint64(32), binary.LittleEndian.Uint64(obj.Attributes[CKA_VALUE_LEN]))
	})

	t.Run("SetAttribute leaves a byte array alone", func(t *testing.T) {
		obj := NewObject(CKO_SECRET_KEY)
		id := []byte{0x01, 0x02, 0x03, 0x04}
		obj.SetAttribute(CKA_ID, id)

		assert.Equal(t, id, obj.Attributes[CKA_ID],
			"widening CKA_ID would change which key it identifies")
	})
}

// TestObjectManager_GeneratedObjectReturnsNativeWidthULongs is the regression
// test for the defect pkcs11-provider found.
//
// A caller that omits CKA_CLASS and CKA_KEY_TYPE from a C_GenerateKeyPair
// template — which pkcs11-provider does, and pkcs11-tool does not — gets values
// the token derived from the mechanism. C_GetAttributeValue reports the stored
// length in ulValueLen (v3.2 §5.7.5), so an application that allocated
// sizeof(CK_ULONG) and received four bytes kept whatever was already in the
// upper half of its buffer: the provider decoded CKO_PUBLIC_KEY as
// 0xFFFFFFFF00000002 and abandoned the new key.
func TestObjectManager_GeneratedObjectReturnsNativeWidthULongs(t *testing.T) {
	readULong := func(t *testing.T, om *ObjectManager, ctx AccessContext, handle ObjectHandle, attrType AttributeType) []byte {
		t.Helper()
		got, err := om.GetAttributeValue(ctx, handle, []Attribute{{Type: attrType}})
		if err != nil {
			t.Fatalf("GetAttributeValue(%s) failed: %v", attrType.String(), err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 attribute back, got %d", len(got))
		}
		return got[0].Value
	}

	t.Run("class and key type the token derived are whole CK_ULONGs", func(t *testing.T) {
		om := NewObjectManager()
		ctx := fullAccessCtx(SessionHandle(1))

		handle, err := om.CreateGeneratedObject(ctx, CKO_PUBLIC_KEY, CKK_RSA, nil)
		if err != nil {
			t.Fatalf("CreateGeneratedObject failed: %v", err)
		}

		class := readULong(t, om, ctx, handle, CKA_CLASS)
		assert.Len(t, class, ckULongSize,
			"CKA_CLASS is a CK_OBJECT_CLASS, which is a CK_ULONG")
		assert.Equal(t, uint64(CKO_PUBLIC_KEY), binary.LittleEndian.Uint64(class))

		keyType := readULong(t, om, ctx, handle, CKA_KEY_TYPE)
		assert.Len(t, keyType, ckULongSize,
			"CKA_KEY_TYPE is a CK_KEY_TYPE, which is a CK_ULONG")
		assert.Equal(t, uint64(CKK_RSA), binary.LittleEndian.Uint64(keyType))
	})

	t.Run("a caller's short CK_ULONG is stored at the native width", func(t *testing.T) {
		om := NewObjectManager()
		ctx := fullAccessCtx(SessionHandle(1))

		// A four-byte CKA_CLASS is not a CK_ULONG on this platform, but a Go
		// caller may still send one and the object must not carry it onward to
		// an application that reads the attribute back.
		handle, err := om.CreateObject(ctx, []Attribute{
			{Type: CKA_CLASS, Value: []byte{0x02, 0x00, 0x00, 0x00}},
			{Type: CKA_KEY_TYPE, Value: []byte{0x03, 0x00, 0x00, 0x00}},
			// Class 2 is CKO_PUBLIC_KEY and key type 3 is CKK_EC, which must
			// carry its curve and point at creation (v3.2 §6.3.3 footnote 1).
			NewAttribute(CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}),
			NewAttribute(CKA_EC_POINT, make([]byte, 67)),
		})
		if err != nil {
			t.Fatalf("CreateObject failed: %v", err)
		}

		assert.Len(t, readULong(t, om, ctx, handle, CKA_CLASS), ckULongSize)
		assert.Len(t, readULong(t, om, ctx, handle, CKA_KEY_TYPE), ckULongSize)
	})

	t.Run("a derived key's token-computed CKA_VALUE_LEN is a whole CK_ULONG", func(t *testing.T) {
		om := NewObjectManager()
		ctx := fullAccessCtx(SessionHandle(1))

		base := NewKeyObject(CKO_SECRET_KEY, CKK_GENERIC_SECRET)
		handle, err := om.CreateDerivedObject(ctx, base, CKO_SECRET_KEY, CKK_AES, []Attribute{
			{Type: CKA_VALUE, Value: make([]byte, 32)},
			{Type: CKA_VALUE_LEN, Value: []byte{0x20, 0x00, 0x00, 0x00}},
		})
		if err != nil {
			t.Fatalf("CreateDerivedObject failed: %v", err)
		}

		valueLen := readULong(t, om, ctx, handle, CKA_VALUE_LEN)
		assert.Len(t, valueLen, ckULongSize,
			"CKA_VALUE_LEN is a CK_ULONG (v3.2 §6.10.3)")
		assert.Equal(t, uint64(32), binary.LittleEndian.Uint64(valueLen))
	})
}

// TestMatchesTemplate_AcceptsEitherULongWidth pins the tolerance that must
// survive the widening.
//
// The token now stores native-width CK_ULONGs, but an application is still free
// to search with whatever width it marshalled. A Go caller that builds a
// four-byte CKA_CLASS must keep finding the object, or C_FindObjects would stop
// returning keys it returned before.
func TestMatchesTemplate_AcceptsEitherULongWidth(t *testing.T) {
	obj := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)

	t.Run("a native-width template matches", func(t *testing.T) {
		assert.True(t, obj.MatchesTemplate([]Attribute{
			NewULongAttribute(CKA_CLASS, uint64(CKO_PRIVATE_KEY)),
			NewULongAttribute(CKA_KEY_TYPE, uint64(CKK_RSA)),
		}))
	})

	t.Run("a four-byte template still matches", func(t *testing.T) {
		assert.True(t, obj.MatchesTemplate([]Attribute{
			{Type: CKA_CLASS, Value: []byte{0x03, 0x00, 0x00, 0x00}},
			{Type: CKA_KEY_TYPE, Value: []byte{0x00, 0x00, 0x00, 0x00}},
		}))
	})

	t.Run("a template naming a different value does not match", func(t *testing.T) {
		assert.False(t, obj.MatchesTemplate([]Attribute{
			{Type: CKA_CLASS, Value: []byte{0x02, 0x00, 0x00, 0x00}},
		}), "CKO_PUBLIC_KEY must not match a private key object")
	})
}

// TestCompleteKeyTemplate_SuppliesNativeWidthULongs proves the class and key
// type the token fills in for a C_GenerateKey or C_GenerateKeyPair template are
// whole CK_ULONGs before they ever reach the object.
//
// This is the site pkcs11-provider's failure pointed at: the provider states
// neither attribute, so both come from the mechanism rather than the caller.
func TestCompleteKeyTemplate_SuppliesNativeWidthULongs(t *testing.T) {
	t.Run("both are supplied at the native width when the caller omits them", func(t *testing.T) {
		completed := completeKeyTemplate(CKO_PRIVATE_KEY, CKK_EC, nil)

		class := templateValue(t, completed, CKA_CLASS)
		assert.Len(t, class, ckULongSize)
		assert.Equal(t, uint64(CKO_PRIVATE_KEY), binary.LittleEndian.Uint64(class))

		keyType := templateValue(t, completed, CKA_KEY_TYPE)
		assert.Len(t, keyType, ckULongSize)
		assert.Equal(t, uint64(CKK_EC), binary.LittleEndian.Uint64(keyType))
	})

	t.Run("the caller's own values are left exactly as stated", func(t *testing.T) {
		// The token supplies nothing here, so it must rewrite nothing: the
		// width of a value the caller stated is normalised once, where it is
		// stored, and not silently in the template the caller can still read.
		stated := []Attribute{
			{Type: CKA_CLASS, Value: []byte{0x03, 0x00, 0x00, 0x00}},
			{Type: CKA_KEY_TYPE, Value: []byte{0x00, 0x00, 0x00, 0x00}},
		}
		completed := completeKeyTemplate(CKO_SECRET_KEY, CKK_AES, stated)

		assert.Equal(t, stated[0].Value, templateValue(t, completed, CKA_CLASS))
		assert.Equal(t, stated[1].Value, templateValue(t, completed, CKA_KEY_TYPE))
	})
}

// templateValue returns the value of one attribute of a template, failing the
// test if the template does not carry it.
func templateValue(t *testing.T, template []Attribute, attrType AttributeType) []byte {
	t.Helper()
	for _, attr := range template {
		if attr.Type == attrType {
			return attr.Value
		}
	}
	t.Fatalf("the template carries no %s", attrType.String())
	return nil
}

// TestULongAttributes_NamesEveryCKULONGTheTokenWrites pins the membership the
// width rule is derived from.
//
// normalizeULongWidth and NewUint32Attribute both read this map, so an
// attribute missing from it is stored at whatever width it was built with. Each
// of these is an attribute the token itself writes onto an object the
// application never supplied a template value for, which is exactly the
// position CKA_CLASS was in when pkcs11-provider read four bytes of it.
func TestULongAttributes_NamesEveryCKULONGTheTokenWrites(t *testing.T) {
	for _, attrType := range []AttributeType{
		CKA_CLASS,            // CK_OBJECT_CLASS, completeKeyTemplate and NewObject
		CKA_KEY_TYPE,         // CK_KEY_TYPE, completeKeyTemplate and NewKeyObject
		CKA_CERTIFICATE_TYPE, // CK_CERTIFICATE_TYPE, the PIV certificate objects
		CKA_VALUE_LEN,        // CK_ULONG, every derived and decapsulated key
		CKA_PARAMETER_SET,    // CK_PARAMETER_SET_TYPE, every ML-DSA/ML-KEM key pair
		CKA_KEY_GEN_MECHANISM,
		CKA_MODULUS_BITS,
	} {
		assert.Truef(t, ulongAttributes[attrType],
			"%s carries a CK_ULONG and must be stored at the native width", attrType.String())
	}

	t.Run("a byte-array attribute is not in the map", func(t *testing.T) {
		// Widening one of these would append zero bytes to a value whose length
		// is part of what it says.
		for _, attrType := range []AttributeType{CKA_ID, CKA_VALUE, CKA_LABEL, CKA_EC_POINT, CKA_MODULUS} {
			assert.Falsef(t, ulongAttributes[attrType],
				"%s is a byte array and must never be re-encoded", attrType.String())
		}
	})
}
