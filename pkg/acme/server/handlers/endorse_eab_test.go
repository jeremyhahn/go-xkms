//go:build codec_json

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

package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEABDAO implements GenericDAO[*entities.ExternalAccountBinding] for testing.
type MockEABDAO struct {
	bindings  map[string]*entities.ExternalAccountBinding
	getError  error
	saveError error
	deleteErr error
}

func NewMockEABDAO() *MockEABDAO {
	return &MockEABDAO{
		bindings: make(map[string]*entities.ExternalAccountBinding),
	}
}

func (m *MockEABDAO) Save(_ context.Context, binding *entities.ExternalAccountBinding) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.bindings[binding.ID] = binding
	return nil
}

func (m *MockEABDAO) SaveWithCondition(_ context.Context, _ *entities.ExternalAccountBinding, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *MockEABDAO) SaveIfAbsent(_ context.Context, _ *entities.ExternalAccountBinding) (bool, error) {
	panic("not implemented")
}

func (m *MockEABDAO) Get(_ context.Context, id uint64) (*entities.ExternalAccountBinding, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, binding := range m.bindings {
		if binding.EntityID() == id {
			return binding, nil
		}
	}
	return nil, qrdbsdk.DAONotFoundError{EntityType: "eab"}
}

func (m *MockEABDAO) Delete(_ context.Context, binding *entities.ExternalAccountBinding) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.bindings, binding.ID)
	return nil
}

func (m *MockEABDAO) Count(_ context.Context) (int, error) {
	return len(m.bindings), nil
}

func (m *MockEABDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *MockEABDAO) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbsdk.PagerFunc[*entities.ExternalAccountBinding]) error {
	panic("not implemented")
}

func (m *MockEABDAO) EntityType() string {
	return "eab"
}

func (m *MockEABDAO) QueryByIndex(_ context.Context, fieldName string, value interface{}) ([]*entities.ExternalAccountBinding, error) {
	if fieldName == "ID" {
		kid, ok := value.(string)
		if ok {
			if b, found := m.bindings[kid]; found {
				return []*entities.ExternalAccountBinding{b}, nil
			}
		}
	}
	return nil, nil
}

func (m *MockEABDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *MockEABDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	return nil, nil
}

func (m *MockEABDAO) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.ExternalAccountBinding, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if fieldName == "ID" {
		kid, ok := value.(string)
		if ok {
			if b, found := m.bindings[kid]; found {
				return b, nil
			}
		}
	}
	return nil, qrdbsdk.DAONotFoundError{EntityType: "eab"}
}

func (m *MockEABDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ExternalAccountBinding, error) {
	panic("not implemented")
}

func (m *MockEABDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ExternalAccountBinding], error) {
	panic("not implemented")
}

func (m *MockEABDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *MockEABDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.ExternalAccountBinding] {
	panic("not implemented")
}

// Test helper to create a valid EAB binding for endorse-01.
func createTestEABBinding(kid string, accountID uint64, status string) *entities.ExternalAccountBinding {
	return &entities.ExternalAccountBinding{
		ID:                kid,
		MACKey:            "test-mac-key-base64url",
		MACAlgorithm:      "HS256",
		AccountID:         accountID,
		ExternalAccountID: "ext-account-123",
		Purpose:           entities.EABPurposeEndorse01, // Required for endorse-01
		Status:            status,
		CreatedAt:         time.Now(),
	}
}

// Test helper to create an EAB binding with metadata.
func createTestEABBindingWithMetadata(kid string, accountID uint64, metadata map[string]string) *entities.ExternalAccountBinding {
	binding := createTestEABBinding(kid, accountID, entities.EABStatusUsed)
	binding.Metadata = metadata
	return binding
}

// Test helper to create an ACME account with EAB reference.
func createTestAccountWithEAB(accountID uint64, eabKID string) *entities.ACMEAccount {
	return &entities.ACMEAccount{
		ID:     accountID,
		Status: "valid",
		ExternalAccountBinding: map[string]interface{}{
			"kid": eabKID,
		},
	}
}

// Test helper to create an ACME account without EAB.
func createTestAccountWithoutEAB(accountID uint64) *entities.ACMEAccount {
	return &entities.ACMEAccount{
		ID:     accountID,
		Status: "valid",
	}
}

// --- Tests for EndorseEABValidator ---

func TestEndorseEABValidator_EABNotRequired_AlwaysAuthorized(t *testing.T) {
	dao := NewMockEABDAO()
	validator := NewEndorseEABValidator(dao, false, "")

	account := createTestAccountWithoutEAB(12345)
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.Nil(t, result.Binding)
}

func TestEndorseEABValidator_EABRequired_NoEAB_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	validator := NewEndorseEABValidator(dao, true, "")

	account := createTestAccountWithoutEAB(12345)
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABRequired)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_ValidEAB_Succeeds(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBinding("test-kid-001", 12345, entities.EABStatusUsed)
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-001")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.NotNil(t, result.Binding)
	assert.Equal(t, "test-kid-001", result.Binding.ID)
	assert.Equal(t, "ext-account-123", result.ExternalAccountID)
}

func TestEndorseEABValidator_EABRequired_EABNotFound_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	validator := NewEndorseEABValidator(dao, true, "")

	account := createTestAccountWithEAB(12345, "nonexistent-kid")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABNotFound)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_EABActive_Fails(t *testing.T) {
	// EAB should be in "used" status for endorse-01, not "active"
	dao := NewMockEABDAO()
	binding := createTestEABBinding("test-kid-002", 12345, entities.EABStatusActive)
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-002")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_EABRevoked_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBinding("test-kid-003", 12345, entities.EABStatusRevoked)
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-003")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_WrongAccount_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	// Binding is for account 99999, but we're checking account 12345
	binding := createTestEABBinding("test-kid-004", 99999, entities.EABStatusUsed)
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-004")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Contains(t, err.Error(), "not associated with this account")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_WrongPurpose_Fails(t *testing.T) {
	// EAB with purpose "account-binding" should fail for endorse-01 challenges
	dao := NewMockEABDAO()
	binding := &entities.ExternalAccountBinding{
		ID:                "test-kid-purpose",
		MACKey:            "test-mac-key-base64url",
		MACAlgorithm:      "HS256",
		AccountID:         12345,
		ExternalAccountID: "ext-account-123",
		Purpose:           entities.EABPurposeAccountBinding, // Wrong purpose
		Status:            entities.EABStatusUsed,
		CreatedAt:         time.Now(),
	}
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-purpose")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Contains(t, err.Error(), "account-binding")
	assert.Contains(t, err.Error(), "endorse-01")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_Enroll01Purpose_Fails(t *testing.T) {
	// EAB with purpose "enroll-01" should fail for endorse-01 challenges
	dao := NewMockEABDAO()
	binding := &entities.ExternalAccountBinding{
		ID:                "test-kid-enroll",
		MACKey:            "test-mac-key-base64url",
		MACAlgorithm:      "HS256",
		AccountID:         12345,
		ExternalAccountID: "ext-account-123",
		Purpose:           entities.EABPurposeEnroll01, // Wrong purpose - enroll instead of endorse
		Status:            entities.EABStatusUsed,
		CreatedAt:         time.Now(),
	}
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-enroll")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Contains(t, err.Error(), "enroll-01")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EABRequired_EmptyPurpose_Fails(t *testing.T) {
	// EAB with empty purpose should fail for endorse-01 challenges
	dao := NewMockEABDAO()
	binding := &entities.ExternalAccountBinding{
		ID:                "test-kid-empty-purpose",
		MACKey:            "test-mac-key-base64url",
		MACAlgorithm:      "HS256",
		AccountID:         12345,
		ExternalAccountID: "ext-account-123",
		Purpose:           "", // Empty purpose
		Status:            entities.EABStatusUsed,
		CreatedAt:         time.Now(),
	}
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-empty-purpose")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DeviceID_NoMetadata_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBinding("test-kid-005", 12345, entities.EABStatusUsed)
	// No metadata on binding
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-005")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABDeviceIDRequired)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DeviceID_MetadataKeyMissing_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-006", 12345, map[string]string{
		"other_key": "some-value",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-006")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABDeviceIDRequired)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DeviceID_Match_Succeeds(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-007", 12345, map[string]string{
		"device_id": "device-abc-123",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-007")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-abc-123")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.Equal(t, "device-abc-123", result.AuthorizedDeviceID)
}

func TestEndorseEABValidator_DeviceID_CaseInsensitive_Succeeds(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-008", 12345, map[string]string{
		"device_id": "DEVICE-ABC-123",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-008")

	// Device ID is lowercase but metadata is uppercase
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-abc-123")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
}

func TestEndorseEABValidator_DeviceID_Mismatch_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-009", 12345, map[string]string{
		"device_id": "authorized-device-xyz",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-009")

	// Trying with a different device ID
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "unauthorized-device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Unauthorized, caErr.Type)
	assert.Contains(t, err.Error(), "authorized-device-xyz")
	assert.Contains(t, err.Error(), "unauthorized-device-123")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DeviceID_HexValues_Succeeds(t *testing.T) {
	// Test with TPM EK public key hash (hex-encoded)
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-010", 12345, map[string]string{
		"ek_pubkey_hash": "A1B2C3D4E5F6789012345678ABCDEF0123456789",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "ek_pubkey_hash")
	account := createTestAccountWithEAB(12345, "test-kid-010")

	// Lowercase hex should match uppercase
	result, err := validator.ValidateEndorseAuthorization(
		context.Background(),
		account,
		"a1b2c3d4e5f6789012345678abcdef0123456789",
	)

	require.NoError(t, err)
	assert.True(t, result.Authorized)
}

func TestEndorseEABValidator_DeviceID_WithWhitespace_Succeeds(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-011", 12345, map[string]string{
		"device_id": "  device-trimmed  ",
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-011")

	// Should match after trimming whitespace
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-trimmed")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
}

// --- New tests to improve coverage ---

func TestEndorseEABValidator_ExtractEABKeyID_Error_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	validator := NewEndorseEABValidator(dao, true, "")

	// Create account with invalid EAB structure that will cause extractEABKeyID to fail
	account := &entities.ACMEAccount{
		ID:     12345,
		Status: "valid",
		ExternalAccountBinding: map[string]interface{}{
			"invalid_field": "no kid here",
		},
	}

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	assert.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.Malformed, caErr.Type)
	assert.Contains(t, err.Error(), "unable to extract key identifier")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_EmptyKID_Fails(t *testing.T) {
	dao := NewMockEABDAO()
	validator := NewEndorseEABValidator(dao, true, "")

	// Create account with empty KID
	account := &entities.ACMEAccount{
		ID:     12345,
		Status: "valid",
		ExternalAccountBinding: map[string]interface{}{
			"kid": "",
		},
	}

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABRequired)
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DAOGetError_Fails(t *testing.T) {
	// Test when DAO returns an error that is NOT ErrExternalAccountBindingNotFound
	dao := NewMockEABDAO()
	dao.getError = errors.New("database connection error")

	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(12345, "test-kid-012")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve EAB binding")
	assert.Contains(t, err.Error(), "database connection error")
	assert.Nil(t, result)
}

func TestEndorseEABValidator_DeviceID_EmptyValue_Fails(t *testing.T) {
	// Test when metadata key exists but has empty string value
	dao := NewMockEABDAO()
	binding := createTestEABBindingWithMetadata("test-kid-013", 12345, map[string]string{
		"device_id": "", // Empty string
	})
	require.NoError(t, dao.Save(context.Background(), binding))

	validator := NewEndorseEABValidator(dao, true, "device_id")
	account := createTestAccountWithEAB(12345, "test-kid-013")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "device-123")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEndorseEABDeviceIDRequired)
	assert.Nil(t, result)
}

// --- Tests for extractEABKeyID ---

func TestExtractEABKeyID_FromMap(t *testing.T) {
	eabRef := map[string]interface{}{
		"kid": "test-kid-from-map",
	}

	kid, err := extractEABKeyID(eabRef)

	require.NoError(t, err)
	assert.Equal(t, "test-kid-from-map", kid)
}

func TestExtractEABKeyID_FromString(t *testing.T) {
	eabRef := "direct-kid-string"

	kid, err := extractEABKeyID(eabRef)

	require.NoError(t, err)
	assert.Equal(t, "direct-kid-string", kid)
}

func TestExtractEABKeyID_Nil(t *testing.T) {
	kid, err := extractEABKeyID(nil)

	require.NoError(t, err)
	assert.Equal(t, "", kid)
}

func TestExtractEABKeyID_InvalidType(t *testing.T) {
	// An interface{} that can't be parsed as a map with kid
	eabRef := 12345 // int

	_, err := extractEABKeyID(eabRef)

	require.Error(t, err)
	// The JSON unmarshal will fail for numeric values
	assert.Contains(t, err.Error(), "failed to unmarshal EAB reference")
}

func TestExtractEABKeyID_MapWithoutKid(t *testing.T) {
	// Map without a kid field
	eabRef := map[string]interface{}{
		"other_field": "some_value",
	}

	_, err := extractEABKeyID(eabRef)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to extract key identifier")
}

func TestExtractEABKeyID_MapWithProtectedHeader(t *testing.T) {
	// Map with a base64url-encoded protected header containing kid
	// {"kid": "test-kid-from-protected"}
	// base64url encoded: eyJraWQiOiJ0ZXN0LWtpZC1mcm9tLXByb3RlY3RlZCJ9
	eabRef := map[string]interface{}{
		"protected": "eyJraWQiOiJ0ZXN0LWtpZC1mcm9tLXByb3RlY3RlZCJ9",
	}

	kid, err := extractEABKeyID(eabRef)

	require.NoError(t, err)
	assert.Equal(t, "test-kid-from-protected", kid)
}

func TestExtractEABKeyID_StructWithKidField(t *testing.T) {
	// Struct-like type that can be JSON marshaled/unmarshaled
	type eabStruct struct {
		Kid string `json:"kid"`
	}
	eabRef := eabStruct{Kid: "test-kid-from-struct"}

	kid, err := extractEABKeyID(eabRef)

	require.NoError(t, err)
	assert.Equal(t, "test-kid-from-struct", kid)
}

func TestExtractEABKeyID_MapWithKidNonString(t *testing.T) {
	// Map with kid field that's not a string
	eabRef := map[string]interface{}{
		"kid": 12345, // integer instead of string
	}

	_, err := extractEABKeyID(eabRef)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to extract key identifier")
}

// --- Tests for extractKIDFromProtected ---

func TestExtractKIDFromProtected_ValidHeader(t *testing.T) {
	// {"kid": "my-key-id"}
	// base64url encoded: eyJraWQiOiJteS1rZXktaWQifQ
	protected := "eyJraWQiOiJteS1rZXktaWQifQ"

	kid, err := extractKIDFromProtected(protected)

	require.NoError(t, err)
	assert.Equal(t, "my-key-id", kid)
}

func TestExtractKIDFromProtected_NotString(t *testing.T) {
	// Protected header is not a string
	protected := 12345

	_, err := extractKIDFromProtected(protected)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "protected header is not a string")
}

func TestExtractKIDFromProtected_InvalidBase64(t *testing.T) {
	// Invalid base64 encoding
	protected := "not-valid-base64!!!"

	_, err := extractKIDFromProtected(protected)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode protected header")
}

func TestExtractKIDFromProtected_InvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON content
	// base64url of "not json"
	protected := "bm90IGpzb24"

	_, err := extractKIDFromProtected(protected)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal protected header")
}

func TestExtractKIDFromProtected_NoKidInHeader(t *testing.T) {
	// Valid JSON but no kid field
	// {"alg": "HS256"}
	// base64url encoded: eyJhbGciOiJIUzI1NiJ9
	protected := "eyJhbGciOiJIUzI1NiJ9"

	_, err := extractKIDFromProtected(protected)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid not found in protected header")
}

func TestExtractKIDFromProtected_KidNotString(t *testing.T) {
	// kid is present but not a string
	// {"kid": 12345}
	// base64url encoded: eyJraWQiOjEyMzQ1fQ
	protected := "eyJraWQiOjEyMzQ1fQ"

	_, err := extractKIDFromProtected(protected)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid not found in protected header")
}

func TestExtractKIDFromProtected_ComplexHeader(t *testing.T) {
	// Header with multiple fields including kid
	// {"alg": "RS256", "kid": "complex-kid", "typ": "JWT"}
	// base64url encoded: eyJhbGciOiJSUzI1NiIsImtpZCI6ImNvbXBsZXgta2lkIiwidHlwIjoiSldUIn0
	protected := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNvbXBsZXgta2lkIiwidHlwIjoiSldUIn0"

	kid, err := extractKIDFromProtected(protected)

	require.NoError(t, err)
	assert.Equal(t, "complex-kid", kid)
}

// --- Tests for IsEndorseChallengeType ---

func TestIsEndorseChallengeType_Endorse01(t *testing.T) {
	assert.True(t, IsEndorseChallengeType("endorse-01"))
}

func TestIsEndorseChallengeType_Endorse01WithPort(t *testing.T) {
	assert.True(t, IsEndorseChallengeType("endorse-01-8443"))
}

func TestIsEndorseChallengeType_HTTP01(t *testing.T) {
	assert.False(t, IsEndorseChallengeType("http-01"))
}

func TestIsEndorseChallengeType_DNS01(t *testing.T) {
	assert.False(t, IsEndorseChallengeType("dns-01"))
}

func TestIsEndorseChallengeType_Enroll01(t *testing.T) {
	assert.False(t, IsEndorseChallengeType("enroll-01"))
}

func TestIsEndorseChallengeType_DeviceAttest01(t *testing.T) {
	assert.False(t, IsEndorseChallengeType("device-attest-01"))
}

// --- Tests for deviceIDMatches ---

func TestDeviceIDMatches_ExactMatch(t *testing.T) {
	assert.True(t, deviceIDMatches("abc123", "abc123"))
}

func TestDeviceIDMatches_CaseInsensitive(t *testing.T) {
	assert.True(t, deviceIDMatches("ABC123", "abc123"))
	assert.True(t, deviceIDMatches("abc123", "ABC123"))
}

func TestDeviceIDMatches_WithWhitespace(t *testing.T) {
	assert.True(t, deviceIDMatches("  abc123  ", "abc123"))
	assert.True(t, deviceIDMatches("abc123", "  abc123  "))
}

func TestDeviceIDMatches_Mismatch(t *testing.T) {
	assert.False(t, deviceIDMatches("abc123", "xyz789"))
}

// --- Tests for EndorseEABAuthorization struct ---

func TestEndorseEABAuthorization_Fields(t *testing.T) {
	binding := createTestEABBinding("auth-kid", 12345, entities.EABStatusUsed)

	auth := &EndorseEABAuthorization{
		Binding:            binding,
		Authorized:         true,
		AuthorizedDeviceID: "device-xyz",
		ExternalAccountID:  "ext-123",
	}

	assert.True(t, auth.Authorized)
	assert.Equal(t, "auth-kid", auth.Binding.ID)
	assert.Equal(t, "device-xyz", auth.AuthorizedDeviceID)
	assert.Equal(t, "ext-123", auth.ExternalAccountID)
}

// --- Error type tests ---

func TestEABErrors_AreDistinct(t *testing.T) {
	// Ensure all error types are distinct and can be identified
	errors := []error{
		ErrEndorseEABRequired,
		ErrEndorseEABNotFound,
		ErrEndorseEABInvalid,
		ErrEndorseEABPurposeMismatch,
		ErrEndorseEABDeviceMismatch,
		ErrEndorseEABDeviceIDRequired,
	}

	for i, err1 := range errors {
		for j, err2 := range errors {
			if i != j {
				assert.NotEqual(t, err1.Error(), err2.Error(),
					"Errors at index %d and %d should be distinct", i, j)
			}
		}
	}
}

// --- Integration-style tests ---

func TestEndorseEABValidator_FullWorkflow_EnterpriseDeviceProvisioning(t *testing.T) {
	// Simulate enterprise device provisioning workflow:
	// 1. Admin creates EAB binding with device serial number
	// 2. Device registers ACME account with EAB
	// 3. Device attempts endorse-01 challenge
	// 4. Server validates EAB and device ID

	dao := NewMockEABDAO()

	// Step 1: Admin creates EAB binding with device metadata
	binding := &entities.ExternalAccountBinding{
		ID:                "enterprise-binding-001",
		MACKey:            "base64url-encoded-key",
		MACAlgorithm:      "HS256",
		AccountID:         54321,
		ExternalAccountID: "enterprise-customer-abc",
		Purpose:           entities.EABPurposeEndorse01, // Required for endorse-01
		Status:            entities.EABStatusUsed,
		CreatedAt:         time.Now(),
		Metadata: map[string]string{
			"serial_number":  "TPM-SN-12345678",
			"device_model":   "Enterprise Server X100",
			"department":     "IT Operations",
			"provisioned_by": "admin@example.com",
		},
	}
	require.NoError(t, dao.Save(context.Background(), binding))

	// Step 2: Account was registered with EAB (simulated)
	account := &entities.ACMEAccount{
		ID:     54321,
		Status: "valid",
		ExternalAccountBinding: map[string]interface{}{
			"kid": "enterprise-binding-001",
		},
	}

	// Step 3 & 4: Device attempts endorse-01, server validates
	validator := NewEndorseEABValidator(dao, true, "serial_number")
	result, err := validator.ValidateEndorseAuthorization(
		context.Background(),
		account,
		"TPM-SN-12345678", // Device provides its serial number
	)

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.Equal(t, "enterprise-customer-abc", result.ExternalAccountID)
	assert.Equal(t, "TPM-SN-12345678", result.AuthorizedDeviceID)
	assert.Equal(t, "IT Operations", result.Binding.Metadata["department"])
}

func TestEndorseEABValidator_FullWorkflow_BatchDeviceProvisioning(t *testing.T) {
	// Simulate batch device provisioning where multiple devices share
	// the same EAB but device ID validation is not required

	dao := NewMockEABDAO()

	// Admin creates EAB binding for a batch of devices (no specific device ID)
	binding := &entities.ExternalAccountBinding{
		ID:                "batch-binding-001",
		MACKey:            "base64url-encoded-key",
		MACAlgorithm:      "HS256",
		AccountID:         11111,
		ExternalAccountID: "manufacturing-batch-2024-Q4",
		Purpose:           entities.EABPurposeEndorse01, // Required for endorse-01
		Status:            entities.EABStatusUsed,
		CreatedAt:         time.Now(),
		Metadata: map[string]string{
			"batch_id":       "MFG-2024-Q4-LOT-A",
			"authorized_qty": "1000",
		},
	}
	require.NoError(t, dao.Save(context.Background(), binding))

	account := createTestAccountWithEAB(11111, "batch-binding-001")

	// Device ID validation NOT configured - any device with this account can enroll
	validator := NewEndorseEABValidator(dao, true, "") // Empty deviceIDMetaKey

	// Any device in the batch can use this
	result, err := validator.ValidateEndorseAuthorization(
		context.Background(),
		account,
		"any-device-identifier", // Not validated
	)

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.Equal(t, "manufacturing-batch-2024-Q4", result.ExternalAccountID)
	assert.Empty(t, result.AuthorizedDeviceID) // Not set when not validating
}

// --- Tests for EndorseEABValidator.BoundTPMManufacturer ---

func TestEndorseEABValidator_BoundTPMManufacturer_ReturnsBoundCode(t *testing.T) {
	dao := NewMockEABDAO()
	binding := createTestEABBinding("mfg-kid-001", 12345, entities.EABStatusUsed)
	binding.DeviceInfo = &entities.EABDeviceInfo{TPMManufacturer: "id:49465800"}
	require.NoError(t, dao.Save(context.Background(), binding))
	validator := NewEndorseEABValidator(dao, false, "")

	got, err := validator.BoundTPMManufacturer(context.Background(), createTestAccountWithEAB(12345, "mfg-kid-001"))

	require.NoError(t, err)
	assert.Equal(t, "id:49465800", got)
}

func TestEndorseEABValidator_BoundTPMManufacturer_NothingBound(t *testing.T) {
	dao := NewMockEABDAO()
	require.NoError(t, dao.Save(context.Background(), createTestEABBinding("mfg-kid-002", 12345, entities.EABStatusUsed)))
	validator := NewEndorseEABValidator(dao, false, "")

	got, err := validator.BoundTPMManufacturer(context.Background(), createTestAccountWithoutEAB(12345))
	require.NoError(t, err)
	assert.Empty(t, got, "an account with no binding binds no manufacturer")

	got, err = validator.BoundTPMManufacturer(context.Background(), createTestAccountWithEAB(12345, "mfg-kid-002"))
	require.NoError(t, err)
	assert.Empty(t, got, "a binding with no device info binds no manufacturer")
}

func TestEndorseEABValidator_BoundTPMManufacturer_Errors(t *testing.T) {
	dao := NewMockEABDAO()
	require.NoError(t, dao.Save(context.Background(), createTestEABBinding("mfg-kid-003", 99999, entities.EABStatusUsed)))
	validator := NewEndorseEABValidator(dao, false, "")

	_, err := validator.BoundTPMManufacturer(context.Background(), createTestAccountWithEAB(12345, "missing-kid"))
	assert.ErrorIs(t, err, ErrEndorseEABNotFound)

	_, err = validator.BoundTPMManufacturer(context.Background(), createTestAccountWithEAB(12345, "mfg-kid-003"))
	assert.ErrorIs(t, err, ErrEndorseEABInvalid)

	dao.getError = errors.New("storage offline")
	_, err = validator.BoundTPMManufacturer(context.Background(), createTestAccountWithEAB(12345, "mfg-kid-003"))
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.StorageFailure, caErr.Type)
}
