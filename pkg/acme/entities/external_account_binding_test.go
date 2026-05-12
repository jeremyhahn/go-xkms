// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package entities

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalAccountBinding_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"active status", EABStatusActive, true},
		{"used status", EABStatusUsed, false},
		{"revoked status", EABStatusRevoked, false},
		{"expired status", EABStatusExpired, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eab := &ExternalAccountBinding{
				Status: tt.status,
			}
			if got := eab.IsActive(); got != tt.expected {
				t.Errorf("IsActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExternalAccountBinding_IsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{"nil expiration", nil, false},
		{"past expiration", &past, true},
		{"future expiration", &future, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eab := &ExternalAccountBinding{
				ExpiresAt: tt.expiresAt,
			}
			if got := eab.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExternalAccountBinding_CanBeUsed(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name      string
		status    string
		expiresAt *time.Time
		expected  bool
	}{
		{"active and not expired", EABStatusActive, &future, true},
		{"active and no expiration", EABStatusActive, nil, true},
		{"active but expired", EABStatusActive, &past, false},
		{"used", EABStatusUsed, nil, false},
		{"revoked", EABStatusRevoked, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eab := &ExternalAccountBinding{
				Status:    tt.status,
				ExpiresAt: tt.expiresAt,
			}
			if got := eab.CanBeUsed(); got != tt.expected {
				t.Errorf("CanBeUsed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExternalAccountBinding_MarkUsed(t *testing.T) {
	eab := &ExternalAccountBinding{
		ID:     "test-kid",
		Status: EABStatusActive,
	}

	accountID := uint64(12345)
	eab.MarkUsed(accountID)

	if eab.Status != EABStatusUsed {
		t.Errorf("Status = %v, want %v", eab.Status, EABStatusUsed)
	}

	if eab.AccountID != accountID {
		t.Errorf("AccountID = %v, want %v", eab.AccountID, accountID)
	}

	if eab.UsedAt == nil {
		t.Error("UsedAt should not be nil")
	}
}

func TestExternalAccountBinding_Constants(t *testing.T) {
	// Verify constant values match expected strings
	if EABStatusActive != "active" {
		t.Errorf("EABStatusActive = %v, want 'active'", EABStatusActive)
	}
	if EABStatusUsed != "used" {
		t.Errorf("EABStatusUsed = %v, want 'used'", EABStatusUsed)
	}
	if EABStatusRevoked != "revoked" {
		t.Errorf("EABStatusRevoked = %v, want 'revoked'", EABStatusRevoked)
	}
	if EABStatusExpired != "expired" {
		t.Errorf("EABStatusExpired = %v, want 'expired'", EABStatusExpired)
	}
}

func TestExternalAccountBindingJWS_Fields(t *testing.T) {
	// Test that the JWS structure can be created and fields accessed
	jws := ExternalAccountBindingJWS{
		Protected: "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidXJsIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hY21lL25ldy1hY2NvdW50In0",
		Payload:   "eyJrdHkiOiJSU0EiLCJuIjoiMDJZTjdLZXkiLCJlIjoiQVFBQiJ9",
		Signature: "dG8fI2LMHXKwU5K8SxJBGP6rKrIFhLCyNYQOl0gXc_c",
	}

	if jws.Protected == "" {
		t.Error("Protected should not be empty")
	}
	if jws.Payload == "" {
		t.Error("Payload should not be empty")
	}
	if jws.Signature == "" {
		t.Error("Signature should not be empty")
	}
}

func TestExternalAccountBindingProtectedHeader_Fields(t *testing.T) {
	header := ExternalAccountBindingProtectedHeader{
		Alg: "HS256",
		KID: "test-kid",
		URL: "https://example.com/acme/new-account",
	}

	if header.Alg != "HS256" {
		t.Errorf("Alg = %v, want 'HS256'", header.Alg)
	}
	if header.KID != "test-kid" {
		t.Errorf("KID = %v, want 'test-kid'", header.KID)
	}
	if header.URL != "https://example.com/acme/new-account" {
		t.Errorf("URL = %v, want 'https://example.com/acme/new-account'", header.URL)
	}
}

// Tests consolidated from coverage_boost_test.go

func TestEABDeviceInfo_Fields(t *testing.T) {
	deviceInfo := &EABDeviceInfo{
		DeviceID:           "device-001",
		Manufacturer:       "Acme Corp",
		Model:              "Widget Pro",
		EKPublicKeyHash:    "abc123def456",
		TPMManufacturer:    "TPM Inc",
		TPMFirmwareVersion: "1.2.3",
		Metadata: map[string]string{
			"location": "datacenter-1",
			"rack":     "A42",
		},
	}

	assert.Equal(t, "device-001", deviceInfo.DeviceID)
	assert.Equal(t, "Acme Corp", deviceInfo.Manufacturer)
	assert.Equal(t, "Widget Pro", deviceInfo.Model)
	assert.Equal(t, "abc123def456", deviceInfo.EKPublicKeyHash)
	assert.Equal(t, "TPM Inc", deviceInfo.TPMManufacturer)
	assert.Equal(t, "1.2.3", deviceInfo.TPMFirmwareVersion)
	assert.Equal(t, "datacenter-1", deviceInfo.Metadata["location"])
	assert.Equal(t, "A42", deviceInfo.Metadata["rack"])
}

func TestEABDeviceInfo_JSONMarshaling(t *testing.T) {
	original := &EABDeviceInfo{
		DeviceID:           "device-002",
		Manufacturer:       "Test Mfg",
		Model:              "TestModel",
		EKPublicKeyHash:    "hash123",
		TPMManufacturer:    "TPM Mfg",
		TPMFirmwareVersion: "2.0.0",
		Metadata: map[string]string{
			"key": "value",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded EABDeviceInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.DeviceID, decoded.DeviceID)
	assert.Equal(t, original.Manufacturer, decoded.Manufacturer)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.EKPublicKeyHash, decoded.EKPublicKeyHash)
	assert.Equal(t, original.TPMManufacturer, decoded.TPMManufacturer)
	assert.Equal(t, original.TPMFirmwareVersion, decoded.TPMFirmwareVersion)
	assert.Equal(t, original.Metadata["key"], decoded.Metadata["key"])
}

func TestEABDeviceInfo_EmptyFields(t *testing.T) {
	deviceInfo := &EABDeviceInfo{}

	assert.Empty(t, deviceInfo.DeviceID)
	assert.Empty(t, deviceInfo.Manufacturer)
	assert.Empty(t, deviceInfo.Model)
	assert.Empty(t, deviceInfo.EKPublicKeyHash)
	assert.Empty(t, deviceInfo.TPMManufacturer)
	assert.Empty(t, deviceInfo.TPMFirmwareVersion)
	assert.Nil(t, deviceInfo.Metadata)
}

func TestEABPurposeConstants(t *testing.T) {
	assert.Equal(t, "account-binding", EABPurposeAccountBinding)
	assert.Equal(t, "endorse-01", EABPurposeEndorse01)
	assert.Equal(t, "enroll-01", EABPurposeEnroll01)
}

func TestExternalAccountBinding_WithDeviceInfo(t *testing.T) {
	eab := &ExternalAccountBinding{
		ID:           "test-kid",
		MACKey:       "test-mac-key",
		MACAlgorithm: "HS256",
		Status:       EABStatusActive,
		Purpose:      EABPurposeEndorse01,
		DeviceInfo: &EABDeviceInfo{
			DeviceID:        "dev-123",
			Manufacturer:    "TestMfg",
			EKPublicKeyHash: "hash-abc",
		},
		CreatedAt: time.Now(),
	}

	assert.NotNil(t, eab.DeviceInfo)
	assert.Equal(t, "dev-123", eab.DeviceInfo.DeviceID)
	assert.Equal(t, "TestMfg", eab.DeviceInfo.Manufacturer)
	assert.Equal(t, "hash-abc", eab.DeviceInfo.EKPublicKeyHash)
	assert.Equal(t, EABPurposeEndorse01, eab.Purpose)
}

func TestExternalAccountBinding_AllPurposes(t *testing.T) {
	purposes := []string{
		EABPurposeAccountBinding,
		EABPurposeEndorse01,
		EABPurposeEnroll01,
	}

	for _, purpose := range purposes {
		t.Run(purpose, func(t *testing.T) {
			eab := &ExternalAccountBinding{
				ID:      "kid-" + purpose,
				Purpose: purpose,
				Status:  EABStatusActive,
			}
			assert.Equal(t, purpose, eab.Purpose)
			assert.True(t, eab.IsActive())
		})
	}
}

func TestExternalAccountBindingProtectedHeader_WithNonce(t *testing.T) {
	// RFC 8555 Section 7.3.4 specifies nonce MUST NOT be present
	// This test verifies the field exists for detection/validation purposes
	header := ExternalAccountBindingProtectedHeader{
		Alg:   "HS256",
		KID:   "test-kid",
		URL:   "https://example.com/acme/new-account",
		Nonce: "invalid-nonce-should-be-rejected",
	}

	assert.Equal(t, "invalid-nonce-should-be-rejected", header.Nonce)
}

func TestExternalAccountBinding_FullLifecycle(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)

	// Create new EAB
	eab := &ExternalAccountBinding{
		ID:                "lifecycle-kid",
		MACKey:            "secret-mac-key",
		MACAlgorithm:      "HS256",
		ExternalAccountID: "ext-acct-123",
		TenantID:          "tenant-1",
		CreatedBy:         "admin-user",
		Purpose:           EABPurposeAccountBinding,
		Status:            EABStatusActive,
		Contact:           []string{"mailto:admin@example.com"},
		CreatedAt:         now,
		ExpiresAt:         &future,
		Metadata: map[string]string{
			"department": "engineering",
		},
	}

	// Verify initial state
	assert.True(t, eab.IsActive())
	assert.False(t, eab.IsExpired())
	assert.True(t, eab.CanBeUsed())
	assert.Nil(t, eab.UsedAt)
	assert.Zero(t, eab.AccountID)

	// Use the EAB
	accountID := uint64(999)
	eab.MarkUsed(accountID)

	// Verify used state
	assert.False(t, eab.IsActive())
	assert.Equal(t, EABStatusUsed, eab.Status)
	assert.Equal(t, accountID, eab.AccountID)
	assert.NotNil(t, eab.UsedAt)
	assert.False(t, eab.CanBeUsed())
}

func TestExternalAccountBinding_JSONWithDeviceInfo(t *testing.T) {
	now := time.Now()
	eab := &ExternalAccountBinding{
		ID:           "json-kid",
		MACKey:       "mac-key",
		MACAlgorithm: "HS256",
		Status:       EABStatusActive,
		Purpose:      EABPurposeEnroll01,
		CreatedAt:    now,
		DeviceInfo: &EABDeviceInfo{
			DeviceID:        "device-json-test",
			Manufacturer:    "JsonMfg",
			Model:           "JsonModel",
			EKPublicKeyHash: "json-hash",
		},
	}

	data, err := json.Marshal(eab)
	require.NoError(t, err)

	var decoded ExternalAccountBinding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, eab.ID, decoded.ID)
	assert.Equal(t, eab.Purpose, decoded.Purpose)
	require.NotNil(t, decoded.DeviceInfo)
	assert.Equal(t, "device-json-test", decoded.DeviceInfo.DeviceID)
	assert.Equal(t, "JsonMfg", decoded.DeviceInfo.Manufacturer)
}

func TestExternalAccountBinding_EntityID(t *testing.T) {
	eab := &ExternalAccountBinding{
		ID: "test-kid-abc",
	}

	id := eab.EntityID()

	// Must match FNV-1a hash of the ID string
	expected := StringToEntityID("test-kid-abc")
	assert.Equal(t, expected, id)
	assert.NotZero(t, id)
}

func TestExternalAccountBinding_EntityID_CachedNumericID(t *testing.T) {
	cachedID := uint64(42)
	eab := &ExternalAccountBinding{
		NumericID: cachedID,
		ID:        "test-kid-abc",
	}

	id := eab.EntityID()

	// Must return the cached NumericID without recomputing
	assert.Equal(t, cachedID, id)
}

func TestExternalAccountBinding_SetEntityID(t *testing.T) {
	eab := &ExternalAccountBinding{
		ID: "test-kid-abc",
	}

	newID := uint64(99999)
	eab.SetEntityID(newID)

	assert.Equal(t, newID, eab.NumericID)
	// Subsequent EntityID() calls must return the set value
	assert.Equal(t, newID, eab.EntityID())
}

func TestExternalAccountBinding_EntityID_EmptyID(t *testing.T) {
	eab := &ExternalAccountBinding{}

	id := eab.EntityID()

	// Both NumericID and ID are zero/empty, so EntityID returns 0
	assert.Zero(t, id)
}
