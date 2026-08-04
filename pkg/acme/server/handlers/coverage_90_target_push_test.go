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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseSpecIDEventTooShortForSignature tests parseSpecIDEvent with data too short
func TestParseSpecIDEventTooShortForSignature(t *testing.T) {
	// Data too short for even the signature
	data := []byte{'S', 'p', 'e', 'c'}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseSpecIDEventInvalidSignaturePush tests parseSpecIDEvent with wrong signature
func TestParseSpecIDEventInvalidSignaturePush(t *testing.T) {
	// Invalid signature - not starting with "Spec ID Event03"
	data := []byte{
		'W', 'r', 'o', 'n', 'g', ' ', 'S', 'i',
		'g', 'n', 'a', 't', 'u', 'r', 'e', 0,
		// padding to make it long enough
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x02,
		0x00,
		0x04,
		0x01, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x14, 0x00,
		0x00,
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseSpecIDEventTruncatedAlgorithmsPush tests parseSpecIDEvent with truncated algorithm data
func TestParseSpecIDEventTruncatedAlgorithmsPush(t *testing.T) {
	// Valid signature but truncated before algorithm data
	data := []byte{
		// Signature: "Spec ID Event03" + null
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		// platformClass (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// specVersionMinor (1 byte)
		0x00,
		// specVersionMajor (1 byte)
		0x02,
		// specErrata (1 byte)
		0x00,
		// uintnSize (1 byte)
		0x04,
		// numberOfAlgorithms (4 bytes) - indicates 2 algorithms
		0x02, 0x00, 0x00, 0x00,
		// Only one algorithm provided (truncated)
		0x04, 0x00, 0x14, 0x00,
		// Missing second algorithm - truncated
	}

	_, err := parseSpecIDEvent(data)
	assert.Error(t, err)
}

// TestParseCryptoAgileEventTruncatedDigestPush tests parseCryptoAgileEvent with truncated digest
func TestParseCryptoAgileEventTruncatedDigestPush(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20}, // SHA-1
	}

	// Event with truncated digest
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID (SHA-1)
		0x04, 0x00,
		// Only 5 bytes of digest instead of 20
		0x01, 0x02, 0x03, 0x04, 0x05,
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestParseCryptoAgileEventUnknownAlgorithmPush tests parseCryptoAgileEvent with unknown algorithm
func TestParseCryptoAgileEventUnknownAlgorithmPush(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20}, // SHA-1
	}

	// Event with unknown algorithm ID in digest
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID (unknown - 0xFFFF)
		0xFF, 0xFF,
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestNewQuoteValidationHookNonTCGCSRPush tests quote validation hook for non-TCG CSR
func TestNewQuoteValidationHookNonTCGCSRPush(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false, // Not a TCG CSR
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip for non-TCG CSR
}

// TestNewQuoteValidationHookEmptyProdCaDataPush tests quote validation hook with empty ProdCaData
func TestNewQuoteValidationHookEmptyProdCaDataPush(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil, // Empty ProdCaData
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when no ProdCaData
}

// TestNewEventLogValidationHookNonTCGPush tests event log validation hook for non-TCG
func TestNewEventLogValidationHookNonTCGPush(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents:  nil,
		ForbiddenEvents: nil,
	}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip for non-TCG
}

// TestNewEventLogValidationHookNilTCGDataPush tests event log validation hook with nil TCGData
func TestNewEventLogValidationHookNilTCGDataPush(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents:  nil,
		ForbiddenEvents: nil,
	}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when TCGData is nil
}

// TestNewEventLogValidationHookEmptyProdCaDataPush tests event log validation with empty ProdCaData
func TestNewEventLogValidationHookEmptyProdCaDataPush(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents:  nil,
		ForbiddenEvents: nil,
	}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil,
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when ProdCaData is empty
}

func TestNewDeviceProfileHookNonTCGPush(t *testing.T) {
	lookupFunc := func(serial, model string) (*DeviceProfile, error) {
		return &DeviceProfile{
			ProductSerial: serial,
			ProductModel:  model,
		}, nil
	}
	hook := NewDeviceProfileHook(lookupFunc)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip for non-TCG
}

// TestNewDeviceProfileHookNilTCGDataPush tests device profile hook with nil TCGData
func TestNewDeviceProfileHookNilTCGDataPush(t *testing.T) {
	lookupFunc := func(serial, model string) (*DeviceProfile, error) {
		return &DeviceProfile{
			ProductSerial: serial,
			ProductModel:  model,
		}, nil
	}
	hook := NewDeviceProfileHook(lookupFunc)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when TCGData is nil
}

// TestNewDeviceProfileHookEmptyProdCaDataPush tests device profile hook with empty ProdCaData
func TestNewDeviceProfileHookEmptyProdCaDataPush(t *testing.T) {
	lookupFunc := func(serial, model string) (*DeviceProfile, error) {
		return &DeviceProfile{
			ProductSerial: serial,
			ProductModel:  model,
		}, nil
	}
	hook := NewDeviceProfileHook(lookupFunc)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil,
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when ProdCaData is empty
}

// TestParseLegacyEventTruncatedPush tests parseLegacyEvent with truncated data
func TestParseLegacyEventTruncatedPush(t *testing.T) {
	// Data too short for a legacy event (needs at least 28 bytes for header + minimal digest)
	data := []byte{
		// PCR index (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// Event type (4 bytes)
		0x01, 0x00, 0x00, 0x00,
		// Only partial data - missing digest and event data
	}

	reader := bytes.NewReader(data)
	_, err := parseLegacyEvent(reader)
	assert.Error(t, err)
}

// TestEventTypeToStringPush tests eventTypeToString function
func TestEventTypeToStringPush(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		contains string
	}{
		{"EV_POST_CODE", 0x00000001, "EV_POST_CODE"},
		{"EV_NO_ACTION", 0x00000003, "EV_NO_ACTION"},
		{"EV_SEPARATOR", 0x00000004, "EV_SEPARATOR"},
		{"EV_S_CRTM_CONTENTS", 0x00000007, "EV_S_CRTM_CONTENTS"},
		{"EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000001, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{"EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000003, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{"Unknown", 0xFFFFFFFF, "FFFFFFFF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eventTypeToString(tt.input)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestParseCryptoAgileEventTruncatedHeaderPush(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20},
	}

	// Only partial header - missing digest count
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Truncated - no digest count
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)
	assert.Error(t, err)
}

// TestParseCryptoAgileEventZeroDigestCountPush tests parseCryptoAgileEvent with zero digest count
func TestParseCryptoAgileEventZeroDigestCountPush(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20},
	}

	// Event with zero digest count
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count - zero
		0x00, 0x00, 0x00, 0x00,
		// Event data size
		0x04, 0x00, 0x00, 0x00,
		// Event data
		0x01, 0x02, 0x03, 0x04,
	}

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestParseLegacyEventValidPush tests parseLegacyEvent with valid data
func TestParseLegacyEventValidPush(t *testing.T) {
	// Build a valid legacy event
	data := []byte{
		// PCR index (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// Event type (4 bytes) - EV_POST_CODE
		0x01, 0x00, 0x00, 0x00,
	}
	// SHA-1 digest (20 bytes)
	digest := make([]byte, 20)
	data = append(data, digest...)
	// Event data size (4 bytes) - 4 bytes of event data
	data = append(data, 0x04, 0x00, 0x00, 0x00)
	// Event data (4 bytes)
	data = append(data, 0x01, 0x02, 0x03, 0x04)

	reader := bytes.NewReader(data)
	entry, err := parseLegacyEvent(reader)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
	assert.Contains(t, entry.EventType, "EV_POST_CODE")
}

// TestCompareKeyMapsWithDifferentKeys tests compareKeyMaps with different key sets
func TestCompareKeyMapsWithDifferentKeys(t *testing.T) {
	map1 := map[string]interface{}{
		"kty": "EC",
		"x":   "test-x",
	}
	map2 := map[string]interface{}{
		"kty": "EC",
		"y":   "test-y", // Different key
	}

	result := compareKeyMaps(map1, map2)
	assert.False(t, result)
}

// TestSpecIDAlgorithmStruct tests SpecIDAlgorithm struct creation
func TestSpecIDAlgorithmStruct(t *testing.T) {
	alg := SpecIDAlgorithm{
		AlgorithmID: 0x000B,
		DigestSize:  32,
	}

	assert.Equal(t, uint16(0x000B), alg.AlgorithmID)
	assert.Equal(t, uint16(32), alg.DigestSize)
}

// TestPreIssuanceHookContextFields tests PreIssuanceHookContext struct
func TestPreIssuanceHookContextFields(t *testing.T) {
	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  &TCGEnrollmentData{},
	}

	assert.True(t, ctx.IsTCGCSR)
	assert.NotNil(t, ctx.TCGData)
}

// TestTCGEnrollmentDataFields tests TCGEnrollmentData struct
func TestTCGEnrollmentDataFields(t *testing.T) {
	data := &TCGEnrollmentData{
		ProductModel:  "TestModel",
		ProductSerial: "TestSerial",
		ProdCaData:    []byte{0x01, 0x02, 0x03},
	}

	assert.Equal(t, "TestModel", data.ProductModel)
	assert.Equal(t, "TestSerial", data.ProductSerial)
	assert.Len(t, data.ProdCaData, 3)
}

// TestEventLogPolicyFields tests EventLogPolicy struct
func TestEventLogPolicyFields(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents:  []string{"EV_POST_CODE"},
		ForbiddenEvents: []string{"EV_NO_ACTION"},
		MaxEventCount:   100,
	}

	assert.Len(t, policy.RequiredEvents, 1)
	assert.Len(t, policy.ForbiddenEvents, 1)
	assert.Equal(t, 100, policy.MaxEventCount)
}

// TestDeviceProfileFields tests DeviceProfile struct
func TestDeviceProfileFields(t *testing.T) {
	profile := &DeviceProfile{
		ProductSerial: "SERIAL123",
		ProductModel:  "MODEL456",
		ExpectedPCRs:  map[int][]byte{0: {0x01, 0x02}},
	}

	assert.Equal(t, "SERIAL123", profile.ProductSerial)
	assert.Equal(t, "MODEL456", profile.ProductModel)
	assert.Len(t, profile.ExpectedPCRs, 1)
}

// TestPCRPolicyFields tests PCRPolicy struct
func TestPCRPolicyFields(t *testing.T) {
	policy := &PCRPolicy{
		StrictMode: true,
	}

	assert.True(t, policy.StrictMode)
}

// TestParseSpecIDEventWithZeroAlgorithms tests parseSpecIDEvent with zero algorithms
func TestParseSpecIDEventWithZeroAlgorithms(t *testing.T) {
	// Valid signature with zero algorithms
	data := []byte{
		// Signature: "Spec ID Event03" + null
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		// platformClass (4 bytes)
		0x00, 0x00, 0x00, 0x00,
		// specVersionMinor (1 byte)
		0x00,
		// specVersionMajor (1 byte)
		0x02,
		// specErrata (1 byte)
		0x00,
		// uintnSize (1 byte)
		0x04,
		// numberOfAlgorithms (4 bytes) - zero
		0x00, 0x00, 0x00, 0x00,
		// vendorInfoSize (1 byte)
		0x00,
	}

	algorithms, err := parseSpecIDEvent(data)
	assert.NoError(t, err)
	assert.Len(t, algorithms, 0)
}

// TestParseCryptoAgileEventMultipleDigests tests parsing with multiple digests
func TestParseCryptoAgileEventMultipleDigests(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20}, // SHA-1
		{AlgorithmID: 0x000B, DigestSize: 32}, // SHA-256
	}

	// Event with 2 digests
	data := []byte{
		// PCR index
		0x01, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count - 2
		0x02, 0x00, 0x00, 0x00,
		// First digest: SHA-1
		0x04, 0x00,
	}
	// Add 20-byte SHA-1 digest
	sha1Digest := make([]byte, 20)
	data = append(data, sha1Digest...)
	// Second digest: SHA-256
	data = append(data, 0x0B, 0x00)
	sha256Digest := make([]byte, 32)
	data = append(data, sha256Digest...)
	// Event data size
	data = append(data, 0x04, 0x00, 0x00, 0x00)
	// Event data
	data = append(data, 0x01, 0x02, 0x03, 0x04)

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 1, entry.PCRIndex)
}
