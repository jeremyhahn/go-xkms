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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewNonceHandlerPOSTMethod tests the new-nonce handler with unsupported POST method
func TestNewNonceHandlerPOSTMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	// POST should return Method Not Allowed
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestNewNonceHandlerDELETEMethod tests the new-nonce handler with unsupported DELETE method
func TestNewNonceHandlerDELETEMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	// DELETE should return Method Not Allowed
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestNewNonceHandlerPUTMethod tests the new-nonce handler with unsupported PUT method
func TestNewNonceHandlerPUTMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "https://acme.test.example.com/acme/new-nonce", nil)
	rr := httptest.NewRecorder()

	service.NewNonceHandler(rr, req)

	// PUT should return Method Not Allowed
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestParseSpecIDEventValidMinimalPush tests parseSpecIDEvent with valid minimal data
func TestParseSpecIDEventValidMinimalPush(t *testing.T) {
	// This test provides complete, valid Spec ID Event data
	// "Spec ID Event03" signature + required fields
	data := []byte{
		// Signature: "Spec ID Event03" + null
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		// platformClass (4 bytes, little endian)
		0x00, 0x00, 0x00, 0x00,
		// specVersionMinor (1 byte)
		0x00,
		// specVersionMajor (1 byte)
		0x02,
		// specErrata (1 byte)
		0x00,
		// uintnSize (1 byte)
		0x04,
		// numberOfAlgorithms (4 bytes, little endian)
		0x02, 0x00, 0x00, 0x00,
		// Algorithm 1: SHA-1 (0x0004), digest size 20
		0x04, 0x00, 0x14, 0x00,
		// Algorithm 2: SHA-256 (0x000B), digest size 32
		0x0B, 0x00, 0x20, 0x00,
		// vendorInfoSize (1 byte)
		0x00,
	}

	algorithms, err := parseSpecIDEvent(data)
	assert.NoError(t, err)
	assert.Len(t, algorithms, 2)
	assert.Equal(t, uint16(0x0004), algorithms[0].AlgorithmID)
	assert.Equal(t, uint16(20), algorithms[0].DigestSize)
	assert.Equal(t, uint16(0x000B), algorithms[1].AlgorithmID)
	assert.Equal(t, uint16(32), algorithms[1].DigestSize)
}

// TestDirectoryHandlerReturnsProperStructure tests the directory handler returns proper structure
func TestDirectoryHandlerReturnsProperStructure(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "https://acme.test.example.com/acme/directory", nil)
	rr := httptest.NewRecorder()

	service.DirectoryHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
	// Verify response contains expected directory fields
	body := rr.Body.String()
	assert.Contains(t, body, "newNonce")
	assert.Contains(t, body, "newAccount")
	assert.Contains(t, body, "newOrder")
}

// TestParseCryptoAgileEventValidPush tests parseCryptoAgileEvent with valid data
func TestParseCryptoAgileEventValidPush(t *testing.T) {
	// Build a valid crypto-agile event
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20}, // SHA-1
	}

	// Event structure:
	// - PCR index (4 bytes)
	// - Event type (4 bytes)
	// - Digest count (4 bytes)
	// - For each digest: alg ID (2 bytes) + digest
	// - Event data size (4 bytes)
	// - Event data
	data := []byte{
		// PCR index
		0x00, 0x00, 0x00, 0x00,
		// Event type
		0x01, 0x00, 0x00, 0x00,
		// Digest count
		0x01, 0x00, 0x00, 0x00,
		// Algorithm ID (SHA-1)
		0x04, 0x00,
	}
	// Add 20-byte digest
	digest := make([]byte, 20)
	data = append(data, digest...)
	// Event data size
	data = append(data, 0x04, 0x00, 0x00, 0x00)
	// Event data
	data = append(data, 0x01, 0x02, 0x03, 0x04)

	reader := bytes.NewReader(data)
	entry, err := parseCryptoAgileEvent(reader, algorithms)
	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestNewQuoteValidationHookNilTCGDataPush tests hook with nil TCGData
func TestNewQuoteValidationHookNilTCGDataPush(t *testing.T) {
	hook := NewQuoteValidationHook(nil)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  nil, // Nil TCG data
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when TCGData is nil
}

// TestParseSpecIDEventVendorInfo tests parseSpecIDEvent with vendor info
func TestParseSpecIDEventVendorInfo(t *testing.T) {
	// Create data with vendor info
	data := []byte{
		// Signature: "Spec ID Event03" + null
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
		'E', 'v', 'e', 'n', 't', '0', '3', 0,
		// platformClass (4 bytes, little endian)
		0x00, 0x00, 0x00, 0x00,
		// specVersionMinor (1 byte)
		0x00,
		// specVersionMajor (1 byte)
		0x02,
		// specErrata (1 byte)
		0x00,
		// uintnSize (1 byte)
		0x04,
		// numberOfAlgorithms (4 bytes, little endian)
		0x01, 0x00, 0x00, 0x00,
		// Algorithm 1: SHA-1 (0x0004), digest size 20
		0x04, 0x00, 0x14, 0x00,
		// vendorInfoSize (1 byte) - 4 bytes of vendor info
		0x04,
		// vendor info
		0x01, 0x02, 0x03, 0x04,
	}

	algorithms, err := parseSpecIDEvent(data)
	assert.NoError(t, err)
	assert.Len(t, algorithms, 1)
}

// TestEventLogEntryTypes tests that EventLogEntry can hold various event types
func TestEventLogEntryTypes(t *testing.T) {
	entry := EventLogEntry{
		PCRIndex:  7,
		EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG",
		Digest:    make([]byte, 32),
		EventData: []byte("test data"),
	}

	assert.Equal(t, 7, entry.PCRIndex)
	assert.Equal(t, "EV_EFI_VARIABLE_DRIVER_CONFIG", entry.EventType)
}

// TestEventLogErrorError tests EventLogError.Error method
func TestEventLogErrorError(t *testing.T) {
	err := &EventLogError{Message: "test message"}
	assert.Contains(t, err.Error(), "test message")
}

// TestEventLogErrorIs tests EventLogError.Is method
func TestEventLogErrorIs(t *testing.T) {
	err := &EventLogError{Message: "test error"}

	// EventLogError.Is() checks against ErrEventLogInvalid
	assert.True(t, err.Is(ErrEventLogInvalid))
	assert.False(t, err.Is(ErrQuoteInvalid))
	assert.False(t, err.Is(ErrEventLogParsingFailed))
}

// TestNewPCRValidationHookNonTCG tests PCR validation hook for non-TCG enrollments
func TestNewPCRValidationHookNonTCG(t *testing.T) {
	policy := &PCRPolicy{
		StrictMode: false,
	}
	hook := NewPCRValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip for non-TCG
}

// TestNewPCRValidationHookNilTCGData tests PCR validation hook with nil TCGData
func TestNewPCRValidationHookNilTCGData(t *testing.T) {
	policy := &PCRPolicy{
		StrictMode: false,
	}
	hook := NewPCRValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData:  nil, // Nil TCG data
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when TCGData is nil
}

// TestNewPCRValidationHookEmptyProdCaData tests PCR validation with empty ProdCaData
func TestNewPCRValidationHookEmptyProdCaData(t *testing.T) {
	policy := &PCRPolicy{
		StrictMode: false,
	}
	hook := NewPCRValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil, // Empty
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip when ProdCaData is empty (non-strict mode)
}

// TestNewPCRValidationHookStrictModeEmptyProdCaData tests PCR validation in strict mode
func TestNewPCRValidationHookStrictModeEmptyProdCaData(t *testing.T) {
	policy := &PCRPolicy{
		StrictMode: true,
	}
	hook := NewPCRValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProdCaData: nil, // Empty
		},
	}

	err := hook(ctx)
	assert.Error(t, err) // Should fail in strict mode when ProdCaData is empty
}

// TestAttestationErrorError tests AttestationError.Error method
func TestAttestationErrorError(t *testing.T) {
	err := &AttestationError{
		Op:  "test_operation",
		Err: ErrAttestationDataMissing,
	}
	errStr := err.Error()
	assert.Contains(t, errStr, "test_operation")
}

// TestAttestationErrorUnwrap tests AttestationError.Unwrap method
func TestAttestationErrorUnwrap(t *testing.T) {
	innerErr := ErrAttestationDataMissing
	err := &AttestationError{
		Op:  "test_operation",
		Err: innerErr,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, innerErr, unwrapped)
}

// TestQuoteValidationErrorErrorStr tests QuoteValidationError.Error method
func TestQuoteValidationErrorErrorStr(t *testing.T) {
	err := &QuoteValidationError{Reason: "test reason"}
	errStr := err.Error()
	assert.Contains(t, errStr, "test reason")
}

// TestPCRMismatchErrorIsCorrectly tests PCRMismatchError.Is method
func TestPCRMismatchErrorIsCorrectly(t *testing.T) {
	err := &PCRMismatchError{
		PCRIndex:      7,
		ExpectedValue: []byte{0x01, 0x02},
		ActualValue:   []byte{0x03, 0x04},
	}

	// PCRMismatchError.Is() checks against ErrPCRMismatch only
	assert.True(t, err.Is(ErrPCRMismatch))
	assert.False(t, err.Is(ErrQuoteInvalid))
}

// TestPCRMismatchErrorErrorPush tests PCRMismatchError.Error method
func TestPCRMismatchErrorErrorPush(t *testing.T) {
	err := &PCRMismatchError{
		PCRIndex:      7,
		ExpectedValue: []byte{0x01, 0x02, 0x03, 0x04},
		ActualValue:   []byte{0x05, 0x06, 0x07, 0x08},
	}

	errStr := err.Error()
	assert.Contains(t, errStr, "PCR")
	assert.Contains(t, errStr, "7")
}

// TestPCRMismatchErrorWithMessagePush tests PCRMismatchError with custom message
func TestPCRMismatchErrorWithMessagePush(t *testing.T) {
	err := &PCRMismatchError{
		PCRIndex:      0,
		ExpectedValue: []byte{0xAA},
		ActualValue:   []byte{0xBB},
		Message:       "custom PCR mismatch message",
	}

	// When Message is set, it should be used directly
	errStr := err.Error()
	assert.Contains(t, errStr, "custom PCR mismatch message")
}

// TestEventLogErrorWithFields tests EventLogError with all fields populated
func TestEventLogErrorWithFields(t *testing.T) {
	err := &EventLogError{
		Message:       "missing required event",
		MissingType:   "EV_EFI_BOOT_SERVICES_APPLICATION",
		ForbiddenType: "",
	}

	assert.Contains(t, err.Error(), "missing required event")
	assert.Equal(t, "EV_EFI_BOOT_SERVICES_APPLICATION", err.MissingType)
}

// TestEventLogErrorForbiddenType tests EventLogError with forbidden type
func TestEventLogErrorForbiddenType(t *testing.T) {
	err := &EventLogError{
		Message:       "forbidden event type found",
		MissingType:   "",
		ForbiddenType: "EV_NO_ACTION",
	}

	assert.Contains(t, err.Error(), "forbidden event type found")
	assert.Equal(t, "EV_NO_ACTION", err.ForbiddenType)
}
