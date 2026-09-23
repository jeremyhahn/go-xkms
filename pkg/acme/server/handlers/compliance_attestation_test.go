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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helper Functions for Creating Test Data
// =============================================================================

// createValidProdCaData creates a valid packed ProdCaData structure for testing.
func createValidProdCaData(quoted, signature, nonce, pcrs []byte) []byte {
	var buf bytes.Buffer

	// Write version (0x00000001)
	_ = binary.Write(&buf, binary.BigEndian, uint32(xkmssdk.ProdCaDataVersion))
	// Write sizes
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(quoted)))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(signature)))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(nonce)))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(pcrs)))
	// Write data
	buf.Write(quoted)
	buf.Write(signature)
	buf.Write(nonce)
	buf.Write(pcrs)

	return buf.Bytes()
}

// createInvalidProdCaData creates invalid packed data for error testing.
func createInvalidProdCaData() []byte {
	// Wrong version
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000099)) // Invalid version
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	return buf.Bytes()
}

// createTruncatedProdCaData creates data that is truncated mid-header.
func createTruncatedProdCaData() []byte {
	return []byte{0x00, 0x00, 0x00} // Only 3 bytes, not enough for version
}

// createTestRSAKeyPair creates an RSA key pair for testing quote verification.
func createTestRSAKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return key, pubKeyBytes
}

// createTestECKeyPair creates an ECDSA key pair for testing quote verification.
func createTestECKeyPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return key, pubKeyBytes
}

// createValidQuoteWithSignature creates a ProdCaData with a valid signature for testing.
func createValidQuoteWithSignature(t *testing.T, key *rsa.PrivateKey, nonce []byte) []byte {
	t.Helper()

	quoted := []byte("test quote data")
	hash := sha256.Sum256(quoted)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err)

	return createValidProdCaData(quoted, signature, nonce, []byte{})
}

// createLegacyEventLogEntry creates a single TCG_PCR_EVENT structure for testing.
func createLegacyEventLogEntry(pcrIndex, eventType uint32, digest []byte, eventData []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, pcrIndex)
	_ = binary.Write(&buf, binary.LittleEndian, eventType)

	// Pad or truncate digest to 20 bytes (SHA-1)
	digestPadded := make([]byte, 20)
	copy(digestPadded, digest)
	buf.Write(digestPadded)

	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(eventData)))
	buf.Write(eventData)

	return buf.Bytes()
}

// createCryptoAgileSpecIDEvent creates a TCG_EfiSpecIDEvent for crypto-agile logs.
func createCryptoAgileSpecIDEvent(algorithms []SpecIDAlgorithm) []byte {
	var buf bytes.Buffer

	// Signature "Spec ID Event03"
	sig := []byte("Spec ID Event03\x00")
	buf.Write(sig)

	// platformClass (4 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	// specVersionMinor (1 byte)
	buf.WriteByte(0)
	// specVersionMajor (1 byte)
	buf.WriteByte(2)
	// specErrata (1 byte)
	buf.WriteByte(0)
	// uintnSize (1 byte)
	buf.WriteByte(2)

	// numberOfAlgorithms (4 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(algorithms)))

	// Algorithm entries
	for _, alg := range algorithms {
		_ = binary.Write(&buf, binary.LittleEndian, alg.AlgorithmID)
		_ = binary.Write(&buf, binary.LittleEndian, alg.DigestSize)
	}

	// vendorInfoSize (1 byte)
	buf.WriteByte(0)

	return buf.Bytes()
}

// =============================================================================
// PCRMismatchError Tests
// =============================================================================

func TestPCRMismatchError_Error(t *testing.T) {
	t.Run("formats error message correctly", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0xab, 0xcd, 0xef},
			ActualValue:   []byte{0x12, 0x34, 0x56},
		}

		expected := "PCR[7] mismatch: expected abcdef, got 123456"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("handles empty values", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      0,
			ExpectedValue: []byte{},
			ActualValue:   []byte{},
		}

		expected := "PCR[0] mismatch: expected , got "
		assert.Equal(t, expected, err.Error())
	})

	t.Run("handles nil values", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      23,
			ExpectedValue: nil,
			ActualValue:   nil,
		}

		expected := "PCR[23] mismatch: expected , got "
		assert.Equal(t, expected, err.Error())
	})

	t.Run("uses custom message when provided", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0xab},
			ActualValue:   []byte{0xcd},
			Message:       "custom error message",
		}

		assert.Equal(t, "custom error message", err.Error())
	})
}

func TestPCRMismatchError_Is(t *testing.T) {
	t.Run("matches ErrPCRMismatch", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0xab},
			ActualValue:   []byte{0xcd},
		}

		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("does not match other errors", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0xab},
			ActualValue:   []byte{0xcd},
		}

		assert.False(t, errors.Is(err, ErrEventLogInvalid))
		assert.False(t, errors.Is(err, ErrQuoteInvalid))
		assert.False(t, errors.Is(err, ErrAttestationDataMissing))
	})
}

// =============================================================================
// EventLogError Tests
// =============================================================================

func TestEventLogError_Error(t *testing.T) {
	t.Run("returns message field", func(t *testing.T) {
		err := &EventLogError{
			Message: "event log validation failed: missing required event",
		}

		assert.Equal(t, "event log validation failed: missing required event", err.Error())
	})

	t.Run("includes missing type in message", func(t *testing.T) {
		err := &EventLogError{
			Message:     "required event type not found: EV_EFI_BOOT_SERVICES_APPLICATION",
			MissingType: "EV_EFI_BOOT_SERVICES_APPLICATION",
		}

		assert.Contains(t, err.Error(), "EV_EFI_BOOT_SERVICES_APPLICATION")
	})

	t.Run("includes forbidden type in message", func(t *testing.T) {
		err := &EventLogError{
			Message:       "forbidden event type found: EV_DEBUG",
			ForbiddenType: "EV_DEBUG",
		}

		assert.Contains(t, err.Error(), "EV_DEBUG")
	})
}

func TestEventLogError_Is(t *testing.T) {
	t.Run("matches ErrEventLogInvalid", func(t *testing.T) {
		err := &EventLogError{
			Message: "validation failed",
		}

		assert.True(t, errors.Is(err, ErrEventLogInvalid))
	})

	t.Run("does not match other errors", func(t *testing.T) {
		err := &EventLogError{
			Message: "validation failed",
		}

		assert.False(t, errors.Is(err, ErrPCRMismatch))
		assert.False(t, errors.Is(err, ErrQuoteInvalid))
		assert.False(t, errors.Is(err, ErrAttestationDataMissing))
	})
}

// =============================================================================
// QuoteValidationError Tests
// =============================================================================

func TestQuoteValidationError_Error(t *testing.T) {
	t.Run("returns formatted message", func(t *testing.T) {
		err := &QuoteValidationError{
			Reason: "nonce mismatch",
		}

		assert.Equal(t, "TPM quote validation failed: nonce mismatch", err.Error())
	})
}

func TestQuoteValidationError_Is(t *testing.T) {
	t.Run("matches ErrQuoteInvalid", func(t *testing.T) {
		err := &QuoteValidationError{
			Reason: "test",
		}

		assert.True(t, errors.Is(err, ErrQuoteInvalid))
	})
}

// =============================================================================
// EventLogPCRMismatchError Tests
// =============================================================================

func TestEventLogPCRMismatchError_Error(t *testing.T) {
	t.Run("formats error message correctly", func(t *testing.T) {
		err := &EventLogPCRMismatchError{
			PCRIndex:      7,
			Algorithm:     "sha256",
			ExpectedValue: []byte{0xab, 0xcd},
			ActualValue:   []byte{0x12, 0x34},
		}

		expected := "event log PCR[7] (sha256) mismatch: computed abcd, got 1234"
		assert.Equal(t, expected, err.Error())
	})
}

func TestEventLogPCRMismatchError_Is(t *testing.T) {
	t.Run("matches ErrEventLogPCRMismatch", func(t *testing.T) {
		err := &EventLogPCRMismatchError{
			PCRIndex: 7,
		}

		assert.True(t, errors.Is(err, ErrEventLogPCRMismatch))
	})

	t.Run("matches ErrEventLogInvalid", func(t *testing.T) {
		err := &EventLogPCRMismatchError{
			PCRIndex: 7,
		}

		assert.True(t, errors.Is(err, ErrEventLogInvalid))
	})
}

// =============================================================================
// AttestationError Tests
// =============================================================================

func TestAttestationError_Error(t *testing.T) {
	t.Run("formats error message correctly", func(t *testing.T) {
		err := &AttestationError{
			Op:  "unpack_prodcadata",
			Err: errors.New("invalid structure"),
		}

		assert.Equal(t, "failed to unpack_prodcadata attestation data: invalid structure", err.Error())
	})
}

func TestAttestationError_Unwrap(t *testing.T) {
	t.Run("returns underlying error", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		err := &AttestationError{
			Op:  "test",
			Err: underlyingErr,
		}

		assert.Equal(t, underlyingErr, err.Unwrap())
		assert.True(t, errors.Is(err, underlyingErr))
	})
}

// =============================================================================
// DeviceProfileError Tests
// =============================================================================

func TestDeviceProfileError_Error(t *testing.T) {
	t.Run("formats error message correctly", func(t *testing.T) {
		err := &DeviceProfileError{
			Op:  "lookup",
			Err: errors.New("database error"),
		}

		assert.Equal(t, "failed to lookup device profile: database error", err.Error())
	})
}

func TestDeviceProfileError_Unwrap(t *testing.T) {
	t.Run("returns underlying error", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		err := &DeviceProfileError{
			Op:  "test",
			Err: underlyingErr,
		}

		assert.Equal(t, underlyingErr, err.Unwrap())
		assert.True(t, errors.Is(err, underlyingErr))
	})
}

// =============================================================================
// findPCRValue Tests
// =============================================================================

func TestFindPCRValue(t *testing.T) {
	t.Run("returns not found for empty data", func(t *testing.T) {
		value, found := findPCRValue([]byte{}, 0)
		assert.False(t, found)
		assert.Nil(t, value)
	})

	t.Run("returns not found for nil data", func(t *testing.T) {
		value, found := findPCRValue(nil, 7)
		assert.False(t, found)
		assert.Nil(t, value)
	})

	t.Run("returns not found for invalid gob data", func(t *testing.T) {
		pcrData := []byte{0x01, 0x02, 0x03, 0x04}
		value, found := findPCRValue(pcrData, 0)
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

// =============================================================================
// parseEventLog Tests
// =============================================================================

func TestParseEventLog(t *testing.T) {
	t.Run("returns empty for empty input", func(t *testing.T) {
		events, err := parseEventLog([]byte{})
		require.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("returns empty for nil input", func(t *testing.T) {
		events, err := parseEventLog(nil)
		require.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("parses valid legacy event log", func(t *testing.T) {
		// Create a valid legacy event
		digest := make([]byte, 20)
		eventData := []byte("test event data")
		eventLog := createLegacyEventLogEntry(0, EVNoAction, digest, eventData)

		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		require.Len(t, events, 1)
		assert.Equal(t, 0, events[0].PCRIndex)
		assert.Equal(t, "EV_NO_ACTION", events[0].EventType)
	})

	t.Run("parses multiple legacy events", func(t *testing.T) {
		var eventLog []byte
		eventLog = append(eventLog, createLegacyEventLogEntry(0, EVNoAction, make([]byte, 20), []byte("event1"))...)
		eventLog = append(eventLog, createLegacyEventLogEntry(7, EVEFIAction, make([]byte, 20), []byte("event2"))...)

		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		require.Len(t, events, 2)
		assert.Equal(t, 0, events[0].PCRIndex)
		assert.Equal(t, 7, events[1].PCRIndex)
	})
}

// =============================================================================
// parseLegacyEvent Tests
// =============================================================================

func TestParseLegacyEvent(t *testing.T) {
	t.Run("parses valid legacy event", func(t *testing.T) {
		eventData := []byte("test event")
		eventBytes := createLegacyEventLogEntry(7, EVEFIAction, make([]byte, 20), eventData)
		reader := bytes.NewReader(eventBytes)

		entry, err := parseLegacyEvent(reader)
		require.NoError(t, err)
		assert.Equal(t, 7, entry.PCRIndex)
		assert.Equal(t, "EV_EFI_ACTION", entry.EventType)
		assert.Len(t, entry.Digest, 20)
		assert.Equal(t, eventData, entry.EventData)
		assert.Equal(t, TCGAlgSHA1, entry.DigestAlg)
	})

	t.Run("returns error for truncated data", func(t *testing.T) {
		reader := bytes.NewReader([]byte{0x00, 0x01, 0x02})

		_, err := parseLegacyEvent(reader)
		assert.ErrorIs(t, err, ErrEventLogParsingFailed)
	})

	t.Run("returns error for event data size too large", func(t *testing.T) {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))     // PCR index
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))     // Event type
		buf.Write(make([]byte, 20))                                // Digest
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1<<21)) // Event data size > 1MB

		reader := bytes.NewReader(buf.Bytes())
		_, err := parseLegacyEvent(reader)
		assert.ErrorIs(t, err, ErrEventLogParsingFailed)
	})
}

// =============================================================================
// parseSpecIDEvent Tests
// =============================================================================

func TestParseSpecIDEvent(t *testing.T) {
	t.Run("parses valid spec ID event", func(t *testing.T) {
		algorithms := []SpecIDAlgorithm{
			{AlgorithmID: TCGAlgSHA1, DigestSize: 20},
			{AlgorithmID: TCGAlgSHA256, DigestSize: 32},
		}
		eventData := createCryptoAgileSpecIDEvent(algorithms)

		result, err := parseSpecIDEvent(eventData)
		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, TCGAlgSHA1, result[0].AlgorithmID)
		assert.Equal(t, uint16(20), result[0].DigestSize)
		assert.Equal(t, TCGAlgSHA256, result[1].AlgorithmID)
		assert.Equal(t, uint16(32), result[1].DigestSize)
	})

	t.Run("returns error for data too small", func(t *testing.T) {
		_, err := parseSpecIDEvent(make([]byte, 10))
		assert.ErrorIs(t, err, ErrEventLogParsingFailed)
	})

	t.Run("returns error for wrong signature", func(t *testing.T) {
		data := make([]byte, 40)
		copy(data, []byte("Wrong Signature!"))

		_, err := parseSpecIDEvent(data)
		assert.ErrorIs(t, err, ErrEventLogParsingFailed)
	})

	t.Run("returns error for too many algorithms", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte("Spec ID Event03\x00"))
		buf.Write(make([]byte, 8))                               // platformClass, versions, uintnSize
		_ = binary.Write(&buf, binary.LittleEndian, uint32(100)) // Too many algorithms

		_, err := parseSpecIDEvent(buf.Bytes())
		assert.ErrorIs(t, err, ErrEventLogParsingFailed)
	})
}

// =============================================================================
// eventTypeToString Tests
// =============================================================================

func TestEventTypeToString(t *testing.T) {
	testCases := []struct {
		eventType uint32
		expected  string
	}{
		{EVPrebootCert, "EV_PREBOOT_CERT"},
		{EVPostCode, "EV_POST_CODE"},
		{EVNoAction, "EV_NO_ACTION"},
		{EVSeparator, "EV_SEPARATOR"},
		{EVAction, "EV_ACTION"},
		{EVEFIVariableDriverConfig, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{EVEFIBootServicesApplication, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{EVEFIAction, "EV_EFI_ACTION"},
		{0xFFFFFFFF, "EV_UNKNOWN_FFFFFFFF"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := eventTypeToString(tc.eventType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// hasEventType Tests
// =============================================================================

func TestHasEventType(t *testing.T) {
	t.Run("returns false for empty events", func(t *testing.T) {
		events := []EventLogEntry{}
		assert.False(t, hasEventType(events, "EV_NO_ACTION"))
	})

	t.Run("returns true when event type exists", func(t *testing.T) {
		events := []EventLogEntry{
			{PCRIndex: 0, EventType: "EV_NO_ACTION", Digest: nil, EventData: nil},
			{PCRIndex: 4, EventType: "EV_EFI_ACTION", Digest: nil, EventData: nil},
			{PCRIndex: 7, EventType: "EV_EFI_BOOT_SERVICES_APPLICATION", Digest: nil, EventData: nil},
		}

		assert.True(t, hasEventType(events, "EV_NO_ACTION"))
		assert.True(t, hasEventType(events, "EV_EFI_ACTION"))
		assert.True(t, hasEventType(events, "EV_EFI_BOOT_SERVICES_APPLICATION"))
	})

	t.Run("returns false when event type does not exist", func(t *testing.T) {
		events := []EventLogEntry{
			{PCRIndex: 0, EventType: "EV_NO_ACTION", Digest: nil, EventData: nil},
			{PCRIndex: 4, EventType: "EV_EFI_ACTION", Digest: nil, EventData: nil},
		}

		assert.False(t, hasEventType(events, "EV_DEBUG"))
		assert.False(t, hasEventType(events, "EV_NONEXISTENT"))
	})

	t.Run("is case sensitive", func(t *testing.T) {
		events := []EventLogEntry{
			{PCRIndex: 0, EventType: "EV_NO_ACTION", Digest: nil, EventData: nil},
		}

		assert.True(t, hasEventType(events, "EV_NO_ACTION"))
		assert.False(t, hasEventType(events, "ev_no_action"))
		assert.False(t, hasEventType(events, "Ev_No_Action"))
	})
}

// =============================================================================
// extendPCR Tests
// =============================================================================

func TestExtendPCR(t *testing.T) {
	t.Run("extends with SHA-1", func(t *testing.T) {
		current := make([]byte, 20)
		digest := make([]byte, 20)
		digest[0] = 0xAB

		result, err := extendPCR(current, digest, TCGAlgSHA1)
		if fips140.Enforced() {
			// A SHA-1 PCR bank cannot be verified under GODEBUG=fips140=only
			// (see extendPCR's FIPS 140-only comment, go-xkms#23): the
			// construction that used to panic now returns
			// ErrUnsupportedHashAlgorithm cleanly instead.
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrUnsupportedHashAlgorithm)
			assert.Nil(t, result)
			return
		}
		require.NoError(t, err)
		assert.Len(t, result, 20)
		// Result should not be all zeros
		assert.NotEqual(t, current, result)
	})

	t.Run("extends with SHA-256", func(t *testing.T) {
		current := make([]byte, 32)
		digest := make([]byte, 32)
		digest[0] = 0xAB

		result, err := extendPCR(current, digest, TCGAlgSHA256)
		require.NoError(t, err)
		assert.Len(t, result, 32)
	})

	t.Run("extends with SHA-384", func(t *testing.T) {
		current := make([]byte, 48)
		digest := make([]byte, 48)
		digest[0] = 0xAB

		result, err := extendPCR(current, digest, TCGAlgSHA384)
		require.NoError(t, err)
		assert.Len(t, result, 48)
	})

	t.Run("extends with SHA-512", func(t *testing.T) {
		current := make([]byte, 64)
		digest := make([]byte, 64)
		digest[0] = 0xAB

		result, err := extendPCR(current, digest, TCGAlgSHA512)
		require.NoError(t, err)
		assert.Len(t, result, 64)
	})

	t.Run("returns error for unsupported algorithm", func(t *testing.T) {
		_, err := extendPCR(nil, nil, 0x9999)
		assert.ErrorIs(t, err, ErrUnsupportedHashAlgorithm)
	})
}

// =============================================================================
// algorithmStringToID Tests
// =============================================================================

func TestAlgorithmStringToID(t *testing.T) {
	testCases := []struct {
		input    string
		expected uint16
	}{
		{"sha1", TCGAlgSHA1},
		{"SHA1", TCGAlgSHA1},
		{"sha256", TCGAlgSHA256},
		{"SHA256", TCGAlgSHA256},
		{"sha384", TCGAlgSHA384},
		{"SHA384", TCGAlgSHA384},
		{"sha512", TCGAlgSHA512},
		{"SHA512", TCGAlgSHA512},
		{"unknown", 0},
		{"", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := algorithmStringToID(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// validateEventLogAgainstPCRs Tests
// =============================================================================

func TestValidateEventLogAgainstPCRs(t *testing.T) {
	t.Run("returns nil for empty event log", func(t *testing.T) {
		err := validateEventLogAgainstPCRs(nil, nil)
		assert.NoError(t, err)
	})

	t.Run("returns nil for empty PCRs", func(t *testing.T) {
		err := validateEventLogAgainstPCRs([]byte{}, []byte{})
		assert.NoError(t, err)
	})

	t.Run("returns nil when only event log provided", func(t *testing.T) {
		eventLog := createLegacyEventLogEntry(0, EVNoAction, make([]byte, 20), nil)
		err := validateEventLogAgainstPCRs(eventLog, nil)
		assert.NoError(t, err)
	})
}

// =============================================================================
// parseTPMSignature Tests
// =============================================================================

func TestParseTPMSignature(t *testing.T) {
	t.Run("returns error for data too short", func(t *testing.T) {
		_, _, err := parseTPMSignature([]byte{0x00, 0x14})
		assert.ErrorIs(t, err, ErrInvalidQuoteStructure)
	})

	t.Run("returns error for unknown algorithm", func(t *testing.T) {
		data := make([]byte, 10)
		binary.BigEndian.PutUint16(data[0:2], 0x9999)

		_, _, err := parseTPMSignature(data)
		assert.ErrorIs(t, err, ErrInvalidQuoteStructure)
	})

	t.Run("parses RSASSA signature", func(t *testing.T) {
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, uint16(TPMAlgRSASSA)) // sigAlg
		binary.Write(&buf, binary.BigEndian, uint16(0x000B))       // hash (SHA-256)
		binary.Write(&buf, binary.BigEndian, uint16(4))            // sig size
		buf.Write([]byte{0x01, 0x02, 0x03, 0x04})                  // signature

		alg, sig, err := parseTPMSignature(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, uint16(TPMAlgRSASSA), alg)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, sig)
	})

	t.Run("parses RSAPSS signature", func(t *testing.T) {
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, uint16(TPMAlgRSAPSS)) // sigAlg
		binary.Write(&buf, binary.BigEndian, uint16(0x000B))       // hash
		binary.Write(&buf, binary.BigEndian, uint16(4))            // sig size
		buf.Write([]byte{0x01, 0x02, 0x03, 0x04})                  // signature

		alg, sig, err := parseTPMSignature(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, uint16(TPMAlgRSAPSS), alg)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, sig)
	})

	t.Run("parses ECDSA signature", func(t *testing.T) {
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, uint16(TPMAlgECDSA)) // sigAlg
		binary.Write(&buf, binary.BigEndian, uint16(0x000B))      // hash
		binary.Write(&buf, binary.BigEndian, uint16(2))           // R size
		buf.Write([]byte{0xAA, 0xBB})                             // R
		binary.Write(&buf, binary.BigEndian, uint16(2))           // S size
		buf.Write([]byte{0xCC, 0xDD})                             // S

		alg, sig, err := parseTPMSignature(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, uint16(TPMAlgECDSA), alg)
		assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, sig)
	})
}

// =============================================================================
// verifyQuoteSignature Tests
// =============================================================================

func TestVerifyQuoteSignature(t *testing.T) {
	t.Run("returns error for empty quoted data", func(t *testing.T) {
		key, _ := createTestRSAKeyPair(t)
		err := verifyQuoteSignature(nil, []byte("sig"), &key.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing quoted data or signature")
	})

	t.Run("returns error for empty signature", func(t *testing.T) {
		key, _ := createTestRSAKeyPair(t)
		err := verifyQuoteSignature([]byte("quoted"), nil, &key.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing quoted data or signature")
	})

	t.Run("returns error for unsupported key type", func(t *testing.T) {
		type unsupportedKey struct{}
		err := verifyQuoteSignature([]byte("quoted"), []byte("sig"), unsupportedKey{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported public key type")
	})

	t.Run("verifies valid RSA PKCS1 signature", func(t *testing.T) {
		key, _ := createTestRSAKeyPair(t)
		quoted := []byte("test quote data")
		hash := sha256.Sum256(quoted)
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		require.NoError(t, err)

		err = verifyQuoteSignature(quoted, signature, &key.PublicKey)
		assert.NoError(t, err)
	})

	t.Run("returns error for invalid RSA signature", func(t *testing.T) {
		key, _ := createTestRSAKeyPair(t)
		quoted := []byte("test quote data")
		invalidSig := []byte("invalid signature")

		err := verifyQuoteSignature(quoted, invalidSig, &key.PublicKey)
		assert.Error(t, err)
	})

	t.Run("verifies valid ECDSA signature with ASN.1", func(t *testing.T) {
		key, _ := createTestECKeyPair(t)
		quoted := []byte("test quote data")
		hash := sha256.Sum256(quoted)
		signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		require.NoError(t, err)

		err = verifyQuoteSignature(quoted, signature, &key.PublicKey)
		assert.NoError(t, err)
	})

	t.Run("returns error for invalid ECDSA signature", func(t *testing.T) {
		key, _ := createTestECKeyPair(t)
		quoted := []byte("test quote data")
		invalidSig := []byte("invalid signature")

		err := verifyQuoteSignature(quoted, invalidSig, &key.PublicKey)
		assert.Error(t, err)
	})
}

// =============================================================================
// NewPCRValidationHook Tests
// =============================================================================

func TestNewPCRValidationHook(t *testing.T) {
	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: false,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when TCGData is nil", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when ProdCaData is empty in non-strict mode", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   false,
		}

		hook := NewPCRValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				ProdCaData:    []byte{},
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error when ProdCaData is empty in strict mode", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				ProdCaData:    []byte{},
			},
		}

		err := hook(ctx)
		assert.ErrorIs(t, err, ErrAttestationDataMissing)
	})

	t.Run("returns error for invalid ProdCaData", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   false,
		}

		hook := NewPCRValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				ProdCaData:    createInvalidProdCaData(),
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation data")
	})
}

// =============================================================================
// NewEventLogValidationHook Tests
// =============================================================================

func TestNewEventLogValidationHook(t *testing.T) {
	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_NO_ACTION"},
		}

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: false,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when TCGData is nil", func(t *testing.T) {
		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_NO_ACTION"},
		}

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error when event log is empty but required events exist", func(t *testing.T) {
		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_NO_ACTION"},
		}

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				EventLog:      []byte{},
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEventLogInvalid)
	})

	t.Run("passes with valid event log containing required event", func(t *testing.T) {
		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_NO_ACTION"},
		}

		// Create event log with EV_NO_ACTION
		eventLog := createLegacyEventLogEntry(0, EVNoAction, make([]byte, 20), []byte("test"))

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				EventLog:      eventLog,
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error when forbidden event is present", func(t *testing.T) {
		policy := &EventLogPolicy{
			ForbiddenEvents: []string{"EV_NO_ACTION"},
		}

		eventLog := createLegacyEventLogEntry(0, EVNoAction, make([]byte, 20), []byte("test"))

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				EventLog:      eventLog,
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEventLogInvalid)
		assert.Contains(t, err.Error(), "forbidden event type found")
	})

	t.Run("returns error when max event count exceeded", func(t *testing.T) {
		policy := &EventLogPolicy{
			MaxEventCount: 1,
		}

		// Create event log with 2 events
		var eventLog []byte
		eventLog = append(eventLog, createLegacyEventLogEntry(0, EVNoAction, make([]byte, 20), []byte("1"))...)
		eventLog = append(eventLog, createLegacyEventLogEntry(7, EVAction, make([]byte, 20), []byte("2"))...)

		hook := NewEventLogValidationHook(policy)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				EventLog:      eventLog,
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max allowed")
	})
}

// =============================================================================
// NewQuoteValidationHook Tests
// =============================================================================

func TestNewQuoteValidationHook(t *testing.T) {
	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: false,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when TCGData is nil", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when ProdCaData is empty", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				ProdCaData:    []byte{},
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error for invalid ProdCaData", func(t *testing.T) {
		hook := NewQuoteValidationHook([]byte("nonce"))
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:         "TestDevice",
				ProductSerial:        "SN001",
				ProdCaData:           createInvalidProdCaData(),
				AttestationPublicKey: []byte("pubkey"),
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation data")
	})

	t.Run("returns error when nonce does not match", func(t *testing.T) {
		expectedNonce := []byte("expected-nonce")
		actualNonce := []byte("actual-nonce")
		hook := NewQuoteValidationHook(expectedNonce)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:         "TestDevice",
				ProductSerial:        "SN001",
				ProdCaData:           createValidProdCaData([]byte("quoted"), []byte("sig"), actualNonce, []byte("pcrs")),
				AttestationPublicKey: []byte("pubkey"),
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrQuoteInvalid)
		assert.Contains(t, err.Error(), "nonce mismatch")
	})

	t.Run("returns error when attestation public key is missing", func(t *testing.T) {
		hook := NewQuoteValidationHook(nil)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:         "TestDevice",
				ProductSerial:        "SN001",
				ProdCaData:           createValidProdCaData([]byte("quoted"), []byte("sig"), []byte("nonce"), []byte("pcrs")),
				AttestationPublicKey: []byte{}, // Empty
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrQuoteInvalid)
		assert.Contains(t, err.Error(), "attestation public key not available")
	})

	t.Run("verifies valid quote with RSA key", func(t *testing.T) {
		key, pubKeyBytes := createTestRSAKeyPair(t)
		nonce := []byte("test-nonce")
		prodCaData := createValidQuoteWithSignature(t, key, nonce)

		hook := NewQuoteValidationHook(nonce)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:         "TestDevice",
				ProductSerial:        "SN001",
				ProdCaData:           prodCaData,
				AttestationPublicKey: pubKeyBytes,
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})
}

// =============================================================================
// NewDeviceProfileHook Tests
// =============================================================================

func TestNewDeviceProfileHook(t *testing.T) {
	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		}

		hook := NewDeviceProfileHook(lookupFunc)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: false,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("skips when TCGData is nil", func(t *testing.T) {
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		}

		hook := NewDeviceProfileHook(lookupFunc)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData:  nil,
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error when lookup fails", func(t *testing.T) {
		lookupErr := errors.New("database connection failed")
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, lookupErr
		}

		hook := NewDeviceProfileHook(lookupFunc)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
			},
		}

		err := hook(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device profile")
		assert.ErrorIs(t, err, lookupErr)
	})

	t.Run("passes when profile is nil (unknown device)", func(t *testing.T) {
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, nil // Unknown device, no profile
		}

		hook := NewDeviceProfileHook(lookupFunc)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("passes serial and model to lookup function", func(t *testing.T) {
		var capturedSerial, capturedModel string
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			capturedSerial = serial
			capturedModel = model
			return nil, nil
		}

		hook := NewDeviceProfileHook(lookupFunc)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "Model-X100",
				ProductSerial: "SN-12345-ABC",
			},
		}

		err := hook(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "SN-12345-ABC", capturedSerial)
		assert.Equal(t, "Model-X100", capturedModel)
	})
}

// =============================================================================
// validateDeviceAgainstProfile Tests
// =============================================================================

func TestValidateDeviceAgainstProfile(t *testing.T) {
	t.Run("passes with empty expected PCRs", func(t *testing.T) {
		profile := &DeviceProfile{
			ProductSerial: "SN001",
			ProductModel:  "TestDevice",
			ExpectedPCRs:  map[int][]byte{},
		}
		tcgData := &TCGEnrollmentData{
			ProductModel:  "TestDevice",
			ProductSerial: "SN001",
		}

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.NoError(t, err)
	})

	t.Run("passes with nil expected PCRs", func(t *testing.T) {
		profile := &DeviceProfile{
			ProductSerial: "SN001",
			ProductModel:  "TestDevice",
			ExpectedPCRs:  nil,
		}
		tcgData := &TCGEnrollmentData{
			ProductModel:  "TestDevice",
			ProductSerial: "SN001",
		}

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.NoError(t, err)
	})

	t.Run("returns error when ProdCaData is invalid", func(t *testing.T) {
		profile := &DeviceProfile{
			ProductSerial: "SN001",
			ProductModel:  "TestDevice",
			ExpectedPCRs:  map[int][]byte{0: {0xaa}},
		}
		tcgData := &TCGEnrollmentData{
			ProductModel:  "TestDevice",
			ProductSerial: "SN001",
			ProdCaData:    createInvalidProdCaData(),
		}

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation data")
	})
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestIntToStr(t *testing.T) {
	testCases := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{-1, "-1"},
		{-123, "-123"},
		{1000000, "1000000"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := intToStr(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUint32ToHex(t *testing.T) {
	testCases := []struct {
		input    uint32
		expected string
	}{
		{0, "00000000"},
		{1, "00000001"},
		{0xFF, "000000FF"},
		{0xDEADBEEF, "DEADBEEF"},
		{0x80000001, "80000001"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := uint32ToHex(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBytesToHex(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0xab}, "ab"},
		{[]byte{0xab, 0xcd, 0xef}, "abcdef"},
		{[]byte{0x00, 0xff}, "00ff"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := bytesToHex(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// Structure Tests
// =============================================================================

func TestDeviceProfile_Fields(t *testing.T) {
	t.Run("all fields can be populated", func(t *testing.T) {
		profile := DeviceProfile{
			ProductSerial:           "SN-12345",
			ProductModel:            "Model-X100",
			ExpectedPCRs:            map[int][]byte{0: {0xaa}, 7: {0xbb}},
			AllowedFirmwareVersions: []string{"1.0.0", "1.0.1", "1.1.0"},
			RequiredSecureBoot:      true,
			AdditionalChecks:        map[string]string{"vendor": "TrustedCorp", "country": "US"},
		}

		assert.Equal(t, "SN-12345", profile.ProductSerial)
		assert.Equal(t, "Model-X100", profile.ProductModel)
		assert.Len(t, profile.ExpectedPCRs, 2)
		assert.Equal(t, []byte{0xaa}, profile.ExpectedPCRs[0])
		assert.Equal(t, []byte{0xbb}, profile.ExpectedPCRs[7])
		assert.Len(t, profile.AllowedFirmwareVersions, 3)
		assert.True(t, profile.RequiredSecureBoot)
		assert.Equal(t, "TrustedCorp", profile.AdditionalChecks["vendor"])
		assert.Equal(t, "US", profile.AdditionalChecks["country"])
	})
}

func TestPCRPolicy_Fields(t *testing.T) {
	t.Run("all fields can be populated", func(t *testing.T) {
		policy := PCRPolicy{
			ExpectedPCRs:    map[int][]byte{0: {0xaa}, 7: {0xbb}},
			AllowedPCRBanks: []string{"SHA256", "SHA384"},
			StrictMode:      true,
		}

		assert.Len(t, policy.ExpectedPCRs, 2)
		assert.Len(t, policy.AllowedPCRBanks, 2)
		assert.True(t, policy.StrictMode)
	})
}

func TestEventLogPolicy_Fields(t *testing.T) {
	t.Run("all fields can be populated", func(t *testing.T) {
		policy := EventLogPolicy{
			RequiredEvents:      []string{"EV_NO_ACTION", "EV_EFI_ACTION"},
			ForbiddenEvents:     []string{"EV_DEBUG"},
			MaxEventCount:       1000,
			ValidateAgainstPCRs: true,
		}

		assert.Len(t, policy.RequiredEvents, 2)
		assert.Len(t, policy.ForbiddenEvents, 1)
		assert.Equal(t, 1000, policy.MaxEventCount)
		assert.True(t, policy.ValidateAgainstPCRs)
	})
}

func TestEventLogEntry_Fields(t *testing.T) {
	t.Run("all fields can be populated", func(t *testing.T) {
		entry := EventLogEntry{
			PCRIndex:  7,
			EventType: "EV_EFI_BOOT_SERVICES_APPLICATION",
			Digest:    []byte{0xaa, 0xbb, 0xcc, 0xdd},
			EventData: []byte{0x01, 0x02, 0x03, 0x04},
			DigestAlg: TCGAlgSHA256,
		}

		assert.Equal(t, 7, entry.PCRIndex)
		assert.Equal(t, "EV_EFI_BOOT_SERVICES_APPLICATION", entry.EventType)
		assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, entry.Digest)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, entry.EventData)
		assert.Equal(t, TCGAlgSHA256, entry.DigestAlg)
	})
}

// =============================================================================
// Error Variable Tests
// =============================================================================

func TestErrorVariables(t *testing.T) {
	t.Run("ErrAttestationDataMissing is defined", func(t *testing.T) {
		assert.NotNil(t, ErrAttestationDataMissing)
		assert.Contains(t, ErrAttestationDataMissing.Error(), "attestation data required")
	})

	t.Run("ErrPCRMismatch is defined", func(t *testing.T) {
		assert.NotNil(t, ErrPCRMismatch)
		assert.Contains(t, ErrPCRMismatch.Error(), "PCR values")
	})

	t.Run("ErrEventLogInvalid is defined", func(t *testing.T) {
		assert.NotNil(t, ErrEventLogInvalid)
		assert.Contains(t, ErrEventLogInvalid.Error(), "event log validation")
	})

	t.Run("ErrQuoteInvalid is defined", func(t *testing.T) {
		assert.NotNil(t, ErrQuoteInvalid)
		assert.Contains(t, ErrQuoteInvalid.Error(), "TPM quote validation")
	})

	t.Run("ErrPCRParsingFailed is defined", func(t *testing.T) {
		assert.NotNil(t, ErrPCRParsingFailed)
		assert.Contains(t, ErrPCRParsingFailed.Error(), "parse PCR")
	})

	t.Run("ErrEventLogParsingFailed is defined", func(t *testing.T) {
		assert.NotNil(t, ErrEventLogParsingFailed)
		assert.Contains(t, ErrEventLogParsingFailed.Error(), "parse event log")
	})

	t.Run("ErrUnsupportedHashAlgorithm is defined", func(t *testing.T) {
		assert.NotNil(t, ErrUnsupportedHashAlgorithm)
		assert.Contains(t, ErrUnsupportedHashAlgorithm.Error(), "unsupported hash")
	})

	t.Run("ErrInvalidQuoteStructure is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidQuoteStructure)
		assert.Contains(t, ErrInvalidQuoteStructure.Error(), "invalid quote")
	})

	t.Run("ErrSignatureVerificationFailed is defined", func(t *testing.T) {
		assert.NotNil(t, ErrSignatureVerificationFailed)
		assert.Contains(t, ErrSignatureVerificationFailed.Error(), "signature verification")
	})

	t.Run("ErrEventLogPCRMismatch is defined", func(t *testing.T) {
		assert.NotNil(t, ErrEventLogPCRMismatch)
		assert.Contains(t, ErrEventLogPCRMismatch.Error(), "event log does not match")
	})
}

// =============================================================================
// Integration with PreIssuanceHookRegistry Tests
// =============================================================================

func TestComplianceHooks_Registry_Integration(t *testing.T) {
	t.Run("multiple compliance hooks can be chained", func(t *testing.T) {
		registry := NewPreIssuanceHookRegistry()

		// Register PCR validation hook
		pcrPolicy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{},
			StrictMode:   false,
		}
		registry.Register(NewPCRValidationHook(pcrPolicy))

		// Register event log validation hook
		eventLogPolicy := &EventLogPolicy{
			RequiredEvents: []string{},
		}
		registry.Register(NewEventLogValidationHook(eventLogPolicy))

		// Register quote validation hook
		registry.Register(NewQuoteValidationHook(nil))

		// Register device profile hook
		registry.Register(NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, nil
		}))

		assert.Equal(t, 4, registry.Count())

		// Execute all hooks on a non-TCG context (should all pass)
		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: false,
		}

		err := registry.Execute(ctx)
		assert.NoError(t, err)
	})

	t.Run("first failing hook stops execution", func(t *testing.T) {
		registry := NewPreIssuanceHookRegistry()

		executed := []string{}

		// Hook 1: passes
		registry.Register(func(ctx *PreIssuanceHookContext) error {
			executed = append(executed, "hook1")
			return nil
		})

		// Hook 2: strict PCR validation that fails
		pcrPolicy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: {0xaa}},
			StrictMode:   true,
		}
		registry.Register(func(ctx *PreIssuanceHookContext) error {
			executed = append(executed, "hook2")
			return NewPCRValidationHook(pcrPolicy)(ctx)
		})

		// Hook 3: should not execute
		registry.Register(func(ctx *PreIssuanceHookContext) error {
			executed = append(executed, "hook3")
			return nil
		})

		ctx := &PreIssuanceHookContext{
			Context:  context.Background(),
			Order:    &entities.ACMEOrder{ID: 1},
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductModel:  "TestDevice",
				ProductSerial: "SN001",
				ProdCaData:    []byte{}, // Empty, will trigger strict mode error
			},
		}

		err := registry.Execute(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationDataMissing)
		assert.Equal(t, []string{"hook1", "hook2"}, executed)
	})
}
