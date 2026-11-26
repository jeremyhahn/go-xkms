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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test helper function
// =============================================================================

// =============================================================================
// NewAccountHandler Coverage Tests - Unique paths not covered elsewhere
// =============================================================================

func TestNewAccountHandler_EABOptionalButProvidedCoverage(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)

	// Create EAB - optional but provided
	ctx := context.Background()
	eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)

	// MACKey should be base64url-encoded
	macKeyRaw := []byte("test-hmac-key-32-bytes-long!!!!")
	macKeyEncoded := base64.RawURLEncoding.EncodeToString(macKeyRaw)

	eab := &entities.ExternalAccountBinding{
		ID:                "test-kid-optional",
		MACKey:            macKeyEncoded,
		MACAlgorithm:      "HS256",
		ExternalAccountID: "external-123",
		Status:            entities.EABStatusActive,
		CreatedAt:         time.Now(),
	}
	err = eabDAO.Save(ctx, eab)
	require.NoError(t, err)

	// Create the EAB JWS
	eabJWS := createTestEABJWSCoverage(t, service, key, eab, macKeyRaw)

	payload := NewAccountRequest{
		Contact:                []string{"mailto:test@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: json.RawMessage(eabJWS),
	}

	url := service.baseRESTURI + "/acme/new-account"
	req := createJWSRequest(t, service, key, url, payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)

	// Should succeed since EAB is optional
	assert.Equal(t, http.StatusCreated, resp.Code)
}

// createTestEABJWSCoverage creates a test EAB JWS for testing
func createTestEABJWSCoverage(t *testing.T, service *RestService, key *TestKey, eab *entities.ExternalAccountBinding, macKeyRaw []byte) []byte {
	// Create the protected header
	protected := map[string]interface{}{
		"alg": "HS256",
		"kid": eab.ID,
		"url": service.baseRESTURI + "/acme/new-account",
	}

	protectedBytes, err := json.Marshal(protected)
	require.NoError(t, err)

	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

	// Create payload with account key
	pubKeyJWK := jose.JSONWebKey{Key: key.PublicKey}
	pubKeyJSON, err := pubKeyJWK.MarshalJSON()
	require.NoError(t, err)

	payloadB64 := base64.RawURLEncoding.EncodeToString(pubKeyJSON)

	// Create signature
	signingInput := protectedB64 + "." + payloadB64
	mac := createHMACCoverage(t, []byte(signingInput), macKeyRaw)
	signatureB64 := base64.RawURLEncoding.EncodeToString(mac)

	// Build JWS
	eabJWS := map[string]interface{}{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signatureB64,
	}

	jwsBytes, err := json.Marshal(eabJWS)
	require.NoError(t, err)

	return jwsBytes
}

// =============================================================================
// KeyChangeHandler Coverage Tests
// =============================================================================

// =============================================================================
// OrderFinalizeHandler Coverage Tests
// =============================================================================

// =============================================================================
// Compliance Attestation Tests
// =============================================================================

func TestPCRMismatchErrorCoverage(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex: 7,
			Message:  "custom error message",
		}
		assert.Equal(t, "custom error message", err.Error())
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("without custom message", func(t *testing.T) {
		err := &PCRMismatchError{
			PCRIndex:      7,
			ExpectedValue: []byte{0x01, 0x02, 0x03},
			ActualValue:   []byte{0x04, 0x05, 0x06},
		}
		errStr := err.Error()
		assert.Contains(t, errStr, "PCR[7]")
		assert.Contains(t, errStr, "mismatch")
	})
}

func TestAttestationErrorCoverage(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &AttestationError{
		Op:  "test_operation",
		Err: innerErr,
	}

	assert.Contains(t, err.Error(), "test_operation")
	assert.Contains(t, err.Error(), "inner error")
	assert.ErrorIs(t, err, innerErr)
}

func TestEventLogErrorCoverage(t *testing.T) {
	err := &EventLogError{
		Message:     "event log error",
		MissingType: "EV_SEPARATOR",
	}

	assert.Equal(t, "event log error", err.Error())
	assert.True(t, errors.Is(err, ErrEventLogInvalid))
}

func TestEventLogPCRMismatchErrorCoverage(t *testing.T) {
	err := &EventLogPCRMismatchError{
		PCRIndex:      0,
		Algorithm:     "SHA256",
		ExpectedValue: []byte{0x01, 0x02},
		ActualValue:   []byte{0x03, 0x04},
	}

	errStr := err.Error()
	assert.Contains(t, errStr, "PCR[0]")
	assert.Contains(t, errStr, "SHA256")
	assert.True(t, errors.Is(err, ErrEventLogPCRMismatch))
	assert.True(t, errors.Is(err, ErrEventLogInvalid))
}

func TestQuoteValidationErrorCoverage(t *testing.T) {
	err := &QuoteValidationError{
		Reason: "test reason",
	}

	assert.Contains(t, err.Error(), "test reason")
	assert.True(t, errors.Is(err, ErrQuoteInvalid))
}

func TestDeviceProfileErrorCoverage(t *testing.T) {
	innerErr := errors.New("profile lookup failed")
	err := &DeviceProfileError{
		Op:  "lookup",
		Err: innerErr,
	}

	assert.Contains(t, err.Error(), "lookup")
	assert.Contains(t, err.Error(), "device profile")
	assert.ErrorIs(t, err, innerErr)
}

// =============================================================================
// Service Tests
// =============================================================================

// =============================================================================
// Tenant Resolution Tests
// =============================================================================

// =============================================================================
// Additional Service Method Tests
// =============================================================================

func TestParseAccountIDCoverage(t *testing.T) {
	t.Run("valid URL", func(t *testing.T) {
		id, err := ParseAccountID("https://example.com/acme/account/12345")
		assert.NoError(t, err)
		assert.Equal(t, uint64(12345), id)
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := ParseAccountID("https://example.com/acme/account/invalid")
		assert.ErrorIs(t, err, ErrInvalidAccountID)
	})
}

// =============================================================================
// compareKeyMaps Tests
// =============================================================================

// =============================================================================
// extendPCR Tests
// =============================================================================

// =============================================================================
// algorithmStringToID Tests
// =============================================================================

// =============================================================================
// eventTypeToString Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// parseLegacyEvent Tests - Target 90% coverage
// =============================================================================

func TestParseLegacyEvent_Handlers90(t *testing.T) {
	t.Run("valid legacy event", func(t *testing.T) {
		// Build a valid TCG_PCR_EVENT structure
		buf := make([]byte, 0, 100)

		// PCR index (4 bytes)
		pcrIndex := make([]byte, 4)
		binary.LittleEndian.PutUint32(pcrIndex, 0)
		buf = append(buf, pcrIndex...)

		// Event type (4 bytes)
		eventType := make([]byte, 4)
		binary.LittleEndian.PutUint32(eventType, EVSeparator)
		buf = append(buf, eventType...)

		// SHA-1 digest (20 bytes)
		digest := make([]byte, 20)
		buf = append(buf, digest...)

		// Event data size (4 bytes)
		dataSize := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataSize, 4)
		buf = append(buf, dataSize...)

		// Event data
		buf = append(buf, []byte("test")...)

		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.NotEmpty(t, events)
		assert.Equal(t, 0, events[0].PCRIndex)
		assert.Equal(t, "EV_SEPARATOR", events[0].EventType)
	})

	t.Run("truncated PCR index", func(t *testing.T) {
		buf := make([]byte, 2) // Too short
		events, err := parseEventLog(buf)
		// Should not fail but should return empty
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("truncated event type", func(t *testing.T) {
		buf := make([]byte, 6) // PCR index ok, event type truncated
		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("truncated digest", func(t *testing.T) {
		buf := make([]byte, 10) // PCR + event type ok, digest truncated
		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})

	t.Run("event data too large", func(t *testing.T) {
		buf := make([]byte, 0, 32)
		pcrIndex := make([]byte, 4)
		eventType := make([]byte, 4)
		digest := make([]byte, 20)
		dataSize := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataSize, 2<<20) // 2MB - too large

		buf = append(buf, pcrIndex...)
		buf = append(buf, eventType...)
		buf = append(buf, digest...)
		buf = append(buf, dataSize...)

		events, err := parseEventLog(buf)
		assert.NoError(t, err)
		assert.Empty(t, events)
	})
}

// =============================================================================
// parseTPMSignature Tests - Target 90% coverage
// =============================================================================

func TestParseTPMSignature_Handlers90(t *testing.T) {
	t.Run("RSA signature", func(t *testing.T) {
		buf := make([]byte, 0, 100)
		// Signature algorithm (2 bytes big-endian)
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgRSASSA)
		buf = append(buf, sigAlg...)

		// Hash algorithm (2 bytes)
		hashAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlg, TCGAlgSHA256)
		buf = append(buf, hashAlg...)

		// Signature size (2 bytes)
		sigSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sigSize, 32)
		buf = append(buf, sigSize...)

		// Signature data
		sig := make([]byte, 32)
		buf = append(buf, sig...)

		alg, sigData, err := parseTPMSignature(buf)
		assert.NoError(t, err)
		assert.Equal(t, TPMAlgRSASSA, alg)
		assert.Len(t, sigData, 32)
	})

	t.Run("ECDSA signature", func(t *testing.T) {
		buf := make([]byte, 0, 100)
		// Signature algorithm
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgECDSA)
		buf = append(buf, sigAlg...)

		// Hash algorithm
		hashAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlg, TCGAlgSHA256)
		buf = append(buf, hashAlg...)

		// R size and value
		rSize := make([]byte, 2)
		binary.BigEndian.PutUint16(rSize, 32)
		buf = append(buf, rSize...)
		rBytes := make([]byte, 32)
		buf = append(buf, rBytes...)

		// S size and value
		sSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sSize, 32)
		buf = append(buf, sSize...)
		sBytes := make([]byte, 32)
		buf = append(buf, sBytes...)

		alg, sigData, err := parseTPMSignature(buf)
		assert.NoError(t, err)
		assert.Equal(t, TPMAlgECDSA, alg)
		assert.Len(t, sigData, 64)
	})

	t.Run("too short", func(t *testing.T) {
		buf := make([]byte, 2)
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf, 0xFFFF) // Unknown algorithm
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("RSA too short", func(t *testing.T) {
		buf := make([]byte, 5) // Need at least 6 for RSA
		binary.BigEndian.PutUint16(buf, TPMAlgRSASSA)
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("RSA signature data too short", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint16(buf, TPMAlgRSASSA)
		binary.BigEndian.PutUint16(buf[2:], TCGAlgSHA256)
		binary.BigEndian.PutUint16(buf[4:], 100) // Claim 100 bytes
		// But only have 2 more bytes
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("ECDSA R too short", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint16(buf, TPMAlgECDSA)
		binary.BigEndian.PutUint16(buf[2:], TCGAlgSHA256)
		binary.BigEndian.PutUint16(buf[4:], 100) // R claims 100 bytes
		// Not enough data
		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})

	t.Run("ECDSA S too short", func(t *testing.T) {
		buf := make([]byte, 0, 50)
		sigAlg := make([]byte, 2)
		binary.BigEndian.PutUint16(sigAlg, TPMAlgECDSA)
		buf = append(buf, sigAlg...)

		hashAlg := make([]byte, 2)
		buf = append(buf, hashAlg...)

		// R size and value (small)
		rSize := make([]byte, 2)
		binary.BigEndian.PutUint16(rSize, 2)
		buf = append(buf, rSize...)
		buf = append(buf, 0x01, 0x02)

		// S size claims large
		sSize := make([]byte, 2)
		binary.BigEndian.PutUint16(sSize, 100)
		buf = append(buf, sSize...)
		// No S data

		_, _, err := parseTPMSignature(buf)
		assert.Error(t, err)
	})
}

// =============================================================================
// parseRawPublicKey Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// NewDeviceProfileHook Tests - Target 90% coverage
// =============================================================================

func TestNewDeviceProfileHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("nil TCGData skipped", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("should not be called")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData:  nil,
		})
		assert.NoError(t, err)
	})

	t.Run("lookup error", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, errors.New("database error")
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.Error(t, err)
		var profileErr *DeviceProfileError
		assert.True(t, errors.As(err, &profileErr))
	})

	t.Run("no profile found - allowed", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return nil, nil // No profile found
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.NoError(t, err)
	})

	t.Run("profile found with no expected PCRs", func(t *testing.T) {
		hook := NewDeviceProfileHook(func(serial, model string) (*DeviceProfile, error) {
			return &DeviceProfile{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
				// No ExpectedPCRs
			}, nil
		})

		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				ProductSerial: "ABC123",
				ProductModel:  "Model-X",
			},
		})
		assert.NoError(t, err)
	})
}

// =============================================================================
// hasEventType Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// NewEventLogValidationHook Tests - Target 90% coverage
// =============================================================================

func TestNewEventLogValidationHook_Handlers90(t *testing.T) {
	t.Run("non-TCG enrollment skipped", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: false,
		})
		assert.NoError(t, err)
	})

	t.Run("empty event log allowed when no required events", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: nil,
			},
		})
		assert.NoError(t, err)
	})

	t.Run("empty event log error when required events specified", func(t *testing.T) {
		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: nil,
			},
		})
		assert.Error(t, err)
	})

	t.Run("max event count exceeded", func(t *testing.T) {
		// Build a simple event log with multiple events
		eventLog := buildLegacyEventLog(t, 5)

		hook := NewEventLogValidationHook(&EventLogPolicy{
			MaxEventCount: 2,
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max allowed")
	})

	t.Run("required event found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVSeparator, EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.NoError(t, err)
	})

	t.Run("required event not found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			RequiredEvents: []string{"EV_SEPARATOR"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required event")
	})

	t.Run("forbidden event found", func(t *testing.T) {
		eventLog := buildLegacyEventLogWithTypes(t, []uint32{EVSeparator, EVPostCode})

		hook := NewEventLogValidationHook(&EventLogPolicy{
			ForbiddenEvents: []string{"EV_POST_CODE"},
		})
		err := hook(&PreIssuanceHookContext{
			IsTCGCSR: true,
			TCGData: &TCGEnrollmentData{
				EventLog: eventLog,
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden")
	})
}

// =============================================================================
// NewPCRValidationHook Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// NewQuoteValidationHook Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// verifyQuoteSignature Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// parseCryptoAgileEvent Tests - Target 90% coverage
// =============================================================================

func TestParseCryptoAgileEvent_Handlers90(t *testing.T) {
	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: TCGAlgSHA256, DigestSize: 32},
		{AlgorithmID: TCGAlgSHA1, DigestSize: 20},
	}

	t.Run("valid event with SHA256", func(t *testing.T) {
		buf := new(bytes.Buffer)
		// PCR index
		binary.Write(buf, binary.LittleEndian, uint32(0))
		// Event type
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		// Digest count
		binary.Write(buf, binary.LittleEndian, uint32(1))
		// Algorithm ID
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA256))
		// Digest (32 bytes for SHA256)
		buf.Write(make([]byte, 32))
		// Event data size
		binary.Write(buf, binary.LittleEndian, uint32(0))

		reader := bytes.NewReader(buf.Bytes())
		entry, err := parseCryptoAgileEvent(reader, algorithms)
		assert.NoError(t, err)
		assert.Equal(t, 0, entry.PCRIndex)
		assert.Equal(t, "EV_SEPARATOR", entry.EventType)
	})

	t.Run("truncated PCR index", func(t *testing.T) {
		buf := make([]byte, 2) // Too short
		reader := bytes.NewReader(buf)
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("truncated event type", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0)) // PCR index only
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("truncated digest count", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0)) // PCR index
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, algorithms)
		assert.Error(t, err)
	})

	t.Run("unknown algorithm uses default sizes", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		binary.Write(buf, binary.LittleEndian, uint32(1))
		binary.Write(buf, binary.LittleEndian, uint16(TCGAlgSHA384)) // Not in algorithms list
		buf.Write(make([]byte, 48))                                  // SHA384 is 48 bytes
		binary.Write(buf, binary.LittleEndian, uint32(0))

		reader := bytes.NewReader(buf.Bytes())
		entry, err := parseCryptoAgileEvent(reader, []SpecIDAlgorithm{})
		assert.NoError(t, err)
		assert.Equal(t, "EV_SEPARATOR", entry.EventType)
	})

	t.Run("truly unknown algorithm fails", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(EVSeparator))
		binary.Write(buf, binary.LittleEndian, uint32(1))
		binary.Write(buf, binary.LittleEndian, uint16(0x9999)) // Unknown algorithm
		reader := bytes.NewReader(buf.Bytes())
		_, err := parseCryptoAgileEvent(reader, []SpecIDAlgorithm{})
		assert.Error(t, err)
	})
}

// =============================================================================
// parseCryptoAgileEventLog Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// parseSpecIDEvent Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// validateDeviceAgainstProfile Tests - Target 90% coverage
// =============================================================================

// =============================================================================
// Helper Functions for building test data
// =============================================================================

func createHMACCoverage(_ *testing.T, message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// buildLegacyEventLog creates a simple legacy event log with n events
func buildLegacyEventLog(t *testing.T, count int) []byte {
	types := make([]uint32, count)
	for i := range types {
		types[i] = EVSeparator
	}
	return buildLegacyEventLogWithTypes(t, types)
}

// buildLegacyEventLogWithTypes creates a legacy event log with specific event types
func buildLegacyEventLogWithTypes(t *testing.T, eventTypes []uint32) []byte {
	var buf []byte

	for i, evType := range eventTypes {
		// PCR index (4 bytes)
		pcrIndex := make([]byte, 4)
		binary.LittleEndian.PutUint32(pcrIndex, uint32(i%8))
		buf = append(buf, pcrIndex...)

		// Event type (4 bytes)
		eventType := make([]byte, 4)
		binary.LittleEndian.PutUint32(eventType, evType)
		buf = append(buf, eventType...)

		// SHA-1 digest (20 bytes)
		digest := make([]byte, 20)
		buf = append(buf, digest...)

		// Event data size (4 bytes) - 0 data
		dataSize := make([]byte, 4)
		buf = append(buf, dataSize...)
	}

	return buf
}
