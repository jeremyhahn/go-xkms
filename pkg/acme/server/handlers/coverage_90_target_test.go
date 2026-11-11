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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
// Helper Functions for building test data
// =============================================================================

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
