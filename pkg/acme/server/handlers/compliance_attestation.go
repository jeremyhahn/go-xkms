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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Attestation compliance errors
var (
	// ErrAttestationDataMissing is returned when attestation data is required but not provided
	ErrAttestationDataMissing = errors.New("attestation data required but not provided")

	// ErrPCRMismatch is returned when PCR values do not match expected values
	ErrPCRMismatch = errors.New("PCR values do not match expected state")

	// ErrEventLogInvalid is returned when the event log fails validation
	ErrEventLogInvalid = errors.New("event log validation failed")

	// ErrQuoteInvalid is returned when the TPM quote is invalid
	ErrQuoteInvalid = errors.New("TPM quote validation failed")

	// ErrPCRParsingFailed is returned when PCR data cannot be parsed
	ErrPCRParsingFailed = errors.New("failed to parse PCR data")

	// ErrEventLogParsingFailed is returned when event log parsing fails
	ErrEventLogParsingFailed = errors.New("failed to parse event log")

	// ErrUnsupportedHashAlgorithm is returned when an unsupported hash algorithm is encountered
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")

	// ErrInvalidQuoteStructure is returned when the quote structure is malformed
	ErrInvalidQuoteStructure = errors.New("invalid quote structure")

	// ErrSignatureVerificationFailed is returned when signature verification fails
	ErrSignatureVerificationFailed = errors.New("signature verification failed")

	// ErrEventLogPCRMismatch is returned when event log replay does not match PCR values
	ErrEventLogPCRMismatch = errors.New("event log does not match PCR values")
)

// PCRPolicy defines expected PCR values for device state validation.
type PCRPolicy struct {
	// ExpectedPCRs maps PCR indices to expected digest values.
	// Only PCRs specified in this map are validated.
	ExpectedPCRs map[int][]byte

	// AllowedPCRBanks specifies which hash algorithms are acceptable.
	// If empty, any algorithm is accepted.
	AllowedPCRBanks []string // e.g., "SHA256", "SHA384"

	// StrictMode requires all specified PCRs to be present in the quote.
	// If false, missing PCRs are ignored.
	StrictMode bool
}

// EventLogPolicy defines validation rules for TPM event logs.
type EventLogPolicy struct {
	// RequiredEvents specifies event types that must be present.
	RequiredEvents []string

	// ForbiddenEvents specifies event types that must NOT be present.
	ForbiddenEvents []string

	// MaxEventCount limits the total number of events (0 = unlimited).
	MaxEventCount int

	// ValidateAgainstPCRs requires the event log to match PCR values.
	ValidateAgainstPCRs bool
}

// NewPCRValidationHook creates a pre-issuance hook that verifies
// PCR values match expected device state.
//
// This hook:
//   - Extracts attestation data from TCGEnrollmentData.ProdCaData
//   - Compares PCR values against the expected values in the policy
//   - Returns an error if any PCR doesn't match the expected value
//
// Parameters:
//   - policy: PCR validation policy defining expected values
//
// Returns nil if PCR validation passes, or an error describing the failure.
func NewPCRValidationHook(policy *PCRPolicy) PreIssuanceHook {
	return func(ctx *PreIssuanceHookContext) error {
		// Skip for non-TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Check if attestation data is available
		if len(ctx.TCGData.ProdCaData) == 0 {
			if policy.StrictMode {
				return ErrAttestationDataMissing
			}
			return nil // No attestation data, skip validation
		}

		// Unpack ProdCaData to extract Quote and PCRs
		prodCaData, err := xkmssdk.UnpackProdCaData(ctx.TCGData.ProdCaData)
		if err != nil {
			return &AttestationError{
				Op:  "unpack_prodcadata",
				Err: err,
			}
		}

		// Extract PCR values from the attestation
		pcrValues := prodCaData.PCRs
		if len(pcrValues) == 0 {
			if policy.StrictMode {
				return &PCRMismatchError{
					PCRIndex:      -1,
					ExpectedValue: nil,
					ActualValue:   nil,
					Message:       "no PCR values in attestation data",
				}
			}
			return nil
		}

		// Validate PCR values against expected values
		for pcrIndex, expectedValue := range policy.ExpectedPCRs {
			// Find the PCR value in the attestation
			actualValue, found := findPCRValue(pcrValues, pcrIndex)
			if !found {
				if policy.StrictMode {
					return &PCRMismatchError{
						PCRIndex:      pcrIndex,
						ExpectedValue: expectedValue,
						ActualValue:   nil,
						Message:       "PCR not present in attestation",
					}
				}
				continue
			}

			// Compare values
			if !bytes.Equal(actualValue, expectedValue) {
				return &PCRMismatchError{
					PCRIndex:      pcrIndex,
					ExpectedValue: expectedValue,
					ActualValue:   actualValue,
				}
			}
		}

		return nil
	}
}

// findPCRValue extracts a specific PCR value from gob-encoded PCR bank data.
// The PCR data is encoded using go-xkms's tpm2.EncodePCRs function which
// uses gob encoding for []PCRBank structures.
func findPCRValue(pcrData []byte, index int) ([]byte, bool) {
	if len(pcrData) == 0 {
		return nil, false
	}

	// Decode the PCR banks using go-xkms's decoder
	banks, err := xkmssdk.DecodePCRs(pcrData)
	if err != nil {
		return nil, false
	}

	// Search through all banks for the requested PCR index
	// Prefer SHA-256 bank if available, otherwise use first match
	var sha256Value []byte
	var firstValue []byte

	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			if int(pcr.ID) == index {
				if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
					sha256Value = pcr.Value
				} else if firstValue == nil {
					firstValue = pcr.Value
				}
			}
		}
	}

	// Return SHA-256 value if available, otherwise first match
	if sha256Value != nil {
		return sha256Value, true
	}
	if firstValue != nil {
		return firstValue, true
	}

	return nil, false
}

// PCRMismatchError represents a PCR validation failure.
type PCRMismatchError struct {
	PCRIndex      int
	ExpectedValue []byte
	ActualValue   []byte
	Message       string
}

// Error implements the error interface.
func (e *PCRMismatchError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "PCR[" + intToStr(e.PCRIndex) + "] mismatch: expected " +
		bytesToHex(e.ExpectedValue) + ", got " + bytesToHex(e.ActualValue)
}

// Is implements errors.Is for error comparison.
func (e *PCRMismatchError) Is(target error) bool {
	return target == ErrPCRMismatch
}

// AttestationError represents a generic attestation error.
type AttestationError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *AttestationError) Error() string {
	return "failed to " + e.Op + " attestation data: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *AttestationError) Unwrap() error {
	return e.Err
}

// NewEventLogValidationHook creates a pre-issuance hook that validates
// the TPM boot event log against a policy.
//
// This hook:
//   - Extracts the event log from TCGEnrollmentData.EventLog
//   - Validates the event log against the specified policy
//   - Checks for required and forbidden events
//
// Parameters:
//   - policy: Event log validation policy
//
// Returns nil if event log validation passes, or an error describing the failure.
func NewEventLogValidationHook(policy *EventLogPolicy) PreIssuanceHook {
	return func(ctx *PreIssuanceHookContext) error {
		// Skip for non-TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Check if event log is available
		if len(ctx.TCGData.EventLog) == 0 {
			// Event log is optional unless required events are specified
			if len(policy.RequiredEvents) > 0 {
				return &EventLogError{
					Message: "event log required but not provided",
				}
			}
			return nil
		}

		// Parse the event log
		events, err := parseEventLog(ctx.TCGData.EventLog)
		if err != nil {
			return &EventLogError{
				Message: "parse error: " + err.Error(),
			}
		}

		// Check max event count
		if policy.MaxEventCount > 0 && len(events) > policy.MaxEventCount {
			return &EventLogError{
				Message: "event log has " + intToStr(len(events)) + " events, max allowed is " + intToStr(policy.MaxEventCount),
			}
		}

		// Check required events
		for _, required := range policy.RequiredEvents {
			if !hasEventType(events, required) {
				return &EventLogError{
					Message:     "required event type not found: " + required,
					MissingType: required,
				}
			}
		}

		// Check forbidden events
		for _, forbidden := range policy.ForbiddenEvents {
			if hasEventType(events, forbidden) {
				return &EventLogError{
					Message:       "forbidden event type found: " + forbidden,
					ForbiddenType: forbidden,
				}
			}
		}

		// Optionally validate event log against PCR values
		if policy.ValidateAgainstPCRs {
			if err := validateEventLogAgainstPCRs(ctx.TCGData.EventLog, ctx.TCGData.ProdCaData); err != nil {
				return err
			}
		}

		return nil
	}
}

// TCG Event Types as defined in TCG PC Client Specific Implementation Specification
const (
	EVPrebootCert         uint32 = 0x00000000
	EVPostCode            uint32 = 0x00000001
	EVUnused              uint32 = 0x00000002
	EVNoAction            uint32 = 0x00000003
	EVSeparator           uint32 = 0x00000004
	EVAction              uint32 = 0x00000005
	EVEventTag            uint32 = 0x00000006
	EVSCRTMContents       uint32 = 0x00000007
	EVSCRTMVersion        uint32 = 0x00000008
	EVCPUMicrocode        uint32 = 0x00000009
	EVPlatformConfigFlags uint32 = 0x0000000A
	EVTableOfDevices      uint32 = 0x0000000B
	EVCompactHash         uint32 = 0x0000000C
	EVIPL                 uint32 = 0x0000000D
	EVIPLPartitionData    uint32 = 0x0000000E
	EVNonhostCode         uint32 = 0x0000000F
	EVNonhostConfig       uint32 = 0x00000010
	EVNonhostInfo         uint32 = 0x00000011
	EVOmitBootDevEvents   uint32 = 0x00000012

	// EFI Event Types
	EVEFIEventBase               uint32 = 0x80000000
	EVEFIVariableDriverConfig    uint32 = 0x80000001
	EVEFIVariableBoot            uint32 = 0x80000002
	EVEFIBootServicesApplication uint32 = 0x80000003
	EVEFIBootServicesDriver      uint32 = 0x80000004
	EVEFIRuntimeServicesDriver   uint32 = 0x80000005
	EVEFIGPTEvent                uint32 = 0x80000006
	EVEFIAction                  uint32 = 0x80000007
	EVEFIPlatformFirmwareBlob    uint32 = 0x80000008
	EVEFIHandoffTables           uint32 = 0x80000009
	EVEFIHCRTMEvent              uint32 = 0x80000010
	EVEFIVariableAuthority       uint32 = 0x800000E0
)

// TCG Hash Algorithm IDs
const (
	TCGAlgSHA1   uint16 = 0x0004
	TCGAlgSHA256 uint16 = 0x000B
	TCGAlgSHA384 uint16 = 0x000C
	TCGAlgSHA512 uint16 = 0x000D
)

// eventTypeNames maps TCG event type constants to their string representations
// for O(1) constant-time lookup.
var eventTypeNames = map[uint32]string{
	EVPrebootCert:                "EV_PREBOOT_CERT",
	EVPostCode:                   "EV_POST_CODE",
	EVUnused:                     "EV_UNUSED",
	EVNoAction:                   "EV_NO_ACTION",
	EVSeparator:                  "EV_SEPARATOR",
	EVAction:                     "EV_ACTION",
	EVEventTag:                   "EV_EVENT_TAG",
	EVSCRTMContents:              "EV_S_CRTM_CONTENTS",
	EVSCRTMVersion:               "EV_S_CRTM_VERSION",
	EVCPUMicrocode:               "EV_CPU_MICROCODE",
	EVPlatformConfigFlags:        "EV_PLATFORM_CONFIG_FLAGS",
	EVTableOfDevices:             "EV_TABLE_OF_DEVICES",
	EVCompactHash:                "EV_COMPACT_HASH",
	EVIPL:                        "EV_IPL",
	EVIPLPartitionData:           "EV_IPL_PARTITION_DATA",
	EVNonhostCode:                "EV_NONHOST_CODE",
	EVNonhostConfig:              "EV_NONHOST_CONFIG",
	EVNonhostInfo:                "EV_NONHOST_INFO",
	EVOmitBootDevEvents:          "EV_OMIT_BOOT_DEVICE_EVENTS",
	EVEFIVariableDriverConfig:    "EV_EFI_VARIABLE_DRIVER_CONFIG",
	EVEFIVariableBoot:            "EV_EFI_VARIABLE_BOOT",
	EVEFIBootServicesApplication: "EV_EFI_BOOT_SERVICES_APPLICATION",
	EVEFIBootServicesDriver:      "EV_EFI_BOOT_SERVICES_DRIVER",
	EVEFIRuntimeServicesDriver:   "EV_EFI_RUNTIME_SERVICES_DRIVER",
	EVEFIGPTEvent:                "EV_EFI_GPT_EVENT",
	EVEFIAction:                  "EV_EFI_ACTION",
	EVEFIPlatformFirmwareBlob:    "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	EVEFIHandoffTables:           "EV_EFI_HANDOFF_TABLES",
	EVEFIHCRTMEvent:              "EV_EFI_HCRTM_EVENT",
	EVEFIVariableAuthority:       "EV_EFI_VARIABLE_AUTHORITY",
}

// EventLogEntry represents a parsed event log entry.
type EventLogEntry struct {
	PCRIndex  int
	EventType string
	Digest    []byte
	EventData []byte
	DigestAlg uint16 // Hash algorithm ID for crypto agile logs
}

// parseEventLog parses a TCG event log into structured entries.
// Supports both legacy SHA-1 format and crypto-agile format (TCG EFI Protocol).
func parseEventLog(eventLog []byte) ([]EventLogEntry, error) {
	if len(eventLog) == 0 {
		return []EventLogEntry{}, nil
	}

	// Try to detect the format by looking at the first event
	// Crypto-agile logs have TCG_PCR_EVENT2 structure
	// Legacy logs have TCG_PCR_EVENT structure

	// First, try parsing as crypto-agile format
	entries, err := parseCryptoAgileEventLog(eventLog)
	if err == nil && len(entries) > 0 {
		return entries, nil
	}

	// Fall back to legacy format
	entries = make([]EventLogEntry, 0)
	reader := bytes.NewReader(eventLog)
	for reader.Len() > 0 {
		entry, err := parseLegacyEvent(reader)
		if err != nil {
			// End of valid entries
			break
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLegacyEvent parses a single TCG_PCR_EVENT structure (SHA-1 only).
// Structure:
//   - PCRIndex: 4 bytes (uint32, little-endian)
//   - EventType: 4 bytes (uint32, little-endian)
//   - Digest: 20 bytes (SHA-1)
//   - EventDataSize: 4 bytes (uint32, little-endian)
//   - EventData: EventDataSize bytes
func parseLegacyEvent(reader *bytes.Reader) (EventLogEntry, error) {
	var entry EventLogEntry

	// Read PCR index
	var pcrIndex uint32
	if err := binary.Read(reader, binary.LittleEndian, &pcrIndex); err != nil {
		return entry, ErrEventLogParsingFailed
	}
	entry.PCRIndex = int(pcrIndex)

	// Read event type
	var eventType uint32
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return entry, ErrEventLogParsingFailed
	}
	entry.EventType = eventTypeToString(eventType)

	// Read SHA-1 digest (20 bytes)
	digest := make([]byte, 20)
	if _, err := reader.Read(digest); err != nil {
		return entry, ErrEventLogParsingFailed
	}
	entry.Digest = digest
	entry.DigestAlg = TCGAlgSHA1

	// Read event data size
	var eventDataSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &eventDataSize); err != nil {
		return entry, ErrEventLogParsingFailed
	}

	// Sanity check event data size
	if eventDataSize > 1<<20 { // 1MB max
		return entry, ErrEventLogParsingFailed
	}

	// Read event data
	if eventDataSize > 0 {
		eventData := make([]byte, eventDataSize)
		if _, err := reader.Read(eventData); err != nil {
			return entry, ErrEventLogParsingFailed
		}
		entry.EventData = eventData
	}

	return entry, nil
}

// parseCryptoAgileEventLog parses TCG_PCR_EVENT2 structures (crypto-agile format).
// The first event is always a TCG_PCR_EVENT (legacy) with EV_NO_ACTION containing
// the TCG_EfiSpecIDEvent structure, followed by TCG_PCR_EVENT2 structures.
func parseCryptoAgileEventLog(eventLog []byte) ([]EventLogEntry, error) {
	if len(eventLog) < 32 { // Minimum size for legacy header
		return nil, ErrEventLogParsingFailed
	}

	entries := make([]EventLogEntry, 0)
	reader := bytes.NewReader(eventLog)

	// Parse the first event as legacy format (TCG_PCR_EVENT)
	// This contains EV_NO_ACTION with TCG_EfiSpecIDEvent
	firstEntry, err := parseLegacyEvent(reader)
	if err != nil {
		return nil, err
	}

	// Verify this is the spec ID event
	if firstEntry.EventType != "EV_NO_ACTION" || firstEntry.PCRIndex != 0 {
		// Not crypto-agile format, return error to fall back to legacy
		return nil, ErrEventLogParsingFailed
	}

	// Parse the spec ID event to get the algorithm list
	algorithms, err := parseSpecIDEvent(firstEntry.EventData)
	if err != nil {
		// Not crypto-agile format
		return nil, ErrEventLogParsingFailed
	}

	entries = append(entries, firstEntry)

	// Parse remaining events as TCG_PCR_EVENT2
	for reader.Len() > 0 {
		entry, err := parseCryptoAgileEvent(reader, algorithms)
		if err != nil {
			break
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// SpecIDAlgorithm represents an algorithm entry in TCG_EfiSpecIDEvent.
type SpecIDAlgorithm struct {
	AlgorithmID uint16
	DigestSize  uint16
}

// parseSpecIDEvent parses the TCG_EfiSpecIDEvent structure to extract supported algorithms.
func parseSpecIDEvent(data []byte) ([]SpecIDAlgorithm, error) {
	if len(data) < 28 { // Minimum size for spec ID event
		return nil, ErrEventLogParsingFailed
	}

	reader := bytes.NewReader(data)

	// Skip signature (16 bytes)
	sig := make([]byte, 16)
	if _, err := reader.Read(sig); err != nil {
		return nil, err
	}

	// Verify signature is "Spec ID Event03"
	expectedSig := []byte("Spec ID Event03")
	if !bytes.HasPrefix(sig, expectedSig) {
		return nil, ErrEventLogParsingFailed
	}

	// Skip platformClass (4 bytes), specVersionMinor (1), specVersionMajor (1), specErrata (1)
	skip := make([]byte, 7)
	if _, err := reader.Read(skip); err != nil {
		return nil, err
	}

	// Read uintnSize (1 byte)
	var uintnSize uint8
	if err := binary.Read(reader, binary.LittleEndian, &uintnSize); err != nil {
		return nil, err
	}
	_ = uintnSize // Used for documentation purposes

	// Read numberOfAlgorithms (4 bytes)
	var numAlgorithms uint32
	if err := binary.Read(reader, binary.LittleEndian, &numAlgorithms); err != nil {
		return nil, err
	}

	if numAlgorithms > 16 { // Sanity check
		return nil, ErrEventLogParsingFailed
	}

	// Read algorithm entries
	algorithms := make([]SpecIDAlgorithm, numAlgorithms)
	for i := uint32(0); i < numAlgorithms; i++ {
		var alg SpecIDAlgorithm
		if err := binary.Read(reader, binary.LittleEndian, &alg.AlgorithmID); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.LittleEndian, &alg.DigestSize); err != nil {
			return nil, err
		}
		algorithms[i] = alg
	}

	return algorithms, nil
}

// parseCryptoAgileEvent parses a single TCG_PCR_EVENT2 structure.
// Structure:
//   - PCRIndex: 4 bytes (uint32, little-endian)
//   - EventType: 4 bytes (uint32, little-endian)
//   - Digests: TPML_DIGEST_VALUES (count + array of TPMT_HA)
//   - EventDataSize: 4 bytes (uint32, little-endian)
//   - EventData: EventDataSize bytes
func parseCryptoAgileEvent(reader *bytes.Reader, algorithms []SpecIDAlgorithm) (EventLogEntry, error) {
	var entry EventLogEntry

	// Read PCR index
	var pcrIndex uint32
	if err := binary.Read(reader, binary.LittleEndian, &pcrIndex); err != nil {
		return entry, ErrEventLogParsingFailed
	}
	entry.PCRIndex = int(pcrIndex)

	// Read event type
	var eventType uint32
	if err := binary.Read(reader, binary.LittleEndian, &eventType); err != nil {
		return entry, ErrEventLogParsingFailed
	}
	entry.EventType = eventTypeToString(eventType)

	// Read digest count
	var digestCount uint32
	if err := binary.Read(reader, binary.LittleEndian, &digestCount); err != nil {
		return entry, ErrEventLogParsingFailed
	}

	// Read digests - use the first SHA-256 digest if available, otherwise SHA-1
	for i := uint32(0); i < digestCount; i++ {
		var algID uint16
		if err := binary.Read(reader, binary.LittleEndian, &algID); err != nil {
			return entry, ErrEventLogParsingFailed
		}

		// Find digest size for this algorithm
		digestSize := uint16(0)
		for _, alg := range algorithms {
			if alg.AlgorithmID == algID {
				digestSize = alg.DigestSize
				break
			}
		}

		if digestSize == 0 {
			// Unknown algorithm, try to infer size
			switch algID {
			case TCGAlgSHA1:
				digestSize = 20
			case TCGAlgSHA256:
				digestSize = 32
			case TCGAlgSHA384:
				digestSize = 48
			case TCGAlgSHA512:
				digestSize = 64
			default:
				return entry, ErrEventLogParsingFailed
			}
		}

		digest := make([]byte, digestSize)
		if _, err := reader.Read(digest); err != nil {
			return entry, ErrEventLogParsingFailed
		}

		// Prefer SHA-256 digest
		if algID == TCGAlgSHA256 || (entry.Digest == nil && algID == TCGAlgSHA1) {
			entry.Digest = digest
			entry.DigestAlg = algID
		}
	}

	// Read event data size
	var eventDataSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &eventDataSize); err != nil {
		return entry, ErrEventLogParsingFailed
	}

	// Sanity check
	if eventDataSize > 1<<20 {
		return entry, ErrEventLogParsingFailed
	}

	// Read event data
	if eventDataSize > 0 {
		eventData := make([]byte, eventDataSize)
		if _, err := reader.Read(eventData); err != nil {
			return entry, ErrEventLogParsingFailed
		}
		entry.EventData = eventData
	}

	return entry, nil
}

// eventTypeToString converts a TCG event type to its string representation
// using O(1) map-based lookup.
func eventTypeToString(eventType uint32) string {
	if s, ok := eventTypeNames[eventType]; ok {
		return s
	}
	return "EV_UNKNOWN_" + uint32ToHex(eventType)
}

// hasEventType checks if any event in the log matches the specified type.
func hasEventType(events []EventLogEntry, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

// validateEventLogAgainstPCRs verifies that the event log's computed
// PCR values match the attested PCR values.
func validateEventLogAgainstPCRs(eventLog, prodCaData []byte) error {
	if len(eventLog) == 0 || len(prodCaData) == 0 {
		return nil // Nothing to validate
	}

	// Parse event log
	events, err := parseEventLog(eventLog)
	if err != nil {
		return &EventLogError{
			Message: "failed to parse event log: " + err.Error(),
		}
	}

	// Unpack ProdCaData to get actual PCR values
	data, err := xkmssdk.UnpackProdCaData(prodCaData)
	if err != nil {
		return &EventLogError{
			Message: "failed to unpack attestation data: " + err.Error(),
		}
	}

	if len(data.PCRs) == 0 {
		return nil // No PCRs to validate against
	}

	// Decode the actual PCR values
	actualBanks, err := xkmssdk.DecodePCRs(data.PCRs)
	if err != nil {
		return &EventLogError{
			Message: "failed to decode PCR banks: " + err.Error(),
		}
	}

	// Compute expected PCR values by replaying the event log
	// Track which PCRs we've computed for each algorithm
	computedPCRs := make(map[uint16]map[int][]byte)

	for _, event := range events {
		if len(event.Digest) == 0 {
			continue
		}

		algID := event.DigestAlg
		if algID == 0 {
			algID = TCGAlgSHA1 // Default to SHA-1 for legacy events
		}

		// Initialize the PCR map for this algorithm if needed
		if computedPCRs[algID] == nil {
			computedPCRs[algID] = make(map[int][]byte)
		}

		// Get the current PCR value (or initialize to zeros)
		pcrValue := computedPCRs[algID][event.PCRIndex]
		if pcrValue == nil {
			// Initialize to zeros based on digest size
			pcrValue = make([]byte, len(event.Digest))
		}

		// Extend the PCR: new_value = Hash(old_value || event_digest)
		newValue, err := extendPCR(pcrValue, event.Digest, algID)
		if err != nil {
			continue // Skip events with unsupported algorithms
		}
		computedPCRs[algID][event.PCRIndex] = newValue
	}

	// Compare computed PCR values against actual values
	for _, bank := range actualBanks {
		algID := algorithmStringToID(bank.Algorithm)
		if algID == 0 {
			continue
		}

		computed := computedPCRs[algID]
		if computed == nil {
			continue // No events for this algorithm
		}

		for _, pcr := range bank.PCRs {
			pcrIndex := int(pcr.ID)
			expectedValue, exists := computed[pcrIndex]
			if !exists {
				continue // PCR not in event log
			}

			if !bytes.Equal(expectedValue, pcr.Value) {
				return &EventLogPCRMismatchError{
					PCRIndex:      pcrIndex,
					Algorithm:     bank.Algorithm,
					ExpectedValue: expectedValue,
					ActualValue:   pcr.Value,
				}
			}
		}
	}

	return nil
}

// extendPCR computes the new PCR value by extending with the given digest.
// new_pcr = Hash(old_pcr || digest)
func extendPCR(currentValue, digest []byte, algID uint16) ([]byte, error) {
	var h hash.Hash
	switch algID {
	case TCGAlgSHA1:
		h = sha1.New() // #nosec G401 -- SHA-1 required for TPM 2.0 specification compatibility
	case TCGAlgSHA256:
		h = sha256.New()
	case TCGAlgSHA384:
		h = sha512.New384()
	case TCGAlgSHA512:
		h = sha512.New()
	default:
		return nil, ErrUnsupportedHashAlgorithm
	}

	h.Write(currentValue)
	h.Write(digest)
	return h.Sum(nil), nil
}

// algorithmStringToID converts an algorithm name to its TCG ID.
func algorithmStringToID(alg string) uint16 {
	switch alg {
	case "sha1", "SHA1":
		return TCGAlgSHA1
	case "sha256", "SHA256":
		return TCGAlgSHA256
	case "sha384", "SHA384":
		return TCGAlgSHA384
	case "sha512", "SHA512":
		return TCGAlgSHA512
	default:
		return 0
	}
}

// EventLogPCRMismatchError represents a mismatch between event log and PCR values.
type EventLogPCRMismatchError struct {
	PCRIndex      int
	Algorithm     string
	ExpectedValue []byte
	ActualValue   []byte
}

// Error implements the error interface.
func (e *EventLogPCRMismatchError) Error() string {
	return "event log PCR[" + intToStr(e.PCRIndex) + "] (" + e.Algorithm +
		") mismatch: computed " + bytesToHex(e.ExpectedValue) +
		", got " + bytesToHex(e.ActualValue)
}

// Is implements errors.Is for error comparison.
func (e *EventLogPCRMismatchError) Is(target error) bool {
	return target == ErrEventLogPCRMismatch || target == ErrEventLogInvalid
}

// EventLogError represents an event log validation failure.
type EventLogError struct {
	Message       string
	MissingType   string // Required event type that was not found
	ForbiddenType string // Forbidden event type that was found
}

// Error implements the error interface.
func (e *EventLogError) Error() string {
	return e.Message
}

// Is implements errors.Is for error comparison.
func (e *EventLogError) Is(target error) bool {
	return target == ErrEventLogInvalid
}

// NewQuoteValidationHook creates a pre-issuance hook that validates
// the TPM quote signature.
//
// This hook:
//   - Extracts the quote from TCGEnrollmentData.ProdCaData
//   - Verifies the quote signature using the attestation public key
//   - Validates the nonce if provided
//
// Parameters:
//   - expectedNonce: Optional nonce that should be in the quote (nil to skip check)
//
// Returns nil if quote validation passes, or an error describing the failure.
func NewQuoteValidationHook(expectedNonce []byte) PreIssuanceHook {
	return func(ctx *PreIssuanceHookContext) error {
		// Skip for non-TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Check if attestation data is available
		if len(ctx.TCGData.ProdCaData) == 0 {
			return nil // No attestation data, skip validation
		}

		// Unpack ProdCaData to extract Quote
		prodCaData, err := xkmssdk.UnpackProdCaData(ctx.TCGData.ProdCaData)
		if err != nil {
			return &AttestationError{
				Op:  "unpack_prodcadata",
				Err: err,
			}
		}

		// Verify nonce if expected
		if expectedNonce != nil {
			if !bytes.Equal(prodCaData.Nonce, expectedNonce) {
				return &QuoteValidationError{
					Reason: "nonce mismatch",
				}
			}
		}

		// Verify quote signature using attestation public key
		if len(ctx.TCGData.AttestationPublicKey) == 0 {
			return &QuoteValidationError{
				Reason: "attestation public key not available",
			}
		}

		// Parse the attestation public key
		pubKey, err := x509.ParsePKIXPublicKey(ctx.TCGData.AttestationPublicKey)
		if err != nil {
			// Try parsing as raw RSA or EC key
			pubKey, err = parseRawPublicKey(ctx.TCGData.AttestationPublicKey)
			if err != nil {
				return &QuoteValidationError{
					Reason: "failed to parse attestation public key: " + err.Error(),
				}
			}
		}

		// Verify the quote signature
		if err := verifyQuoteSignature(prodCaData.Quoted, prodCaData.Signature, pubKey); err != nil {
			return err
		}

		return nil
	}
}

// QuoteValidationError represents a quote validation failure.
type QuoteValidationError struct {
	Reason string
}

// Error implements the error interface.
func (e *QuoteValidationError) Error() string {
	return "TPM quote validation failed: " + e.Reason
}

// Is implements errors.Is for error comparison.
func (e *QuoteValidationError) Is(target error) bool {
	return target == ErrQuoteInvalid
}

// verifyQuoteSignature verifies the TPM quote signature.
// The signature is over the Quoted (TPMS_ATTEST) structure.
func verifyQuoteSignature(quoted, signature []byte, pubKey crypto.PublicKey) error {
	if len(quoted) == 0 || len(signature) == 0 {
		return &QuoteValidationError{
			Reason: "missing quoted data or signature",
		}
	}

	// Parse the signature to determine the algorithm
	// TPM signatures are wrapped in TPMT_SIGNATURE structure
	sigAlg, sigData, err := parseTPMSignature(signature)
	if err != nil {
		// Try as raw signature
		sigAlg = 0
		sigData = signature
	}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return verifyRSAQuoteSignature(quoted, sigAlg, sigData, key)
	case *ecdsa.PublicKey:
		return verifyECDSAQuoteSignature(quoted, sigAlg, sigData, key)
	default:
		return &QuoteValidationError{
			Reason: "unsupported public key type",
		}
	}
}

// TPM Signature Algorithm IDs
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016
	TPMAlgECDSA  uint16 = 0x0018
)

// parseTPMSignature parses a TPMT_SIGNATURE structure.
// Structure:
//   - sigAlg: 2 bytes (uint16, big-endian) - signature algorithm
//   - signature: algorithm-specific data
func parseTPMSignature(data []byte) (uint16, []byte, error) {
	if len(data) < 4 {
		return 0, nil, ErrInvalidQuoteStructure
	}

	sigAlg := binary.BigEndian.Uint16(data[0:2])

	switch sigAlg {
	case TPMAlgRSASSA, TPMAlgRSAPSS:
		// TPMS_SIGNATURE_RSA:
		// - hash: 2 bytes
		// - sig size: 2 bytes
		// - sig: variable
		if len(data) < 6 {
			return 0, nil, ErrInvalidQuoteStructure
		}
		sigSize := binary.BigEndian.Uint16(data[4:6])
		if len(data) < int(6+sigSize) {
			return 0, nil, ErrInvalidQuoteStructure
		}
		return sigAlg, data[6 : 6+sigSize], nil

	case TPMAlgECDSA:
		// TPMS_SIGNATURE_ECDSA:
		// - hash: 2 bytes
		// - signatureR: TPM2B_ECC_PARAMETER
		// - signatureS: TPM2B_ECC_PARAMETER
		if len(data) < 6 {
			return 0, nil, ErrInvalidQuoteStructure
		}
		offset := 4

		// Read R
		rSize := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if len(data) < offset+int(rSize)+2 {
			return 0, nil, ErrInvalidQuoteStructure
		}
		rBytes := data[offset : offset+int(rSize)]
		offset += int(rSize)

		// Read S
		sSize := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if len(data) < offset+int(sSize) {
			return 0, nil, ErrInvalidQuoteStructure
		}
		sBytes := data[offset : offset+int(sSize)]

		// Combine R and S
		sigData := make([]byte, len(rBytes)+len(sBytes))
		copy(sigData, rBytes)
		copy(sigData[len(rBytes):], sBytes)
		return sigAlg, sigData, nil

	default:
		return 0, nil, ErrInvalidQuoteStructure
	}
}

// verifyRSAQuoteSignature verifies an RSA signature over the quote.
func verifyRSAQuoteSignature(quoted []byte, sigAlg uint16, signature []byte, pubKey *rsa.PublicKey) error {
	// Hash the quoted data - use SHA-256 by default
	hash := sha256.Sum256(quoted)

	var err error
	if sigAlg == TPMAlgRSAPSS {
		// PSS signature
		err = rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		})
	} else {
		// PKCS#1 v1.5 signature
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
	}

	if err != nil {
		return &QuoteValidationError{
			Reason: "RSA signature verification failed: " + err.Error(),
		}
	}

	return nil
}

// verifyECDSAQuoteSignature verifies an ECDSA signature over the quote.
func verifyECDSAQuoteSignature(quoted []byte, _ uint16, signature []byte, pubKey *ecdsa.PublicKey) error {
	// Hash the quoted data - use appropriate hash based on curve
	var hashFunc crypto.Hash
	var digest []byte

	curveSize := pubKey.Curve.Params().BitSize
	switch {
	case curveSize <= 256:
		hashFunc = crypto.SHA256
		h := sha256.Sum256(quoted)
		digest = h[:]
	case curveSize <= 384:
		hashFunc = crypto.SHA384
		h := sha512.Sum384(quoted)
		digest = h[:]
	default:
		hashFunc = crypto.SHA512
		h := sha512.Sum512(quoted)
		digest = h[:]
	}

	// For ECDSA, the signature should be R || S
	coordLen := (curveSize + 7) / 8
	if len(signature) != 2*coordLen {
		// Try ASN.1 DER encoding
		if ecdsa.VerifyASN1(pubKey, digest, signature) {
			return nil
		}
		return &QuoteValidationError{
			Reason: "invalid ECDSA signature length",
		}
	}

	// Parse R and S from concatenated format
	rBytes := signature[:coordLen]
	sBytes := signature[coordLen:]

	// Convert to big integers and verify
	_ = hashFunc // Used for documentation
	if !ecdsa.Verify(pubKey, digest, bytesToBigInt(rBytes), bytesToBigInt(sBytes)) {
		return &QuoteValidationError{
			Reason: "ECDSA signature verification failed",
		}
	}

	return nil
}

// parseRawPublicKey attempts to parse a public key from various formats.
func parseRawPublicKey(data []byte) (crypto.PublicKey, error) {
	// Try RSA public key
	if key, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return key, nil
	}

	// Try EC public key from certificate
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert.PublicKey, nil
	}

	return nil, ErrUnsupportedKeyType
}

// NewDeviceProfileHook creates a pre-issuance hook that validates
// the device against a profile stored in an external service.
//
// This hook:
//   - Looks up the expected device profile by product serial/model
//   - Compares the device's attestation data against the profile
//   - Validates that the device is in an acceptable state
//
// Parameters:
//   - lookupFunc: Function to retrieve expected profile by device identifier
//
// Returns nil if device profile validation passes, or an error describing the failure.
func NewDeviceProfileHook(lookupFunc func(productSerial, productModel string) (*DeviceProfile, error)) PreIssuanceHook {
	return func(ctx *PreIssuanceHookContext) error {
		// Skip for non-TCG enrollments
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}

		// Look up the expected device profile
		profile, err := lookupFunc(ctx.TCGData.ProductSerial, ctx.TCGData.ProductModel)
		if err != nil {
			return &DeviceProfileError{
				Op:  "lookup",
				Err: err,
			}
		}

		if profile == nil {
			// No profile found - behavior depends on policy
			// For now, allow unknown devices
			return nil
		}

		// Validate device state against profile
		if err := validateDeviceAgainstProfile(ctx.TCGData, profile); err != nil {
			return err
		}

		return nil
	}
}

// DeviceProfileError represents a device profile validation error.
type DeviceProfileError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *DeviceProfileError) Error() string {
	return "failed to " + e.Op + " device profile: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *DeviceProfileError) Unwrap() error {
	return e.Err
}

// DeviceProfile represents the expected state of a device.
type DeviceProfile struct {
	// ProductSerial identifies the specific device
	ProductSerial string

	// ProductModel identifies the device model
	ProductModel string

	// ExpectedPCRs contains expected PCR values for this device
	ExpectedPCRs map[int][]byte

	// AllowedFirmwareVersions lists acceptable firmware versions
	AllowedFirmwareVersions []string

	// RequiredSecureBoot indicates if Secure Boot must be enabled
	RequiredSecureBoot bool

	// AdditionalChecks contains custom validation parameters
	AdditionalChecks map[string]string
}

// validateDeviceAgainstProfile validates the device's attestation data
// against the expected profile.
func validateDeviceAgainstProfile(tcgData *TCGEnrollmentData, profile *DeviceProfile) error {
	// Validate PCRs if profile specifies expected values
	if len(profile.ExpectedPCRs) > 0 {
		prodCaData, err := xkmssdk.UnpackProdCaData(tcgData.ProdCaData)
		if err != nil {
			return &AttestationError{
				Op:  "unpack_prodcadata",
				Err: err,
			}
		}

		for pcrIndex, expectedValue := range profile.ExpectedPCRs {
			actualValue, found := findPCRValue(prodCaData.PCRs, pcrIndex)
			if !found {
				return &PCRMismatchError{
					PCRIndex:      pcrIndex,
					ExpectedValue: expectedValue,
					ActualValue:   nil,
					Message:       "device missing expected PCR[" + intToStr(pcrIndex) + "]",
				}
			}
			if !bytes.Equal(actualValue, expectedValue) {
				return &PCRMismatchError{
					PCRIndex:      pcrIndex,
					ExpectedValue: expectedValue,
					ActualValue:   actualValue,
				}
			}
		}
	}

	// Additional validations can be added here based on profile requirements

	return nil
}

// Helper functions for string conversion without fmt package dependency

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func uint32ToHex(n uint32) string {
	const hexChars = "0123456789ABCDEF"
	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		result[i] = hexChars[n&0xF]
		n >>= 4
	}
	return string(result)
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0F]
	}
	return string(result)
}

func bytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
