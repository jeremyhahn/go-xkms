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
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"hash"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock PCR Structures
// =============================================================================

// MockPCR represents a single mock PCR value for testing.
type MockPCR struct {
	ID    int32
	Value []byte
}

// MockPCRBank represents a mock PCR bank for testing.
// It contains a set of PCRs with a specific hash algorithm.
type MockPCRBank struct {
	Algorithm string // "SHA1", "SHA256", "SHA384", "SHA512"
	PCRs      []MockPCR
}

// NewMockPCRBank creates a new mock PCR bank with the specified algorithm.
// Common algorithms are "SHA1" (20 bytes), "SHA256" (32 bytes),
// "SHA384" (48 bytes), and "SHA512" (64 bytes).
func NewMockPCRBank(algorithm string) *MockPCRBank {
	return &MockPCRBank{
		Algorithm: algorithm,
		PCRs:      make([]MockPCR, 0),
	}
}

// WithPCR adds a PCR value to the bank.
func (b *MockPCRBank) WithPCR(id int32, value []byte) *MockPCRBank {
	b.PCRs = append(b.PCRs, MockPCR{ID: id, Value: value})
	return b
}

// WithZeroPCR adds a PCR with all-zero value of the appropriate size for the algorithm.
func (b *MockPCRBank) WithZeroPCR(id int32) *MockPCRBank {
	size := getHashSize(b.Algorithm)
	b.PCRs = append(b.PCRs, MockPCR{ID: id, Value: make([]byte, size)})
	return b
}

// Build converts the mock PCR bank to a xkmssdk.PCRBank structure.
func (b *MockPCRBank) Build() xkmssdk.PCRBank {
	pcrs := make([]xkmssdk.PCR, len(b.PCRs))
	for i, p := range b.PCRs {
		pcrs[i] = xkmssdk.PCR{ID: p.ID, Value: p.Value}
	}
	return xkmssdk.PCRBank{Algorithm: b.Algorithm, PCRs: pcrs}
}

// =============================================================================
// Mock Event Log Structures
// =============================================================================

// MockEvent represents a single event log entry for testing.
// Events are used to compute PCR values via PCR extension.
type MockEvent struct {
	PCRIndex  int
	EventType uint32
	Digest    []byte // Event digest (hash of event data)
	EventData []byte // Raw event data
	DigestAlg uint16 // TCG algorithm ID (optional, defaults to SHA-1)
}

// MockEventLog builds mock event logs for testing.
type MockEventLog struct {
	events []MockEvent
	format string // "legacy" or "crypto-agile"
}

// NewMockEventLog creates a new mock event log builder.
// Default format is "legacy" (SHA-1 only).
func NewMockEventLog() *MockEventLog {
	return &MockEventLog{
		events: make([]MockEvent, 0),
		format: "legacy",
	}
}

// SetFormat sets the event log format.
// Supported values: "legacy" (SHA-1 only) or "crypto-agile" (multiple hashes).
func (l *MockEventLog) SetFormat(format string) *MockEventLog {
	l.format = format
	return l
}

// AddEvent adds an event to the log.
func (l *MockEventLog) AddEvent(event MockEvent) *MockEventLog {
	l.events = append(l.events, event)
	return l
}

// AddSeparatorEvent adds an EV_SEPARATOR event, commonly used to mark boundaries.
func (l *MockEventLog) AddSeparatorEvent(pcrIndex int) *MockEventLog {
	// Separator events have a specific digest pattern (all 0xFF)
	digest := bytes.Repeat([]byte{0xFF}, 20)
	return l.AddEvent(MockEvent{
		PCRIndex:  pcrIndex,
		EventType: EVSeparator,
		Digest:    digest,
		EventData: digest[:4], // Common separator data
	})
}

// sha1EventDigest returns a 20-byte digest for a mock TPM event log entry.
// TCG event logs -- legacy and the SHA-1 bank of crypto-agile alike -- always
// carry a SHA-1-sized digest per event, but crypto/sha1.Sum panics under
// GODEBUG=fips140=only (Go's SHA-1 implementation refuses to run at all in
// that mode, not just to report a weak-hash finding). The code under test
// that consumes these fixtures (pkg/acme/server/handlers.extendPCR) already
// refuses a SHA-1-bank replay under FIPS with a typed error before it would
// ever compare digest bytes, so no test's result depends on this value being
// a real SHA-1 output -- only its length. Substituting a truncated SHA-256
// digest under fips140.Enforced() keeps every fixture buildable without
// crashing the process assembling it.
func sha1EventDigest(data []byte) []byte {
	if fips140.Enforced() {
		digest := sha256.Sum256(data)
		return digest[:20]
	}
	h := sha1.New() // #nosec G401 -- SHA-1 required for legacy TPM event log format
	h.Write(data)
	return h.Sum(nil)
}

// AddPostCodeEvent adds an EV_POST_CODE event for BIOS POST operations.
func (l *MockEventLog) AddPostCodeEvent(pcrIndex int, data []byte) *MockEventLog {
	digest := sha1EventDigest(data)
	return l.AddEvent(MockEvent{
		PCRIndex:  pcrIndex,
		EventType: EVPostCode,
		Digest:    digest,
		EventData: data,
	})
}

// AddNoActionEvent adds an EV_NO_ACTION event (often used for spec ID).
func (l *MockEventLog) AddNoActionEvent(pcrIndex int, data []byte) *MockEventLog {
	return l.AddEvent(MockEvent{
		PCRIndex:  pcrIndex,
		EventType: EVNoAction,
		Digest:    make([]byte, 20), // No-action events typically have zero digest
		EventData: data,
	})
}

// AddEFIBootEvent adds an EV_EFI_BOOT_SERVICES_APPLICATION event.
func (l *MockEventLog) AddEFIBootEvent(pcrIndex int, appPath string) *MockEventLog {
	data := []byte(appPath)
	digest := sha1EventDigest(data)
	return l.AddEvent(MockEvent{
		PCRIndex:  pcrIndex,
		EventType: EVEFIBootServicesApplication,
		Digest:    digest,
		EventData: data,
	})
}

// Build creates the binary event log data.
func (l *MockEventLog) Build() []byte {
	if l.format == "crypto-agile" {
		return l.buildCryptoAgile()
	}
	return l.buildLegacy()
}

// buildLegacy creates a legacy (SHA-1 only) event log.
func (l *MockEventLog) buildLegacy() []byte {
	var buf bytes.Buffer
	for _, event := range l.events {
		// PCR Index (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(event.PCRIndex))
		// Event Type (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, event.EventType)
		// Digest (20 bytes for SHA-1)
		digest := make([]byte, 20)
		copy(digest, event.Digest)
		buf.Write(digest)
		// Event Data Size (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(event.EventData)))
		// Event Data
		buf.Write(event.EventData)
	}
	return buf.Bytes()
}

// buildCryptoAgile creates a crypto-agile event log.
// The first event must be EV_NO_ACTION with spec ID event data.
func (l *MockEventLog) buildCryptoAgile() []byte {
	var buf bytes.Buffer

	// First event: Spec ID Event (legacy format)
	specIDData := buildSpecIDEventData([]SpecIDAlgorithm{
		{AlgorithmID: TCGAlgSHA1, DigestSize: 20},
		{AlgorithmID: TCGAlgSHA256, DigestSize: 32},
	})

	// Write first event as legacy format
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))  // PCR 0
	_ = binary.Write(&buf, binary.LittleEndian, EVNoAction) // Event type
	buf.Write(make([]byte, 20))                             // Zero digest
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(specIDData)))
	buf.Write(specIDData)

	// Subsequent events: crypto-agile format
	for _, event := range l.events {
		if event.EventType == EVNoAction && event.PCRIndex == 0 {
			continue // Skip spec ID event if user added one
		}
		// PCR Index (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(event.PCRIndex))
		// Event Type (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, event.EventType)
		// Digest Count (4 bytes)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(2)) // SHA1 + SHA256

		// SHA-1 digest
		_ = binary.Write(&buf, binary.LittleEndian, TCGAlgSHA1)
		sha1Digest := make([]byte, 20)
		copy(sha1Digest, event.Digest)
		buf.Write(sha1Digest)

		// SHA-256 digest
		_ = binary.Write(&buf, binary.LittleEndian, TCGAlgSHA256)
		sha256Digest := make([]byte, 32)
		// Compute SHA-256 digest from event data
		if len(event.EventData) > 0 {
			h := sha256.Sum256(event.EventData)
			copy(sha256Digest, h[:])
		}
		buf.Write(sha256Digest)

		// Event Data Size (4 bytes, little-endian)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(event.EventData)))
		// Event Data
		buf.Write(event.EventData)
	}
	return buf.Bytes()
}

// buildSpecIDEventData creates the Spec ID Event data for crypto-agile logs.
func buildSpecIDEventData(algorithms []SpecIDAlgorithm) []byte {
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
// Mock TCG Enrollment Data Builder
// =============================================================================

// MockTCGEnrollmentDataBuilder helps create TCGEnrollmentData for testing.
type MockTCGEnrollmentDataBuilder struct {
	data *TCGEnrollmentData
}

// NewMockTCGEnrollmentData creates a new TCGEnrollmentData builder.
func NewMockTCGEnrollmentData() *MockTCGEnrollmentDataBuilder {
	return &MockTCGEnrollmentDataBuilder{
		data: &TCGEnrollmentData{},
	}
}

// WithProductModel sets the product model.
func (b *MockTCGEnrollmentDataBuilder) WithProductModel(model string) *MockTCGEnrollmentDataBuilder {
	b.data.ProductModel = model
	return b
}

// WithProductSerial sets the product serial number.
func (b *MockTCGEnrollmentDataBuilder) WithProductSerial(serial string) *MockTCGEnrollmentDataBuilder {
	b.data.ProductSerial = serial
	return b
}

// WithPermanentIdentifier sets the permanent identifier.
func (b *MockTCGEnrollmentDataBuilder) WithPermanentIdentifier(id string) *MockTCGEnrollmentDataBuilder {
	b.data.PermanentIdentifier = id
	return b
}

// WithEKCertificate sets the EK certificate.
func (b *MockTCGEnrollmentDataBuilder) WithEKCertificate(cert *x509.Certificate) *MockTCGEnrollmentDataBuilder {
	b.data.EKCertificate = cert
	return b
}

// WithIAKCertificateDER sets the IAK certificate DER bytes.
func (b *MockTCGEnrollmentDataBuilder) WithIAKCertificateDER(certDER []byte) *MockTCGEnrollmentDataBuilder {
	b.data.IAKCertificateDER = certDER
	return b
}

// WithIDevIDCertificateDER sets the IDevID certificate DER bytes.
func (b *MockTCGEnrollmentDataBuilder) WithIDevIDCertificateDER(certDER []byte) *MockTCGEnrollmentDataBuilder {
	b.data.IDevIDCertificateDER = certDER
	return b
}

// WithAttestationPublicKey sets the attestation public key bytes.
func (b *MockTCGEnrollmentDataBuilder) WithAttestationPublicKey(pubKey []byte) *MockTCGEnrollmentDataBuilder {
	b.data.AttestationPublicKey = pubKey
	return b
}

// WithSigningPublicKey sets the signing public key bytes.
func (b *MockTCGEnrollmentDataBuilder) WithSigningPublicKey(pubKey []byte) *MockTCGEnrollmentDataBuilder {
	b.data.SigningPublicKey = pubKey
	return b
}

// WithEventLog sets the event log bytes.
func (b *MockTCGEnrollmentDataBuilder) WithEventLog(eventLog []byte) *MockTCGEnrollmentDataBuilder {
	b.data.EventLog = eventLog
	return b
}

// WithProdCaData sets the ProdCaData bytes directly.
func (b *MockTCGEnrollmentDataBuilder) WithProdCaData(prodCaData []byte) *MockTCGEnrollmentDataBuilder {
	b.data.ProdCaData = prodCaData
	return b
}

// WithMockProdCaData creates and sets ProdCaData from mock components.
func (b *MockTCGEnrollmentDataBuilder) WithMockProdCaData(quoted, signature, nonce, pcrs []byte) *MockTCGEnrollmentDataBuilder {
	b.data.ProdCaData = createMockProdCaData(quoted, signature, nonce, pcrs)
	return b
}

// WithPCRBanks creates ProdCaData with the specified PCR banks.
func (b *MockTCGEnrollmentDataBuilder) WithPCRBanks(banks ...xkmssdk.PCRBank) *MockTCGEnrollmentDataBuilder {
	pcrsBytes := encodePCRBanks(banks)
	b.data.ProdCaData = createMockProdCaData(nil, nil, nil, pcrsBytes)
	return b
}

// Build returns the constructed TCGEnrollmentData.
func (b *MockTCGEnrollmentDataBuilder) Build() *TCGEnrollmentData {
	return b.data
}

// =============================================================================
// Mock Pre-Issuance Hook Context Builder
// =============================================================================

// MockPreIssuanceHookContextBuilder helps create PreIssuanceHookContext for testing.
type MockPreIssuanceHookContextBuilder struct {
	ctx *PreIssuanceHookContext
}

// NewMockPreIssuanceHookContext creates a new PreIssuanceHookContext builder.
func NewMockPreIssuanceHookContext() *MockPreIssuanceHookContextBuilder {
	return &MockPreIssuanceHookContextBuilder{
		ctx: &PreIssuanceHookContext{
			Context: context.Background(),
		},
	}
}

// WithContext sets the Go context.
func (b *MockPreIssuanceHookContextBuilder) WithContext(ctx context.Context) *MockPreIssuanceHookContextBuilder {
	b.ctx.Context = ctx
	return b
}

// WithOrder sets the ACME order.
func (b *MockPreIssuanceHookContextBuilder) WithOrder(order *entities.ACMEOrder) *MockPreIssuanceHookContextBuilder {
	b.ctx.Order = order
	return b
}

// WithCSR sets the certificate signing request.
func (b *MockPreIssuanceHookContextBuilder) WithCSR(csr *x509.CertificateRequest) *MockPreIssuanceHookContextBuilder {
	b.ctx.CSR = csr
	return b
}

// WithClientIP sets the client IP address.
func (b *MockPreIssuanceHookContextBuilder) WithClientIP(ip string) *MockPreIssuanceHookContextBuilder {
	b.ctx.ClientIP = ip
	return b
}

// WithIsTCGCSR marks this as a TCG-CSR-IDEVID enrollment.
func (b *MockPreIssuanceHookContextBuilder) WithIsTCGCSR(isTCG bool) *MockPreIssuanceHookContextBuilder {
	b.ctx.IsTCGCSR = isTCG
	return b
}

// WithTCGData sets the TCG enrollment data.
func (b *MockPreIssuanceHookContextBuilder) WithTCGData(tcgData *TCGEnrollmentData) *MockPreIssuanceHookContextBuilder {
	b.ctx.TCGData = tcgData
	return b
}

// WithComplianceData sets the compliance data.
func (b *MockPreIssuanceHookContextBuilder) WithComplianceData(data *ComplianceData) *MockPreIssuanceHookContextBuilder {
	b.ctx.ComplianceData = data
	return b
}

// WithComplianceConfig sets the compliance configuration.
func (b *MockPreIssuanceHookContextBuilder) WithComplianceConfig(config *ComplianceConfig) *MockPreIssuanceHookContextBuilder {
	b.ctx.ComplianceConfig = config
	return b
}

// Build returns the constructed PreIssuanceHookContext.
func (b *MockPreIssuanceHookContextBuilder) Build() *PreIssuanceHookContext {
	return b.ctx
}

// =============================================================================
// Sample PCR Values - Known Good Values for Testing
// =============================================================================

// SamplePCRValues contains pre-computed PCR values for testing.
// These are known values that can be used to verify PCR validation logic.
var SamplePCRValues = struct {
	// SHA1 PCR values (20 bytes each)
	SHA1 map[int][]byte
	// SHA256 PCR values (32 bytes each)
	SHA256 map[int][]byte
	// SHA384 PCR values (48 bytes each)
	SHA384 map[int][]byte
}{
	SHA1: map[int][]byte{
		0: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		7: {0x8e, 0xc6, 0x3e, 0x42, 0xd4, 0x8c, 0x2f, 0x3f, 0x7b, 0xb1,
			0x23, 0xd8, 0x78, 0x6e, 0x3a, 0x4b, 0x5c, 0x3e, 0x9d, 0x12},
		16: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	SHA256: map[int][]byte{
		0: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		7: {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
			0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0},
		16: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	SHA384: map[int][]byte{
		0: make([]byte, 48), // All zeros
		7: {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
			0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
			0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f},
	},
}

// =============================================================================
// Helper Functions
// =============================================================================

// createMockProdCaData creates a valid packed ProdCaData structure for testing.
// This is compatible with xkmssdk.UnpackProdCaData().
func createMockProdCaData(quoted, signature, nonce, pcrs []byte) []byte {
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

// createMockPCRData creates gob-encoded PCR bank data for testing.
// This is compatible with xkmssdk.DecodePCRs().
func createMockPCRData(alg string, pcrValues map[int][]byte) []byte {
	banks := []xkmssdk.PCRBank{
		{
			Algorithm: alg,
			PCRs:      make([]xkmssdk.PCR, 0, len(pcrValues)),
		},
	}

	for id, value := range pcrValues {
		banks[0].PCRs = append(banks[0].PCRs, xkmssdk.PCR{
			ID:    int32(id),
			Value: value,
		})
	}

	return encodePCRBanks(banks)
}

// createMockMultiBankPCRData creates gob-encoded PCR data with multiple banks.
func createMockMultiBankPCRData(sha1Values, sha256Values map[int][]byte) []byte {
	banks := make([]xkmssdk.PCRBank, 0, 2)

	if len(sha1Values) > 0 {
		sha1Bank := xkmssdk.PCRBank{Algorithm: "SHA1", PCRs: make([]xkmssdk.PCR, 0)}
		for id, value := range sha1Values {
			sha1Bank.PCRs = append(sha1Bank.PCRs, xkmssdk.PCR{ID: int32(id), Value: value})
		}
		banks = append(banks, sha1Bank)
	}

	if len(sha256Values) > 0 {
		sha256Bank := xkmssdk.PCRBank{Algorithm: "sha256", PCRs: make([]xkmssdk.PCR, 0)}
		for id, value := range sha256Values {
			sha256Bank.PCRs = append(sha256Bank.PCRs, xkmssdk.PCR{ID: int32(id), Value: value})
		}
		banks = append(banks, sha256Bank)
	}

	return encodePCRBanks(banks)
}

// encodePCRBanks encodes PCR banks to gob format (compatible with xkmssdk.EncodePCRs).
func encodePCRBanks(banks []xkmssdk.PCRBank) []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	_ = enc.Encode(banks)
	return buf.Bytes()
}

// hashSumTPM writes parts to a hasher of the requested algorithm and returns
// its digest, except when hashAlg is SHA-1 and the process is running under
// GODEBUG=fips140=only, where crypto/sha1's Sum panics unconditionally (see
// sha1EventDigest above). The production PCR-replay path this package
// exercises (extendPCR) already refuses a SHA-1 bank under FIPS enforcement
// with a typed error before it would ever compare a digest computed this
// way, so a same-length SHA-256-derived placeholder keeps the fixture
// buildable without crashing the process assembling it.
func hashSumTPM(hashAlg crypto.Hash, parts ...[]byte) []byte {
	if hashAlg == crypto.SHA1 && fips140.Enforced() {
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)[:20]
	}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA1:
		h = sha1.New() // #nosec G401 -- SHA-1 required for TPM 2.0 specification compatibility
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		h = sha256.New()
	}
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// computePCRFromEvents computes the expected PCR value by replaying events.
// This simulates the TPM's PCR extend operation: newPCR = Hash(oldPCR || eventDigest)
func computePCRFromEvents(events []MockEvent, initialPCR []byte, hashAlg crypto.Hash) []byte {
	current := make([]byte, len(initialPCR))
	copy(current, initialPCR)

	for _, event := range events {
		// TPM PCR extend: new = Hash(old || digest)
		current = hashSumTPM(hashAlg, current, event.Digest)
	}

	return current
}

// computeEventDigest computes the digest for event data using the specified algorithm.
func computeEventDigest(eventData []byte, hashAlg crypto.Hash) []byte {
	return hashSumTPM(hashAlg, eventData)
}

// getHashSize returns the digest size for the given algorithm name.
func getHashSize(alg string) int {
	switch alg {
	case "SHA1", "sha1":
		return 20
	case "SHA256", "sha256":
		return 32
	case "SHA384", "sha384":
		return 48
	case "SHA512", "sha512":
		return 64
	default:
		return 32 // Default to SHA-256
	}
}

// createMockEventLog creates a simple mock event log for testing.
// Returns event log bytes and the expected PCR values after replay.
func createMockEventLog(eventData [][]byte, pcrIndex int) ([]byte, []byte) {
	log := NewMockEventLog()
	events := make([]MockEvent, 0, len(eventData))

	for _, data := range eventData {
		digest := computeEventDigest(data, crypto.SHA1)
		event := MockEvent{
			PCRIndex:  pcrIndex,
			EventType: EVPostCode,
			Digest:    digest,
			EventData: data,
		}
		events = append(events, event)
		log.AddEvent(event)
	}

	// Compute expected final PCR value
	initialPCR := make([]byte, 20) // SHA-1 zeros
	expectedPCR := computePCRFromEvents(events, initialPCR, crypto.SHA1)

	return log.Build(), expectedPCR
}

// =============================================================================
// Test Key Pair Generation Helpers
// =============================================================================

// createTestRSAKeyPairForQuote creates an RSA key pair for testing quote verification.
// Returns the private key and PKIX-encoded public key bytes.
func createTestRSAKeyPairForQuote(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return key, pubKeyBytes
}

// createTestECKeyPairForQuote creates an ECDSA key pair for testing quote verification.
// Returns the private key and PKIX-encoded public key bytes.
func createTestECKeyPairForQuote(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return key, pubKeyBytes
}

// createSignedQuoteProdCaData creates ProdCaData with a properly signed quote.
// The quote is signed with the provided RSA private key.
func createSignedQuoteProdCaData(t *testing.T, key *rsa.PrivateKey, nonce []byte, pcrs []byte) []byte {
	t.Helper()

	quoted := []byte("test quote data - TPMS_ATTEST structure")
	hash := sha256.Sum256(quoted)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err)

	return createMockProdCaData(quoted, signature, nonce, pcrs)
}

// =============================================================================
// Device Profile Helpers
// =============================================================================

// createMockDeviceProfile creates a DeviceProfile for testing.
func createMockDeviceProfile(serial, model string, expectedPCRs map[int][]byte) *DeviceProfile {
	return &DeviceProfile{
		ProductSerial:           serial,
		ProductModel:            model,
		ExpectedPCRs:            expectedPCRs,
		AllowedFirmwareVersions: []string{"1.0.0", "1.1.0", "2.0.0"},
		RequiredSecureBoot:      true,
		AdditionalChecks:        make(map[string]string),
	}
}

// =============================================================================
// Comprehensive Test Data Generators
// =============================================================================

// GenerateValidTCGEnrollmentWithPCRs creates a complete TCGEnrollmentData
// with valid ProdCaData containing the specified PCR values.
func GenerateValidTCGEnrollmentWithPCRs(t *testing.T, pcrValues map[int][]byte) *TCGEnrollmentData {
	t.Helper()

	// Create PCR data
	pcrsBytes := createMockPCRData("sha256", pcrValues)

	return NewMockTCGEnrollmentData().
		WithProductModel("TestDevice-X100").
		WithProductSerial("SN-12345-ABCDE").
		WithPermanentIdentifier("permanent-id-001").
		WithMockProdCaData(
			[]byte("quoted-attestation-data"),
			[]byte("signature-bytes"),
			[]byte("nonce-bytes"),
			pcrsBytes,
		).
		Build()
}

// GenerateValidPreIssuanceContext creates a complete PreIssuanceHookContext
// for TCG-CSR-IDEVID enrollments with the specified PCR values.
func GenerateValidPreIssuanceContext(t *testing.T, pcrValues map[int][]byte) *PreIssuanceHookContext {
	t.Helper()

	tcgData := GenerateValidTCGEnrollmentWithPCRs(t, pcrValues)

	return NewMockPreIssuanceHookContext().
		WithIsTCGCSR(true).
		WithTCGData(tcgData).
		WithClientIP("192.168.1.100").
		WithOrder(&entities.ACMEOrder{ID: 12345, Status: "processing"}).
		Build()
}

// GenerateEventLogWithMatchingPCRs creates an event log and corresponding
// ProdCaData where the event log correctly computes to the PCR values.
func GenerateEventLogWithMatchingPCRs(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	// Create some events
	eventData := [][]byte{
		[]byte("BIOS POST code 1"),
		[]byte("BIOS POST code 2"),
		[]byte("Bootloader signature"),
	}

	// Build event log and compute expected PCR
	eventLog, expectedPCR := createMockEventLog(eventData, 0)

	// Create PCR data with the computed value
	pcrData := createMockPCRData("SHA1", map[int][]byte{
		0: expectedPCR,
	})

	// Create ProdCaData with the PCRs
	prodCaData := createMockProdCaData(nil, nil, nil, pcrData)

	return eventLog, prodCaData, expectedPCR
}

// =============================================================================
// Tests for the Helper Functions and Mock Structures
// =============================================================================

func TestTPMHelpers_MockPCRBank(t *testing.T) {
	t.Run("creates SHA256 bank with PCRs", func(t *testing.T) {
		bank := NewMockPCRBank("sha256").
			WithPCR(0, SamplePCRValues.SHA256[0]).
			WithPCR(7, SamplePCRValues.SHA256[7]).
			Build()

		assert.Equal(t, "sha256", bank.Algorithm)
		assert.Len(t, bank.PCRs, 2)
		assert.Equal(t, int32(0), bank.PCRs[0].ID)
		assert.Equal(t, int32(7), bank.PCRs[1].ID)
	})

	t.Run("creates zero PCR with correct size", func(t *testing.T) {
		sha1Bank := NewMockPCRBank("SHA1").WithZeroPCR(0).Build()
		sha256Bank := NewMockPCRBank("SHA256").WithZeroPCR(0).Build()
		sha384Bank := NewMockPCRBank("SHA384").WithZeroPCR(0).Build()

		assert.Len(t, sha1Bank.PCRs[0].Value, 20)
		assert.Len(t, sha256Bank.PCRs[0].Value, 32)
		assert.Len(t, sha384Bank.PCRs[0].Value, 48)
	})
}

func TestTPMHelpers_MockEventLog(t *testing.T) {
	t.Run("builds legacy event log", func(t *testing.T) {
		log := NewMockEventLog().
			AddPostCodeEvent(0, []byte("test data")).
			AddSeparatorEvent(0)

		eventLog := log.Build()
		assert.NotEmpty(t, eventLog)

		// Parse it back
		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		assert.Len(t, events, 2)
		assert.Equal(t, "EV_POST_CODE", events[0].EventType)
		assert.Equal(t, "EV_SEPARATOR", events[1].EventType)
	})

	t.Run("builds crypto-agile event log", func(t *testing.T) {
		log := NewMockEventLog().
			SetFormat("crypto-agile").
			AddPostCodeEvent(0, []byte("test data"))

		eventLog := log.Build()
		assert.NotEmpty(t, eventLog)

		// Verify it starts with Spec ID Event
		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(events), 1)
		assert.Equal(t, "EV_NO_ACTION", events[0].EventType)
	})

	t.Run("adds EFI boot event", func(t *testing.T) {
		log := NewMockEventLog().
			AddEFIBootEvent(4, "/EFI/BOOT/BOOTX64.EFI")

		eventLog := log.Build()
		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, "EV_EFI_BOOT_SERVICES_APPLICATION", events[0].EventType)
		assert.Equal(t, 4, events[0].PCRIndex)
	})
}

func TestTPMHelpers_MockTCGEnrollmentData(t *testing.T) {
	t.Run("builds complete enrollment data", func(t *testing.T) {
		tcgData := NewMockTCGEnrollmentData().
			WithProductModel("Model-X").
			WithProductSerial("SN-123").
			WithPermanentIdentifier("perm-id").
			WithEventLog([]byte("event-log")).
			WithMockProdCaData([]byte("quoted"), []byte("sig"), []byte("nonce"), nil).
			Build()

		assert.Equal(t, "Model-X", tcgData.ProductModel)
		assert.Equal(t, "SN-123", tcgData.ProductSerial)
		assert.Equal(t, "perm-id", tcgData.PermanentIdentifier)
		assert.Equal(t, []byte("event-log"), tcgData.EventLog)
		assert.NotEmpty(t, tcgData.ProdCaData)
	})

	t.Run("builds with PCR banks", func(t *testing.T) {
		bank := NewMockPCRBank("sha256").
			WithPCR(0, SamplePCRValues.SHA256[0]).
			Build()

		tcgData := NewMockTCGEnrollmentData().
			WithPCRBanks(bank).
			Build()

		// Verify ProdCaData can be unpacked
		prodCaData, err := xkmssdk.UnpackProdCaData(tcgData.ProdCaData)
		require.NoError(t, err)
		assert.NotEmpty(t, prodCaData.PCRs)

		// Verify PCRs can be decoded
		banks, err := xkmssdk.DecodePCRs(prodCaData.PCRs)
		require.NoError(t, err)
		assert.Len(t, banks, 1)
		assert.Equal(t, "sha256", banks[0].Algorithm)
	})
}

func TestTPMHelpers_MockPreIssuanceHookContext(t *testing.T) {
	t.Run("builds complete context", func(t *testing.T) {
		tcgData := NewMockTCGEnrollmentData().
			WithProductSerial("SN-123").
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			WithClientIP("10.0.0.1").
			WithOrder(&entities.ACMEOrder{ID: 100}).
			Build()

		assert.True(t, ctx.IsTCGCSR)
		assert.NotNil(t, ctx.TCGData)
		assert.Equal(t, "10.0.0.1", ctx.ClientIP)
		assert.Equal(t, uint64(100), ctx.Order.ID)
	})
}

func TestTPMHelpers_createMockPCRData(t *testing.T) {
	t.Run("creates valid gob-encoded PCR data", func(t *testing.T) {
		pcrValues := map[int][]byte{
			0: SamplePCRValues.SHA256[0],
			7: SamplePCRValues.SHA256[7],
		}

		pcrData := createMockPCRData("sha256", pcrValues)

		// Decode and verify
		banks, err := xkmssdk.DecodePCRs(pcrData)
		require.NoError(t, err)
		assert.Len(t, banks, 1)
		assert.Equal(t, "sha256", banks[0].Algorithm)
		assert.Len(t, banks[0].PCRs, 2)
	})

	t.Run("creates multi-bank PCR data", func(t *testing.T) {
		sha1Values := map[int][]byte{0: SamplePCRValues.SHA1[0]}
		sha256Values := map[int][]byte{0: SamplePCRValues.SHA256[0]}

		pcrData := createMockMultiBankPCRData(sha1Values, sha256Values)

		banks, err := xkmssdk.DecodePCRs(pcrData)
		require.NoError(t, err)
		assert.Len(t, banks, 2)
	})
}

func TestTPMHelpers_createMockProdCaData(t *testing.T) {
	t.Run("creates valid ProdCaData structure", func(t *testing.T) {
		prodCaData := createMockProdCaData(
			[]byte("quoted data"),
			[]byte("signature"),
			[]byte("nonce"),
			[]byte("pcrs"),
		)

		// Unpack and verify
		unpacked, err := xkmssdk.UnpackProdCaData(prodCaData)
		require.NoError(t, err)
		assert.Equal(t, []byte("quoted data"), unpacked.Quoted)
		assert.Equal(t, []byte("signature"), unpacked.Signature)
		assert.Equal(t, []byte("nonce"), unpacked.Nonce)
		assert.Equal(t, []byte("pcrs"), unpacked.PCRs)
	})

	t.Run("handles empty fields", func(t *testing.T) {
		prodCaData := createMockProdCaData(nil, nil, nil, nil)

		unpacked, err := xkmssdk.UnpackProdCaData(prodCaData)
		require.NoError(t, err)
		assert.Empty(t, unpacked.Quoted)
		assert.Empty(t, unpacked.Signature)
	})
}

func TestTPMHelpers_computePCRFromEvents(t *testing.T) {
	t.Run("computes correct PCR value", func(t *testing.T) {
		// Create a known event
		eventData := []byte("test event data")
		digest := computeEventDigest(eventData, crypto.SHA1)

		event := MockEvent{
			PCRIndex: 0,
			Digest:   digest,
		}

		initialPCR := make([]byte, 20)
		result := computePCRFromEvents([]MockEvent{event}, initialPCR, crypto.SHA1)

		var expected []byte
		if fips140.Enforced() {
			// crypto/sha1.Sum panics unconditionally under
			// GODEBUG=fips140=only, so there is no independent SHA-1 to
			// recompute against; hashSumTPM's own FIPS-only substitute
			// (see its doc comment) is the only value that can agree with
			// computePCRFromEvents here, which routes through the same
			// helper. This still confirms computePCRFromEvents calls the
			// extend step with (old, digest) in that order; "supports
			// multiple events" below covers the chaining across steps.
			expected = hashSumTPM(crypto.SHA1, initialPCR, digest)
		} else {
			// Manual computation: SHA1(zeros || digest)
			h := sha1.New() // #nosec G401 -- test code
			h.Write(initialPCR)
			h.Write(digest)
			expected = h.Sum(nil)
		}

		assert.Equal(t, expected, result)
	})

	t.Run("supports multiple events", func(t *testing.T) {
		events := []MockEvent{
			{Digest: bytes.Repeat([]byte{0x01}, 20)},
			{Digest: bytes.Repeat([]byte{0x02}, 20)},
		}

		initialPCR := make([]byte, 20)
		result := computePCRFromEvents(events, initialPCR, crypto.SHA1)

		assert.Len(t, result, 20)
		assert.NotEqual(t, initialPCR, result) // Value changed
	})

	t.Run("supports SHA-256", func(t *testing.T) {
		events := []MockEvent{
			{Digest: bytes.Repeat([]byte{0x01}, 32)},
		}

		initialPCR := make([]byte, 32)
		result := computePCRFromEvents(events, initialPCR, crypto.SHA256)

		assert.Len(t, result, 32)
	})
}

func TestTPMHelpers_GenerateValidPreIssuanceContext(t *testing.T) {
	t.Run("generates valid context with PCRs", func(t *testing.T) {
		pcrValues := map[int][]byte{
			0: SamplePCRValues.SHA256[0],
			7: SamplePCRValues.SHA256[7],
		}

		ctx := GenerateValidPreIssuanceContext(t, pcrValues)

		assert.True(t, ctx.IsTCGCSR)
		require.NotNil(t, ctx.TCGData)
		assert.NotEmpty(t, ctx.TCGData.ProdCaData)

		// Verify PCRs are accessible via findPCRValue
		prodCaData, err := xkmssdk.UnpackProdCaData(ctx.TCGData.ProdCaData)
		require.NoError(t, err)

		value, found := findPCRValue(prodCaData.PCRs, 0)
		assert.True(t, found)
		assert.Equal(t, SamplePCRValues.SHA256[0], value)
	})
}

func TestTPMHelpers_GenerateEventLogWithMatchingPCRs(t *testing.T) {
	t.Run("generates matching event log and PCRs", func(t *testing.T) {
		eventLog, prodCaData, expectedPCR := GenerateEventLogWithMatchingPCRs(t)

		assert.NotEmpty(t, eventLog)
		assert.NotEmpty(t, prodCaData)
		assert.NotEmpty(t, expectedPCR)

		// Verify event log parses correctly
		events, err := parseEventLog(eventLog)
		require.NoError(t, err)
		assert.NotEmpty(t, events)

		// Verify ProdCaData contains the expected PCR
		unpacked, err := xkmssdk.UnpackProdCaData(prodCaData)
		require.NoError(t, err)

		value, found := findPCRValue(unpacked.PCRs, 0)
		assert.True(t, found)
		assert.Equal(t, expectedPCR, value)
	})
}

// =============================================================================
// Tests Targeting Low-Coverage Functions Using Helpers
// =============================================================================

func TestTPMHelpers_findPCRValue_WithMockData(t *testing.T) {
	t.Run("finds SHA-256 PCR value", func(t *testing.T) {
		expectedValue := SamplePCRValues.SHA256[7]
		pcrData := createMockPCRData("sha256", map[int][]byte{
			0: SamplePCRValues.SHA256[0],
			7: expectedValue,
		})

		value, found := findPCRValue(pcrData, 7)
		assert.True(t, found)
		assert.Equal(t, expectedValue, value)
	})

	t.Run("prefers SHA-256 over SHA-1", func(t *testing.T) {
		sha1Value := SamplePCRValues.SHA1[0]
		sha256Value := SamplePCRValues.SHA256[0]

		pcrData := createMockMultiBankPCRData(
			map[int][]byte{0: sha1Value},
			map[int][]byte{0: sha256Value},
		)

		value, found := findPCRValue(pcrData, 0)
		assert.True(t, found)
		assert.Equal(t, sha256Value, value)
	})

	t.Run("returns false for non-existent PCR", func(t *testing.T) {
		pcrData := createMockPCRData("sha256", map[int][]byte{
			0: SamplePCRValues.SHA256[0],
		})

		value, found := findPCRValue(pcrData, 23)
		assert.False(t, found)
		assert.Nil(t, value)
	})

	t.Run("handles empty banks", func(t *testing.T) {
		pcrData := encodePCRBanks([]xkmssdk.PCRBank{})
		value, found := findPCRValue(pcrData, 0)
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

func TestTPMHelpers_NewPCRValidationHook_WithMockData(t *testing.T) {
	t.Run("validates matching PCR values", func(t *testing.T) {
		expectedPCR := SamplePCRValues.SHA256[7]

		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{7: expectedPCR},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)

		// Create context with matching PCR
		ctx := GenerateValidPreIssuanceContext(t, map[int][]byte{
			7: expectedPCR,
		})

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("fails on mismatched PCR values", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{
				7: SamplePCRValues.SHA256[7],
			},
			StrictMode: true,
		}

		hook := NewPCRValidationHook(policy)

		// Create context with different PCR value
		differentValue := make([]byte, 32)
		copy(differentValue, SamplePCRValues.SHA256[7])
		differentValue[0] ^= 0xFF // Flip bits

		ctx := GenerateValidPreIssuanceContext(t, map[int][]byte{
			7: differentValue,
		})

		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: SamplePCRValues.SHA256[0]},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(false).
			Build()

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("strict mode requires attestation data", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: SamplePCRValues.SHA256[0]},
			StrictMode:   true,
		}

		hook := NewPCRValidationHook(policy)

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(&TCGEnrollmentData{ProdCaData: nil}).
			Build()

		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAttestationDataMissing))
	})

	t.Run("non-strict mode allows missing attestation data", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{0: SamplePCRValues.SHA256[0]},
			StrictMode:   false,
		}

		hook := NewPCRValidationHook(policy)

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(&TCGEnrollmentData{ProdCaData: nil}).
			Build()

		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("strict mode fails on missing PCR in attestation", func(t *testing.T) {
		policy := &PCRPolicy{
			ExpectedPCRs: map[int][]byte{
				7:  SamplePCRValues.SHA256[7],
				16: SamplePCRValues.SHA256[16], // This one won't be in attestation
			},
			StrictMode: true,
		}

		hook := NewPCRValidationHook(policy)

		// Only include PCR 7
		ctx := GenerateValidPreIssuanceContext(t, map[int][]byte{
			7: SamplePCRValues.SHA256[7],
		})

		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})
}

func TestTPMHelpers_validateDeviceAgainstProfile_WithMockData(t *testing.T) {
	t.Run("validates device with matching PCRs", func(t *testing.T) {
		pcrValue := SamplePCRValues.SHA256[7]
		pcrData := createMockPCRData("sha256", map[int][]byte{7: pcrValue})

		tcgData := NewMockTCGEnrollmentData().
			WithProductSerial("SN-123").
			WithProductModel("Model-X").
			WithMockProdCaData(nil, nil, nil, pcrData).
			Build()

		profile := createMockDeviceProfile("SN-123", "Model-X", map[int][]byte{
			7: pcrValue,
		})

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.NoError(t, err)
	})

	t.Run("fails on PCR mismatch", func(t *testing.T) {
		actualPCR := SamplePCRValues.SHA256[7]
		expectedPCR := make([]byte, len(actualPCR))
		copy(expectedPCR, actualPCR)
		expectedPCR[0] ^= 0xFF // Different value

		pcrData := createMockPCRData("sha256", map[int][]byte{7: actualPCR})

		tcgData := NewMockTCGEnrollmentData().
			WithMockProdCaData(nil, nil, nil, pcrData).
			Build()

		profile := createMockDeviceProfile("SN-123", "Model-X", map[int][]byte{
			7: expectedPCR,
		})

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("fails on missing expected PCR", func(t *testing.T) {
		pcrData := createMockPCRData("sha256", map[int][]byte{
			0: SamplePCRValues.SHA256[0],
		})

		tcgData := NewMockTCGEnrollmentData().
			WithMockProdCaData(nil, nil, nil, pcrData).
			Build()

		profile := createMockDeviceProfile("SN-123", "Model-X", map[int][]byte{
			7: SamplePCRValues.SHA256[7], // Expecting PCR 7, but only 0 is present
		})

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPCRMismatch))
	})

	t.Run("passes with empty expected PCRs", func(t *testing.T) {
		tcgData := NewMockTCGEnrollmentData().
			WithMockProdCaData(nil, nil, nil, nil).
			Build()

		profile := &DeviceProfile{
			ProductSerial: "SN-123",
			ProductModel:  "Model-X",
			ExpectedPCRs:  map[int][]byte{}, // No expected PCRs
		}

		err := validateDeviceAgainstProfile(tcgData, profile)
		assert.NoError(t, err)
	})
}

func TestTPMHelpers_NewDeviceProfileHook_WithMockData(t *testing.T) {
	t.Run("validates device against profile lookup", func(t *testing.T) {
		pcrValue := SamplePCRValues.SHA256[0]
		pcrData := createMockPCRData("sha256", map[int][]byte{0: pcrValue})

		tcgData := NewMockTCGEnrollmentData().
			WithProductSerial("SN-12345").
			WithProductModel("TestModel").
			WithMockProdCaData(nil, nil, nil, pcrData).
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		// Create lookup function that returns a matching profile
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			if serial == "SN-12345" && model == "TestModel" {
				return createMockDeviceProfile(serial, model, map[int][]byte{
					0: pcrValue,
				}), nil
			}
			return nil, errors.New("device not found")
		}

		hook := NewDeviceProfileHook(lookupFunc)
		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("allows unknown devices when profile not found", func(t *testing.T) {
		tcgData := NewMockTCGEnrollmentData().
			WithProductSerial("UNKNOWN-SN").
			WithProductModel("UNKNOWN-MODEL").
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		// Lookup returns nil profile (not found)
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, nil
		}

		hook := NewDeviceProfileHook(lookupFunc)
		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("returns error on lookup failure", func(t *testing.T) {
		tcgData := NewMockTCGEnrollmentData().
			WithProductSerial("SN-123").
			WithProductModel("Model-X").
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		// Lookup returns error
		lookupErr := errors.New("database connection failed")
		lookupFunc := func(serial, model string) (*DeviceProfile, error) {
			return nil, lookupErr
		}

		hook := NewDeviceProfileHook(lookupFunc)
		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, lookupErr))
	})
}

func TestTPMHelpers_validateEventLogAgainstPCRs_WithMockData(t *testing.T) {
	t.Run("validates matching event log and PCRs", func(t *testing.T) {
		eventLog, prodCaData, _ := GenerateEventLogWithMatchingPCRs(t)

		err := validateEventLogAgainstPCRs(eventLog, prodCaData)
		assert.NoError(t, err)
	})

	t.Run("returns nil for empty event log", func(t *testing.T) {
		err := validateEventLogAgainstPCRs(nil, nil)
		assert.NoError(t, err)
	})

	t.Run("returns nil for empty prodCaData", func(t *testing.T) {
		eventLog := NewMockEventLog().
			AddPostCodeEvent(0, []byte("test")).
			Build()

		err := validateEventLogAgainstPCRs(eventLog, nil)
		assert.NoError(t, err)
	})

	t.Run("handles invalid event log gracefully", func(t *testing.T) {
		invalidEventLog := []byte{0x01, 0x02, 0x03} // Too short to be valid
		pcrData := createMockPCRData("SHA1", map[int][]byte{0: SamplePCRValues.SHA1[0]})
		prodCaData := createMockProdCaData(nil, nil, nil, pcrData)

		err := validateEventLogAgainstPCRs(invalidEventLog, prodCaData)
		// Should not return error for unparseable event logs
		// The function parses what it can and validates against PCRs
		assert.NoError(t, err)
	})
}

func TestTPMHelpers_NewEventLogValidationHook_WithMockData(t *testing.T) {
	t.Run("validates event log with required events", func(t *testing.T) {
		eventLog := NewMockEventLog().
			AddPostCodeEvent(0, []byte("BIOS code")).
			AddSeparatorEvent(0).
			Build()

		tcgData := NewMockTCGEnrollmentData().
			WithEventLog(eventLog).
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		policy := &EventLogPolicy{
			RequiredEvents:      []string{"EV_POST_CODE"},
			ValidateAgainstPCRs: false,
		}

		hook := NewEventLogValidationHook(policy)
		err := hook(ctx)
		assert.NoError(t, err)
	})

	t.Run("fails on missing required event", func(t *testing.T) {
		eventLog := NewMockEventLog().
			AddPostCodeEvent(0, []byte("BIOS code")).
			Build()

		tcgData := NewMockTCGEnrollmentData().
			WithEventLog(eventLog).
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_EFI_BOOT_SERVICES_APPLICATION"}, // Not in log
		}

		hook := NewEventLogValidationHook(policy)
		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrEventLogInvalid))
	})

	t.Run("fails on forbidden event present", func(t *testing.T) {
		eventLog := NewMockEventLog().
			AddSeparatorEvent(0).
			Build()

		tcgData := NewMockTCGEnrollmentData().
			WithEventLog(eventLog).
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		policy := &EventLogPolicy{
			ForbiddenEvents: []string{"EV_SEPARATOR"},
		}

		hook := NewEventLogValidationHook(policy)
		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrEventLogInvalid))
	})

	t.Run("enforces max event count", func(t *testing.T) {
		eventLog := NewMockEventLog().
			AddPostCodeEvent(0, []byte("event 1")).
			AddPostCodeEvent(0, []byte("event 2")).
			AddPostCodeEvent(0, []byte("event 3")).
			Build()

		tcgData := NewMockTCGEnrollmentData().
			WithEventLog(eventLog).
			Build()

		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(true).
			WithTCGData(tcgData).
			Build()

		policy := &EventLogPolicy{
			MaxEventCount: 2, // Only allow 2 events
		}

		hook := NewEventLogValidationHook(policy)
		err := hook(ctx)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrEventLogInvalid))
	})

	t.Run("skips non-TCG enrollments", func(t *testing.T) {
		ctx := NewMockPreIssuanceHookContext().
			WithIsTCGCSR(false).
			Build()

		policy := &EventLogPolicy{
			RequiredEvents: []string{"EV_POST_CODE"},
		}

		hook := NewEventLogValidationHook(policy)
		err := hook(ctx)
		assert.NoError(t, err)
	})
}
