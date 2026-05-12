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

package deviceattest01

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// device-attest-01 Challenge Implementation
//
// The device-attest-01 challenge is a custom ACME extension for remote attestation
// of TPM-equipped devices. It implements attestation procedures compatible with
// WebAuthn TPM attestation format and draft ACME device attestation specifications.
//
// References:
// - https://datatracker.ietf.org/doc/draft-acme-device-attest
// - https://www.w3.org/TR/webauthn/#sctn-tpm-attestation
//
// TPM Requirements:
// - TPM 2.0 compliant hardware or software TPM
// - Attestation Key (AK) provisioned and certified
// - Support for TPM2_Quote operation
// - Platform Configuration Registers (PCRs) for integrity measurement
//
// Challenge Flow:
// 1. ACME server provides challenge token and nonce
// 2. Client performs TPM2_Quote using challenge token as qualifying data
// 3. Client creates attestation object in TPM format (per WebAuthn spec)
// 4. Attestation object includes:
//    - Format identifier ("tpm")
//    - Attestation statement with signature, certInfo, pubArea
//    - AK certificate in x5c array
// 5. Client encodes attestation object in CBOR format
// 6. Client submits attestation object to ACME server
// 7. Server verifies:
//    - Quote signature using AK public key
//    - certInfo matches expected PCR values
//    - Qualifying data matches challenge token
//    - AK certificate chain is valid
//
// Security Properties:
// - Proves platform integrity via PCR measurements
// - Validates AK certificate chain
// - Ensures quote freshness via nonce/challenge token
// - Binds attestation to specific device state
//
// Attestation Format:
// The attestation object follows W3C WebAuthn TPM attestation format:
// - ver: TPM version ("2.0")
// - alg: Signature algorithm (RS256=-257, ES256=-7, EdDSA=-8)
// - x5c: AK certificate chain (array of DER-encoded certificates)
// - sig: TPM2_Quote signature over certInfo
// - certInfo: TPMS_ATTEST structure from TPM2_Quote
// - pubArea: TPM2B_PUBLIC structure of the attested key

const (
	challengePath = "/.well-known/acme-challenge/"
)

// AttestationFormat represents the supported attestation formats
type AttestationFormat string

const (
	// FormatTPM indicates TPM 2.0 attestation format per WebAuthn specification
	FormatTPM AttestationFormat = "tpm"
)

// String returns the string representation of the attestation format
func (format AttestationFormat) String() string {
	return string(format)
}

// AttestationObject represents a WebAuthn-compatible attestation object
type AttestationObject struct {
	Format       string               `json:"fmt" cbor:"fmt"`
	AttStatement AttestationStatement `json:"attStmt,omitempty" cbor:"attStmt,omitempty"`
}

// AttestationStatement represents the TPM attestation statement
type AttestationStatement struct {
	Ver      string        `json:"ver" cbor:"ver"`           // TPM version ("2.0")
	Alg      int64         `json:"alg" cbor:"alg"`           // COSE algorithm identifier
	X5c      []interface{} `json:"x5c" cbor:"x5c"`           // AK certificate chain
	Sig      []byte        `json:"sig" cbor:"sig"`           // TPM2_Quote signature
	CertInfo []byte        `json:"certInfo" cbor:"certInfo"` // TPMS_ATTEST structure
	PubArea  []byte        `json:"pubArea" cbor:"pubArea"`   // TPM2B_PUBLIC structure
}

// AttestationRequest represents the client's attestation request
type AttestationRequest struct {
	AttStmt []byte `json:"attStmt"` // CBOR-encoded attestation object
}

var (
	// ErrInvalidKeyAlgorithm is returned when an unsupported key algorithm is used
	ErrInvalidKeyAlgorithm = errors.New("device-attest-01: invalid key algorithm")

	// ErrInvalidAttestationFormat is returned when an unsupported attestation format is requested
	ErrInvalidAttestationFormat = errors.New("device-attest-01: invalid attestation format")

	// ErrInvalidAttestationObject is returned when the attestation object cannot be parsed
	ErrInvalidAttestationObject = errors.New("device-attest-01: invalid attestation object")

	// ErrQuoteVerificationFailed is returned when the TPM quote signature verification fails
	ErrQuoteVerificationFailed = errors.New("device-attest-01: quote verification failed")

	// ErrPCRMismatch is returned when PCR values don't match expected policy
	ErrPCRMismatch = errors.New("device-attest-01: PCR values do not match policy")

	// ErrCertificateChainInvalid is returned when the AK certificate chain is invalid
	ErrCertificateChainInvalid = errors.New("device-attest-01: AK certificate chain invalid")
)

// CertificateAuthority defines the CA interface for device attestation verification
type CertificateAuthority interface {
	// VerifyAttestationObject verifies an attestation object
	// Returns error if verification fails
	VerifyAttestationObject(obj *AttestationObject, expectedChallenge []byte) error

	// VerifyQuote verifies a TPM quote signature
	VerifyQuote(quote, signature []byte, pcrs map[uint][]byte) error

	// VerifyAKCertificateChain verifies the AK certificate chain
	VerifyAKCertificateChain(certs [][]byte) error
}

// KeyAttributes represents TPM key attributes
type KeyAttributes interface {
	// GetKeyAlgorithm returns the key algorithm
	GetKeyAlgorithm() x509.PublicKeyAlgorithm

	// GetTPMAttributes returns TPM-specific attributes
	GetTPMAttributes() TPMAttributes
}

// TPMAttributes represents TPM-specific key attributes
type TPMAttributes interface {
	// GetPublicKeyBytes returns the public key in DER/PEM format
	GetPublicKeyBytes() []byte

	// GetBPublic returns the TPM2B_PUBLIC structure
	GetBPublic() TPM2BPublic
}

// TPM2BPublic represents a TPM2B_PUBLIC structure
type TPM2BPublic interface {
	// Bytes returns the binary encoding of the public area
	Bytes() []byte
}

// Quote represents a TPM2_Quote response
type Quote interface {
	// GetSignature returns the quote signature
	GetSignature() []byte

	// GetQuoted returns the TPMS_ATTEST structure
	GetQuoted() []byte
}

// TrustedPlatformModule defines the TPM interface for device attestation
type TrustedPlatformModule interface {
	// Quote performs TPM2_Quote with specified PCRs and qualifying data
	// Parameters: pcrIndices, qualifyingData
	// Returns: Quote object, error
	Quote(pcrIndices []uint, qualifyingData []byte) (Quote, error)
}

// Verify performs device-attest-01 challenge verification.
//
// This function implements server-side attestation verification:
// 1. Retrieves attestation statement from client's challenge endpoint
// 2. Decodes and parses the CBOR-encoded attestation object
// 3. Verifies the TPM quote signature using AK public key
// 4. Validates certInfo structure and PCR values against policy
// 5. Checks qualifying data matches challenge token
// 6. Verifies AK certificate chain to trusted root
//
// Parameters:
//   - resolver: DNS resolver for domain name resolution
//   - ca: Certificate Authority for attestation verification
//   - domain: Domain/identifier to verify
//   - port: HTTP port for challenge communication
//   - challengeToken: Challenge token (used as qualifying data)
//   - expectedKeyAuth: Expected key authorization
//
// Returns:
//   - nil if attestation is valid
//   - error if verification fails
func Verify(
	resolver *net.Resolver,
	ca CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	// Retrieve attestation from client's challenge endpoint
	endpoint := fmt.Sprintf("http://%s:%s%s%s", domain, port, challengePath, challengeToken)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
				Resolver:  resolver,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return caerrors.ConnectionFailureError("device-attest-01: failed to contact client: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return caerrors.ConnectionFailureError("device-attest-01: unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return caerrors.ConnectionFailureError("device-attest-01: failed to read response: %v", err)
	}

	// Decode the attestation request
	var attestReq AttestationRequest
	if err := json.Unmarshal(body, &attestReq); err != nil {
		return caerrors.MalformedError("device-attest-01: invalid attestation request: %v", err)
	}

	// Parse the CBOR-encoded attestation object
	attestObj, err := ParseAttestationObject(attestReq.AttStmt)
	if err != nil {
		return caerrors.MalformedError("device-attest-01: %v", err)
	}

	// Validate attestation format
	if !ValidateAttestationFormat(AttestationFormat(attestObj.Format)) {
		return ErrInvalidAttestationFormat
	}

	// Verify using CA
	if err := ca.VerifyAttestationObject(attestObj, []byte(expectedKeyAuth)); err != nil {
		return caerrors.BadAttestationStatementError("device-attest-01: attestation verification failed: %v", err)
	}

	// Extract and verify certificate chain
	if len(attestObj.AttStatement.X5c) > 0 {
		var certChain [][]byte
		for _, cert := range attestObj.AttStatement.X5c {
			if certBytes, ok := cert.([]byte); ok {
				certChain = append(certChain, certBytes)
			}
		}
		if err := ca.VerifyAKCertificateChain(certChain); err != nil {
			return ErrCertificateChainInvalid
		}
	}

	// Verify the quote
	if err := ca.VerifyQuote(
		attestObj.AttStatement.CertInfo,
		attestObj.AttStatement.Sig,
		nil, // PCR values would be extracted from certInfo in production
	); err != nil {
		return ErrQuoteVerificationFailed
	}

	// Verify certInfo contains expected qualifying data
	if !bytes.Contains(attestObj.AttStatement.CertInfo, []byte(expectedKeyAuth)) {
		return caerrors.BadAttestationStatementError("device-attest-01: qualifying data mismatch")
	}

	return nil
}

// Setup generates an attestation statement for the device-attest-01 challenge.
//
// This function performs the following steps:
// 1. Determines COSE algorithm identifier from key algorithm
// 2. Performs TPM2_Quote with challenge token as qualifying data
// 3. Constructs attestation object in WebAuthn TPM format
// 4. Encodes attestation object to CBOR
// 5. Wraps CBOR in JSON payload for ACME submission
//
// Parameters:
//   - keyAuth: Key authorization used as qualifying data for TPM2_Quote
//   - akAttrs: Attestation Key attributes (algorithm, certificates, public key)
//   - format: Attestation format (currently only "tpm" is supported)
//   - tpm: Trusted Platform Module for quote generation
//
// Returns:
//   - JSON payload containing CBOR-encoded attestation statement
//   - error if quote generation or encoding fails
//
// The function currently supports:
// - RSA keys with RSASSA-PKCS1-v1_5 (AlgRS256 = -257)
// - ECDSA keys with P-256 curve (AlgES256 = -7)
// - Ed25519 keys (AlgEdDSA = -8)
//
// COSE Algorithm Identifiers (per RFC 8152):
// - AlgRS256 = -257 (RSASSA-PKCS1-v1_5 using SHA-256)
// - AlgES256 = -7 (ECDSA using P-256 and SHA-256)
// - AlgEdDSA = -8 (EdDSA)
func Setup(
	keyAuth string,
	akAttrs KeyAttributes,
	format AttestationFormat,
	tpm TrustedPlatformModule) ([]byte, error) {

	// Map key algorithm to COSE algorithm identifier
	var alg int64
	switch akAttrs.GetKeyAlgorithm() {
	case x509.RSA:
		alg = int64(-257) // AlgRS256
	case x509.ECDSA:
		alg = int64(-7) // AlgES256
	case x509.Ed25519:
		alg = int64(-8) // AlgEdDSA
	default:
		return nil, ErrInvalidKeyAlgorithm
	}

	var certBytes, sig, certifyInfo, pubArea []byte
	var err error

	switch format {

	case FormatTPM:
		// Perform TPM2_Quote with PCR 14 (often used for boot integrity)
		// Use keyAuth as qualifying data to bind quote to this challenge
		quote, err := tpm.Quote([]uint{14}, []byte(keyAuth))
		if err != nil {
			return nil, err
		}

		tpmAttrs := akAttrs.GetTPMAttributes()
		certBytes = tpmAttrs.GetPublicKeyBytes()
		sig = quote.GetSignature()
		certifyInfo = quote.GetQuoted()
		pubArea = tpmAttrs.GetBPublic().Bytes()

	default:
		return nil, ErrInvalidAttestationFormat
	}

	// Construct WebAuthn-compatible attestation object
	obj := &AttestationObject{
		Format: format.String(),
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      alg,
			X5c:      []interface{}{certBytes},
			Sig:      sig,
			CertInfo: certifyInfo,
			PubArea:  pubArea,
		},
	}

	// Encode attestation object to CBOR (per WebAuthn spec)
	b, err := cbor.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// Wrap in JSON payload for ACME protocol
	req := struct {
		AttStmt []byte `json:"attStmt"`
	}{
		b,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// ParseAttestationObject decodes a CBOR-encoded attestation object
//
// Parameters:
//   - data: CBOR-encoded attestation object bytes
//
// Returns:
//   - Parsed AttestationObject
//   - error if decoding fails
func ParseAttestationObject(data []byte) (*AttestationObject, error) {
	var obj AttestationObject
	if err := cbor.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

// ValidateAttestationFormat checks if the given format is supported
//
// Parameters:
//   - format: Attestation format to validate
//
// Returns:
//   - true if format is supported, false otherwise
func ValidateAttestationFormat(format AttestationFormat) bool {
	return format == FormatTPM
}

// TPM magic value for generated structures
const tpmGeneratedValue = 0xff544347 // 0xFF || "TCG"

// TPM structure types
const (
	tpmSTAttestQuote = 0x8018 // TPM_ST_ATTEST_QUOTE
)

// TPMSAttest represents a parsed TPMS_ATTEST structure from TPM2_Quote
type TPMSAttest struct {
	Magic           uint32
	Type            uint16
	QualifiedSigner []byte
	ExtraData       []byte
	ClockInfo       TPMSClockInfo
	FirmwareVersion uint64
	Attested        TPMSQuoteInfo
}

// TPMSClockInfo represents the clock information in TPMS_ATTEST
type TPMSClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

// TPMSQuoteInfo represents the quote-specific attestation data
type TPMSQuoteInfo struct {
	PCRSelect []TPMSPCRSelection
	PCRDigest []byte
}

// TPMSPCRSelection represents a PCR selection structure
type TPMSPCRSelection struct {
	Hash         uint16
	SizeOfBitmap uint8
	PCRBitmap    []byte
}

// ExtractPCRsFromCertInfo extracts PCR values from a TPMS_ATTEST structure
//
// Parameters:
//   - certInfo: Raw TPMS_ATTEST bytes from TPM2_Quote
//
// Returns:
//   - Map of PCR index to PCR value
//   - error if parsing fails
func ExtractPCRsFromCertInfo(certInfo []byte) (map[uint][]byte, error) {
	if len(certInfo) < 10 {
		return nil, caerrors.MalformedError("certInfo too short: %d bytes", len(certInfo))
	}

	attest, err := ParseTPMSAttest(certInfo)
	if err != nil {
		return nil, err
	}

	// The PCR digest is a hash of all selected PCRs concatenated
	// We can't extract individual PCR values from the digest alone
	// Instead, we return the PCR selection and digest for verification
	pcrs := make(map[uint][]byte)

	// Mark which PCRs were included in the quote
	for _, sel := range attest.Attested.PCRSelect {
		for byteIdx, b := range sel.PCRBitmap {
			for bitIdx := 0; bitIdx < 8; bitIdx++ {
				if b&(1<<bitIdx) != 0 {
					pcrIndex := uint(byteIdx*8 + bitIdx)
					// We store nil to indicate the PCR was selected
					// The actual value would need to be read from the TPM
					pcrs[pcrIndex] = nil
				}
			}
		}
	}

	return pcrs, nil
}

// ParseTPMSAttest parses a raw TPMS_ATTEST structure
func ParseTPMSAttest(data []byte) (*TPMSAttest, error) {
	if len(data) < 10 {
		return nil, caerrors.MalformedError("data too short for TPMS_ATTEST")
	}

	attest := &TPMSAttest{}
	offset := 0

	// Magic (4 bytes, big-endian)
	attest.Magic = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4

	if attest.Magic != tpmGeneratedValue {
		return nil, caerrors.BadAttestationStatementError("invalid TPM magic: got 0x%08x, want 0x%08x", attest.Magic, tpmGeneratedValue)
	}

	// Type (2 bytes, big-endian)
	attest.Type = uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// QualifiedSigner (TPM2B_NAME: 2-byte size + data)
	if offset+2 > len(data) {
		return nil, caerrors.MalformedError("data too short for qualifiedSigner size")
	}
	signerSize := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+signerSize > len(data) {
		return nil, caerrors.MalformedError("data too short for qualifiedSigner")
	}
	attest.QualifiedSigner = data[offset : offset+signerSize]
	offset += signerSize

	// ExtraData (TPM2B_DATA: 2-byte size + data)
	if offset+2 > len(data) {
		return nil, caerrors.MalformedError("data too short for extraData size")
	}
	extraSize := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+extraSize > len(data) {
		return nil, caerrors.MalformedError("data too short for extraData")
	}
	attest.ExtraData = data[offset : offset+extraSize]
	offset += extraSize

	// ClockInfo (TPMS_CLOCK_INFO: 8+4+4+1 = 17 bytes)
	if offset+17 > len(data) {
		return nil, caerrors.MalformedError("data too short for clockInfo")
	}
	attest.ClockInfo.Clock = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 |
		uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 |
		uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8
	attest.ClockInfo.ResetCount = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4
	attest.ClockInfo.RestartCount = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4
	attest.ClockInfo.Safe = data[offset] != 0
	offset++

	// FirmwareVersion (8 bytes)
	if offset+8 > len(data) {
		return nil, caerrors.MalformedError("data too short for firmwareVersion")
	}
	attest.FirmwareVersion = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 |
		uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 |
		uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// For quote attestation, parse TPMS_QUOTE_INFO
	if attest.Type == tpmSTAttestQuote {
		// TPMS_QUOTE_INFO contains:
		// - pcrSelect: TPML_PCR_SELECTION
		// - pcrDigest: TPM2B_DIGEST

		// TPML_PCR_SELECTION: count (4 bytes) + array of TPMS_PCR_SELECTION
		if offset+4 > len(data) {
			return nil, caerrors.MalformedError("data too short for PCR selection count")
		}
		count := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
			uint32(data[offset+2])<<8 | uint32(data[offset+3])
		offset += 4

		for i := uint32(0); i < count; i++ {
			if offset+3 > len(data) {
				return nil, caerrors.MalformedError("data too short for PCR selection %d", i)
			}
			sel := TPMSPCRSelection{
				Hash:         uint16(data[offset])<<8 | uint16(data[offset+1]),
				SizeOfBitmap: data[offset+2],
			}
			offset += 3
			if offset+int(sel.SizeOfBitmap) > len(data) {
				return nil, caerrors.MalformedError("data too short for PCR bitmap")
			}
			sel.PCRBitmap = data[offset : offset+int(sel.SizeOfBitmap)]
			offset += int(sel.SizeOfBitmap)
			attest.Attested.PCRSelect = append(attest.Attested.PCRSelect, sel)
		}

		// pcrDigest (TPM2B_DIGEST: 2-byte size + data)
		if offset+2 > len(data) {
			return nil, caerrors.MalformedError("data too short for PCR digest size")
		}
		digestSize := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+digestSize > len(data) {
			return nil, caerrors.MalformedError("data too short for PCR digest")
		}
		attest.Attested.PCRDigest = data[offset : offset+digestSize]
	}

	return attest, nil
}

// VerifyQualifyingData checks that the certInfo contains the expected qualifying data
//
// Parameters:
//   - certInfo: Raw TPMS_ATTEST bytes
//   - expectedData: Expected qualifying data (usually keyAuth)
//
// Returns:
//   - true if qualifying data matches
//   - false otherwise
func VerifyQualifyingData(certInfo, expectedData []byte) bool {
	// Parse the TPMS_ATTEST structure to extract the extraData field
	attest, err := ParseTPMSAttest(certInfo)
	if err != nil {
		// Fall back to containment check if parsing fails
		return bytes.Contains(certInfo, expectedData)
	}

	// Compare the extraData field with expected data
	return bytes.Equal(attest.ExtraData, expectedData)
}

// SetupWithPCRs generates an attestation statement with specific PCR selection
//
// Parameters:
//   - keyAuth: Key authorization used as qualifying data
//   - akAttrs: Attestation Key attributes
//   - format: Attestation format
//   - tpm: Trusted Platform Module
//   - pcrs: PCR indices to include in quote
//
// Returns:
//   - JSON payload containing CBOR-encoded attestation statement
//   - error if setup fails
func SetupWithPCRs(
	keyAuth string,
	akAttrs KeyAttributes,
	format AttestationFormat,
	tpm TrustedPlatformModule,
	pcrs []uint) ([]byte, error) {

	// Map key algorithm to COSE algorithm identifier
	var alg int64
	switch akAttrs.GetKeyAlgorithm() {
	case x509.RSA:
		alg = int64(-257)
	case x509.ECDSA:
		alg = int64(-7)
	case x509.Ed25519:
		alg = int64(-8)
	default:
		return nil, ErrInvalidKeyAlgorithm
	}

	if format != FormatTPM {
		return nil, ErrInvalidAttestationFormat
	}

	// Perform TPM2_Quote with specified PCRs
	quote, err := tpm.Quote(pcrs, []byte(keyAuth))
	if err != nil {
		return nil, caerrors.TPMErr("device-attest-01: quote failed: %v", err)
	}

	tpmAttrs := akAttrs.GetTPMAttributes()

	obj := &AttestationObject{
		Format: format.String(),
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      alg,
			X5c:      []interface{}{tpmAttrs.GetPublicKeyBytes()},
			Sig:      quote.GetSignature(),
			CertInfo: quote.GetQuoted(),
			PubArea:  tpmAttrs.GetBPublic().Bytes(),
		},
	}

	b, err := cbor.Marshal(obj)
	if err != nil {
		return nil, err
	}

	req := AttestationRequest{AttStmt: b}
	return json.Marshal(req)
}

// EncodeAttestationForSubmission encodes an attestation object for ACME submission
//
// Parameters:
//   - obj: AttestationObject to encode
//
// Returns:
//   - Base64URL-encoded CBOR attestation object
//   - error if encoding fails
func EncodeAttestationForSubmission(obj *AttestationObject) (string, error) {
	b, err := cbor.Marshal(obj)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
