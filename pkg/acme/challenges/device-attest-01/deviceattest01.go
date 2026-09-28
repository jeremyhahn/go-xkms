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

package deviceattest01

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
// Server-side verification of the "tpm" format is the WebAuthn Level 2
// section 8.3 procedure, with the key authorization in place of
// authenticatorData || clientDataHash (see TPMExtraData):
//    - certInfo is a TPM2_Certify: TPM_GENERATED_VALUE, TPM_ST_ATTEST_CERTIFY
//    - its attested Name is the Name of pubArea under pubArea's nameAlg
//    - its extraData is the alg hash of the key authorization
//    - sig verifies over certInfo under x5c[0], the AIK certificate, with alg
//    - x5c chains to the configured roots, and x5c[0] meets section 8.3.1
//    - at finalization, pubArea's key is the CSR's key (BindCSRKey)
//
// The last step is why Verify refuses this format: the attested key is only
// known to be the certified key once the CSR has been compared with pubArea,
// and the CSR arrives one request after the challenge. See binding.go.
//
// Attestation Format:
// The attestation object follows W3C WebAuthn TPM attestation format:
// - ver: TPM version ("2.0")
// - alg: COSE algorithm of sig (RS256=-257, ES256=-7, PS256=-37, ...)
// - x5c: AIK certificate followed by its chain (DER-encoded certificates)
// - sig: the AIK's signature over certInfo (WebAuthn L2 section 6.5.6 encoding)
// - certInfo: TPMS_ATTEST structure from TPM2_Certify of the attested key
// - pubArea: TPMT_PUBLIC structure of the attested key

const (
	challengePath = "/.well-known/acme-challenge/"
)

// AttestationFormat represents the supported attestation formats
type AttestationFormat string

const (
	// FormatTPM indicates TPM 2.0 attestation format per WebAuthn specification
	FormatTPM AttestationFormat = "tpm"

	// FormatDICE indicates DICE-based device identity with a hardware root of
	// trust, presented as an X.509 chain whose leaf carries the TCG DICE
	// evidence extensions.
	//
	// It differs from FormatTPM in what carries the freshness. A TPM signs a
	// quote over qualifying data; a DICE device has no clock and no quote, so
	// the challenge is echoed in the leaf's DiceTcbInfo.vendorInfo and the
	// certificate signature is what authenticates it.
	FormatDICE AttestationFormat = "dice"
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
	Sig      []byte        `json:"sig" cbor:"sig"`           // AIK signature over certInfo
	CertInfo []byte        `json:"certInfo" cbor:"certInfo"` // TPMS_ATTEST structure (TPM2_Certify)
	PubArea  []byte        `json:"pubArea" cbor:"pubArea"`   // TPMT_PUBLIC of the attested key
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

	// ErrTPMAttestationInvalid is returned when a "tpm" attestation statement
	// does not satisfy the WebAuthn Level 2 section 8.3 verification
	// procedure: a missing or malformed field, an unknown alg, or a
	// certification that does not verify. The cause is joined, so a caller can
	// tell a quote offered as a certification from a certification of the
	// wrong key or over the wrong challenge.
	ErrTPMAttestationInvalid = errors.New("device-attest-01: tpm attestation statement invalid")

	// ErrAIKCertificateInvalid is returned when x5c[0] does not meet the
	// WebAuthn Level 2 section 8.3.1 TPM attestation certificate requirements.
	ErrAIKCertificateInvalid = errors.New("device-attest-01: AIK certificate does not meet the tpm attestation requirements")

	// ErrCertificateChainInvalid is returned when the AK certificate chain is invalid
	ErrCertificateChainInvalid = errors.New("device-attest-01: AK certificate chain invalid")

	// ErrKeyBindingRequired is returned when a format's evidence was verified
	// but its key binding cannot be completed without the CSR.
	//
	// The challenge and the finalize are two requests, and only the second one
	// carries the key being certified. A verifier that answered "valid" from
	// the first would have authorized issuance for a key it never compared
	// against the device's, so it says this instead. Verification for such a
	// format goes through VerifyAttestation, and its result authorizes nothing
	// until VerifiedAttestation.BindCSRKey has run.
	ErrKeyBindingRequired = errors.New("device-attest-01: this format binds the attested key through the CSR, so issuance must go through VerifyAttestation and BindCSRKey")

	// ErrKeyBindingUnavailable is returned when a binding was asked for that
	// this evidence cannot express -- a format with no leaf that certifies the
	// enrolled key, or a record missing the certificate the comparison is made
	// against. It is not a refusal of the device: it is the verifier saying the
	// check could not run, which must never read as the check passing.
	ErrKeyBindingUnavailable = errors.New("device-attest-01: the attested key cannot be bound to the certificate request")

	// ErrNoVerifiedAttestation is returned when a binding is asked for without
	// a verified attestation to bind. A nil record is a caller that never
	// verified anything, not one whose device failed.
	ErrNoVerifiedAttestation = errors.New("device-attest-01: no verified attestation to bind")
)

// AttestationVerifier is the server's policy over a device attestation: any
// check it adds to the attestation object, and the trust anchors the
// attestation certificate chain must reach.
type AttestationVerifier interface {
	// VerifyAttestationObject verifies an attestation object
	// Returns error if verification fails
	VerifyAttestationObject(obj *AttestationObject, expectedChallenge []byte) error

	// VerifyAKCertificateChain verifies the x5c chain, leaf first, against
	// the configured roots. For the "tpm" format the leaf is the AIK
	// certificate whose key signed certInfo.
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

// Verify performs device-attest-01 challenge verification, in the shape an
// ACME challenge verifier is called in.
//
// This function implements server-side attestation verification:
//  1. Retrieves attestation statement from client's challenge endpoint
//  2. Decodes and parses the CBOR-encoded attestation object
//  3. Anchors the x5c certificate chain to the configured roots
//  4. Verifies the format's evidence: for "tpm", the WebAuthn Level 2 section
//     8.3 TPM2_Certify procedure over the key authorization; for "dice", the
//     nonce the alias certificate echoes
//
// IT REFUSES EVERY FORMAT IT CAN VERIFY, and that refusal is the point rather
// than a gap. Both "tpm" and "dice" attest a key -- pubArea, the alias
// certificate's key -- and a challenge verifier renders its verdict with no
// CSR in front of it: the CSR arrives at finalization, one request later. An
// attestation declared valid here would have authorized issuance for a key
// nobody compared against the device's. The evidence is public, so anyone
// holding a genuine device's answer could then present it beside a CSR for a
// key they generated in software. These formats are verified through
// VerifyAttestation, whose result cannot authorize anything until
// VerifiedAttestation.BindCSRKey has run against the key being certified.
//
// Parameters:
//   - client: the shared challenge-validation client
//   - ca: attestation verifier for the attestation object and x5c anchoring
//   - domain: Domain/identifier to verify
//   - port: HTTP port for challenge communication
//   - challengeToken: Challenge token, naming the endpoint to fetch
//   - expectedKeyAuth: Expected key authorization
//
// Returns:
//   - nil if attestation is valid
//   - ErrKeyBindingRequired for a format whose binding needs the CSR
//   - error if verification fails
func Verify(
	client *validation.Client,
	ca AttestationVerifier,
	domain, port, challengeToken, expectedKeyAuth string) error {

	verified, err := VerifyAttestation(client, ca, domain, port, challengeToken, expectedKeyAuth)
	if err != nil {
		return err
	}
	if verified.bindsThroughTheCSR() {
		return &errs.Detail{Err: ErrKeyBindingRequired, Detail: string(verified.Format)}
	}
	return nil
}

// VerifyAttestation is Verify, returning what the attestation established so a
// caller can finish the job at finalization.
//
// The returned value is NOT an authorization on its own for a format that
// binds through the CSR: see VerifiedAttestation.
func VerifyAttestation(
	client *validation.Client,
	ca AttestationVerifier,
	domain, port, challengeToken, expectedKeyAuth string) (*VerifiedAttestation, error) {

	// Retrieve attestation from client's challenge endpoint through the
	// shared challenge-validation client: a bare host only, no reserved
	// target address, no redirects, and a capped response.
	body, err := client.Get(context.Background(), validation.Target{
		Host: domain,
		Port: port,
		Path: challengePath + challengeToken,
	})
	if err != nil {
		return nil, err
	}

	// Decode the attestation request
	var attestReq AttestationRequest
	if err := json.Unmarshal(body, &attestReq); err != nil {
		return nil, caerrors.MalformedError("device-attest-01: invalid attestation request: %v", err)
	}

	// Parse the CBOR-encoded attestation object
	attestObj, err := ParseAttestationObject(attestReq.AttStmt)
	if err != nil {
		return nil, caerrors.MalformedError("device-attest-01: %v", err)
	}

	// Validate attestation format
	format := AttestationFormat(attestObj.Format)
	if !ValidateAttestationFormat(format) {
		return nil, ErrInvalidAttestationFormat
	}

	// Verify using CA
	if err := ca.VerifyAttestationObject(attestObj, []byte(expectedKeyAuth)); err != nil {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: attestation verification failed: %v", err)
	}

	// Extract and verify certificate chain. Every entry must be a certificate:
	// dropping one that is not would anchor a chain other than the one sent.
	if len(attestObj.AttStatement.X5c) > 0 {
		certChain := make([][]byte, 0, len(attestObj.AttStatement.X5c))
		for _, cert := range attestObj.AttStatement.X5c {
			certBytes, ok := cert.([]byte)
			if !ok {
				return nil, &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "an x5c entry is not a byte string"}
			}
			certChain = append(certChain, certBytes)
		}
		if err := ca.VerifyAKCertificateChain(certChain); err != nil {
			return nil, ErrCertificateChainInvalid
		}
	}

	// Verify the format-specific evidence. What proves freshness differs by
	// format -- a TPM quote over qualifying data, a DICE nonce echoed in a
	// certificate extension -- so the step that checks it is dispatched rather
	// than assumed to be a quote.
	verifyEvidence, supported := evidenceVerifiers[format]
	if !supported {
		return nil, ErrInvalidAttestationFormat
	}
	verified, err := verifyEvidence(attestObj, ca, expectedKeyAuth)
	if err != nil {
		return nil, err
	}

	verified.Format = format
	verified.KeyAuthorization = expectedKeyAuth
	if verified.Leaf != nil {
		verified.LeafDER = verified.Leaf.Raw
	}
	return verified, nil
}

// evidenceVerifier checks the format-specific half of an attestation object,
// after the shared steps (format recognition, attestation object verification
// and certificate chain anchoring) have run.
//
// It returns the evidence its checks were made against -- the format-specific
// fields of a VerifiedAttestation, which the caller completes. The evidence is
// returned rather than discarded because a format whose key binding needs the
// CSR cannot complete at challenge time, and the evidence the binding is made
// against must be the evidence that was actually verified -- not evidence
// re-fetched later from a device that has moved on.
type evidenceVerifier func(*AttestationObject, AttestationVerifier, string) (*VerifiedAttestation, error)

// evidenceVerifiers dispatches an attestation object to its format's evidence
// check. It is also the single source of truth for which formats this server
// can verify, so ValidateAttestationFormat cannot drift away from what Verify
// is actually able to dispatch.
var evidenceVerifiers = map[AttestationFormat]evidenceVerifier{
	FormatTPM:  verifyTPMEvidence,
	FormatDICE: verifyDICEEvidence,
}

// verifyDICEEvidence checks that the DICE leaf echoed this challenge.
//
// There is no quote to verify: a DICE device does not sign a separate
// attestation structure. The evidence is the certificate chain itself, already
// anchored by the caller, and the freshness is the nonce the device placed in
// the eat_nonce claim of the leaf's tcg-dice-UCCS-evidence extension -- the
// mechanism TCG DICE Attestation Architecture section 6.1.4 defines. The
// device has no clock, so this nonce is the whole of the freshness argument
// and nothing here consults a timestamp.
func verifyDICEEvidence(attestObj *AttestationObject, _ AttestationVerifier, expectedKeyAuth string) (*VerifiedAttestation, error) {
	if expectedKeyAuth == "" {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: no key authorization to bind the dice attestation to")
	}
	if len(attestObj.AttStatement.X5c) == 0 {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: dice attestation carries no certificate chain")
	}

	leafDER, ok := attestObj.AttStatement.X5c[0].([]byte)
	if !ok {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: dice leaf certificate is not a byte string")
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: dice leaf certificate could not be parsed: %v", err)
	}

	challenge, err := dice.Challenge(leaf)
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: %v", err)
	}

	// The device echoes SHA-256 of the key authorization, not the string.
	//
	// EAT bounds eat_nonce at 8-64 bytes, and a key authorization is
	// "<token>.<RFC 7638 thumbprint>" -- 87 bytes, since the thumbprint alone
	// is 43 base64url characters. So the raw form cannot be carried by a
	// conforming UCCS claims set at all, and a verifier that expected it would
	// be asking every attester to emit evidence that a strictly conforming EAT
	// verifier rejects -- which would undo the interoperability this extension
	// was chosen for. Hashing is what Apple's device-attest-01 profile does,
	// for the same reason.
	//
	// FormatTPM binds the key authorization through the certification's
	// extraData instead, hashed with the statement's alg (TPMExtraData). For
	// the SHA-256 algorithms the two digests coincide; they are defined
	// separately because the DICE container fixes the hash and the WebAuthn
	// "tpm" statement lets alg choose it.
	want := sha256.Sum256([]byte(expectedKeyAuth))
	if subtle.ConstantTimeCompare(challenge, want[:]) != 1 {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: dice attestation nonce mismatch")
	}

	// The leaf goes back to the caller because THIS IS NOT THE WHOLE CHECK.
	// The nonce says the device answered this challenge; it says nothing about
	// which key the certificate the CA is about to sign is for. That comparison
	// is VerifiedAttestation.BindCSRKey and it needs the CSR, which arrives one
	// request later.
	return &VerifiedAttestation{Leaf: leaf}, nil
}

// DICENonce is the value a DICE attester places in its eat_nonce claim for a
// given ACME key authorization.
//
// Exported because a device, a provisioning tool and a test all need to agree
// on it, and three copies of `sha256.Sum256([]byte(keyAuth))` is three chances
// for one of them to hash something slightly different -- a trailing newline, a
// token rather than the whole authorization -- and produce a mismatch whose
// cause is invisible from either end.
func DICENonce(keyAuth string) []byte {
	sum := sha256.Sum256([]byte(keyAuth))
	return sum[:]
}

// Setup generates an attestation statement for the device-attest-01 challenge.
//
// It builds TPM 2.0 evidence and supports FormatTPM alone. FormatDICE has no
// counterpart here by design: a DICE device mints its own alias certificate
// carrying the challenge, so the evidence arrives already formed and there is
// nothing for this host to construct.
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

// ValidateAttestationFormat reports whether the server can verify the given
// attestation format.
//
// It answers for the verification path only. Setup builds evidence with a
// local TPM and supports FormatTPM alone: DICE evidence is minted by the
// device itself, so there is nothing for this host to construct.
//
// Parameters:
//   - format: Attestation format to validate
//
// Returns:
//   - true if format is supported, false otherwise
func ValidateAttestationFormat(format AttestationFormat) bool {
	_, supported := evidenceVerifiers[format]
	return supported
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
