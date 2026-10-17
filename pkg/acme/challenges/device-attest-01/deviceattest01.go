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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// device-attest-01 Challenge Implementation
//
// The device-attest-01 challenge is the ACME extension for remote attestation
// of devices defined by draft-ietf-acme-device-attest-10. It implements the
// draft's challenge-response model together with the WebAuthn TPM attestation
// format and the DICE format this repository models.
//
// References:
// - https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest-10
// - https://www.w3.org/TR/webauthn/#sctn-tpm-attestation
//
// The exchange (draft-ietf-acme-device-attest-10, "Device Attestation Challenge"):
// the server issues a challenge carrying a token; the client answers by POSTing
// the challenge URL, as an ordinary authenticated ACME request, with a payload
//
//	{"attObj": "<base64url of the CBOR attestation object>"}
//
// and the server verifies the attestation from that payload. THE SERVER NEVER
// CONTACTS THE DEVICE. The device need not run a server or be addressable at
// all, which is what lets a device on a serial port enroll through a gateway
// that holds the ACME account. Freshness is the key authorization derived from
// the challenge token, which the attestation must cover (TPMExtraData for
// "tpm", DICENonce for "dice"); a recording of an earlier answer does not
// verify against a new token.
//
// TPM Requirements:
// - TPM 2.0 compliant hardware or software TPM
// - Initial Attestation Key (IAK) provisioned, with its certificate
// - Support for TPM2_Certify
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
	// TPM2_Certify over qualifying data; a DICE device has no clock and signs
	// no attestation structure, so the challenge is echoed in the leaf's DiceTcbInfo.vendorInfo and the
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

// AttestationRequest is the payload of the client's POST to the challenge URL
// (draft-ietf-acme-device-attest-10, "Device Attestation Challenge").
type AttestationRequest struct {
	// AttObj is the base64url (RFC 4648 section 5, unpadded) encoding of the
	// CBOR attestation object. EncodeAttestationForSubmission produces it.
	AttObj string `json:"attObj"`
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

	// ErrAttestationPayloadInvalid is returned when the client's POST to the
	// challenge URL does not carry a decodable attestation object: the
	// payload is not the JSON {"attObj": ...}, attObj is not unpadded
	// base64url, or what it decodes to is not a CBOR attestation object. The
	// layer that failed is in the detail.
	ErrAttestationPayloadInvalid = errors.New("device-attest-01: the challenge response payload is not a decodable attestation object")

	// ErrNoTrustAnchors is returned when a verifier is asked to anchor a
	// chain it holds no trust anchors for: none at all at construction, or none
	// for the format being verified. A verifier without anchors cannot tell a
	// genuine chain from one the caller minted, so the absence is a refusal.
	ErrNoTrustAnchors = errors.New("device-attest-01: no trust anchors configured")

	// ErrNoAttestationVerifier is returned when an attestation is asked to be
	// verified with no AttestationVerifier. Verifying without the server's
	// trust anchors would accept a chain the caller minted, so the absence is
	// a refusal.
	ErrNoAttestationVerifier = errors.New("device-attest-01: no attestation verifier configured")

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

// Verify performs device-attest-01 challenge verification, in the shape of a
// one-shot challenge verifier: it takes the client's payload and answers
// whether the attestation is an authorization.
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
//   - verifier: the server's policy over the attestation object and its x5c
//   - payload: the body of the client's POST to the challenge URL
//   - expectedKeyAuth: the key authorization the attestation must answer
//
// Returns:
//   - ErrKeyBindingRequired for a format whose binding needs the CSR
//   - error if verification fails
func Verify(ctx context.Context, verifier AttestationVerifier, payload []byte, expectedKeyAuth string) error {
	verified, err := VerifyAttestation(ctx, verifier, payload, expectedKeyAuth)
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
// payload is the body of the client's POST to the challenge URL: the
// AttestationRequest JSON. Nothing is fetched: the evidence is exactly what the
// authenticated ACME request carried, so there is no address to resolve and no
// device to reach.
//
// The returned value is NOT an authorization on its own for a format that
// binds through the CSR: see VerifiedAttestation.
//
// ctx bounds the device registry lookup a "dice" attestation is anchored in
// (RegisteredDeviceVerifier).
func VerifyAttestation(ctx context.Context, verifier AttestationVerifier, payload []byte, expectedKeyAuth string) (*VerifiedAttestation, error) {
	if verifier == nil {
		return nil, ErrNoAttestationVerifier
	}

	attestObj, err := ParseAttestationRequest(payload)
	if err != nil {
		return nil, caerrors.MalformedError("device-attest-01: %v", err)
	}

	// Verify the format's evidence. What anchors it and what proves freshness
	// differ by format -- an AIK chain and a TPM2_Certify over qualifying data,
	// a provisioning record and a DICE nonce echoed in a certificate extension
	// -- so the whole check is dispatched rather than assumed to be one of them.
	format := AttestationFormat(attestObj.Format)
	verifyEvidence, supported := evidenceVerifiers[format]
	if !supported {
		return nil, ErrInvalidAttestationFormat
	}
	verified, err := verifyEvidence(ctx, attestObj, verifier, expectedKeyAuth)
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

// ParseAttestationRequest decodes the payload of the client's POST to the
// challenge URL into its attestation object: the JSON AttestationRequest, its
// base64url attObj, and the CBOR attestation object inside.
//
// Each layer is a separate failure, reported as ErrAttestationPayloadInvalid
// with the layer named, so a client can tell a payload that is not JSON from an
// attObj that is not base64url from one that is not CBOR.
func ParseAttestationRequest(payload []byte) (*AttestationObject, error) {
	var request AttestationRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationPayloadInvalid, Detail: "the payload is not a JSON attestation request", Cause: err}
	}
	if request.AttObj == "" {
		return nil, &errs.Detail{Err: ErrAttestationPayloadInvalid, Detail: "attObj is absent"}
	}
	encoded, err := base64.RawURLEncoding.DecodeString(request.AttObj)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationPayloadInvalid, Detail: "attObj is not unpadded base64url", Cause: err}
	}
	object, err := ParseAttestationObject(encoded)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationPayloadInvalid, Detail: "attObj is not a CBOR attestation object", Cause: err}
	}
	return object, nil
}

// EncodeAttestationRequest is the client half of ParseAttestationRequest: the
// payload to POST to the challenge URL for obj.
func EncodeAttestationRequest(obj *AttestationObject) ([]byte, error) {
	attObj, err := EncodeAttestationForSubmission(obj)
	if err != nil {
		return nil, err
	}
	return json.Marshal(AttestationRequest{AttObj: attObj})
}

// evidenceVerifier checks an attestation object of one format: what anchors it
// and what makes it this challenge's answer.
//
// It returns the evidence its checks were made against -- the format-specific
// fields of a VerifiedAttestation, which the caller completes. The evidence is
// returned rather than discarded because a format whose key binding needs the
// CSR cannot complete at challenge time, and the evidence the binding is made
// against must be the evidence that was actually verified -- not evidence
// re-fetched later from a device that has moved on.
type evidenceVerifier func(context.Context, *AttestationObject, AttestationVerifier, string) (*VerifiedAttestation, error)

// evidenceVerifiers dispatches an attestation object to its format's evidence
// check. It is also the single source of truth for which formats this server
// can verify, so ValidateAttestationFormat cannot drift away from what Verify
// is actually able to dispatch.
var evidenceVerifiers = map[AttestationFormat]evidenceVerifier{
	FormatTPM:  verifyTPMAttestation,
	FormatDICE: verifyDICEAttestation,
}

// verifyTPMAttestation applies the server's policy to a "tpm" attestation
// object, anchors its AIK chain, and verifies the certification
// (verifyTPMEvidence).
func verifyTPMAttestation(_ context.Context, attestObj *AttestationObject, verifier AttestationVerifier, expectedKeyAuth string) (*VerifiedAttestation, error) {
	if err := verifier.VerifyAttestationObject(attestObj, []byte(expectedKeyAuth)); err != nil {
		return nil, caerrors.BadAttestationStatementError("device-attest-01: attestation verification failed: %v", err)
	}

	// Every x5c entry must be a certificate: dropping one that is not would
	// anchor a chain other than the one sent.
	if len(attestObj.AttStatement.X5c) > 0 {
		certChain := make([][]byte, 0, len(attestObj.AttStatement.X5c))
		for _, cert := range attestObj.AttStatement.X5c {
			certBytes, ok := cert.([]byte)
			if !ok {
				return nil, &errs.Detail{Err: ErrCertificateChainInvalid, Detail: "an x5c entry is not a byte string"}
			}
			certChain = append(certChain, certBytes)
		}
		if err := verifier.VerifyAKCertificateChain(certChain); err != nil {
			return nil, &errs.Joined{Lead: ErrCertificateChainInvalid, Cause: err}
		}
	}
	return verifyTPMEvidence(attestObj, verifier, expectedKeyAuth)
}

// verifyDICEAttestation anchors a "dice" alias certificate in its device's
// provisioning record and checks that it echoed this challenge
// (RegisteredDeviceVerifier, go-xkms#1441).
//
// There is no certification to verify: a DICE device does not sign a separate
// attestation structure. The evidence is the alias certificate in x5c[0], and
// the freshness is the nonce the device placed in the eat_nonce claim of its
// tcg-dice-UCCS-evidence extension -- the mechanism TCG DICE Attestation
// Architecture section 6.1.4 defines. The device has no clock, so this nonce
// is the whole of the freshness argument and nothing here consults a
// timestamp. Any certificate after x5c[0] is the client's to send and is not
// used: on the endorsement path the DeviceID certificate comes from the
// provisioning record, never from the payload.
func verifyDICEAttestation(ctx context.Context, attestObj *AttestationObject, verifier AttestationVerifier, expectedKeyAuth string) (*VerifiedAttestation, error) {
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

	registry, ok := verifier.(RegisteredDeviceVerifier)
	if !ok {
		return nil, notAuthorized(ErrNoDeviceResolver)
	}
	verified, err := registry.VerifyRegisteredDevice(ctx, leaf, expectedKeyAuth)
	if err != nil {
		return nil, err
	}

	// The leaf goes back to the caller because THIS IS NOT THE WHOLE CHECK.
	// The record says which key the device holds and the nonce says the
	// device answered this challenge; neither says which key the certificate
	// the CA is about to sign is for. That comparison is
	// VerifiedAttestation.BindCSRKey, against AttestedSPKI, and it needs the
	// CSR, which arrives one request later.
	return verified, nil
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
// It answers for the verification path only. Setup builds FormatTPM evidence
// with a local TPM: DICE evidence is minted by the device itself, so there is
// nothing for this host to construct.
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
