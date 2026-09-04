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

package keybackend

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Attestation errors.
var (
	// ErrNoAttestationKey indicates no attestation key has been provisioned on
	// this device. Callers must degrade to the "none" attestation format: an
	// unprovisioned device still registers, it simply conveys no provenance.
	ErrNoAttestationKey = errors.New("keybackend: no attestation key provisioned")

	// ErrNoAttestationCertificate indicates an attestation key is present but
	// no certificate chain vouches for it. Basic attestation is the only form
	// this authenticator emits, so without a chain there is nothing to present.
	ErrNoAttestationCertificate = errors.New("keybackend: no attestation certificate chain provisioned")

	// ErrAttestationKeyMismatch indicates the attestation certificate does not
	// certify the attestation key that would sign the statement.
	ErrAttestationKeyMismatch = errors.New("keybackend: attestation certificate does not match the attestation key")

	// ErrAttestationCertInvalid indicates the attestation certificate does not
	// meet the WebAuthn Level 2 §8.2.1 packed attestation certificate
	// requirements.
	ErrAttestationCertInvalid = errors.New("keybackend: attestation certificate violates WebAuthn L2 §8.2.1")

	// ErrAttestationSignatureInvalid indicates the attestation signature failed
	// self-verification against the leaf certificate. A statement that cannot be
	// verified is never returned to a relying party.
	ErrAttestationSignatureInvalid = errors.New("keybackend: attestation signature failed self-verification")

	// ErrAttestationAuthDataInvalid indicates the authenticator data does not
	// carry attested credential data, so the AAGUID the certificate must vouch
	// for cannot be determined.
	ErrAttestationAuthDataInvalid = errors.New("keybackend: authenticator data carries no attested credential data")

	// ErrAttestationAAGUIDMismatch indicates the AAGUID in the attestation
	// certificate extension differs from the AAGUID in the authenticator data.
	ErrAttestationAAGUIDMismatch = errors.New("keybackend: attestation certificate AAGUID does not match authenticator data")

	// ErrUnsupportedAttestationKey indicates the attestation key uses an
	// algorithm this authenticator cannot express as a COSE algorithm.
	ErrUnsupportedAttestationKey = errors.New("keybackend: unsupported attestation key algorithm")
)

// OIDFIDOGenCEAAGUID is id-fido-gen-ce-aaguid, the certificate extension that
// binds an attestation certificate to an authenticator model. WebAuthn Level 2
// §8.2.1 requires it whenever the attestation root certifies more than one
// model, and §8.2 step 3 requires a relying party to check it against the
// AAGUID in the authenticator data.
var OIDFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// AttestationCertificateOU is the literal string WebAuthn Level 2 §8.2.1
// requires in the attestation certificate's Subject Organizational Unit.
const AttestationCertificateOU = "Authenticator Attestation"

// aaguidSize is the length of an AAGUID in bytes.
const aaguidSize = 16

// authDataAAGUIDOffset is the offset of the AAGUID within authenticator data
// that carries attested credential data: 32-byte RP ID hash, 1 flags byte and
// a 4-byte signature counter precede it.
const authDataAAGUIDOffset = 37

// authDataFlagAttestedCredentialData is the AT flag (bit 6) that marks
// authenticator data as carrying attested credential data.
const authDataFlagAttestedCredentialData = 0x40

// AttestationKeySource supplies the device attestation identity: the private
// key that signs attestation statements and the certificate chain that vouches
// for it.
//
// The attestation identity is a property of the device, not of the key backend
// that holds credential keys, which is why it is a separate collaborator: an
// operator's Security Officer provisions one key and one chain per device, and
// every credential — software, TPM2, PKCS#11 or cloud KMS — is attested by it.
// A backend that holds its own attestation key in hardware supplies a different
// implementation rather than changing this contract.
type AttestationKeySource interface {
	// GenerateAttestationKey creates a new device attestation key, replacing
	// any existing one, and returns it. The returned signer's public key is
	// what the operator's attestation CA certifies.
	GenerateAttestationKey() (crypto.Signer, error)

	// AttestationSigner returns the provisioned attestation key.
	// Returns ErrNoAttestationKey when the device has not been provisioned.
	AttestationSigner() (crypto.Signer, error)

	// AttestationCertificateChain returns the attestation certificate chain in
	// leaf-first order, excluding the root.
	// Returns ErrNoAttestationCertificate when no chain is installed.
	AttestationCertificateChain() ([]*x509.Certificate, error)
}

// AttestationStatementProvider produces WebAuthn attestation statements. It is
// the only part of FIDO2AttestingKeyBackend the authenticator consumes at
// registration time, so both a key backend that attests in hardware and the
// device attestation identity can satisfy it.
type AttestationStatementProvider interface {
	// GetAttestationStatement generates an attestation statement.
	GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error)
}

// AttestingBackend adds WebAuthn attestation to any FIDO2KeyBackend by pairing
// it with a device AttestationKeySource. It is the production implementation of
// FIDO2AttestingKeyBackend.
//
// Wrapping rather than extending each backend keeps a single device attestation
// identity in front of the composite backend, so which backend generated a
// credential key does not change the provenance the relying party sees.
type AttestingBackend struct {
	FIDO2KeyBackend

	source AttestationKeySource
}

// Compile-time proof that the decorator satisfies the attesting contract.
var _ FIDO2AttestingKeyBackend = (*AttestingBackend)(nil)

// NewAttestingBackend returns inner extended with attestation backed by source.
func NewAttestingBackend(inner FIDO2KeyBackend, source AttestationKeySource) *AttestingBackend {
	return &AttestingBackend{FIDO2KeyBackend: inner, source: source}
}

// Capabilities reports the inner backend's capabilities with attestation
// enabled. The claim is about the device attestation identity this decorator
// adds, not about the key provider underneath.
func (b *AttestingBackend) Capabilities() FIDO2KeyCapabilities {
	caps := b.FIDO2KeyBackend.Capabilities()
	caps.SupportsAttestation = true
	return caps
}

// GenerateAttestationKey creates a new device attestation key and returns a
// handle plus the COSE-encoded public key the attestation CA must certify.
func (b *AttestingBackend) GenerateAttestationKey() (KeyHandle, []byte, error) {
	signer, err := b.source.GenerateAttestationKey()
	if err != nil {
		return nil, nil, err
	}

	algorithm, err := coseAlgorithmForKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}

	publicKeyCOSE, err := EncodeCOSEPublicKey(signer.Public(), algorithm)
	if err != nil {
		return nil, nil, err
	}

	return &attestationKeyHandle{algorithm: algorithm, backend: b.Type()}, publicKeyCOSE, nil
}

// AttestationCertificateChain returns the provisioned chain, leaf first.
func (b *AttestingBackend) AttestationCertificateChain() ([]*x509.Certificate, error) {
	return b.source.AttestationCertificateChain()
}

// GetAttestationStatement builds an attestation statement for the requested
// format. Only "packed" is produced; every other format is reported as
// unsupported so the caller degrades to "none" rather than emitting something
// a relying party cannot verify.
func (b *AttestingBackend) GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error) {
	return AttestationStatement(b.source, format, authData, clientDataHash)
}

// AttestationStatement builds an attestation statement from a device
// attestation identity. Only "packed" is produced; every other format is
// reported as unsupported so the caller degrades to "none" rather than emitting
// something a relying party cannot verify.
func AttestationStatement(source AttestationKeySource, format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error) {
	if source == nil {
		return nil, ErrNoAttestationKey
	}
	if format != AttestationFormatPacked {
		return nil, ErrAttestationNotSupported
	}

	signer, err := source.AttestationSigner()
	if err != nil {
		return nil, err
	}

	chain, err := source.AttestationCertificateChain()
	if err != nil {
		return nil, err
	}

	return PackedAttestationStatement(signer, chain, authData, clientDataHash)
}

// attestationKeyHandle references the device attestation key. It carries no
// credential ID because the attestation key is a device identity rather than a
// credential.
type attestationKeyHandle struct {
	algorithm int
	backend   xkms.BackendType
}

func (h *attestationKeyHandle) CredentialID() []byte        { return nil }
func (h *attestationKeyHandle) Algorithm() int              { return h.algorithm }
func (h *attestationKeyHandle) BackendID() xkms.BackendType { return h.backend }

// AttestationFormatPacked is the WebAuthn Level 2 §8.2 packed attestation
// statement format. It is duplicated from the authenticator package because
// keybackend must not import its parent.
const AttestationFormatPacked = "packed"

// PackedAttestationStatement builds a WebAuthn Level 2 §8.2 packed attestation
// statement: the COSE algorithm of the attestation key, a signature over
// authData ‖ clientDataHash, and the x5c certificate chain that vouches for the
// signing key.
//
// Only Basic/AttCA attestation is produced. Self attestation — packed with no
// x5c — is deliberately unreachable: §8.2 requires it to be signed by the
// credential private key over a zeroed AAGUID, which conveys no device
// provenance beyond what the assertion signature already proves, and a relying
// party enforcing a hardware policy gains nothing from it.
//
// Every check a relying party performs in §8.2 is performed here first, and the
// signature is verified against the leaf certificate before it is returned, so
// a statement that could not be verified is never presented as valid.
func PackedAttestationStatement(signer crypto.Signer, chain []*x509.Certificate, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error) {
	if signer == nil {
		return nil, ErrNoAttestationKey
	}
	if len(chain) == 0 {
		return nil, ErrNoAttestationCertificate
	}

	leaf := chain[0]
	if leaf == nil {
		return nil, ErrNoAttestationCertificate
	}

	// The chain must certify the key that signs, or the relying party's §8.2
	// step 1 signature check fails against a leaf that vouches for a different
	// key. Catching it here keeps the failure on this side of the wire.
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return nil, ErrAttestationKeyMismatch
	}

	aaguid, err := aaguidFromAuthData(authData)
	if err != nil {
		return nil, err
	}

	if err := ValidateAttestationCertificate(leaf, aaguid); err != nil {
		return nil, err
	}

	algorithm, err := coseAlgorithmForKey(signer.Public())
	if err != nil {
		return nil, err
	}

	hash, err := hashForCOSEAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	signedData := make([]byte, 0, len(authData)+len(clientDataHash))
	signedData = append(signedData, authData...)
	signedData = append(signedData, clientDataHash...)

	signature, err := signWithHash(signer, signedData, hash)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: err}
	}

	// Normalize to low-S for the same reason credential assertions are
	// normalized: some relying-party stacks reject the high-S variant even
	// though ECDSA accepts both.
	if curve := curveForAlgorithm(algorithm); curve != nil {
		signature, err = NormalizeLowS(signature, curve)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: err}
		}
	}

	if err := verifyAttestationSignature(leaf, hash, signedData, signature); err != nil {
		return nil, err
	}

	return &FIDO2AttestationStatement{
		Format:           AttestationFormatPacked,
		Algorithm:        algorithm,
		Signature:        signature,
		CertificateChain: chain,
	}, nil
}

// ValidateAttestationCertificate checks cert against the WebAuthn Level 2
// §8.2.1 packed attestation statement certificate requirements, and against the
// AAGUID the authenticator reports. A relying party runs the same checks; a
// certificate that fails here would be rejected on arrival, so it is rejected
// at provisioning time instead.
//
// Pass a nil aaguid to skip the AAGUID comparison when the device identity is
// not yet known to the caller; the extension's encoding is still validated.
func ValidateAttestationCertificate(cert *x509.Certificate, aaguid []byte) error {
	if cert == nil {
		return ErrNoAttestationCertificate
	}

	// §8.2.1: "Version MUST be set to 3". x509.Certificate.Version is the
	// human-readable version number, so v3 reads as 3.
	if cert.Version != 3 {
		return &DetailError{Err: ErrAttestationCertInvalid, Detail: ": certificate is not X.509 v3"}
	}

	// §8.2.1 requires Subject-C (vendor country), Subject-O (vendor legal name)
	// and the literal Subject-OU.
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] == "" {
		return &DetailError{Err: ErrAttestationCertInvalid, Detail: ": subject is missing the country (C) attribute"}
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
		return &DetailError{Err: ErrAttestationCertInvalid, Detail: ": subject is missing the organization (O) attribute"}
	}
	if !containsString(cert.Subject.OrganizationalUnit, AttestationCertificateOU) {
		return &DetailError{Err: ErrAttestationCertInvalid, Detail: ": subject OU is not \"" + AttestationCertificateOU + "\""}
	}

	// §8.2.1: "The Basic Constraints extension MUST have the CA component set
	// to false." A CA certificate presented as an attestation leaf would let
	// the holder mint further attestation identities.
	if cert.IsCA {
		return &DetailError{Err: ErrAttestationCertInvalid, Detail: ": basic constraints assert CA:true"}
	}

	certAAGUID, found, err := aaguidFromCertificate(cert)
	if err != nil {
		return err
	}
	if found && len(aaguid) > 0 && !bytes.Equal(certAAGUID, aaguid) {
		return ErrAttestationAAGUIDMismatch
	}

	return nil
}

// MarshalAAGUIDExtensionValue encodes an AAGUID as the value of the
// id-fido-gen-ce-aaguid extension. §8.2.1 specifies the AAGUID as a DER OCTET
// STRING, which is then carried in the extension's own OCTET STRING wrapper.
func MarshalAAGUIDExtensionValue(aaguid []byte) ([]byte, error) {
	if len(aaguid) != aaguidSize {
		return nil, &DetailError{Err: ErrAttestationCertInvalid, Detail: ": AAGUID must be 16 bytes"}
	}
	value, err := asn1.Marshal(aaguid)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAttestationCertInvalid, Cause: err}
	}
	return value, nil
}

// aaguidFromCertificate extracts the AAGUID from the id-fido-gen-ce-aaguid
// extension. The second result reports whether the extension is present;
// §8.2.1 only requires it when the attestation root certifies more than one
// authenticator model, so absence is not an error.
func aaguidFromCertificate(cert *x509.Certificate) ([]byte, bool, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDFIDOGenCEAAGUID) {
			continue
		}

		// §8.2.1: "The extension MUST NOT be marked as critical." A critical
		// extension a relying party does not understand invalidates the chain.
		if ext.Critical {
			return nil, false, &DetailError{Err: ErrAttestationCertInvalid, Detail: ": id-fido-gen-ce-aaguid extension is marked critical"}
		}

		var aaguid []byte
		rest, err := asn1.Unmarshal(ext.Value, &aaguid)
		if err != nil {
			return nil, false, &SentinelCauseError{Sentinel: ErrAttestationCertInvalid, Cause: err}
		}
		if len(rest) != 0 {
			return nil, false, &DetailError{Err: ErrAttestationCertInvalid, Detail: ": trailing data after the id-fido-gen-ce-aaguid OCTET STRING"}
		}
		if len(aaguid) != aaguidSize {
			return nil, false, &DetailError{Err: ErrAttestationCertInvalid, Detail: ": id-fido-gen-ce-aaguid is not 16 bytes"}
		}

		return aaguid, true, nil
	}

	return nil, false, nil
}

// aaguidFromAuthData reads the AAGUID out of authenticator data that carries
// attested credential data. MakeCredential always sets the AT flag, so the
// absence of attested credential data means the caller assembled the wrong
// buffer and no statement should be signed over it.
func aaguidFromAuthData(authData []byte) ([]byte, error) {
	if len(authData) < authDataAAGUIDOffset+aaguidSize {
		return nil, ErrAttestationAuthDataInvalid
	}
	if authData[32]&authDataFlagAttestedCredentialData == 0 {
		return nil, ErrAttestationAuthDataInvalid
	}
	return authData[authDataAAGUIDOffset : authDataAAGUIDOffset+aaguidSize], nil
}

// verifyAttestationSignature re-checks a freshly produced signature against the
// leaf certificate. The cost is one verification per registration and it makes
// "never present an unverifiable statement as valid" a property of the code
// rather than of the reviewer's confidence in it.
func verifyAttestationSignature(leaf *x509.Certificate, hash crypto.Hash, signedData, signature []byte) error {
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedAttestationKey
	}

	h := hash.New()
	h.Write(signedData)
	if !ecdsa.VerifyASN1(publicKey, h.Sum(nil), signature) {
		return ErrAttestationSignatureInvalid
	}

	return nil
}

// coseAlgorithmForKey maps an attestation public key to its COSE algorithm.
func coseAlgorithmForKey(publicKey crypto.PublicKey) (int, error) {
	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, ErrUnsupportedAttestationKey
	}

	switch ecKey.Curve {
	case elliptic.P256():
		return COSEAlgES256, nil
	case elliptic.P384():
		return COSEAlgES384, nil
	case elliptic.P521():
		return COSEAlgES512, nil
	default:
		return 0, ErrUnsupportedAttestationKey
	}
}

// hashForCOSEAlgorithm returns the digest algorithm paired with a COSE ECDSA
// algorithm identifier.
func hashForCOSEAlgorithm(algorithm int) (crypto.Hash, error) {
	switch algorithm {
	case COSEAlgES256:
		return crypto.SHA256, nil
	case COSEAlgES384:
		return crypto.SHA384, nil
	case COSEAlgES512:
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedAttestationKey
	}
}

// publicKeysEqual reports whether two public keys are the same key.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }

	lhs, ok := a.(equaler)
	if !ok {
		return false
	}

	return lhs.Equal(b)
}

// containsString reports whether values contains target.
func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
