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
	"crypto/x509"
	"errors"

	"github.com/fxamacker/cbor/v2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// AttestationFormatTPM is the WebAuthn Level 2 §8.3 TPM attestation statement
// format. It is duplicated from the authenticator package because keybackend
// must not import its parent -- see AttestationFormatPacked.
const AttestationFormatTPM = "tpm"

// tpmAttestationVersion is the only "ver" value WebAuthn L2 §8.3 defines.
const tpmAttestationVersion = "2.0"

// TPM2 attestation errors.
var (
	// ErrTPMCertifyFailed indicates TPM2_Certify could not certify the
	// credential key under the device's Initial Attestation Key.
	ErrTPMCertifyFailed = errors.New("keybackend: TPM2_Certify failed")

	// ErrTPMIAKUnavailable indicates the device's Initial Attestation Key is
	// not provisioned, so no "tpm" attestation statement can be produced.
	ErrTPMIAKUnavailable = errors.New("keybackend: TPM Initial Attestation Key is not provisioned")
)

// TPM2AttestingBackend adds WebAuthn Level 2 §8.3 "tpm" attestation to a
// TPM2-backed FIDO2KeyBackend.
//
// Unlike AttestingBackend, which signs authData‖clientDataHash directly with a
// device identity key, this certifies each credential key with TPM2_Certify
// under the device's Initial Attestation Key (IAK). The IAK is a TPM
// restricted signing key: the TPM refuses to use it to sign caller-supplied
// bytes, so it cannot produce an ordinary "packed" signature over
// authData‖clientDataHash. TPM2_Certify is the operation a restricted key can
// perform instead -- the TPM itself signs a TPMS_ATTEST it generates, naming
// the credential key and carrying the caller's nonce as extraData -- which is
// exactly what §8.3 requires the "tpm" format's certInfo/sig/pubArea triple to
// be. Per the FIDO2AttestingKeyBackend doc comment, a TPM2 key backend
// implements this interface directly and takes precedence over the generic
// device attestation identity AttestingBackend adds.
type TPM2AttestingBackend struct {
	*BackendAdapter

	tpm   xkms.TrustedPlatformModule
	blobs xkms.TPMKeyBackend
}

// Compile-time proof that the decorator satisfies the attesting contract.
var _ FIDO2AttestingKeyBackend = (*TPM2AttestingBackend)(nil)

// NewTPM2AttestingBackend returns inner extended with WebAuthn "tpm"
// attestation backed by tpm's Initial Attestation Key. blobs is the key
// storage backend that holds the transient credential key blobs inner
// generates -- TPM2_Certify must load them before it can certify them, the
// same way Sign does.
func NewTPM2AttestingBackend(inner *BackendAdapter, tpm xkms.TrustedPlatformModule, blobs xkms.TPMKeyBackend) *TPM2AttestingBackend {
	return &TPM2AttestingBackend{BackendAdapter: inner, tpm: tpm, blobs: blobs}
}

// Capabilities reports the inner adapter's capabilities with attestation
// enabled: this decorator's whole purpose is producing WebAuthn statements.
func (b *TPM2AttestingBackend) Capabilities() FIDO2KeyCapabilities {
	caps := b.BackendAdapter.Capabilities()
	caps.SupportsAttestation = true
	return caps
}

// GenerateAttestationKey loads the device's provisioned IAK and returns its
// COSE-encoded public key. The IAK is provisioned once per device (`xkey tpm
// iak create`), not per credential, so this is a load rather than a creation;
// it errors when no IAK has been provisioned.
func (b *TPM2AttestingBackend) GenerateAttestationKey() (KeyHandle, []byte, error) {
	iakAttrs, err := b.tpm.IAKAttributes()
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrTPMIAKUnavailable, Cause: err}
	}

	pub, err := b.tpm.IAK()
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrTPMIAKUnavailable, Cause: err}
	}

	algorithm, err := coseAlgorithmFromSignatureAlgorithm(iakAttrs.SignatureAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	publicKeyCOSE, err := EncodeCOSEPublicKey(pub, algorithm)
	if err != nil {
		return nil, nil, err
	}

	return &attestationKeyHandle{algorithm: algorithm, backend: b.Type()}, publicKeyCOSE, nil
}

// AttestationCertificateChain returns the provisioned IAK certificate. §8.3.1
// requires the "tpm" format's x5c[0] to be the AIK certificate; TCG device
// identity certificates are issued singly, with the root trusted out of band,
// so there is no intermediate chain to append.
func (b *TPM2AttestingBackend) AttestationCertificateChain() ([]*x509.Certificate, error) {
	cert, err := b.tpm.IAKCertificate()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrNoAttestationCertificate, Cause: err}
	}
	return []*x509.Certificate{cert}, nil
}

// GetAttestationStatement builds a WebAuthn Level 2 §8.3 "tpm" attestation
// statement for the credential authData describes, by certifying that
// credential's key with TPM2_Certify under the device's IAK.
//
// The credential's identity is read out of authData itself -- the credential
// ID and the COSE algorithm of the key MakeCredential just generated -- rather
// than threaded through a wider interface change, because authData already
// carries everything needed to resolve the same KeyAttributes GenerateKey and
// Sign use.
func (b *TPM2AttestingBackend) GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error) {
	if format != AttestationFormatTPM {
		return nil, ErrAttestationNotSupported
	}
	if b.tpm == nil {
		return nil, ErrNoAttestationKey
	}

	credentialID, algorithm, err := credentialFromAuthData(authData)
	if err != nil {
		return nil, err
	}

	credAttrs, err := b.lookupCredentialAttrs(credentialID, algorithm)
	if err != nil {
		return nil, err
	}

	// The credential key was created by BackendAdapter.GenerateCredentialKey
	// through the SDK's TPM2 backend, which parents every key it creates off
	// the Platform SRK, never the Shared SRK (pkg/backend/tpm2.resolveSRKAttributes).
	// TPM2_Certify must load the credential key blob under the same parent it
	// was wrapped with, or the TPM rejects the blob's integrity check.
	srkAttrs, err := b.tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTPMCertifyFailed, Cause: err}
	}
	credAttrs.Parent = srkAttrs
	credAttrs.TPMAttributes = &xkms.TPMAttributes{Hierarchy: xkms.TPMRHOwner}

	iakAttrs, err := b.tpm.IAKAttributes()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTPMIAKUnavailable, Cause: err}
	}

	hash, err := hashForSignatureAlgorithm(iakAttrs.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	coseAlg, err := coseAlgorithmFromSignatureAlgorithm(iakAttrs.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// WebAuthn L2 §8.3: extraData is set to the hash of attToBeSigned
	// (authData ‖ clientDataHash) using the hash algorithm employed in "alg".
	attToBeSigned := make([]byte, 0, len(authData)+len(clientDataHash))
	attToBeSigned = append(attToBeSigned, authData...)
	attToBeSigned = append(attToBeSigned, clientDataHash...)
	h := hash.New()
	h.Write(attToBeSigned)
	extraData := h.Sum(nil)

	result, err := b.tpm.CertifyKey(credAttrs, extraData, b.blobs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTPMCertifyFailed, Cause: err}
	}

	chain, err := b.AttestationCertificateChain()
	if err != nil {
		return nil, err
	}

	return &FIDO2AttestationStatement{
		Format:    AttestationFormatTPM,
		Algorithm: coseAlg,
		// §8.3 "sig" is the ordinary signature value for the AIK's algorithm
		// (ASN.1 DER for ECDSA, the raw big-endian value for RSA), the same
		// convention x509.Certificate.CheckSignature and every other WebAuthn
		// format use -- not the marshalled TPMT_SIGNATURE. Result.Signature is
		// already decoded to that form.
		Signature:        result.Signature,
		CertificateChain: chain,
		Ver:              tpmAttestationVersion,
		CertInfo:         result.CertifyInfo,
		PubArea:          result.AttestedKeyPublicArea,
	}, nil
}

// credentialFromAuthData extracts the credential ID and COSE algorithm from
// authenticator data that carries attested credential data, per WebAuthn L2
// §6.5.1: a 32-byte rpIdHash, 1 flags byte, a 4-byte signCount, a 16-byte
// AAGUID, a 2-byte big-endian credential ID length, the credential ID and the
// credential public key as a single canonical COSE_Key CBOR map.
func credentialFromAuthData(authData []byte) (credentialID []byte, algorithm int, err error) {
	aaguidEnd := authDataAAGUIDOffset + aaguidSize
	if len(authData) < aaguidEnd+2 {
		return nil, 0, ErrAttestationAuthDataInvalid
	}
	if authData[32]&authDataFlagAttestedCredentialData == 0 {
		return nil, 0, ErrAttestationAuthDataInvalid
	}

	credIDLen := int(authData[aaguidEnd])<<8 | int(authData[aaguidEnd+1])
	credIDStart := aaguidEnd + 2
	credIDEnd := credIDStart + credIDLen
	if credIDLen == 0 || len(authData) < credIDEnd {
		return nil, 0, ErrAttestationAuthDataInvalid
	}

	var coseKey map[int]interface{}
	dec := cbor.NewDecoder(bytes.NewReader(authData[credIDEnd:]))
	if decErr := dec.Decode(&coseKey); decErr != nil {
		return nil, 0, &SentinelCauseError{Sentinel: ErrAttestationAuthDataInvalid, Cause: decErr}
	}

	algorithm, err = coseAlgorithmFromCBORValue(coseKey[3])
	if err != nil {
		return nil, 0, err
	}

	id := make([]byte, credIDLen)
	copy(id, authData[credIDStart:credIDEnd])

	return id, algorithm, nil
}

// coseAlgorithmFromCBORValue converts a decoded COSE_Key "alg" label value to
// an int. fxamacker/cbor decodes CBOR integers into int64 or uint64 depending
// on sign when the target is interface{}, so both are accepted.
func coseAlgorithmFromCBORValue(v interface{}) (int, error) {
	switch n := v.(type) {
	case int64:
		return int(n), nil
	case uint64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, ErrAttestationAuthDataInvalid
	}
}

// coseAlgorithmFromSignatureAlgorithm maps an x509 signature algorithm -- as
// carried on IAK KeyAttributes -- to its COSE algorithm identifier. An IAK is
// restricted to ECDSA, RSASSA-PKCS1-v1_5 or RSASSA-PSS with SHA-2, per the TCG
// IDevID/IAK key templates this library creates.
func coseAlgorithmFromSignatureAlgorithm(sigAlg x509.SignatureAlgorithm) (int, error) {
	switch sigAlg {
	case x509.ECDSAWithSHA256:
		return COSEAlgES256, nil
	case x509.ECDSAWithSHA384:
		return COSEAlgES384, nil
	case x509.ECDSAWithSHA512:
		return COSEAlgES512, nil
	case x509.SHA256WithRSA:
		return COSEAlgRS256, nil
	case x509.SHA384WithRSA:
		return COSEAlgRS384, nil
	case x509.SHA512WithRSA:
		return COSEAlgRS512, nil
	case x509.SHA256WithRSAPSS:
		return COSEAlgPS256, nil
	case x509.SHA384WithRSAPSS:
		return COSEAlgPS384, nil
	case x509.SHA512WithRSAPSS:
		return COSEAlgPS512, nil
	default:
		return 0, ErrUnsupportedAttestationKey
	}
}

// hashForSignatureAlgorithm returns the digest algorithm an x509 signature
// algorithm signs with.
func hashForSignatureAlgorithm(sigAlg x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch sigAlg {
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedAttestationKey
	}
}
