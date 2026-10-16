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

package client

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// maxTPMQualifyingData is the largest qualifyingData buffer the TPM will
// accept for TPM2_Certify. TPM2B_DATA is bounded by MAX_DIGEST_BUFFER
// (typically 64 bytes on real hardware). ACME HTTP-01 keyAuth is
// `<token>.<base64url(sha256(jwk))>` which is ~66 bytes and overflows
// the TPM, producing TPM_RC_SIZE. Hash anything larger to SHA-256 (32
// bytes) before handing it to the TPM. The CA does not inspect the
// qualifyingData bytes during verification (see
// ca.VerifyTCG_CSR_IDevIDBytes), so the hash is transparent to both
// sides.
const maxTPMQualifyingData = 64

// TPM-related error types
var (
	// ErrTPMNotConfigured indicates that the TPM module was not configured
	// in the ACME client but TPM operations were attempted
	ErrTPMNotConfigured = errors.New("acme-client: TPM module not configured")

	// ErrEKNotFound indicates that the Endorsement Key certificate could not
	// be found in the TPM or was not provisioned
	ErrEKNotFound = errors.New("acme-client: EK certificate not found")

	// ErrIAKNotFound indicates that the Initial Attestation Key could not
	// be found or has not been created
	ErrIAKNotFound = errors.New("acme-client: IAK not found")

	// ErrCredentialActivation indicates that the TPM2_ActivateCredential
	// operation failed, possibly due to incorrect credential blobs or
	// key authorization issues
	ErrCredentialActivation = errors.New("acme-client: credential activation failed")

	// ErrAttestedKeyNameRequired indicates a device-attest-01 certificate key
	// was requested without a name. The key is the device's key for that
	// name, so without one there is no key to create or certify.
	ErrAttestedKeyNameRequired = errors.New("acme-client: the device-attest-01 certificate key needs a name")

	// ErrKeyBackendNotConfigured indicates a TPM key was to be created or
	// loaded by an adapter given no store for TPM key blobs.
	ErrKeyBackendNotConfigured = errors.New("acme-client: no TPM key store configured")

	// ErrDeviceIdentityFailed indicates the device's identity could not be
	// read from its IAK certificate.
	ErrDeviceIdentityFailed = errors.New("acme-client: the device identity cannot be read")

	// ErrAttestedKeyFailed indicates the device-attest-01 certificate key
	// could not be created, loaded or certified.
	ErrAttestedKeyFailed = errors.New("acme-client: device-attest-01 certificate key attestation failed")

	// ErrIDevIDCreation indicates that creating an IDevID failed
	ErrIDevIDCreation = errors.New("acme-client: IDevID creation failed")
)

// TPMModule defines the interface for TPM operations.
// This allows integration with go-xkms's TPM2 module for hardware-backed
// cryptographic operations and attestation workflows.
//
// The TPM module provides secure key storage, credential activation, and
// attestation capabilities required for the ACME enroll-01 challenge type
// as specified in the TCG specifications.
//
// This interface is designed to be compatible with the challenge packages:
// - pkg/acme/challenges/enroll-01
// - pkg/acme/challenges/endorse-01
// - pkg/acme/challenges/device-attest-01
type TPMModule interface {
	// EK returns the Endorsement Key public key.
	// This is the raw public key without requiring an EK certificate.
	// Used for endorse-01 challenge where no manufacturer EK certificate exists.
	//
	// Returns:
	//   - The EK public key
	EK() crypto.PublicKey

	// EKCertificate returns the Endorsement Key (EK) certificate.
	// The EK certificate is a credential issued by the TPM manufacturer
	// that certifies the authenticity of the TPM.
	//
	// Returns:
	//   - The EK certificate if found
	//   - ErrEKNotFound if no EK certificate is provisioned
	//   - Any other error that occurred during retrieval
	EKCertificate() (*x509.Certificate, error)

	// EKAttributes returns the Endorsement Key attributes including
	// the key ID, algorithm, and public key material.
	//
	// Returns:
	//   - KeyAttributes containing EK metadata
	//   - ErrEKNotFound if the EK is not available
	//   - Any other error that occurred during retrieval
	EKAttributes() (*KeyAttributes, error)

	// TPMManufacturer returns the TCG TPM manufacturer code the TPM reports
	// in TPM_PT_MANUFACTURER, in the form tcg-at-tpmManufacturer carries it,
	// e.g. "id:49465800". endorse-01 asks the CA to record it in the EK
	// certificate, because a later IDevID enrollment names the TPM by it
	// (TCG DevID v1 r12 §8.1).
	//
	// Returns:
	//   - The manufacturer code
	//   - An error if the TPM's fixed properties cannot be read
	TPMManufacturer() (string, error)

	// IAKAttributes returns the Initial Attestation Key (IAK) attributes.
	// The IAK is used to sign attestation data and create IDevID credentials.
	//
	// Returns:
	//   - KeyAttributes containing IAK metadata
	//   - ErrIAKNotFound if the IAK is not available
	//   - Any other error that occurred during retrieval
	IAKAttributes() (*KeyAttributes, error)

	// CreateIDevID creates an Initial Device Identifier (IDevID) certificate
	// signing request from the IAK. The IDevID is the device's initial identity
	// credential as specified in IEEE 802.1AR.
	//
	// Parameters:
	//   - qualifyingData: Nonce or challenge data to bind to the CSR
	//
	// Returns:
	//   - IDevIDCSR containing the CSR and supporting attestation data
	//   - ErrIAKNotFound if the IAK is not available
	//   - Any other error that occurred during CSR creation
	CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error)

	// ActivateCredential performs TPM2_ActivateCredential operation.
	// This is used in the credential activation protocol where the ACME server
	// encrypts a secret to the TPM's EK, and the TPM must prove possession
	// of both the EK and IAK to decrypt it.
	//
	// Parameters:
	//   - credentialBlob: The encrypted credential blob
	//   - encryptedSecret: The encrypted secret wrapped to the EK
	//
	// Returns:
	//   - The decrypted secret
	//   - ErrCredentialActivation if activation fails
	//   - Any other error that occurred during activation
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)

	// ProvisionEKCert provisions an EK certificate in the TPM's NVRAM.
	// This is typically done when the TPM does not have a manufacturer-issued
	// EK certificate, or when using a test/development EK certificate.
	//
	// Parameters:
	//   - certDER: DER-encoded X.509 certificate
	//
	// Returns:
	//   - Error if provisioning fails, nil on success
	ProvisionEKCert(certDER []byte) error

	// ProvisionIAKCert installs the IAK certificate enroll-01 issues, so a
	// later device-attest-01 challenge can read it back for its statement's
	// x5c[0] (deviceattest01.Setup). Without this, a device that enrolls and
	// later attests in a separate process -- the common case for real
	// hardware -- has no certificate to answer with, even though enrollment
	// succeeded.
	//
	// Parameters:
	//   - cert: the IAK certificate issued during enrollment
	//
	// Returns:
	//   - Error if provisioning fails, nil on success
	ProvisionIAKCert(cert *x509.Certificate) error

	// DeviceIdentity returns the identity this device attests under: the RFC
	// 4043 permanentIdentifier of its IAK certificate. A device-attest-01
	// order names it as its permanent-identifier, because the server refuses
	// a challenge whose attested identity is not the order's identifier.
	//
	// Returns:
	//   - The device identity
	//   - deviceattest01.ErrDeviceIdentityUnavailable if the IAK certificate
	//     carries no permanentIdentifier
	//   - Any other error that occurred reading the IAK certificate
	DeviceIdentity() (string, error)

	// CreateAttestedKey answers a device-attest-01 challenge for the
	// certificate key called name: a signing key in the TPM under the
	// Platform SRK, created on first use and reused after. The IAK certifies
	// it with TPM2_Certify over the key authorization, and the returned
	// Signer is the key the CSR must be signed with.
	//
	// Parameters:
	//   - name: The certificate key's name
	//   - keyAuth: The ACME key authorization the challenge answers
	//
	// Returns:
	//   - AttestedKey holding the challenge response and the key's Signer
	//   - ErrAttestedKeyNameRequired if name is empty
	//   - Any other error that occurred creating or certifying the key
	CreateAttestedKey(name, keyAuth string) (*AttestedKey, error)

	// Close releases TPM resources
	Close() error
}

// KeyAttributes represents cryptographic key metadata and material.
// This structure provides a uniform representation of key attributes
// regardless of the underlying key storage mechanism.
type KeyAttributes struct {
	// KeyID is the unique identifier for the key
	KeyID string

	// Algorithm specifies the cryptographic algorithm (e.g., "RSA-2048", "ECDSA-P256")
	Algorithm string

	// PublicKey is the public key material
	PublicKey crypto.PublicKey

	// Certificate is the X.509 certificate for this key, if available
	Certificate *x509.Certificate

	// SignatureAlgorithm specifies the signature algorithm to use
	SignatureAlgorithm x509.SignatureAlgorithm

	// Hash specifies the hash algorithm to use
	Hash crypto.Hash

	// KeyType specifies the purpose of the key (attestation, endorsement, etc.)
	KeyType string

	// TPMHandle is the TPM handle for TPM-backed keys (if applicable)
	TPMHandle uint32

	// TPMPublicBytes contains the encoded TPM public key structure
	TPMPublicBytes []byte
}

// IDevIDCSR represents an Initial Device Identifier certificate signing request
// and its associated attestation data. This structure encapsulates all the
// information needed for the ACME server to validate device identity and
// issue an IDevID certificate.
type IDevIDCSR struct {
	// CSR is the DER-encoded PKCS#10 certificate signing request or
	// packed TCG-CSR-IDEVID structure
	CSR []byte

	// IAKPublic is the TPM public key structure for the IAK
	// This is typically a TPM2B_PUBLIC structure serialized as bytes
	IAKPublic []byte

	// EKCert is the Endorsement Key certificate that vouches for
	// the authenticity of the TPM hardware
	EKCert *x509.Certificate

	// QualifyingData is the nonce or challenge data that was bound
	// to this CSR to provide freshness guarantees
	QualifyingData []byte

	// IDevIDPublic is the TPM public key structure for the IDevID
	IDevIDPublic []byte

	// SignatureAlgorithm used to sign the CSR
	SignatureAlgorithm x509.SignatureAlgorithm

	// CertifyInfo contains attestation information from TPM2_Certify
	CertifyInfo []byte

	// Signature is the signature over the CertifyInfo
	Signature []byte
}

// AttestedKey is a device-attest-01 certificate key and the challenge
// response that attests it.
type AttestedKey struct {
	// Statement is the payload the client POSTs to the challenge URL
	// (draft-ietf-acme-device-attest-10): the JSON {"attObj": base64url(CBOR)}
	// whose attestation object is a WebAuthn "tpm" statement certifying the
	// key.
	Statement []byte

	// Signer is the attested key. The CSR at finalization must be signed by
	// it: the server refuses a CSR for any key other than the one the
	// statement certifies.
	Signer crypto.Signer

	// Format is the attestation format of Statement. It decides the CSR:
	// a FormatDICE device proves possession with the possession request
	// over the challenge it answered (deviceattest01.SignPossessionCSR),
	// and every other format sends an ordinary request naming the device.
	Format deviceattest01.AttestationFormat
}

// XKMSTPMAdapter adapts go-xkms's TrustedPlatformModule to our TPMModule interface.
// This adapter bridges the ACME client's TPM requirements with go-xkms's comprehensive
// TPM2 implementation, ensuring all algorithms are configurable via go-xkms's types.
type XKMSTPMAdapter struct {
	tpm xkmssdk.TrustedPlatformModule

	// keys stores the blobs of the TPM keys this adapter creates.
	keys xkmssdk.TPMKeyBackend

	// Cached attributes to avoid repeated lookups
	ekAttrs     *xkmssdk.KeyAttributes
	iakAttrs    *xkmssdk.KeyAttributes
	idevidAttrs *xkmssdk.KeyAttributes
	ekCert      *x509.Certificate
}

// NewXKMSTPMAdapter creates a new adapter wrapping a go-xkms TPM module.
// The TPM module should already be initialized and provisioned. keys stores
// the blobs of the keys the adapter creates under the Platform SRK -- the
// device-attest-01 certificate key -- and is where they are found again.
func NewXKMSTPMAdapter(tpm xkmssdk.TrustedPlatformModule, keys xkmssdk.TPMKeyBackend) *XKMSTPMAdapter {
	return &XKMSTPMAdapter{
		tpm:  tpm,
		keys: keys,
	}
}

// EK returns the Endorsement Key public key
func (a *XKMSTPMAdapter) EK() crypto.PublicKey {
	pubKey, err := a.tpm.EK()
	if err != nil {
		return nil
	}
	return pubKey
}

// EKCertificate returns the Endorsement Key certificate
func (a *XKMSTPMAdapter) EKCertificate() (*x509.Certificate, error) {
	if a.ekCert != nil {
		return a.ekCert, nil
	}

	cert, err := a.tpm.EKCertificate()
	if err != nil {
		return nil, caerrors.NotFoundError("EK certificate not found: %v", err)
	}
	a.ekCert = cert
	return cert, nil
}

// EKAttributes returns the Endorsement Key attributes
func (a *XKMSTPMAdapter) EKAttributes() (*KeyAttributes, error) {
	if a.ekAttrs != nil {
		return convertKeyAttributes(a.ekAttrs), nil
	}

	attrs, err := a.tpm.EKAttributes()
	if err != nil {
		return nil, caerrors.NotFoundError("EK attributes not found: %v", err)
	}
	a.ekAttrs = attrs
	return convertKeyAttributes(attrs), nil
}

// TPMManufacturer returns the TCG TPM manufacturer code from the TPM's fixed
// properties.
func (a *XKMSTPMAdapter) TPMManufacturer() (string, error) {
	props, err := a.tpm.FixedProperties()
	if err != nil {
		return "", caerrors.NotFoundError("TPM manufacturer not available: %v", err)
	}
	if props.ManufacturerCode == "" {
		return "", caerrors.NotFoundError("TPM manufacturer not available: the TPM reported no manufacturer code")
	}
	return props.ManufacturerCode, nil
}

// IAKAttributes returns the Initial Attestation Key attributes
func (a *XKMSTPMAdapter) IAKAttributes() (*KeyAttributes, error) {
	if a.iakAttrs != nil {
		return convertKeyAttributes(a.iakAttrs), nil
	}

	attrs, err := a.tpm.IAKAttributes()
	if err != nil {
		return nil, caerrors.NotFoundError("IAK not found: %v", err)
	}
	a.iakAttrs = attrs
	return convertKeyAttributes(attrs), nil
}

// CreateIDevID creates an Initial Device Identifier and returns the TCG-CSR-IDEVID
func (a *XKMSTPMAdapter) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	// Get IAK attributes if not cached
	if a.iakAttrs == nil {
		attrs, err := a.tpm.IAKAttributes()
		if err != nil {
			return nil, caerrors.NotFoundError("IDevID creation failed: failed to get IAK: %v", err)
		}
		a.iakAttrs = attrs
	}

	// Get EK certificate if not cached
	if a.ekCert == nil {
		cert, err := a.tpm.EKCertificate()
		if err != nil {
			return nil, caerrors.NotFoundError("IDevID creation failed: failed to get EK certificate: %v", err)
		}
		a.ekCert = cert
	}

	// ACME HTTP-01 keyAuth is ~66 bytes — longer than the TPM's TPM2B_DATA
	// MAX_DIGEST_BUFFER. Hash to SHA-256 (32 bytes) so TPM2_Certify's
	// qualifyingData fits; the server doesn't validate the raw bytes.
	tpmQualifyingData := qualifyingData
	if len(tpmQualifyingData) > maxTPMQualifyingData {
		h := sha256.Sum256(tpmQualifyingData)
		tpmQualifyingData = h[:]
	}

	// Create the IDevID via go-xkms
	idevidAttrs, tcgCSR, err := a.tpm.CreateIDevID(a.iakAttrs, a.ekCert, tpmQualifyingData)
	if err != nil {
		return nil, caerrors.InternalServerError("IDevID creation failed: %v", err)
	}
	a.idevidAttrs = idevidAttrs

	// Pack the TCG-CSR-IDEVID for transmission
	packedCSR, err := xkmssdk.PackIDevIDCSR(tcgCSR)
	if err != nil {
		return nil, caerrors.InternalServerError("IDevID creation failed: failed to pack TCG-CSR: %v", err)
	}

	// Extract signature algorithm from IAK attributes
	sigAlgo := x509.UnknownSignatureAlgorithm
	if a.iakAttrs != nil {
		sigAlgo = a.iakAttrs.SignatureAlgorithm
	}

	// Build the IDevIDCSR result
	result := &IDevIDCSR{
		CSR:                packedCSR,
		EKCert:             a.ekCert,
		QualifyingData:     qualifyingData,
		SignatureAlgorithm: sigAlgo,
	}

	// Include IAK public key bytes if available
	if a.iakAttrs != nil && a.iakAttrs.TPMAttributes != nil {
		result.IAKPublic = a.iakAttrs.TPMAttributes.PublicKeyBytes
		if len(a.iakAttrs.TPMAttributes.CertifyInfo) > 0 {
			result.CertifyInfo = a.iakAttrs.TPMAttributes.CertifyInfo
		}
		if len(a.iakAttrs.TPMAttributes.Signature) > 0 {
			result.Signature = a.iakAttrs.TPMAttributes.Signature
		}
	}

	// Include IDevID public key bytes if available
	if idevidAttrs != nil && idevidAttrs.TPMAttributes != nil {
		result.IDevIDPublic = idevidAttrs.TPMAttributes.PublicKeyBytes
	}

	return result, nil
}

// ActivateCredential performs TPM2_ActivateCredential
func (a *XKMSTPMAdapter) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	secret, err := a.tpm.ActivateCredential(credentialBlob, encryptedSecret)
	if err != nil {
		return nil, caerrors.InternalServerError("credential activation failed: %v", err)
	}
	return secret, nil
}

// ProvisionEKCert provisions an EK certificate
func (a *XKMSTPMAdapter) ProvisionEKCert(certDER []byte) error {
	// Pass nil for hierarchy auth - go-xkms handles this internally
	if err := a.tpm.ProvisionEKCert(nil, certDER); err != nil {
		return caerrors.StorageFailureError("failed to provision EK certificate: %v", err)
	}

	// Parse and cache the certificate
	cert, err := a.tpm.ParseEKCertificate(certDER)
	if err != nil {
		return caerrors.MalformedError("failed to parse provisioned EK certificate: %v", err)
	}
	a.ekCert = cert

	return nil
}

// ProvisionIAKCert installs the IAK certificate enroll-01 issued, so a later
// device-attest-01 challenge (deviceattest01.Setup, via IAKCertificate) can
// read it back for the statement's x5c[0].
func (a *XKMSTPMAdapter) ProvisionIAKCert(cert *x509.Certificate) error {
	if err := a.tpm.ProvisionIAKCert(cert); err != nil {
		return caerrors.StorageFailureError("failed to provision IAK certificate: %v", err)
	}
	return nil
}

// DeviceIdentity reads the permanentIdentifier of the IAK certificate, the
// same certificate and the same rule the server reads the attested identity
// from (deviceattest01.DeviceIdentityFromCertificate).
func (a *XKMSTPMAdapter) DeviceIdentity() (string, error) {
	cert, err := a.tpm.IAKCertificate()
	if err != nil {
		return "", &errs.Joined{Lead: ErrDeviceIdentityFailed, Detail: "the IAK certificate cannot be read", Cause: err}
	}
	return deviceattest01.DeviceIdentityFromCertificate(deviceattest01.FormatTPM, cert)
}

// CreateAttestedKey creates or loads the certificate key called name under
// the Platform SRK and has the IAK certify it for keyAuth.
//
// The key is a P-256 ECDSA signing key whose blobs live in the adapter's key
// store under name. The first attestation for a name creates it; later ones
// certify the same key again, so a device renewing its certificate keeps the
// key it already uses.
func (a *XKMSTPMAdapter) CreateAttestedKey(name, keyAuth string) (*AttestedKey, error) {
	if name == "" {
		return nil, ErrAttestedKeyNameRequired
	}
	if a.keys == nil {
		return nil, ErrKeyBackendNotConfigured
	}

	backend, err := xkmssdk.NewTPM2BackendWithTPM(&xkmssdk.TPM2BackendExternalConfig{
		TPM:        a.tpm,
		KeyBackend: a.keys,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestedKeyFailed, Detail: "the Platform SRK is unavailable", Cause: err}
	}

	attrs := attestedKeyAttributes(name)
	ctx := context.Background()
	key, err := backend.GetKey(ctx, attrs)
	if errors.Is(err, xkmssdk.ErrBackendKeyNotFound) {
		key, err = backend.GenerateKey(ctx, attrs)
	}
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestedKeyFailed, Detail: name, Cause: err}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Detail{Err: ErrAttestedKeyFailed, Detail: name + " is not a signing key"}
	}

	statement, err := deviceattest01.Setup(keyAuth, a.tpm, attrs, a.keys)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestedKeyFailed, Detail: name, Cause: err}
	}
	return &AttestedKey{Statement: statement, Signer: signer, Format: deviceattest01.FormatTPM}, nil
}

// attestedKeyAttributes describes the device-attest-01 certificate key called
// name. Its parent is left for the TPM2 backend to set: the Platform SRK.
func attestedKeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:                 name,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            xkmssdk.KeyTypeTLS,
		StoreType:          xkmssdk.StoreTPM2,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ECCAttributes:      &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		TPMAttributes:      &xkmssdk.TPMAttributes{Hierarchy: xkmssdk.TPMRHOwner},
	}
}

// Close releases TPM resources
func (a *XKMSTPMAdapter) Close() error {
	return a.tpm.Close()
}

// convertKeyAttributes converts go-xkms KeyAttributes to our KeyAttributes
func convertKeyAttributes(attrs *xkmssdk.KeyAttributes) *KeyAttributes {
	if attrs == nil {
		return nil
	}

	result := &KeyAttributes{
		KeyID:              attrs.CN,
		SignatureAlgorithm: attrs.SignatureAlgorithm,
		Hash:               attrs.Hash,
		KeyType:            attrs.KeyType.String(),
	}

	// Set algorithm string based on key algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil {
			result.Algorithm = fmt.Sprintf("RSA-%d", attrs.RSAAttributes.KeySize)
		} else {
			result.Algorithm = "RSA"
		}
	case x509.ECDSA:
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			result.Algorithm = fmt.Sprintf("ECDSA-%s", attrs.ECCAttributes.Curve.Params().Name)
		} else {
			result.Algorithm = "ECDSA"
		}
	case x509.Ed25519:
		result.Algorithm = "Ed25519"
	default:
		result.Algorithm = attrs.KeyAlgorithm.String()
	}

	// Extract TPM-specific attributes
	if attrs.TPMAttributes != nil {
		result.TPMHandle = uint32(attrs.TPMAttributes.Handle)
		result.TPMPublicBytes = attrs.TPMAttributes.PublicKeyBytes
	}

	return result
}

// SignatureAlgorithmFromCOSE converts COSE algorithm to x509.SignatureAlgorithm
func SignatureAlgorithmFromCOSE(alg COSEAlgorithm) x509.SignatureAlgorithm {
	switch alg {
	case COSEAlgorithmES256:
		return x509.ECDSAWithSHA256
	case COSEAlgorithmES384:
		return x509.ECDSAWithSHA384
	case COSEAlgorithmES512:
		return x509.ECDSAWithSHA512
	case COSEAlgorithmRS256:
		return x509.SHA256WithRSA
	case COSEAlgorithmRS384:
		return x509.SHA384WithRSA
	case COSEAlgorithmRS512:
		return x509.SHA512WithRSA
	case COSEAlgorithmPS256:
		return x509.SHA256WithRSAPSS
	case COSEAlgorithmPS384:
		return x509.SHA384WithRSAPSS
	case COSEAlgorithmPS512:
		return x509.SHA512WithRSAPSS
	case COSEAlgorithmEdDSA:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
