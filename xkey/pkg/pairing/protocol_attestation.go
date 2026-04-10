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

package pairing

// TPM2 Attestation Enrollment Protocol
//
// This file defines protocol types for TCG-CSR-IDEVID enrollment, which enables
// a device with a TPM2 to enroll with a Certificate Authority and obtain an
// IDevID (Initial Device Identifier) certificate.
//
// The enrollment flow follows the TCG (Trusted Computing Group) specification:
//
//  1. Device generates TCG-CSR-IDEVID containing:
//     - TPM2 public Endorsement Key (EK) certificate
//     - Initial Attestation Key (IAK) public key
//     - Initial Device Identity Key (IDevID) public key
//     - Platform identity information
//
//  2. CA verifies the EK certificate against known TPM manufacturer roots
//
//  3. CA performs credential activation challenge:
//     - Creates a secret encrypted to the EK
//     - Device must prove possession of EK by decrypting with TPM2_ActivateCredential
//
//  4. CA may request attestation quote:
//     - Device provides TPM2 quote over specified PCRs
//     - Quote is signed by the IAK
//     - CA verifies platform integrity state
//
//  5. CA issues IAK and IDevID certificates:
//     - IAK certificate: Used for future attestation operations
//     - IDevID certificate: Permanent device identity
//
// Protocol Direction:
//   - These are local.* methods: Laptop sends TO phone
//   - Phone executes TPM2 operations and returns results
//
// Reference: TCG TPM 2.0 Keys for Device Identity and Attestation

// Attestation enrollment method names.
// These methods support TCG-CSR-IDEVID enrollment for obtaining
// device identity certificates from a Certificate Authority.
const (
	// MethodLocalGetTCGCSRIDevID requests the TCG-CSR-IDEVID enrollment package.
	// The CSR contains the EK certificate, IAK public key, and device identity
	// information needed for CA enrollment.
	MethodLocalGetTCGCSRIDevID = "local.getTCGCSRIDevID"

	// MethodLocalActivateCredential performs TPM2_ActivateCredential.
	// This proves possession of the Endorsement Key by decrypting a secret
	// that was encrypted by the CA using the EK's public key.
	MethodLocalActivateCredential = "local.activateCredential"

	// MethodLocalGetAttestationQuote requests a TPM2 attestation quote.
	// The quote provides signed evidence of the platform's PCR state,
	// allowing the CA to verify platform integrity before issuing certificates.
	MethodLocalGetAttestationQuote = "local.getAttestationQuote"

	// MethodLocalGetIAKPublicKey retrieves the Initial Attestation Key's public key.
	// The CA uses this to verify quote signatures during enrollment.
	MethodLocalGetIAKPublicKey = "local.getIAKPublicKey"

	// MethodLocalStoreEnrollmentCerts stores the certificates issued by the CA.
	// After successful enrollment, the CA provides IAK and IDevID certificates
	// that must be stored on the device for future attestation operations.
	MethodLocalStoreEnrollmentCerts = "local.storeEnrollmentCerts"
)

// LocalGetTCGCSRIDevIDResult contains the result of local.getTCGCSRIDevID.
// This method takes no parameters - it retrieves the device's current
// enrollment package.
//
// The CSR is a TCG-defined structure containing:
//   - TPMT_PUBLIC for the IDevID key
//   - TPMT_PUBLIC for the IAK key
//   - TPM2B_ATTEST containing certifyInfo
//   - TPMT_SIGNATURE over the certifyInfo
//   - Platform manufacturer information
type LocalGetTCGCSRIDevIDResult struct {
	// CSR is the packed TCG-CSR-IDEVID structure as defined by TCG.
	// This is a DER-encoded ASN.1 structure ready for submission to a CA.
	CSR []byte `json:"csr"`

	// EKCert is the Endorsement Key certificate in DER format.
	// The CA uses this to verify the TPM is from a trusted manufacturer.
	// May be nil if no EK certificate is provisioned.
	EKCert []byte `json:"ekCert,omitempty"`

	// IAKPublicKey is the Initial Attestation Key's public portion.
	// Encoded as TPMT_PUBLIC in TPM2B format for direct use by the CA.
	IAKPublicKey []byte `json:"iakPublicKey"`

	// IDevIDPublicKey is the Initial Device Identity Key's public portion.
	// Encoded as TPMT_PUBLIC in TPM2B format.
	IDevIDPublicKey []byte `json:"idevidPublicKey"`

	// PlatformSerial is the device's platform serial number, if available.
	PlatformSerial string `json:"platformSerial,omitempty"`

	// PlatformModel is the device's platform model identifier, if available.
	PlatformModel string `json:"platformModel,omitempty"`

	// FirmwareVersion is the TPM firmware version string.
	FirmwareVersion string `json:"firmwareVersion,omitempty"`
}

// LocalActivateCredentialParams contains parameters for local.activateCredential.
// The CA creates these values by encrypting a secret to the device's EK.
type LocalActivateCredentialParams struct {
	// CredentialBlob is the TPM2B_ID_OBJECT containing the encrypted credential.
	// Created by the CA using TPM2_MakeCredential with the EK's public key.
	// Contains the wrapped secret and integrity HMAC.
	CredentialBlob []byte `json:"credentialBlob"`

	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET.
	// Contains the seed value encrypted under the EK's public key.
	// The TPM uses this with the EK's private portion to unwrap the credential.
	EncryptedSecret []byte `json:"encryptedSecret"`
}

// LocalActivateCredentialResult contains the result of local.activateCredential.
// Success proves the device possesses the private portion of the EK,
// authenticating it as a genuine TPM from the claimed manufacturer.
type LocalActivateCredentialResult struct {
	// DecryptedSecret is the secret value recovered from the credential.
	// The CA compares this against the original secret it encrypted
	// to verify successful activation.
	DecryptedSecret []byte `json:"decryptedSecret"`
}

// LocalGetAttestationQuoteParams contains parameters for local.getAttestationQuote.
// The CA specifies which PCRs to include and provides a fresh nonce
// to prevent replay attacks.
type LocalGetAttestationQuoteParams struct {
	// Nonce is a fresh random value (typically 32 bytes) from the CA.
	// Included in the quote to prove freshness and prevent replay.
	Nonce []byte `json:"nonce"`

	// PCRIndices specifies which PCR registers to include in the quote.
	// Common selections:
	//   - [0,1,2,3,4,5,6,7] for SRTM (Static Root of Trust for Measurement)
	//   - [0,1,2,3,4,5,6,7,8,9] for full boot chain
	//   - [17,18,19,20,21,22] for DRTM (Dynamic Root of Trust)
	PCRIndices []int `json:"pcrIndices"`

	// PCRBank specifies the hash algorithm for PCR values.
	// Supported: "sha256" (default), "sha384", "sha512", "sha1" (deprecated).
	PCRBank string `json:"pcrBank,omitempty"`
}

// LocalGetAttestationQuoteResult contains the result of local.getAttestationQuote.
// The quote provides cryptographic evidence of the platform's state.
type LocalGetAttestationQuoteResult struct {
	// Quoted is the TPMS_ATTEST structure containing the quote information.
	// Includes the nonce, PCR selection, and PCR digest.
	// Serialized in TPM2B_ATTEST format.
	Quoted []byte `json:"quoted"`

	// Signature is the TPMT_SIGNATURE over the quoted data.
	// Signed by the IAK, allowing the CA to verify authenticity.
	// The signature algorithm matches the IAK's key type (RSA-PSS or ECDSA).
	Signature []byte `json:"signature"`

	// PCRValues contains the actual PCR values for the requested indices.
	// Map keys are PCR indices, values are the hash digests.
	// The CA verifies these match expected "known good" values.
	PCRValues map[int][]byte `json:"pcrValues"`

	// EventLog is the TCG event log (optional).
	// Contains the measurement events that led to the current PCR state.
	// Allows the CA to understand why PCRs have their current values.
	// May be nil if event log retrieval is not supported or not requested.
	EventLog []byte `json:"eventLog,omitempty"`

	// PCRBank indicates which hash algorithm was used for PCR values.
	PCRBank string `json:"pcrBank"`
}

// LocalGetIAKPublicKeyResult contains the result of local.getIAKPublicKey.
// This method takes no parameters.
type LocalGetIAKPublicKeyResult struct {
	// PublicKey is the IAK's public key.
	// Format depends on the Algorithm field:
	//   - "RSA2048", "RSA3072": PKCS#1 RSAPublicKey DER
	//   - "ECCP256", "ECCP384": SEC1 uncompressed point
	// Wrapped in TPM2B_PUBLIC for TPM-native consumers.
	PublicKey []byte `json:"publicKey"`

	// Algorithm identifies the key algorithm and parameters.
	// Values: "RSA2048", "RSA3072", "ECCP256", "ECCP384".
	Algorithm string `json:"algorithm"`

	// PublicKeyDER is the public key in standard DER encoding.
	// SubjectPublicKeyInfo format for interoperability with non-TPM tools.
	PublicKeyDER []byte `json:"publicKeyDer,omitempty"`

	// Name is the TPM2B_NAME of the IAK.
	// The cryptographic name uniquely identifies this key.
	// Used for binding operations and verification.
	Name []byte `json:"name,omitempty"`
}

// LocalStoreEnrollmentCertsParams contains parameters for local.storeEnrollmentCerts.
// The CA calls this after successful enrollment to provision the device
// with its identity certificates.
type LocalStoreEnrollmentCertsParams struct {
	// IAKCert is the X.509 certificate for the Initial Attestation Key.
	// DER-encoded. Used to sign future attestation quotes.
	// The CA issues this after verifying the device's identity.
	IAKCert []byte `json:"iakCert"`

	// IDevIDCert is the X.509 certificate for the Initial Device Identity Key.
	// DER-encoded. Provides the device's permanent cryptographic identity.
	// Valid for the lifetime of the device.
	IDevIDCert []byte `json:"idevidCert"`

	// Chain contains intermediate CA certificates.
	// DER-encoded X.509 certificates in order from issuer to root.
	// Allows the device to present a complete certificate chain.
	Chain [][]byte `json:"chain,omitempty"`
}

// LocalStoreEnrollmentCertsResult contains the result of local.storeEnrollmentCerts.
type LocalStoreEnrollmentCertsResult struct {
	// Stored indicates whether the certificates were successfully stored.
	Stored bool `json:"stored"`

	// IAKCertFingerprint is the SHA-256 fingerprint of the stored IAK certificate.
	// Hex-encoded for verification purposes.
	IAKCertFingerprint string `json:"iakCertFingerprint,omitempty"`

	// IDevIDCertFingerprint is the SHA-256 fingerprint of the stored IDevID certificate.
	// Hex-encoded for verification purposes.
	IDevIDCertFingerprint string `json:"idevidCertFingerprint,omitempty"`
}

// attestationMethodNames contains all valid attestation method names for validation.
var attestationMethodNames = map[string]bool{
	MethodLocalGetTCGCSRIDevID:      true,
	MethodLocalActivateCredential:   true,
	MethodLocalGetAttestationQuote:  true,
	MethodLocalGetIAKPublicKey:      true,
	MethodLocalStoreEnrollmentCerts: true,
}

// IsAttestationMethod returns true if the method name is a valid attestation enrollment method.
func IsAttestationMethod(method string) bool {
	return attestationMethodNames[method]
}
