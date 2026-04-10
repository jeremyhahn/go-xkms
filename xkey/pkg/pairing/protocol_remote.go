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

// Remote method names for the phone-to-laptop direction.
// These methods operate on the laptop's xkmsd backends, allowing
// the phone to invoke cryptographic operations on the laptop remotely.
const (
	MethodRemoteListBackends = "remote.listBackends"
	MethodRemoteListKeys     = "remote.listKeys"
	MethodRemoteGetPublicKey = "remote.getPublicKey"
	MethodRemoteSign         = "remote.sign"
	MethodRemoteVerify       = "remote.verify"
	MethodRemoteEncrypt      = "remote.encrypt"
	MethodRemoteDecrypt      = "remote.decrypt"
	MethodRemoteDeriveKey    = "remote.deriveKey"
	MethodRemoteGenerateKey  = "remote.generateKey"
	MethodRemoteGetKeyInfo   = "remote.getKeyInfo"
	MethodRemoteDeleteKey    = "remote.deleteKey"
	MethodRemoteAttestKey    = "remote.attestKey"
	MethodRemoteAttestDevice = "remote.attestDevice"
)

// TCG-CSR-IDEVID enrollment methods for Android CA enrollment.
// These methods allow the phone to request TPM2 operations from the laptop
// for device identity certificate enrollment following the TCG TPM 2.0 Keys
// for Device Identity and Attestation specification.
//
// The enrollment flow consists of three phases:
//
//  1. CSR Generation (remote.getTCGCSRIDevID):
//     The phone requests the laptop to generate a TCG-CSR-IDEVID structure
//     containing the IDevID public key, IAK public key, EK certificate, and
//     platform identification. This is sent to the CA for enrollment.
//
//  2. Credential Activation (remote.activateCredential):
//     The CA uses TPM2_MakeCredential to create an encrypted challenge that
//     can only be decrypted by the TPM possessing the EK private key. The
//     phone forwards this challenge to the laptop, which uses TPM2_ActivateCredential
//     to prove EK possession and return the decrypted secret.
//
//  3. Attestation Quote (remote.getAttestationQuote):
//     After credential activation, the CA may request a TPM2 quote over
//     platform PCRs signed by the IAK to verify platform integrity and
//     binding between the IAK and EK.
//
// Reference: TCG TPM 2.0 Keys for Device Identity and Attestation, Section 6.
const (
	MethodRemoteGetTCGCSRIDevID     = "remote.getTCGCSRIDevID"
	MethodRemoteActivateCredential  = "remote.activateCredential"
	MethodRemoteGetAttestationQuote = "remote.getAttestationQuote"
)

// BackendInfo describes a xkmsd backend available on the laptop.
type BackendInfo struct {
	Name            string `json:"name"`
	Type            string `json:"type"` // "tpm2", "pkcs11", "software", "awskms", etc.
	HardwareBacked  bool   `json:"hardwareBacked"`
	Signing         bool   `json:"signing"`
	Decryption      bool   `json:"decryption"`
	SymmetricCrypto bool   `json:"symmetricCrypto"`
	KeyAgreement    bool   `json:"keyAgreement"`
	Attestation     bool   `json:"attestation"`
}

// RemoteListBackendsResult contains the result of remote.listBackends.
type RemoteListBackendsResult struct {
	Backends []BackendInfo `json:"backends"`
}

// RemoteListKeysParams contains parameters for remote.listKeys.
type RemoteListKeysParams struct {
	Backend   string `json:"backend"`
	Algorithm string `json:"algorithm,omitempty"` // Filter by algorithm
}

// RemoteKeyInfo describes a key on a xkmsd backend.
type RemoteKeyInfo struct {
	KeyID       string `json:"keyId"`
	Backend     string `json:"backend"`
	Algorithm   string `json:"algorithm"`
	KeySizeBits int    `json:"keySizeBits"`
	Label       string `json:"label"`
	CreatedAt   int64  `json:"createdAt"`
}

// RemoteListKeysResult contains the result of remote.listKeys.
type RemoteListKeysResult struct {
	Keys []RemoteKeyInfo `json:"keys"`
}

// RemoteGetPublicKeyParams contains parameters for remote.getPublicKey.
type RemoteGetPublicKeyParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"keyId"`
	Format  string `json:"format"` // "der", "pem"
}

// RemoteGetPublicKeyResult contains the result of remote.getPublicKey.
type RemoteGetPublicKeyResult struct {
	PublicKey []byte `json:"publicKey"`
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
}

// RemoteSignParams contains parameters for remote.sign.
type RemoteSignParams struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"keyId"`
	Data      []byte `json:"data"`
	Algorithm string `json:"algorithm,omitempty"`
}

// RemoteSignResult contains the result of remote.sign.
type RemoteSignResult struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// RemoteVerifyParams contains parameters for remote.verify.
type RemoteVerifyParams struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"keyId"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
}

// RemoteVerifyResult contains the result of remote.verify.
type RemoteVerifyResult struct {
	Valid bool `json:"valid"`
}

// RemoteEncryptParams contains parameters for remote.encrypt.
type RemoteEncryptParams struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"keyId"`
	Plaintext []byte `json:"plaintext"`
	Algorithm string `json:"algorithm,omitempty"`
	AAD       []byte `json:"aad,omitempty"`
}

// RemoteEncryptResult contains the result of remote.encrypt.
type RemoteEncryptResult struct {
	Ciphertext []byte `json:"ciphertext"`
}

// RemoteDecryptParams contains parameters for remote.decrypt.
type RemoteDecryptParams struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
	Algorithm  string `json:"algorithm,omitempty"`
	AAD        []byte `json:"aad,omitempty"`
}

// RemoteDecryptResult contains the result of remote.decrypt.
type RemoteDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// RemoteDeriveKeyParams contains parameters for remote.deriveKey (ECDH).
type RemoteDeriveKeyParams struct {
	Backend       string `json:"backend"`
	KeyID         string `json:"keyId"`
	PeerPublicKey []byte `json:"peerPublicKey"` // DER-encoded peer public key
}

// RemoteDeriveKeyResult contains the result of remote.deriveKey.
type RemoteDeriveKeyResult struct {
	SharedSecret []byte `json:"sharedSecret"`
}

// RemoteGenerateKeyParams contains parameters for remote.generateKey.
type RemoteGenerateKeyParams struct {
	Backend     string `json:"backend"`
	KeyID       string `json:"keyId"`
	Algorithm   string `json:"algorithm"`
	KeySizeBits int    `json:"keySizeBits,omitempty"`
	Label       string `json:"label,omitempty"`
}

// RemoteGenerateKeyResult contains the result of remote.generateKey.
type RemoteGenerateKeyResult struct {
	KeyID       string `json:"keyId"`
	PublicKey   []byte `json:"publicKey,omitempty"` // DER-encoded
	Algorithm   string `json:"algorithm"`
	KeySizeBits int    `json:"keySizeBits"`
	Backend     string `json:"backend"`
}

// RemoteGetKeyInfoParams contains parameters for remote.getKeyInfo.
type RemoteGetKeyInfoParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"keyId"`
}

// RemoteGetKeyInfoResult contains the result of remote.getKeyInfo.
type RemoteGetKeyInfoResult struct {
	RemoteKeyInfo
	HardwareBacked bool `json:"hardwareBacked"`
	Exportable     bool `json:"exportable"`
}

// RemoteDeleteKeyParams contains parameters for remote.deleteKey.
type RemoteDeleteKeyParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"keyId"`
}

// RemoteDeleteKeyResult contains the result of remote.deleteKey.
type RemoteDeleteKeyResult struct {
	Deleted bool `json:"deleted"`
}

// RemoteAttestKeyParams contains parameters for remote.attestKey.
type RemoteAttestKeyParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"keyId"`
	Nonce   []byte `json:"nonce"`
}

// RemoteAttestKeyResult contains the result of remote.attestKey.
type RemoteAttestKeyResult struct {
	Format           string   `json:"format"`           // "tpm2", "pkcs11", etc.
	CertificateChain [][]byte `json:"certificateChain"` // Attestation certificate chain
	AttestationData  []byte   `json:"attestationData"`  // Backend-specific attestation data
	Nonce            []byte   `json:"nonce"`            // Echoed challenge
}

// RemoteAttestDeviceParams contains parameters for remote.attestDevice.
// This requests device-level attestation from the laptop (e.g., TPM2 platform attestation).
type RemoteAttestDeviceParams struct {
	Nonce []byte `json:"nonce"` // 32-byte challenge nonce
}

// RemoteAttestDeviceResult contains the result of remote.attestDevice.
// Provides laptop/desktop device attestation for the phone to verify.
type RemoteAttestDeviceResult struct {
	Format           string   `json:"format"`           // "tpm2", "software", etc.
	CertificateChain [][]byte `json:"certificateChain"` // Attestation certificate chain
	SecurityLevel    string   `json:"securityLevel"`    // "hardware" (TPM), "software"
	Nonce            []byte   `json:"nonce"`            // Echoed challenge
	// Platform attestation fields (TPM2-specific)
	PlatformPCRs    map[int][]byte `json:"platformPcrs,omitempty"`    // PCR values
	QuoteData       []byte         `json:"quoteData,omitempty"`       // TPM2 quote structure
	QuoteSignature  []byte         `json:"quoteSignature,omitempty"`  // Quote signature
	FirmwareVersion string         `json:"firmwareVersion,omitempty"` // TPM firmware version
	// Boot measurement fields
	BootHashHex       string `json:"bootHashHex,omitempty"`       // Platform boot hash (comparable)
	BootStateVerified bool   `json:"bootStateVerified,omitempty"` // True if secure boot verified
}

// RemoteGetTCGCSRIDevIDParams contains parameters for remote.getTCGCSRIDevID.
// This requests generation of a TCG-CSR-IDEVID structure for device identity
// certificate enrollment with a CA.
type RemoteGetTCGCSRIDevIDParams struct {
	// Backend specifies the TPM2 backend to use. Defaults to "tpm2" if empty.
	Backend string `json:"backend,omitempty"`
}

// RemoteGetTCGCSRIDevIDResult contains the result of remote.getTCGCSRIDevID.
// This provides the complete TCG-CSR-IDEVID enrollment package that should be
// sent to a CA for IDevID certificate issuance.
//
// The CSR field contains a packed TCG-CSR-IDEVID structure as defined in
// TCG TPM 2.0 Keys for Device Identity and Attestation, Section 6.2.
// The structure includes:
//   - Version and flags
//   - IDevID CSR Info (PKCS#10 CertificationRequestInfo)
//   - IAK public key (TPMT_PUBLIC)
//   - Platform identity claims
//   - Optional EK certificate or EK public key
type RemoteGetTCGCSRIDevIDResult struct {
	// CSR is the packed TCG-CSR-IDEVID structure ready for CA submission.
	CSR []byte `json:"csr"`

	// EKCert is the Endorsement Key certificate in DER format.
	// May be nil if the EK is not provisioned with a manufacturer certificate.
	// In this case, the CA should use EKPublicKey for credential challenge.
	EKCert []byte `json:"ekCert,omitempty"`

	// IAKPublicKey is the Initial Attestation Key public key in TPM2B_PUBLIC format.
	// Used by the CA to verify attestation quotes and bind to the EK.
	IAKPublicKey []byte `json:"iakPublicKey"`

	// IDevIDPublicKey is the Initial Device Identity Key public key in TPM2B_PUBLIC format.
	// This is the key that will be certified in the IDevID certificate.
	IDevIDPublicKey []byte `json:"idevidPublicKey"`

	// PlatformManufacturer identifies the device manufacturer (e.g., "Dell Inc.").
	PlatformManufacturer string `json:"platformManufacturer"`

	// PlatformModel identifies the device model (e.g., "XPS 15 9520").
	PlatformModel string `json:"platformModel"`

	// PlatformSerial is the device serial number for unique identification.
	PlatformSerial string `json:"platformSerial"`
}

// RemoteActivateCredentialParams contains parameters for remote.activateCredential.
// This forwards a TPM2_MakeCredential challenge from the CA to the laptop for
// proof of EK possession.
//
// The CA creates this challenge using TPM2_MakeCredential with:
//   - The EK public key (from EKCert or TCG-CSR-IDEVID)
//   - The IAK name (hash of IAK public area)
//   - A random secret (typically 32 bytes)
//
// Only the TPM possessing the EK private key can decrypt the credential blob
// to recover the secret, proving EK possession without exposing the EK.
type RemoteActivateCredentialParams struct {
	// Backend specifies the TPM2 backend to use. Defaults to "tpm2" if empty.
	Backend string `json:"backend,omitempty"`

	// CredentialBlob is the TPM2B_ID_OBJECT from TPM2_MakeCredential.
	// Contains the secret encrypted to the EK, bound to the IAK name.
	CredentialBlob []byte `json:"credentialBlob"`

	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET from TPM2_MakeCredential.
	// Contains the seed value encrypted with the EK public key.
	EncryptedSecret []byte `json:"encryptedSecret"`
}

// RemoteActivateCredentialResult contains the result of remote.activateCredential.
// Returns the decrypted secret proving the TPM possesses the EK private key.
type RemoteActivateCredentialResult struct {
	// DecryptedSecret is the original secret from TPM2_MakeCredential.
	// The CA compares this against its original value to verify EK possession.
	DecryptedSecret []byte `json:"decryptedSecret"`
}

// RemoteGetAttestationQuoteParams contains parameters for remote.getAttestationQuote.
// This requests a TPM2 attestation quote over platform PCRs, signed by the IAK.
//
// The quote provides cryptographic proof of:
//   - Platform boot state (measured into PCRs)
//   - Binding between IAK and EK (via credential activation)
//   - TPM possession of the IAK private key
type RemoteGetAttestationQuoteParams struct {
	// Backend specifies the TPM2 backend to use. Defaults to "tpm2" if empty.
	Backend string `json:"backend,omitempty"`

	// Nonce is a challenge value from the CA to ensure quote freshness.
	// Should be at least 16 bytes, typically 32 bytes.
	Nonce []byte `json:"nonce"`

	// PCRIndices specifies which PCRs to include in the quote.
	// Common selections:
	//   - [0,1,2,3,4,5,6,7]: BIOS/UEFI and boot measurements
	//   - [0,1,2,3,4,5,6,7,8,9]: Including bootloader
	//   - [0,1,2,3,4,5,6,7,14]: Including Secure Boot policy (PCR 14)
	PCRIndices []int `json:"pcrIndices"`

	// PCRBank specifies the hash algorithm for PCR bank selection.
	// Supported values: "sha256" (default), "sha384", "sha1" (deprecated).
	PCRBank string `json:"pcrBank,omitempty"`
}

// RemoteGetAttestationQuoteResult contains the result of remote.getAttestationQuote.
// Provides a TPM2 attestation quote for platform integrity verification.
type RemoteGetAttestationQuoteResult struct {
	// Quoted is the TPMS_ATTEST structure containing:
	//   - TPM magic and attestation type
	//   - Qualified signer name (IAK)
	//   - Extra data (includes nonce)
	//   - Clock info and firmware version
	//   - Attested data (PCR selection and digest)
	Quoted []byte `json:"quoted"`

	// Signature is the IAK signature over the Quoted structure.
	// Algorithm depends on IAK key type (typically ECDSA P-256 or RSA-2048).
	Signature []byte `json:"signature"`

	// PCRValues contains the PCR values keyed by PCR index.
	// The digest in Quoted should match the hash of concatenated PCR values.
	PCRValues map[int][]byte `json:"pcrValues"`

	// PCRBank is the hash algorithm used for the PCR bank.
	PCRBank string `json:"pcrBank"`

	// Nonce is the echoed challenge nonce for freshness verification.
	Nonce []byte `json:"nonce"`
}

// remoteMethodNames contains all valid remote.* method names for validation.
var remoteMethodNames = map[string]bool{
	MethodRemoteListBackends:        true,
	MethodRemoteListKeys:            true,
	MethodRemoteGetPublicKey:        true,
	MethodRemoteSign:                true,
	MethodRemoteVerify:              true,
	MethodRemoteEncrypt:             true,
	MethodRemoteDecrypt:             true,
	MethodRemoteDeriveKey:           true,
	MethodRemoteGenerateKey:         true,
	MethodRemoteGetKeyInfo:          true,
	MethodRemoteDeleteKey:           true,
	MethodRemoteAttestKey:           true,
	MethodRemoteAttestDevice:        true,
	MethodRemoteGetTCGCSRIDevID:     true,
	MethodRemoteActivateCredential:  true,
	MethodRemoteGetAttestationQuote: true,
}

// IsRemoteMethod returns true if the method name is a valid remote.* method.
func IsRemoteMethod(method string) bool {
	return remoteMethodNames[method]
}
