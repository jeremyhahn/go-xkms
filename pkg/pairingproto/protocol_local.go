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

package pairingproto

// Local method names for the laptop-to-phone direction.
// These methods operate on the phone's Android Keystore and are
// namespaced under "local.*" to distinguish them from the base
// protocol methods used for FIDO2 credential operations.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (operates on phone's keystore)
//   - remote.* methods: Phone sends TO laptop (operates on laptop's xkms)
//
// For phone-initiated attestation, the phone should use remote.attestDevice
// to request the laptop to attest itself. This is defined in protocol_remote.go.
const (
	MethodLocalGenerateKey          = "local.generateKey"
	MethodLocalSign                 = "local.sign"
	MethodLocalDecrypt              = "local.decrypt"
	MethodLocalSymmetricEncrypt     = "local.symmetricEncrypt"
	MethodLocalSymmetricDecrypt     = "local.symmetricDecrypt"
	MethodLocalHMAC                 = "local.hmac"
	MethodLocalECDH                 = "local.ecdh"
	MethodLocalGetPublicKey         = "local.getPublicKey"
	MethodLocalListKeys             = "local.listKeys"
	MethodLocalGetKeyInfo           = "local.getKeyInfo"
	MethodLocalDeleteKey            = "local.deleteKey"
	MethodLocalSetKeyPolicy         = "local.setKeyPolicy"
	MethodLocalAttestKey            = "local.attestKey"
	MethodLocalAttestDevice         = "local.attestDevice"
	MethodLocalGetCapabilities      = "local.getCapabilities"
	MethodLocalListFido2Credentials = "local.listFido2Credentials"
	MethodLocalSignFido2Assertion   = "local.signFido2Assertion"

	// Notification from phone when biometric is pending (fire-and-forget)
	MethodLocalBiometricPending = "local.biometricPending"
)

// LocalGenerateKeyParams contains parameters for local.generateKey.
// Algorithm accepts: "ES256", "ES384", "ES512", "RS256", "RS384",
// "RS512", "AES128", "AES256", "HMAC-SHA256", "HMAC-SHA512".
type LocalGenerateKeyParams struct {
	KeyID                    string `json:"keyId"`
	Algorithm                string `json:"algorithm"`
	KeySizeBits              int    `json:"keySizeBits,omitempty"` // For RSA: 2048, 3072, 4096
	StrongBoxBacked          bool   `json:"strongBoxBacked,omitempty"`
	BiometricRequired        bool   `json:"biometricRequired,omitempty"`
	AuthDurationSeconds      int    `json:"authDurationSeconds,omitempty"`
	UserVerificationRequired bool   `json:"userVerificationRequired,omitempty"`
	// Exportable requests a software-backed (exportable) key instead of a
	// hardware-backed Keystore key. Only valid for symmetric algorithms; the
	// phone refuses exportable asymmetric keys (hardware-backing is required
	// for asymmetric keys on a security key).
	Exportable bool `json:"exportable,omitempty"`
}

// LocalGenerateKeyResult contains the result of local.generateKey.
type LocalGenerateKeyResult struct {
	KeyID         string `json:"keyId"`
	PublicKeyDER  []byte `json:"publicKeyDer,omitempty"`
	PublicKeyCOSE []byte `json:"publicKeyCose,omitempty"`
	Algorithm     string `json:"algorithm"`
	KeySizeBits   int    `json:"keySizeBits"`
	SecurityLevel string `json:"securityLevel"` // "tee" or "strongbox"
}

// LocalSignParams contains parameters for local.sign.
type LocalSignParams struct {
	KeyID                    string `json:"keyId"`
	Data                     []byte `json:"data"`
	Algorithm                string `json:"algorithm,omitempty"` // Optional: override signing algorithm
	UserVerificationRequired bool   `json:"userVerificationRequired,omitempty"`
}

// LocalSignResult contains the result of local.sign.
type LocalSignResult struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// LocalDecryptParams contains parameters for local.decrypt.
type LocalDecryptParams struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
	Algorithm  string `json:"algorithm,omitempty"` // e.g., "RSA-OAEP-SHA256"
}

// LocalDecryptResult contains the result of local.decrypt.
type LocalDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// LocalSymmetricEncryptParams contains parameters for local.symmetricEncrypt.
type LocalSymmetricEncryptParams struct {
	KeyID     string `json:"keyId"`
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"` // Additional authenticated data
}

// LocalSymmetricEncryptResult contains the result of local.symmetricEncrypt.
type LocalSymmetricEncryptResult struct {
	Ciphertext []byte `json:"ciphertext"` // IV + encrypted data + tag
}

// LocalSymmetricDecryptParams contains parameters for local.symmetricDecrypt.
type LocalSymmetricDecryptParams struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"` // IV + encrypted data + tag
	AAD        []byte `json:"aad,omitempty"`
}

// LocalSymmetricDecryptResult contains the result of local.symmetricDecrypt.
type LocalSymmetricDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// LocalHMACParams contains parameters for local.hmac.
type LocalHMACParams struct {
	KeyID string `json:"keyId"`
	Data  []byte `json:"data"`
}

// LocalHMACResult contains the result of local.hmac.
type LocalHMACResult struct {
	MAC []byte `json:"mac"`
}

// LocalECDHParams contains parameters for local.ecdh.
type LocalECDHParams struct {
	KeyID         string `json:"keyId"`
	PeerPublicKey []byte `json:"peerPublicKey"` // DER-encoded peer public key
}

// LocalECDHResult contains the result of local.ecdh.
type LocalECDHResult struct {
	SharedSecret []byte `json:"sharedSecret"`
}

// LocalGetPublicKeyParams contains parameters for local.getPublicKey.
type LocalGetPublicKeyParams struct {
	KeyID  string `json:"keyId"`
	Format string `json:"format"` // "der", "pem", "ssh", "cose"
}

// LocalGetPublicKeyResult contains the result of local.getPublicKey.
type LocalGetPublicKeyResult struct {
	PublicKey []byte `json:"publicKey"`
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
}

// LocalListKeysParams contains parameters for local.listKeys.
type LocalListKeysParams struct {
	KeyType   string `json:"keyType,omitempty"`   // Filter: "fido2", "ssh", "tls", "signing", "encryption", "symmetric"
	Algorithm string `json:"algorithm,omitempty"` // Filter: "ES256", "RS256", etc.
}

// KeyInfo contains metadata about a key stored in the phone's keystore.
type KeyInfo struct {
	KeyID             string `json:"keyId"`
	KeyType           string `json:"keyType"`
	Algorithm         string `json:"algorithm"`
	KeySizeBits       int    `json:"keySizeBits"`
	Label             string `json:"label"`
	StrongBoxBacked   bool   `json:"strongBoxBacked"`
	BiometricRequired bool   `json:"biometricRequired"`
	Exportable        bool   `json:"exportable"`
	Shareable         bool   `json:"shareable"`
	Source            string `json:"source"` // "local", "remote_ble", "remote_usb", "xkmsd"
	UseCount          int64  `json:"useCount"`
	CreatedAt         int64  `json:"createdAt"`
	LastUsedAt        int64  `json:"lastUsedAt"`
}

// LocalListKeysResult contains the result of local.listKeys.
type LocalListKeysResult struct {
	Keys []KeyInfo `json:"keys"`
}

// LocalGetKeyInfoParams contains parameters for local.getKeyInfo.
type LocalGetKeyInfoParams struct {
	KeyID string `json:"keyId"`
}

// LocalGetKeyInfoResult contains the result of local.getKeyInfo.
// When KeyType is "fido2", the FIDO2-specific fields are populated.
type LocalGetKeyInfoResult struct {
	KeyInfo

	// FIDO2-specific fields (populated when KeyType == "fido2").
	RpID            string `json:"rpId,omitempty"`
	RpName          string `json:"rpName,omitempty"`
	UserID          string `json:"userId,omitempty"`
	UserName        string `json:"userName,omitempty"`
	UserDisplayName string `json:"userDisplayName,omitempty"`
	IsDiscoverable  bool   `json:"isDiscoverable,omitempty"`
	SignCount       int64  `json:"signCount,omitempty"`
}

// LocalDeleteKeyParams contains parameters for local.deleteKey.
type LocalDeleteKeyParams struct {
	KeyID string `json:"keyId"`
}

// LocalDeleteKeyResult contains the result of local.deleteKey.
type LocalDeleteKeyResult struct {
	Deleted bool `json:"deleted"`
}

// LocalSetKeyPolicyParams contains parameters for local.setKeyPolicy.
// Pointer fields allow distinguishing between "not set" and zero values.
type LocalSetKeyPolicyParams struct {
	KeyID               string `json:"keyId"`
	Shareable           *bool  `json:"shareable,omitempty"`
	BiometricRequired   *bool  `json:"biometricRequired,omitempty"`
	AuthDurationSeconds *int   `json:"authDurationSeconds,omitempty"`
}

// LocalSetKeyPolicyResult contains the result of local.setKeyPolicy.
type LocalSetKeyPolicyResult struct {
	Updated bool `json:"updated"`
}

// LocalAttestKeyParams contains parameters for local.attestKey.
type LocalAttestKeyParams struct {
	KeyID string `json:"keyId"`
	Nonce []byte `json:"nonce"` // Challenge nonce from the verifier
}

// LocalAttestKeyResult contains the result of local.attestKey.
type LocalAttestKeyResult struct {
	Format           string   `json:"format"`           // "android-keystore"
	CertificateChain [][]byte `json:"certificateChain"` // X.509 cert chain: [leaf, intermediate..., root]
	SecurityLevel    string   `json:"securityLevel"`    // "tee" or "strongbox"
	Nonce            []byte   `json:"nonce"`            // Echoed challenge
}

// LocalAttestDeviceParams contains parameters for local.attestDevice.
// This method attests to the device itself, not a specific key.
//
// Under protocol version 2 (#129) it is a challenge: the verifier states the
// nonce, the purpose and the channel it expects the answer to be bound to, and
// the device answers with a live signature over all three. Under version 1 the
// nonce was instead baked into a freshly generated key's attestation
// certificate; see attest_challenge.go for why that could not coexist with a
// stable device identity.
type LocalAttestDeviceParams struct {
	// ProtocolVersion selects the attestation model. Absent or 1 is the
	// legacy embedded-challenge request; 2 is challenge-response.
	ProtocolVersion int `json:"protocolVersion,omitempty"`

	// Nonce is the verifier's fresh 32-byte challenge.
	Nonce []byte `json:"nonce"`

	// Purpose is the version 2 transcript purpose: "pair" or "reattest". It
	// keeps a signature obtained during pairing from satisfying a reconnect.
	Purpose string `json:"purpose,omitempty"`
}

// NOTE — the version 2 request deliberately carries NO channel binding.
//
// The transcript commits to one (ComputeAttestChannelBinding: a SHA-256 over
// the two Noise static public keys in initiator-then-responder order plus the
// length-prefixed prologue), and each side derives it from its OWN session.
//
// It was briefly sent here as a diagnostic and removed, because a field whose
// only safe handling is "never use it" is not a diagnostic — it is a footgun
// with an undetectable failure mode. A prover that signs the supplied value and
// a prover that derives its own are BYTE-INDISTINGUISHABLE to the verifier
// under normal operation; they diverge only under exactly the relay attack the
// binding exists to stop, at which point the relayed signature verifies. And a
// request field named channelBinding carrying exactly 32 bytes reads as "sign
// this", so every implementer would have to independently rediscover why the
// obvious reading is the wrong one.
//
// Removing it makes the dangerous implementation unwritable rather than merely
// forbidden. Each side logs its own derived value at debug level instead: an
// operator diffing two logs learns which side is wrong, which the old
// "they differ" warning could never say. (Ruled on #129.)

// LocalAttestDeviceResult contains the result of local.attestDevice.
// This provides Android hardware-backed device attestation.
//
// Only CertificateChain, Signature, SignatureAlgorithm and ProtocolVersion
// carry weight. SecurityLevel, Nonce and the RootOfTrust fields are the
// device's own unauthenticated JSON: the verifier reads every one of those
// claims out of the SIGNED attestation extension in the leaf instead, and
// keeps the JSON copies only for display and diagnostics (#95).
type LocalAttestDeviceResult struct {
	// ProtocolVersion is the model the device answered under. A version 2
	// request refuses anything but a version 2 answer — see
	// ErrAttestProtocolDowngrade.
	ProtocolVersion int `json:"protocolVersion,omitempty"`

	Format           string   `json:"format"`           // "android-keystore"
	CertificateChain [][]byte `json:"certificateChain"` // X.509 cert chain: [leaf(DAK), intermediate..., root]
	SecurityLevel    string   `json:"securityLevel"`    // "software", "tee", "strongbox"
	Nonce            []byte   `json:"nonce"`            // Echoed challenge

	// Purpose echoes the requested transcript purpose (version 2). It is
	// advisory: the verifier rebuilds the transcript from what IT asked for,
	// never from this field.
	Purpose string `json:"purpose,omitempty"`

	// Signature is the DAK's live signature over the attestation transcript
	// (version 2), ASN.1 DER.
	Signature []byte `json:"signature,omitempty"`

	// SignatureAlgorithm names the signature scheme, "ES256". It is checked
	// rather than inferred so a peer cannot pick a weaker verification path by
	// mislabelling its signature.
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`

	// RootOfTrust fields from Android attestation extension
	BootState        int    `json:"bootState"`        // 0=VERIFIED, 1=SELF_SIGNED, 2=UNVERIFIED, 3=FAILED
	DeviceLocked     bool   `json:"deviceLocked"`     // True if bootloader is locked
	VerifiedBootKey  []byte `json:"verifiedBootKey"`  // Public key hash
	VerifiedBootHash []byte `json:"verifiedBootHash"` // Boot partition hash
}

// LocalGetCapabilitiesResult contains the result of local.getCapabilities.
// This method takes no parameters.
type LocalGetCapabilitiesResult struct {
	Version             string   `json:"version"`
	DeviceName          string   `json:"deviceName"`
	SupportedAlgorithms []string `json:"supportedAlgorithms"` // ["ES256", "ES384", "ES512", "RS256", ...]
	StrongBoxAvailable  bool     `json:"strongBoxAvailable"`
	MaxKeys             int      `json:"maxKeys"`
	CurrentKeyCount     int      `json:"currentKeyCount"`
	SupportedFormats    []string `json:"supportedFormats"` // ["der", "pem", "ssh", "cose"]
	AttestationSupport  bool     `json:"attestationSupport"`
}

// Fido2CredentialInfo contains metadata about a FIDO2 credential for discovery.
type Fido2CredentialInfo struct {
	CredentialID    []byte `json:"credentialId"`
	RpID            string `json:"rpId"`
	RpName          string `json:"rpName"`
	UserID          []byte `json:"userId"`
	UserName        string `json:"userName"`
	UserDisplayName string `json:"userDisplayName"`
	IsDiscoverable  bool   `json:"isDiscoverable"`
	CreatedAt       int64  `json:"createdAt"`
}

// LocalListFido2CredentialsParams contains parameters for local.listFido2Credentials.
type LocalListFido2CredentialsParams struct {
	RpID string `json:"rpId"`
}

// LocalListFido2CredentialsResult contains the result of local.listFido2Credentials.
type LocalListFido2CredentialsResult struct {
	Credentials []Fido2CredentialInfo `json:"credentials"`
}

// LocalSignFido2AssertionParams contains parameters for local.signFido2Assertion.
type LocalSignFido2AssertionParams struct {
	CredentialID             []byte `json:"credentialId"`
	ClientDataHash           []byte `json:"clientDataHash"`
	RpID                     string `json:"rpId"`
	UserVerificationRequired bool   `json:"userVerificationRequired,omitempty"`
}

// LocalSignFido2AssertionResult contains the result of local.signFido2Assertion.
type LocalSignFido2AssertionResult struct {
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle,omitempty"`
	SignCount         int64  `json:"signCount"`
}

// LocalBiometricPendingParams contains parameters for local.biometricPending.
// This is a notification from the phone indicating biometric auth is pending.
type LocalBiometricPendingParams struct {
	Operation   string `json:"operation"` // "sign", "decrypt", "attestKey", etc.
	RPName      string `json:"rpName,omitempty"`
	TimeoutSecs int    `json:"timeoutSecs"` // How long phone will wait
}

// localMethodNames contains all valid local.* method names for validation.
var localMethodNames = map[string]bool{
	MethodLocalGenerateKey:          true,
	MethodLocalSign:                 true,
	MethodLocalDecrypt:              true,
	MethodLocalSymmetricEncrypt:     true,
	MethodLocalSymmetricDecrypt:     true,
	MethodLocalHMAC:                 true,
	MethodLocalECDH:                 true,
	MethodLocalGetPublicKey:         true,
	MethodLocalListKeys:             true,
	MethodLocalGetKeyInfo:           true,
	MethodLocalDeleteKey:            true,
	MethodLocalSetKeyPolicy:         true,
	MethodLocalAttestKey:            true,
	MethodLocalAttestDevice:         true,
	MethodLocalGetCapabilities:      true,
	MethodLocalListFido2Credentials: true,
	MethodLocalSignFido2Assertion:   true,
	MethodLocalBiometricPending:     true,
	MethodLocalVerifyUser:           true,

	// Android-native device enrollment, this host acting as the CA.
	MethodLocalGetDeviceEnrollmentRequest: true,
	MethodLocalStoreDeviceCredential:      true,
}

// IsLocalMethod returns true if the method name is a valid local.* method.
func IsLocalMethod(method string) bool {
	return localMethodNames[method]
}
