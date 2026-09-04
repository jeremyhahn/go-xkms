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

package fido2

import (
	"errors"
	"strconv"
	"time"
)

var (
	ErrNoDeviceFound         = errors.New("fido2: no FIDO2 device found")
	ErrDeviceNotResponding   = errors.New("fido2: device not responding")
	ErrInvalidCredentialID   = errors.New("fido2: invalid credential ID")
	ErrInvalidSalt           = errors.New("fido2: invalid salt")
	ErrUserPresenceRequired  = errors.New("fido2: user presence required")
	ErrOperationTimeout      = errors.New("fido2: operation timeout")
	ErrInvalidCBOR           = errors.New("fido2: invalid CBOR encoding")
	ErrUnsupportedExtension  = errors.New("fido2: extension not supported")
	ErrInvalidHMACSecret     = errors.New("fido2: invalid HMAC-secret")
	ErrDeviceError           = errors.New("fido2: device error")
	ErrInvalidAssertion      = errors.New("fido2: invalid assertion")
	ErrCredentialNotFound    = errors.New("fido2: credential not found")
	ErrPINRequired           = errors.New("fido2: PIN required")
	ErrInvalidPIN            = errors.New("fido2: invalid PIN")
	ErrPINBlocked            = errors.New("fido2: PIN blocked")
	ErrPINNotSet             = errors.New("fido2: no PIN is set on this authenticator")
	ErrPINAuthInvalid        = errors.New("fido2: pinUvAuthParam verification failed")
	ErrPINAuthBlocked        = errors.New("fido2: pinUvAuthParam blocked; power-cycle the authenticator")
	ErrPINRetriesUnavailable = errors.New("fido2: the authenticator did not report its remaining PIN attempts")
	ErrUVRequired            = errors.New("fido2: user verification required")
	ErrInvalidRelyingParty   = errors.New("fido2: invalid relying party")
	ErrInvalidClientDataHash = errors.New("fido2: invalid client data hash")
	ErrCBORTruncated         = errors.New("fido2: CBOR response truncated")

	// Server-issued assertion options (BeginLogin output) validation errors,
	// surfaced by AssertWithOptions when parsing the relying party's
	// PublicKeyCredentialRequestOptions JSON.
	ErrAssertionOptionsRequired  = errors.New("assertion options JSON required")
	ErrAssertionChallengeMissing = errors.New("assertion options missing challenge")
	ErrAssertionRPIDMissing      = errors.New("assertion options missing rpId")

	// Authenticator data parsing errors, surfaced by
	// ParseAuthDataExtensions when the authenticator data supplied by a
	// device (or relayed by a client) does not conform to the structure
	// defined in WebAuthn Level 3 6.1.
	ErrAuthDataTooShort              = errors.New("fido2: authenticator data shorter than the fixed 37-byte header")
	ErrInvalidAttestedCredentialData = errors.New("fido2: malformed attested credential data")
	ErrInvalidCOSEKey                = errors.New("fido2: malformed credential public key")
	ErrInvalidExtensions             = errors.New("fido2: malformed authenticator extension data")
	ErrAuthDataTrailingBytes         = errors.New("fido2: trailing bytes after authenticator data")

	// PIN/UV auth protocol errors, surfaced while establishing the ECDH
	// shared secret that protects hmac-secret salts and outputs
	// (CTAP 2.1 6.5).
	ErrUnsupportedPINUVAuthProtocol = errors.New("fido2: unsupported PIN/UV auth protocol")
	ErrKeyAgreementFailed           = errors.New("fido2: PIN/UV auth key agreement failed")
	ErrPINTokenFailed               = errors.New("fido2: failed to obtain pinUvAuthToken")
	ErrInvalidCOSEKeyAgreement      = errors.New("fido2: malformed PIN/UV auth key agreement key")
	ErrInvalidPINUVAuthPlaintext    = errors.New("fido2: malformed PIN/UV auth plaintext")
	ErrInvalidPINUVAuthCiphertext   = errors.New("fido2: malformed PIN/UV auth ciphertext")

	// hmac-secret extension errors, surfaced by DeriveSecret when the
	// authenticator does not return a usable hmac-secret output. Every one
	// of these is terminal: no key is derived, because a key that is not
	// the authenticator's secret is not hardware-bound.
	ErrHMACSecretMissing       = errors.New("fido2: authenticator returned no hmac-secret extension output")
	ErrHMACSecretOutputInvalid = errors.New("fido2: malformed hmac-secret extension output")
	ErrAuthenticationConfigNil = errors.New("fido2: authentication configuration required")
)

// PINAttemptsError reports a PIN failure together with the number of attempts
// the authenticator will still accept before it locks out.
//
// A wrong PIN that reports only "invalid PIN" tells an operator nothing about
// how close they are to a lockout, and a lockout discovered by hitting it is a
// key that needs a reset. The count comes from the authenticator's own
// getPINRetries counter, so it is what the device will actually enforce.
type PINAttemptsError struct {
	// Err is the underlying PIN failure, normally ErrInvalidPIN.
	Err error

	// Retries is the number of attempts remaining. Zero means the
	// authenticator is now blocked.
	Retries uint64
}

// Error implements the error interface.
func (e *PINAttemptsError) Error() string {
	return e.Err.Error() + " (" + strconv.FormatUint(e.Retries, 10) + " attempts remaining before lockout)"
}

// Unwrap returns the underlying PIN failure, so errors.Is still matches
// ErrInvalidPIN.
func (e *PINAttemptsError) Unwrap() error { return e.Err }

// CTAP2 Command codes
const (
	CmdMakeCredential              = 0x01
	CmdGetAssertion                = 0x02
	CmdGetInfo                     = 0x04
	CmdClientPIN                   = 0x06
	CmdReset                       = 0x07
	CmdGetNextAssertion            = 0x08
	CmdBioEnrollment               = 0x09
	CmdCredentialManagement        = 0x0A
	CmdSelection                   = 0x0B
	CmdLargeBlobs                  = 0x0C
	CmdConfig                      = 0x0D
	CmdBioEnrollmentPreview        = 0x40
	CmdCredentialManagementPreview = 0x41
)

// CTAP2 Status codes
const (
	StatusOK                     = 0x00
	StatusInvalidCommand         = 0x01
	StatusInvalidParameter       = 0x02
	StatusInvalidLength          = 0x03
	StatusInvalidSeq             = 0x04
	StatusTimeout                = 0x05
	StatusChannelBusy            = 0x06
	StatusLockRequired           = 0x0A
	StatusInvalidChannel         = 0x0B
	StatusCBORUnexpectedType     = 0x11
	StatusInvalidCBOR            = 0x12
	StatusMissingParameter       = 0x14
	StatusLimitExceeded          = 0x15
	StatusUnsupportedExtension   = 0x16
	StatusCredentialExcluded     = 0x19
	StatusProcessing             = 0x21
	StatusInvalidCredential      = 0x22
	StatusUserActionPending      = 0x23
	StatusOperationPending       = 0x24
	StatusNoOperations           = 0x25
	StatusUnsupportedAlgorithm   = 0x26
	StatusOperationDenied        = 0x27
	StatusKeyStoreFull           = 0x28
	StatusNotBusy                = 0x29
	StatusNoOperationPending     = 0x2A
	StatusUnsupportedOption      = 0x2B
	StatusInvalidOption          = 0x2C
	StatusKeepaliveCancel        = 0x2D
	StatusNoCredentials          = 0x2E
	StatusUserActionTimeout      = 0x2F
	StatusNotAllowed             = 0x30
	StatusPINInvalid             = 0x31
	StatusPINBlocked             = 0x32
	StatusPINAuthInvalid         = 0x33
	StatusPINAuthBlocked         = 0x34
	StatusPINNotSet              = 0x35
	StatusPINRequired            = 0x36
	StatusPINPolicyViolation     = 0x37
	StatusPINTokenExpired        = 0x38
	StatusRequestTooLarge        = 0x39
	StatusActionTimeout          = 0x3A
	StatusUPRequired             = 0x3B
	StatusUVBlocked              = 0x3C
	StatusIntegrityFailure       = 0x3D
	StatusInvalidSubcommand      = 0x3E
	StatusUVInvalid              = 0x3F
	StatusUnauthorizedPermission = 0x40
	StatusOtherError             = 0x7F
	StatusSpecLast               = 0xDF
	StatusExtensionFirst         = 0xE0
	StatusExtensionLast          = 0xEF
	StatusVendorFirst            = 0xF0
	StatusVendorLast             = 0xFF
)

// COSE Algorithm identifiers
const (
	COSEAlgES256 = -7   // ECDSA w/ SHA-256
	COSEAlgES384 = -35  // ECDSA w/ SHA-384
	COSEAlgES512 = -36  // ECDSA w/ SHA-512
	COSEAlgRS256 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
	COSEAlgEdDSA = -8   // EdDSA
)

// CTAP2 Extension identifiers
const (
	ExtensionHMACSecret   = "hmac-secret"
	ExtensionCredProtect  = "credProtect"
	ExtensionCredBlob     = "credBlob"
	ExtensionLargeBlobKey = "largeBlobKey"
	ExtensionMinPINLength = "minPinLength"
)

// Default timeouts and retry settings
const (
	DefaultTimeout             = 30 * time.Second
	DefaultUserPresenceTimeout = 30 * time.Second
	DefaultRetryCount          = 3
	DefaultRetryDelay          = 100 * time.Millisecond
)

// Device represents a FIDO2 authenticator device
type Device struct {
	Path         string
	VendorID     uint16
	ProductID    uint16
	Manufacturer string
	Product      string
	SerialNumber string
	Transport    string // "usb", "nfc", "ble", "internal"
}

// DeviceInfo contains authenticator capabilities from GetInfo
type DeviceInfo struct {
	Versions                         []string
	Extensions                       []string
	AAGUID                           []byte
	Options                          map[string]bool
	MaxMsgSize                       uint64
	PINProtocols                     []uint64
	MaxCredentialCount               uint64
	MaxCredentialIDLen               uint64
	Transports                       []string
	Algorithms                       []PublicKeyCredentialParameter
	MaxSerializedLargeBlobArray      uint64
	ForcePINChange                   bool
	MinPINLength                     uint64
	FirmwareVersion                  uint64
	MaxCredBlobLen                   uint64
	MaxRPIDsForSetMinPIN             uint64
	PreferredPlatformUvAttempts      uint64
	UVModality                       uint64
	Certifications                   map[string]interface{}
	RemainingDiscoverableCredentials uint64
	VendorPrototypeConfigCommands    []uint64
}

// RelyingParty represents an RP entity
type RelyingParty struct {
	ID   string
	Name string
	Icon string // Optional
}

// User represents a user entity
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Icon        string // Optional
}

// PublicKeyCredentialParameter describes a credential type and algorithm
type PublicKeyCredentialParameter struct {
	Type string // "public-key"
	Alg  int    // COSE algorithm identifier
}

// PublicKeyCredentialDescriptor identifies a credential
type PublicKeyCredentialDescriptor struct {
	Type       string   // "public-key"
	ID         []byte   // Credential ID
	Transports []string // Optional transport hints
}

// AuthenticatorOptions represents authenticator options
type AuthenticatorOptions struct {
	RK bool // Resident key
	UP bool // User presence
	UV bool // User verification
}

// MakeCredentialRequest for creating credentials (CTAP2 authenticatorMakeCredential)
type MakeCredentialRequest struct {
	ClientDataHash        []byte
	RP                    RelyingParty
	User                  User
	PubKeyCredParams      []PublicKeyCredentialParameter
	ExcludeList           []PublicKeyCredentialDescriptor
	Extensions            map[string]interface{}
	Options               AuthenticatorOptions
	PinUVAuthParam        []byte
	PinUVAuthProtocol     uint64
	EnterpriseAttestation uint64
}

// MakeCredentialResponse from authenticatorMakeCredential
type MakeCredentialResponse struct {
	Fmt          string
	AuthData     []byte
	AttStmt      map[string]interface{}
	EPAtt        bool
	LargeBlobKey []byte
}

// GetAssertionRequest for getting assertions (CTAP2 authenticatorGetAssertion)
type GetAssertionRequest struct {
	RPID              string
	ClientDataHash    []byte
	AllowList         []PublicKeyCredentialDescriptor
	Extensions        map[string]interface{}
	Options           AuthenticatorOptions
	PinUVAuthParam    []byte
	PinUVAuthProtocol uint64
}

// GetAssertionResponse from authenticatorGetAssertion
type GetAssertionResponse struct {
	Credential          PublicKeyCredentialDescriptor
	AuthData            []byte
	Signature           []byte
	User                *User
	NumberOfCredentials uint64
	UserSelected        bool
	LargeBlobKey        []byte
}

// HMACSecretInput for hmac-secret extension (CTAP 2.0)
type HMACSecretInput struct {
	KeyAgreement      map[string]interface{} // COSE_Key
	SaltEnc           []byte                 // Encrypted salt(s)
	SaltAuth          []byte                 // Authentication tag
	PinUVAuthProtocol uint64                 // PIN/UV protocol version
}

// HMACSecretOutput from hmac-secret extension
type HMACSecretOutput struct {
	Output []byte // HMAC-SHA256 output (32 or 64 bytes)
}

// EnrollmentConfig for FIDO2 enrollment
type EnrollmentConfig struct {
	RelyingParty            RelyingParty
	User                    User
	Salt                    []byte
	RequireUserVerification bool
	Timeout                 time.Duration
}

// EnrollmentResult contains enrollment data
type EnrollmentResult struct {
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
	RelyingParty RelyingParty
	User         User
	Salt         []byte
	Created      time.Time
}

// DerivationMode selects how DeriveSecret obtains an hmac-secret value.
// The zero value is the CTAP2 derivation, so a caller must opt in
// explicitly to anything else.
type DerivationMode uint8

const (
	// DerivationModeCTAP2 extracts the genuine hmac-secret extension
	// output and decrypts it with the PIN/UV auth shared secret, as
	// specified by CTAP 2.1 12.5. It is the only mode that yields a
	// hardware-bound key.
	DerivationModeCTAP2 DerivationMode = iota

	// DerivationModeLegacyInsecure reproduces the derivation go-xkms used
	// before the hmac-secret extension was parsed correctly. It reads raw
	// bytes from a fixed offset in the authenticator data and, when that
	// yields nothing, computes SHA-256(credentialID || salt) — a value
	// derived entirely from non-secret material that is normally stored
	// beside the encrypted volume. A key produced in this mode is NOT
	// hardware-bound and can be recomputed without the authenticator.
	//
	// It exists for one purpose: unlocking a volume that was enrolled with
	// the broken derivation, once, so it can be re-enrolled with
	// DerivationModeCTAP2. It is deprecated and will be removed.
	//
	// Deprecated: migration only. Re-enroll the volume immediately.
	DerivationModeLegacyInsecure
)

// AuthenticationConfig for FIDO2 authentication
type AuthenticationConfig struct {
	RelyingPartyID          string
	CredentialID            []byte
	Salt                    []byte
	Salt2                   []byte
	Challenge               []byte
	RequireUserVerification bool
	Timeout                 time.Duration

	// DerivationMode selects the hmac-secret derivation. It is tagged out
	// of every serialization format on purpose: the insecure legacy mode
	// must never become reachable through a configuration file, only
	// through an explicit in-process decision such as a CLI flag.
	DerivationMode DerivationMode `yaml:"-" json:"-" mapstructure:"-"`
}

// AuthenticationResult contains authentication data
type AuthenticationResult struct {
	// HMACSecret is the hmac-secret output for Salt.
	HMACSecret []byte

	// HMACSecret2 is the hmac-secret output for Salt2, populated only when
	// a second salt was requested.
	HMACSecret2 []byte

	SignCount      uint32
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	Signature      []byte
	AuthData       []byte
}
