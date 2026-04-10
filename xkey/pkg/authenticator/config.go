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

// Package authenticator provides a native software FIDO2/CTAP2 authenticator
// implementation for go-xkms. This authenticator can be used for testing,
// development, and as a software-based credential storage solution when hardware
// security keys are not available.
package authenticator

import (
	"errors"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
)

// Default AAGUID for go-xkms authenticator.
// ASCII "go-xkms" (11 bytes) + null padding + version byte.
var DefaultAAGUID = [16]byte{
	0x67, 0x6f, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, // "go-keych"
	0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x01, // "ain" + padding + v1
}

// Default configuration values
const (
	DefaultMaxCredentials         = 100
	DefaultMaxResidentCredentials = 25
	DefaultPINMinLength           = 4
	DefaultPINMaxRetries          = 8
)

// Configuration errors
var (
	ErrNilConfig               = errors.New("authenticator: config is nil")
	ErrInvalidAAGUID           = errors.New("authenticator: AAGUID must be exactly 16 bytes")
	ErrNoAlgorithms            = errors.New("authenticator: at least one algorithm must be supported")
	ErrUnsupportedAlgorithm    = errors.New("authenticator: unsupported algorithm specified")
	ErrInvalidMaxCredentials   = errors.New("authenticator: max credentials must be positive")
	ErrInvalidMaxResidentCreds = errors.New("authenticator: max resident credentials must be positive and not exceed max credentials")
	ErrInvalidPINMinLength     = errors.New("authenticator: PIN min length must be at least 4")
	ErrInvalidPINMaxRetries    = errors.New("authenticator: PIN max retries must be positive")
	ErrNilStorage              = errors.New("authenticator: storage backend is required")
)

// CredentialStorage defines the interface for credential persistence.
// Implementations must be safe for concurrent use.
type CredentialStorage interface {
	// Store persists a credential
	Store(credential *StoredCredential) error

	// Load retrieves a credential by its ID
	Load(credentialID []byte) (*StoredCredential, error)

	// LoadByRPID retrieves all credentials for a relying party
	LoadByRPID(rpID string) ([]*StoredCredential, error)

	// Delete removes a credential
	Delete(credentialID []byte) error

	// Count returns the total number of stored credentials
	Count() (int, error)

	// CountDiscoverable returns the number of discoverable credentials
	CountDiscoverable() (int, error)
}

// CredentialIndexer is an optional interface for storage backends that
// maintain a metadata index for fast credential existence checks.
// Implementations avoid expensive storage I/O by consulting an in-memory
// index built at startup and maintained on Store/Delete operations.
type CredentialIndexer interface {
	// IndexReady returns true when the background index build has completed.
	// Callers should fall back to full storage scans when this returns false.
	IndexReady() bool

	// HasCredentialsForRP returns true if any credentials exist for the given RPID.
	HasCredentialsForRP(rpID string) bool

	// HasDiscoverableForRP returns true if any discoverable (resident)
	// credentials exist for the given RPID.
	HasDiscoverableForRP(rpID string) bool
}

// StoredCredential represents a persisted FIDO2 credential.
type StoredCredential struct {
	// CredentialID is the unique identifier for this credential
	CredentialID []byte

	// RPID is the relying party identifier
	RPID string

	// RPName is the relying party display name
	RPName string

	// UserID is the user handle
	UserID []byte

	// UserName is the user name
	UserName string

	// UserDisplayName is the user display name
	UserDisplayName string

	// PrivateKey is the credential private key (PKCS#8 encoded)
	PrivateKey []byte

	// PublicKeyCOSE is the COSE-encoded public key
	PublicKeyCOSE []byte

	// Algorithm is the COSE algorithm identifier
	Algorithm int

	// SignCount is the signature counter
	SignCount uint32

	// Discoverable indicates if this is a resident/discoverable credential
	Discoverable bool

	// HMACSecretKey is the per-credential hmac-secret key (32 bytes)
	HMACSecretKey []byte

	// CredProtect is the credential protection level (0-3).
	// See CredProtect* constants for valid values.
	CredProtect uint8

	// CreatedAt is the Unix timestamp of credential creation
	CreatedAt int64

	// RPUVPolicy is the RP's userVerification requirement at credential creation.
	// Values: "required", "preferred", "discouraged", ""
	RPUVPolicy string `json:"rp_uv_policy,omitempty"`

	// RPUPPolicy is whether the RP required user presence at creation.
	// Default true per CTAP2 spec.
	RPUPPolicy bool `json:"rp_up_policy"`

	// RPResidentKeyPolicy is the RP's resident key requirement.
	// Values: "required", "preferred", "discouraged", ""
	RPResidentKeyPolicy string `json:"rp_resident_key_policy,omitempty"`

	// RPAttestationPref is the RP's attestation preference at creation.
	// Values: "none", "indirect", "direct", "enterprise", ""
	RPAttestationPref string `json:"rp_attestation_pref,omitempty"`

	// BackendID identifies which key backend manages this credential's private key.
	// Values: "software", "tpm2", "pkcs11", "phone". Empty string means software
	// (backward compatibility with credentials created before this field existed).
	BackendID types.BackendType `json:"backend_id,omitempty"`
}

// Config contains authenticator configuration options.
type Config struct {
	// AAGUID is the 16-byte Authenticator Attestation GUID.
	// This uniquely identifies the authenticator model.
	AAGUID [16]byte `yaml:"aaguid" json:"aaguid" mapstructure:"aaguid"`

	// SupportedAlgorithms specifies which COSE algorithms are supported.
	// Default: []int{COSEAlgES256} (-7)
	SupportedAlgorithms []int `yaml:"supported-algorithms" json:"supported_algorithms" mapstructure:"supported-algorithms"`

	// MaxCredentials is the maximum number of credentials to store.
	// Default: 100
	MaxCredentials int `yaml:"max-credentials" json:"max_credentials" mapstructure:"max-credentials"`

	// MaxResidentCredentials is the maximum number of discoverable credentials.
	// Must not exceed MaxCredentials.
	// Default: 25
	MaxResidentCredentials int `yaml:"max-resident-credentials" json:"max_resident_credentials" mapstructure:"max-resident-credentials"`

	// PINMinLength is the minimum PIN length in characters.
	// CTAP2 spec requires minimum of 4.
	// Default: 4
	PINMinLength int `yaml:"pin-min-length" json:"pin_min_length" mapstructure:"pin-min-length"`

	// PINMaxRetries is the maximum PIN attempts before lockout.
	// Default: 8
	PINMaxRetries int `yaml:"pin-max-retries" json:"pin_max_retries" mapstructure:"pin-max-retries"`

	// EnablePIN enables PIN support for user verification.
	// Default: true
	EnablePIN bool `yaml:"enable-pin" json:"enable_pin" mapstructure:"enable-pin"`

	// EnableResidentKey enables support for discoverable credentials.
	// Default: true
	EnableResidentKey bool `yaml:"enable-resident-key" json:"enable_resident_key" mapstructure:"enable-resident-key"`

	// EnableCredentialManagement enables credential management commands.
	// Allows enumeration and deletion of stored credentials.
	// Default: true
	EnableCredentialManagement bool `yaml:"enable-credential-management" json:"enable_credential_management" mapstructure:"enable-credential-management"`

	// EnableHMACSecret enables the hmac-secret extension.
	// This is required for go-xkms key derivation functionality.
	// Default: true
	EnableHMACSecret bool `yaml:"enable-hmac-secret" json:"enable_hmac_secret" mapstructure:"enable-hmac-secret"`

	// AlwaysUV requires user verification for all operations, even when
	// the relying party does not request it. This provides stronger security
	// but may impact usability.
	// Default: false
	AlwaysUV bool `yaml:"always-uv" json:"always_uv" mapstructure:"always-uv"`

	// UserPresenceHandler is the handler for user presence and verification requests.
	// If nil, an AutoGrantHandler is used (auto-approve all requests).
	// Default: nil (auto-grant)
	UserPresenceHandler UserPresenceHandler `yaml:"-" json:"-" mapstructure:"-"`

	// UserPresenceTimeout is the timeout for user presence/verification requests.
	// Only used if UserPresenceHandler is set to an interactive handler.
	// Default: 30 seconds
	UserPresenceTimeout time.Duration `yaml:"user-presence-timeout" json:"user_presence_timeout" mapstructure:"user-presence-timeout"`

	// RequireUserPresence controls whether physical touch is required even when
	// PIN verification has been performed. When true, behaves like hardware
	// authenticators (YubiKey) that require touch for every operation.
	// When false, follows CTAP2 spec where valid pinUvAuthParam implicitly
	// satisfies the UP requirement.
	// Default: false
	RequireUserPresence bool `yaml:"require-user-presence" json:"require_user_presence" mapstructure:"require-user-presence"`

	// EnableUserIntentCheck enables a user presence dialog before returning
	// StatusPINRequired on MakeCredential and GetAssertion. This allows users
	// with multiple security keys to decline and let Chrome fall through to
	// a different device.
	//
	// When enabled (and PIN is set, and no pinUvAuthParam is provided):
	//   - The authenticator calls requestUserPresence() BEFORE returning ErrPINRequired
	//   - If the user approves: returns ErrPINRequired (Chrome does PIN exchange)
	//   - If the user denies: returns ErrOperationDenied (Chrome falls through)
	//
	// When disabled: existing behavior (immediate ErrPINRequired).
	// Default: false
	EnableUserIntentCheck bool `yaml:"enable-user-intent-check" json:"enable_user_intent_check" mapstructure:"enable-user-intent-check"`

	// KeyBackend is the pluggable key backend for credential key operations.
	// If nil, the legacy crypto.go path is used for key generation and signing.
	// Default: nil (legacy path)
	KeyBackend keybackend.FIDO2KeyBackend `yaml:"-" json:"-" mapstructure:"-"`

	// AttestationFormat specifies the attestation statement format.
	// Supported values: "none", "packed", "tpm"
	// Default: "none"
	AttestationFormat string `yaml:"attestation-format" json:"attestation_format" mapstructure:"attestation-format"`

	// Storage is the credential storage backend.
	// This field is required and must be set before calling Validate().
	Storage CredentialStorage `yaml:"-" json:"-" mapstructure:"-"`

	// Logger is the structured logger for CTAP2 command diagnostics.
	// If nil, no command-level logging is performed.
	Logger *slog.Logger `yaml:"-" json:"-" mapstructure:"-"`

	// OnCredentialCreated is an optional callback invoked after a new credential
	// is successfully stored during MakeCredential. The callback receives the
	// stored credential metadata. If nil, no notification is sent.
	OnCredentialCreated func(cred *StoredCredential) `yaml:"-" json:"-" mapstructure:"-"`

	// OnAssertionCompleted is an optional callback invoked after a successful
	// GetAssertion. The callback receives the RP ID of the assertion.
	// Used by AutoFillService to suppress autofill during post-ceremony
	// page navigations that would otherwise trigger credential filling.
	OnAssertionCompleted func(rpID string) `yaml:"-" json:"-" mapstructure:"-"`

	// UnifiedPIN enables unified PIN coordination across FIDO2, PKCS#11, and
	// file-based PIN managers. When enabled, a PIN change in any subsystem
	// propagates to all other registered subsystems.
	// Default: true
	UnifiedPIN bool `yaml:"unified-pin" json:"unified_pin" mapstructure:"unified-pin"`

	// PolicyIntegrityProvider is the HMAC integrity provider for SO-controlled
	// policy fields. When set, policy HMAC tags are verified on startup and
	// computed during SO operations. If nil, policy integrity checking is disabled.
	//
	// Available providers:
	//   - SoftwarePolicyProvider: HMAC-SHA256 with software key (dev/test)
	//   - TPM2 and PKCS#11 providers are available for production use
	//
	// Default: nil (policy integrity checking disabled)
	PolicyIntegrityProvider PolicyIntegrityProvider `yaml:"-" json:"-" mapstructure:"-"`

	// RPPolicyStore is the per-RP policy store for SO-configurable overrides.
	// When set, the authenticator checks per-RP policies during MakeCredential
	// and GetAssertion operations. If nil, no per-RP overrides are applied.
	// Default: nil (no per-RP policy overrides)
	RPPolicyStore RPPolicyStore `yaml:"-" json:"-" mapstructure:"-"`

	// Transports configures the transports list in GetInfo response.
	// Default: ["usb"]. Options: "usb", "nfc", "ble", "internal", "hybrid"
	Transports []string `yaml:"transports" json:"transports" mapstructure:"transports"`

	// EnableEnterpriseAttestation advertises enterprise attestation support in GetInfo.
	// Default: false
	EnableEnterpriseAttestation bool `yaml:"enable-enterprise-attestation" json:"enable_enterprise_attestation" mapstructure:"enable-enterprise-attestation"`

	// EnableLargeBlobs advertises largeBlob extension support in GetInfo.
	// Default: false (future implementation)
	EnableLargeBlobs bool `yaml:"enable-large-blobs" json:"enable_large_blobs" mapstructure:"enable-large-blobs"`

	// FirmwareVersion is an unsigned integer reported in the CTAP2 GetInfo
	// response (key 0x0E). The encoding scheme is device-specific; xkey uses
	// major*10000 + minor*100 + patch (e.g., 1.2.3 → 10203).
	// Default: 0 (not reported)
	FirmwareVersion uint32 `yaml:"firmware-version" json:"firmware_version" mapstructure:"firmware-version"`
}

// DefaultConfig returns a Config with sensible default values.
// Note: Storage must still be set before use.
func DefaultConfig() *Config {
	return &Config{
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256},
		MaxCredentials:             DefaultMaxCredentials,
		MaxResidentCredentials:     DefaultMaxResidentCredentials,
		PINMinLength:               DefaultPINMinLength,
		PINMaxRetries:              DefaultPINMaxRetries,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		UserPresenceTimeout:        30 * time.Second,
		AttestationFormat:          "none",
		Storage:                    nil,
		UnifiedPIN:                 true,
	}
}

// SetDefaults sets default values for any zero-valued fields.
// This allows partial configuration while ensuring all fields have valid values.
func (c *Config) SetDefaults() {
	if c.AAGUID == [16]byte{} {
		c.AAGUID = DefaultAAGUID
	}

	if len(c.SupportedAlgorithms) == 0 {
		c.SupportedAlgorithms = []int{COSEAlgES256}
	}

	if c.MaxCredentials <= 0 {
		c.MaxCredentials = DefaultMaxCredentials
	}

	if c.MaxResidentCredentials <= 0 {
		c.MaxResidentCredentials = DefaultMaxResidentCredentials
	}

	if c.PINMinLength < DefaultPINMinLength {
		c.PINMinLength = DefaultPINMinLength
	}

	if c.PINMaxRetries <= 0 {
		c.PINMaxRetries = DefaultPINMaxRetries
	}

	if c.UserPresenceTimeout == 0 {
		c.UserPresenceTimeout = 30 * time.Second
	}

	if c.AttestationFormat == "" {
		c.AttestationFormat = "none"
	}

	// CTAP2.1 requires user verification (PIN or built-in UV) when credential
	// management is enabled. Force EnablePIN to prevent advertising FIDO_2_1
	// without a functional UV method, which Chrome rejects.
	if c.EnableCredentialManagement && !c.EnablePIN {
		c.EnablePIN = true
	}
}

// Validate validates the configuration and returns an error if invalid.
// This should be called after SetDefaults() or after all fields are configured.
func (c *Config) Validate() error {
	if c == nil {
		return ErrNilConfig
	}

	if len(c.SupportedAlgorithms) == 0 {
		return ErrNoAlgorithms
	}

	for _, alg := range c.SupportedAlgorithms {
		if !isSupportedAlgorithm(alg) {
			return ErrUnsupportedAlgorithm
		}
	}

	if c.MaxCredentials <= 0 {
		return ErrInvalidMaxCredentials
	}

	if c.MaxResidentCredentials <= 0 || c.MaxResidentCredentials > c.MaxCredentials {
		return ErrInvalidMaxResidentCreds
	}

	if c.PINMinLength < 4 {
		return ErrInvalidPINMinLength
	}

	if c.PINMaxRetries <= 0 {
		return ErrInvalidPINMaxRetries
	}

	if c.Storage == nil {
		return ErrNilStorage
	}

	return nil
}

// SupportsAlgorithm checks if the given algorithm is supported by this configuration.
func (c *Config) SupportsAlgorithm(algorithm int) bool {
	for _, alg := range c.SupportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// isSupportedAlgorithm checks if an algorithm is one we can implement.
func isSupportedAlgorithm(algorithm int) bool {
	switch algorithm {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA:
		return true
	default:
		return false
	}
}
