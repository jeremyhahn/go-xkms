// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package authenticator provides a native software FIDO2/CTAP2 authenticator
// implementation for go-keychain. This authenticator can be used for testing,
// development, and as a software-based credential storage solution when hardware
// security keys are not available.
package authenticator

import (
	"errors"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
)

// Default AAGUID for go-keychain authenticator.
// ASCII "go-keychain" (11 bytes) + null padding + version byte.
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
	// This is required for go-keychain key derivation functionality.
	// Default: true
	EnableHMACSecret bool `yaml:"enable-hmac-secret" json:"enable_hmac_secret" mapstructure:"enable-hmac-secret"`

	// UserPresenceHandler is the handler for user presence and verification requests.
	// If nil, an AutoGrantHandler is used (auto-approve all requests).
	// Default: nil (auto-grant)
	UserPresenceHandler UserPresenceHandler `yaml:"-" json:"-" mapstructure:"-"`

	// UserPresenceTimeout is the timeout for user presence/verification requests.
	// Only used if UserPresenceHandler is set to an interactive handler.
	// Default: 30 seconds
	UserPresenceTimeout time.Duration `yaml:"user-presence-timeout" json:"user_presence_timeout" mapstructure:"user-presence-timeout"`

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
