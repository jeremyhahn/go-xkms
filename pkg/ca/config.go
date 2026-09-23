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

package ca

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// Default Configuration Values
// =============================================================================

const (
	// Default validity periods in days
	DefaultRootValidityYears         = 10
	DefaultIntermediateValidityYears = 5
	DefaultCertValidityDays          = 365

	// Default key configuration
	DefaultKeyAlgorithm = "ECDSA"
	DefaultKeyCurve     = "P-256"
	DefaultRSAKeySize   = 2048
)

// =============================================================================
// Identity Configuration
// =============================================================================

// Identity represents a CA identity (root or intermediate).
//
// Each identity has a subject, validity period, key configuration, and optional
// parent reference for intermediate CAs.
type Identity struct {
	// Subject contains the distinguished name fields for this CA
	// Uses the Subject type from types.go
	Subject Subject `yaml:"subject" json:"subject" mapstructure:"subject"`

	// Valid specifies the certificate validity period in years
	// For root CAs, this is typically 10 years
	// For intermediate CAs, this is typically 5 years
	Valid int `yaml:"valid" json:"valid" mapstructure:"valid"`

	// Keys contains the key configurations for this identity
	// Multiple keys can be configured for multi-key CA setups
	// (e.g., RSA + ECDSA for hybrid certificates)
	Keys []*types.KeyConfig `yaml:"keys" json:"keys" mapstructure:"keys"`

	// SANS contains Subject Alternative Names for this identity
	SANS *SubjectAlternativeNames `yaml:"sans,omitempty" json:"sans,omitempty" mapstructure:"sans"`

	// IsRoot indicates whether this is a root CA identity
	// Root CAs self-sign their certificates
	IsRoot bool `yaml:"is-root" json:"is_root" mapstructure:"is-root"`

	// ParentCA specifies the CN of the parent CA for intermediate CAs
	// This is used to locate the signing CA in the hierarchy
	ParentCA string `yaml:"parent-ca,omitempty" json:"parent_ca,omitempty" mapstructure:"parent-ca"`

	// CRLDistributionPoints specifies URLs where the CRL can be retrieved.
	CRLDistributionPoints []string `yaml:"crl-distribution-points,omitempty" json:"crl_distribution_points,omitempty" mapstructure:"crl-distribution-points"`

	// OCSPServers specifies URLs of OCSP responders.
	OCSPServers []string `yaml:"ocsp-servers,omitempty" json:"ocsp_servers,omitempty" mapstructure:"ocsp-servers"`

	// IssuingCertificateURLs specifies URLs where the issuing CA certificate
	// can be retrieved (Authority Information Access).
	IssuingCertificateURLs []string `yaml:"issuing-certificate-urls,omitempty" json:"issuing_certificate_urls,omitempty" mapstructure:"issuing-certificate-urls"`

	// PolicyIdentifiers specifies certificate policy OIDs.
	PolicyIdentifiers []string `yaml:"policy-identifiers,omitempty" json:"policy_identifiers,omitempty" mapstructure:"policy-identifiers"`

	// CRLValidityDays is the validity period for generated CRLs.
	// Default: DefaultCRLValidityDays (7 days)
	CRLValidityDays int `yaml:"crl-validity-days,omitempty" json:"crl_validity_days,omitempty" mapstructure:"crl-validity-days"`

	// MaxPathLength specifies the maximum number of intermediate CAs
	// that can appear below this CA in the certificate chain.
	// Default: 0 for intermediate CAs, 1 for root CAs.
	MaxPathLength int `yaml:"max-path-length,omitempty" json:"max_path_length,omitempty" mapstructure:"max-path-length"`

	// MaxPathLengthZero indicates whether MaxPathLength should be set to 0
	// (as opposed to being absent from the certificate).
	MaxPathLengthZero bool `yaml:"max-path-length-zero,omitempty" json:"max_path_length_zero,omitempty" mapstructure:"max-path-length-zero"`

	// Keystores holds per-backend configuration (SRK handle, PIN, password,
	// platform policy) for the backends named by this identity's Keys[*]
	// StoreType. Every key is always routed to its backend via
	// Params.BackendForStore / Identity.Keys[*].StoreType regardless of
	// whether Keystores is set; a nil (or nil sub-field) entry here just
	// means that backend uses its zero-value settings. Optional.
	Keystores *CAKeystoresConfig `yaml:"keystores,omitempty" json:"keystores,omitempty" mapstructure:"keystores"`
}

// =============================================================================
// Per-Identity Keystore Configuration
// =============================================================================
//
// These types describe the "keystores:" block that the platform YAML
// declares per CA identity: per-backend settings (SRK handle, PIN, password,
// platform policy) for the backends its Keys[*] StoreType names. They are
// optional; a nil CAKeystoresConfig (or nil sub-field) means that backend
// uses its zero-value settings, not that the backend goes unused.

// CAKeystoreSoftwareConfig carries per-identity configuration for the
// software (PKCS#8) backend.
type CAKeystoreSoftwareConfig struct {
	// PlatformPolicy enables TPM platform policy binding for software keys
	// that are encrypted-at-rest under a TPM SRK.
	PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`

	// Password is the passphrase used to protect software CA keys at rest
	// (encrypted PKCS#8). When non-empty it is applied as the fallback
	// key-level password for any key in this identity whose KeyConfig.Password
	// is empty. Operators SHOULD source this from a secrets manager or the
	// node's PIN backend rather than embedding it directly in YAML.
	//
	// Password decodes from, and re-encodes to, a plain reference string in
	// YAML/JSON; the resolved plaintext is sealed into this field's own
	// memguard enclave rather than kept as a plain Go string. See
	// types.SecretValue and types.NewPasswordFromSecretValue.
	Password types.SecretValue `yaml:"password,omitempty" json:"password,omitempty" mapstructure:"password"`
}

// CAKeystoreTPM2Config carries per-identity configuration for the tpm2 backend.
// Mirrors tpm2.PlatformSRKConfig but lives in pkg/ca so the CA package keeps
// zero dependency on pkg/tpm2.
type CAKeystoreTPM2Config struct {
	// SRKHandle is the persistent TPM handle for the SRK used to wrap CA keys
	// (e.g. 0x81000001).
	SRKHandle uint32 `yaml:"srk-handle" json:"srk_handle" mapstructure:"srk-handle"`
	// SRKAuth is a KMS URI resolving to the SRK password (e.g.
	// "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=base64").
	SRKAuth string `yaml:"srk-auth,omitempty" json:"srk_auth,omitempty" mapstructure:"srk-auth"`
	// PlatformPolicy enables PCR-bound platform policy on TPM CA keys.
	PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}

// CAKeystorePKCS11Config carries per-identity configuration for PKCS#11 backends.
type CAKeystorePKCS11Config struct {
	Pin    string `yaml:"pin,omitempty" json:"pin,omitempty" mapstructure:"pin"`
	Slot   int    `yaml:"slot,omitempty" json:"slot,omitempty" mapstructure:"slot"`
	Module string `yaml:"module,omitempty" json:"module,omitempty" mapstructure:"module"`
}

// CAKeystoresConfig holds per-backend keystore configuration for one CA
// identity. Each field corresponds to a well-known store type; nil fields are
// ignored. This maps to the "keystores:" block in the platform YAML config.
type CAKeystoresConfig struct {
	Software *CAKeystoreSoftwareConfig `yaml:"software,omitempty" json:"software,omitempty" mapstructure:"software"`
	TPM2     *CAKeystoreTPM2Config     `yaml:"tpm2,omitempty" json:"tpm2,omitempty" mapstructure:"tpm2"`
	PKCS11   *CAKeystorePKCS11Config   `yaml:"pkcs11,omitempty" json:"pkcs11,omitempty" mapstructure:"pkcs11"`
}

// Validate checks that the Identity configuration is valid.
func (id *Identity) Validate() error {
	if id.Subject.CommonName == "" {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "common name is required"}
	}
	if id.Valid <= 0 {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "validity period must be positive"}
	}
	if len(id.Keys) == 0 {
		return &errs.Joined{Lead: ErrInvalidConfig, Cause: ErrNoKeysConfigured}
	}
	return nil
}

// GetValidityDays returns the validity period in days.
func (id *Identity) GetValidityDays() int {
	return id.Valid * 365
}

// GetCRLValidityDays returns the CRL validity period in days.
// Returns CRLValidityDays if > 0, otherwise DefaultCRLValidityDays.
func (id *Identity) GetCRLValidityDays() int {
	if id.CRLValidityDays > 0 {
		return id.CRLValidityDays
	}
	return DefaultCRLValidityDays
}

// GetStoreType returns the primary (Keys[0]) keystore type for this
// identity. This preserves custom backend names (e.g., "pkcs8-ca2") instead
// of converting them to "unknown" via ParseStoreType, allowing the xkms
// facade to route operations to the correct registered backend. Returns
// types.StoreSoftware when no keys are configured or Keys[0].StoreType is
// unset.
func (id *Identity) GetStoreType() types.StoreType {
	if len(id.Keys) == 0 || id.Keys[0] == nil || id.Keys[0].StoreType == "" {
		return types.StoreSoftware
	}
	return id.Keys[0].StoreType
}

// =============================================================================
// Multi-Identity CA Configuration
// =============================================================================

// MultiIdentityCAConfig represents the configuration for a CA with multiple
// identities (root and one or more intermediate CAs).
//
// The configuration supports:
//   - Single root CA (one identity with IsRoot=true)
//   - Root + intermediate CA hierarchy (multiple identities)
//   - Multiple intermediate CAs in a chain
//
// The SelectedCA field determines which CA is used for issuing certificates.
// Index 0 is always the root CA, and indices 1+ are intermediate CAs.
type MultiIdentityCAConfig struct {
	// Identity contains all CA identities (root and intermediates)
	// Index 0 must be the root CA (IsRoot=true)
	Identity []Identity `yaml:"identity" json:"identity" mapstructure:"identity"`

	// SelectedCA specifies which identity to use for issuing certificates
	// 0 = root CA, 1+ = intermediate CAs
	SelectedCA int `yaml:"selected-ca" json:"selected_ca" mapstructure:"selected-ca"`

	// DefaultValidityDays is the default validity period for issued certificates
	DefaultValidityDays int `yaml:"default-validity-days" json:"default_validity_days" mapstructure:"default-validity-days"`

	// IncludeLocalhostSANS adds localhost and 127.0.0.1 to all issued certificates
	// Useful for development environments
	IncludeLocalhostSANS bool `yaml:"include-localhost-sans" json:"include_localhost_sans" mapstructure:"include-localhost-sans"`

	// HomeDir is the base directory for CA storage
	// Keys and certificates are stored relative to this path
	HomeDir string `yaml:"home-dir" json:"home_dir" mapstructure:"home-dir"`

	// RequireKeyPassword is an opt-in operator knob that forces every
	// software-backed CA key to carry a non-empty password, ensuring the
	// key is persisted as encrypted PKCS#8. The default is false: an empty
	// password is permitted and the key is written as plaintext PKCS#8 —
	// this is the correct posture when the filesystem or volume already
	// provides equivalent protection, or for ephemeral/development setups.
	//
	// Set to true only when you want the CA itself to reject empty passwords
	// at key-generation time with ErrKeyPasswordRequired, before any I/O
	// occurs. The low-level pkcs8 backend's AllowPlaintextKeys knob remains
	// an independent, lower-level control for callers that use the raw
	// pkcs8.PKCS8Backend directly.
	RequireKeyPassword bool `yaml:"require-key-password" json:"require_key_password" mapstructure:"require-key-password"`
}

// Validate checks that the configuration is valid.
func (c *MultiIdentityCAConfig) Validate() error {
	if len(c.Identity) == 0 {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "at least one identity is required"}
	}

	// First identity must be root CA
	if !c.Identity[0].IsRoot {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "first identity must be root CA (IsRoot=true)"}
	}

	// Validate each identity
	for i, id := range c.Identity {
		if err := id.Validate(); err != nil {
			return &errs.Joined{Lead: ErrInvalidConfig, Detail: fmt.Sprintf("identity[%d] validation failed", i), Cause: err}
		}
	}

	// A non-empty ParentCA must name the root or an EARLIER identity in the
	// list (issuers are created in list order, so forward references cannot
	// be signed). The root itself must not reference a parent.
	if c.Identity[0].ParentCA != "" {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "root identity must not set parent-ca"}
	}
	for i := 1; i < len(c.Identity); i++ {
		parent := c.Identity[i].ParentCA
		if parent == "" {
			continue
		}
		known := false
		for j := 0; j < i; j++ {
			if c.Identity[j].Subject.CommonName == parent {
				known = true
				break
			}
		}
		if !known {
			return &errs.Joined{Lead: ErrInvalidConfig, Cause: &ErrUnknownParentCA{
				Identity: c.Identity[i].Subject.CommonName,
				ParentCA: parent,
			}}
		}
	}

	// SelectedCA must be valid
	if c.SelectedCA < 0 || c.SelectedCA >= len(c.Identity) {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: fmt.Sprintf("selected CA index %d is out of range", c.SelectedCA)}
	}

	return nil
}

// HasIntermediate returns true if the CA has intermediate identities.
func (c *MultiIdentityCAConfig) HasIntermediate() bool {
	return len(c.Identity) > 1
}

// RootIdentity returns the root CA identity.
func (c *MultiIdentityCAConfig) RootIdentity() *Identity {
	if len(c.Identity) == 0 {
		return nil
	}
	return &c.Identity[0]
}

// IssuingIdentity returns the identity used for issuing certificates.
// This is determined by SelectedCA.
func (c *MultiIdentityCAConfig) IssuingIdentity() *Identity {
	if c.SelectedCA < 0 || c.SelectedCA >= len(c.Identity) {
		return nil
	}
	return &c.Identity[c.SelectedCA]
}

// IntermediateIdentities returns all intermediate CA identities (excludes root).
func (c *MultiIdentityCAConfig) IntermediateIdentities() []Identity {
	if len(c.Identity) <= 1 {
		return nil
	}
	return c.Identity[1:]
}

// GetDefaultValidityDays returns the default certificate validity in days.
func (c *MultiIdentityCAConfig) GetDefaultValidityDays() int {
	if c.DefaultValidityDays > 0 {
		return c.DefaultValidityDays
	}
	return DefaultCertValidityDays
}

// =============================================================================
// Default Configurations
// =============================================================================

// DefaultMultiIdentityCAConfig returns a default configuration with
// a single root CA identity. RequireKeyPassword defaults to false:
// an empty key password is allowed and results in a plaintext PKCS#8
// key. Set RequireKeyPassword to true when operators must supply an
// explicit password for every CA signing key.
func DefaultMultiIdentityCAConfig() *MultiIdentityCAConfig {
	return &MultiIdentityCAConfig{
		Identity: []Identity{
			{
				Subject: Subject{
					CommonName:   "Root CA",
					Organization: "Organization",
					Country:      "US",
				},
				Valid:         DefaultRootValidityYears,
				Keys:          DefaultKeyConfig(),
				IsRoot:        true,
				MaxPathLength: 1,
			},
		},
		SelectedCA:          0,
		DefaultValidityDays: DefaultCertValidityDays,
		RequireKeyPassword:  false,
	}
}

// DefaultMultiIdentityCAConfigWithIntermediate returns a default configuration
// with a root CA and one intermediate CA. RequireKeyPassword defaults to false.
func DefaultMultiIdentityCAConfigWithIntermediate() *MultiIdentityCAConfig {
	return &MultiIdentityCAConfig{
		Identity: []Identity{
			{
				Subject: Subject{
					CommonName:   "Root CA",
					Organization: "Organization",
					Country:      "US",
				},
				Valid:         DefaultRootValidityYears,
				Keys:          DefaultKeyConfig(),
				IsRoot:        true,
				MaxPathLength: 1,
			},
			{
				Subject: Subject{
					CommonName:   "Intermediate CA",
					Organization: "Organization",
					Country:      "US",
				},
				Valid:  DefaultIntermediateValidityYears,
				Keys:   DefaultKeyConfig(),
				IsRoot: false,
				// ParentCA deliberately unset: with a single intermediate the
				// sequential default (signed by the previous identity — the
				// root) yields the identical topology, and a hardcoded name
				// here would go stale the moment a caller renames the root's
				// CommonName. Multi-intermediate (sibling) hierarchies set
				// ParentCA explicitly per identity.
				MaxPathLengthZero: true,
			},
		},
		SelectedCA:          1, // Use intermediate for issuing
		DefaultValidityDays: DefaultCertValidityDays,
		RequireKeyPassword:  false,
	}
}

// DefaultKeyConfig returns a default key configuration.
func DefaultKeyConfig() []*types.KeyConfig {
	return []*types.KeyConfig{
		{
			KeyAlgorithm:       types.AlgorithmECDSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigECDSAWithSHA256,
			StoreType:          types.StoreSoftware,
			ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
		},
	}
}

// =============================================================================
// Configuration Builder
// =============================================================================

// ConfigBuilder provides a fluent interface for building CA configurations.
type ConfigBuilder struct {
	config *MultiIdentityCAConfig
	err    error
}

// NewConfigBuilder creates a new configuration builder.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: &MultiIdentityCAConfig{
			Identity:            []Identity{},
			SelectedCA:          0,
			DefaultValidityDays: DefaultCertValidityDays,
		},
	}
}

// WithRootCA adds a root CA identity. keystoreType, when non-empty, is
// applied to any key in keys whose own StoreType is unset — it does not
// override a key's explicit StoreType.
func (b *ConfigBuilder) WithRootCA(subject Subject, validYears int, keys []*types.KeyConfig, keystoreType types.StoreType) *ConfigBuilder {
	if b.err != nil {
		return b
	}

	if len(keys) == 0 {
		keys = DefaultKeyConfig()
	}
	applyDefaultStoreType(keys, keystoreType)

	b.config.Identity = append([]Identity{
		{
			Subject: subject,
			Valid:   validYears,
			Keys:    keys,
			IsRoot:  true,
		},
	}, b.config.Identity...)

	return b
}

// WithIntermediateCA adds an intermediate CA identity. keystoreType, when
// non-empty, is applied to any key in keys whose own StoreType is unset — it
// does not override a key's explicit StoreType.
func (b *ConfigBuilder) WithIntermediateCA(subject Subject, validYears int, keys []*types.KeyConfig, keystoreType types.StoreType, parentCA string) *ConfigBuilder {
	if b.err != nil {
		return b
	}

	if len(keys) == 0 {
		keys = DefaultKeyConfig()
	}
	applyDefaultStoreType(keys, keystoreType)

	b.config.Identity = append(b.config.Identity, Identity{
		Subject:  subject,
		Valid:    validYears,
		Keys:     keys,
		IsRoot:   false,
		ParentCA: parentCA,
	})

	return b
}

// applyDefaultStoreType sets StoreType on every key in keys whose own
// StoreType is unset. A no-op when keystoreType is empty.
func applyDefaultStoreType(keys []*types.KeyConfig, keystoreType types.StoreType) {
	if keystoreType == "" {
		return
	}
	for _, k := range keys {
		if k != nil && k.StoreType == "" {
			k.StoreType = keystoreType
		}
	}
}

// WithSelectedCA sets the issuing CA index.
func (b *ConfigBuilder) WithSelectedCA(index int) *ConfigBuilder {
	if b.err != nil {
		return b
	}
	b.config.SelectedCA = index
	return b
}

// WithDefaultValidityDays sets the default certificate validity.
func (b *ConfigBuilder) WithDefaultValidityDays(days int) *ConfigBuilder {
	if b.err != nil {
		return b
	}
	b.config.DefaultValidityDays = days
	return b
}

// WithHomeDir sets the home directory for CA storage.
func (b *ConfigBuilder) WithHomeDir(dir string) *ConfigBuilder {
	if b.err != nil {
		return b
	}
	b.config.HomeDir = dir
	return b
}

// WithIncludeLocalhostSANS enables adding localhost SANs to all certificates.
func (b *ConfigBuilder) WithIncludeLocalhostSANS(include bool) *ConfigBuilder {
	if b.err != nil {
		return b
	}
	b.config.IncludeLocalhostSANS = include
	return b
}

// Build validates and returns the configuration.
func (b *ConfigBuilder) Build() (*MultiIdentityCAConfig, error) {
	if b.err != nil {
		return nil, b.err
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	return b.config, nil
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// ToKeyAttributes converts an Identity's primary key configuration to KeyAttributes.
// Returns nil if the identity has no keys configured.
// IMPORTANT: This method sets the CN from the Identity's Subject.CommonName
// to ensure keys are stored with the correct identifier.
//
// Password precedence (highest to lowest):
//  1. KeyConfig.Password — per-key password set directly on the key entry
//  2. Keystores.Software.Password — identity-wide software keystore password
//
// Both are wired through types.KeyAttributesFromConfig so that the pkcs8
// backend writes encrypted-at-rest PKCS#8 when a password is present.
func (id *Identity) ToKeyAttributes() (*types.KeyAttributes, error) {
	if len(id.Keys) == 0 {
		return nil, ErrNoKeysConfigured
	}
	attrs, err := types.KeyAttributesFromConfig(id.Keys[0])
	if err != nil {
		return nil, err
	}
	// CRITICAL: Set the CN from the Identity's Subject, not from the KeyConfig
	// This ensures keys are stored and retrieved using the certificate's CommonName
	attrs.CN = id.Subject.CommonName

	// Apply identity-level software keystore password as fallback when the
	// per-key password was not set (Password is nil after KeyAttributesFromConfig).
	if attrs.Password == nil && id.Keystores != nil && id.Keystores.Software != nil {
		pw, err := types.NewPasswordFromSecretValue(&id.Keystores.Software.Password)
		if err != nil {
			return nil, err
		}
		attrs.Password = pw
	}

	return attrs, nil
}

// GetSignatureAlgorithm returns the appropriate x509.SignatureAlgorithm
// for the identity's primary key configuration.
func (id *Identity) GetSignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	if len(id.Keys) == 0 {
		return x509.UnknownSignatureAlgorithm, ErrNoKeysConfigured
	}

	keyConf := id.Keys[0]

	// If explicitly configured, use that
	if keyConf.SignatureAlgorithm != "" {
		return types.ParseSignatureAlgorithm(string(keyConf.SignatureAlgorithm))
	}

	// Otherwise derive from key algorithm and curve/size
	keyAlgo, err := types.ParseKeyAlgorithm(string(keyConf.KeyAlgorithm))
	if err != nil {
		return x509.UnknownSignatureAlgorithm, err
	}

	switch keyAlgo {
	case x509.RSA:
		return x509.SHA256WithRSA, nil
	case x509.ECDSA:
		curveName := DefaultKeyCurve
		if keyConf.ECCConfig != nil && keyConf.ECCConfig.Curve != "" {
			curveName = string(keyConf.ECCConfig.Curve)
		}
		parsedCurve, _ := types.ParseCurve(curveName)
		if parsedCurve == nil {
			return x509.ECDSAWithSHA256, nil
		}
		switch parsedCurve.Params().BitSize {
		case 224, 256:
			return x509.ECDSAWithSHA256, nil
		case 384:
			return x509.ECDSAWithSHA384, nil
		case 521:
			return x509.ECDSAWithSHA512, nil
		default:
			return x509.ECDSAWithSHA256, nil
		}
	case x509.Ed25519:
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, &errs.Detail{Err: ErrInvalidKeyAlgorithm, Detail: keyAlgo.String()}
	}
}

// GetKeyAlgorithm returns the x509.PublicKeyAlgorithm for the identity's
// primary key configuration.
func (id *Identity) GetKeyAlgorithm() (x509.PublicKeyAlgorithm, error) {
	if len(id.Keys) == 0 {
		return x509.UnknownPublicKeyAlgorithm, ErrNoKeysConfigured
	}
	return types.ParseKeyAlgorithm(string(id.Keys[0].KeyAlgorithm))
}

// GetCurve returns the elliptic curve for ECDSA keys.
// Returns nil for non-ECDSA keys.
func (id *Identity) GetCurve() elliptic.Curve {
	if len(id.Keys) == 0 {
		return nil
	}
	keyConf := id.Keys[0]
	if keyConf.ECCConfig == nil || keyConf.ECCConfig.Curve == "" {
		return nil
	}
	curve, _ := types.ParseCurve(string(keyConf.ECCConfig.Curve))
	return curve
}

// GetKeySize returns the RSA key size.
// Returns 0 for non-RSA keys or if not configured.
func (id *Identity) GetKeySize() int {
	if len(id.Keys) == 0 {
		return 0
	}
	if id.Keys[0].RSAConfig == nil {
		return 0
	}
	return id.Keys[0].RSAConfig.KeySize
}
