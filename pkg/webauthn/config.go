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

package webauthn

import (
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config configures the WebAuthn service.
type Config struct {
	// RPID is the Relying Party identifier, typically the domain name.
	// Example: "example.com"
	RPID string `yaml:"id" json:"id" mapstructure:"id"`

	// RPDisplayName is the human-readable name of the Relying Party.
	// Example: "Example Corp"
	RPDisplayName string `yaml:"display_name" json:"display_name" mapstructure:"display_name"`

	// RPOrigins are the allowed origins for WebAuthn operations.
	// Example: []string{"https://example.com", "https://www.example.com"}
	RPOrigins []string `yaml:"origins" json:"origins" mapstructure:"origins"`

	// RPIcon is an optional URL to the Relying Party's icon (deprecated in WebAuthn L2).
	RPIcon string `yaml:"icon,omitempty" json:"icon,omitempty" mapstructure:"icon"`

	// Timeout is the timeout for WebAuthn ceremonies in milliseconds.
	// Default: 60000 (60 seconds)
	Timeout time.Duration `yaml:"timeout" json:"timeout" mapstructure:"timeout"`

	// UserVerification specifies the user verification requirement.
	// Options: "required", "preferred", "discouraged"
	// Default: "preferred"
	UserVerification string `yaml:"user_verification" json:"user_verification" mapstructure:"user_verification"`

	// AttestationPreference specifies the attestation conveyance preference.
	// Options: "none", "indirect", "direct", "enterprise"
	// Default: "none"
	AttestationPreference string `yaml:"attestation" json:"attestation" mapstructure:"attestation"`

	// ResidentKeyRequirement specifies whether to require resident keys (passkeys).
	// Options: "required", "preferred", "discouraged"
	// Default: "preferred"
	ResidentKeyRequirement string `yaml:"resident_key" json:"resident_key" mapstructure:"resident_key"`

	// AuthenticatorAttachment limits the type of authenticators allowed.
	// Options: "platform", "cross-platform", "" (any)
	// Default: "" (any)
	AuthenticatorAttachment string `yaml:"authenticator_attachment" json:"authenticator_attachment" mapstructure:"authenticator_attachment"`

	// Debug enables debug logging.
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.RPID == "" {
		return fmt.Errorf("RPID is required")
	}
	if c.RPDisplayName == "" {
		return fmt.Errorf("RPDisplayName is required")
	}
	if len(c.RPOrigins) == 0 {
		return fmt.Errorf("at least one RPOrigin is required")
	}

	// Validate user verification
	switch c.UserVerification {
	case "", "required", "preferred", "discouraged":
		// Valid
	default:
		return fmt.Errorf("invalid user verification: %s", c.UserVerification)
	}

	// Validate attestation preference
	switch c.AttestationPreference {
	case "", "none", "indirect", "direct", "enterprise":
		// Valid
	default:
		return fmt.Errorf("invalid attestation preference: %s", c.AttestationPreference)
	}

	// Validate resident key requirement
	switch c.ResidentKeyRequirement {
	case "", "required", "preferred", "discouraged":
		// Valid
	default:
		return fmt.Errorf("invalid resident key requirement: %s", c.ResidentKeyRequirement)
	}

	// Validate authenticator attachment
	switch c.AuthenticatorAttachment {
	case "", "platform", "cross-platform":
		// Valid
	default:
		return fmt.Errorf("invalid authenticator attachment: %s", c.AuthenticatorAttachment)
	}

	return nil
}

// SetDefaults sets default values for unset configuration fields.
func (c *Config) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 60 * time.Second
	}
	if c.UserVerification == "" {
		c.UserVerification = "preferred"
	}
	if c.AttestationPreference == "" {
		c.AttestationPreference = "none"
	}
	if c.ResidentKeyRequirement == "" {
		c.ResidentKeyRequirement = "preferred"
	}
}

// ToWebAuthnConfig converts the Config to the go-webauthn library's configuration.
func (c *Config) ToWebAuthnConfig() *webauthn.Config {
	cfg := &webauthn.Config{
		RPID:          c.RPID,
		RPDisplayName: c.RPDisplayName,
		RPOrigins:     c.RPOrigins,
		Debug:         c.Debug,
	}

	// Set timeout in milliseconds
	if c.Timeout > 0 {
		cfg.Timeouts = webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    c.Timeout,
				TimeoutUVD: c.Timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    c.Timeout,
				TimeoutUVD: c.Timeout,
			},
		}
	}

	// Set attestation preference
	switch c.AttestationPreference {
	case "none":
		cfg.AttestationPreference = protocol.PreferNoAttestation
	case "indirect":
		cfg.AttestationPreference = protocol.PreferIndirectAttestation
	case "direct":
		cfg.AttestationPreference = protocol.PreferDirectAttestation
	case "enterprise":
		cfg.AttestationPreference = protocol.PreferEnterpriseAttestation
	}

	// Set authenticator selection
	cfg.AuthenticatorSelection = protocol.AuthenticatorSelection{}

	// Set user verification
	switch c.UserVerification {
	case "required":
		cfg.AuthenticatorSelection.UserVerification = protocol.VerificationRequired
	case "preferred":
		cfg.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
	case "discouraged":
		cfg.AuthenticatorSelection.UserVerification = protocol.VerificationDiscouraged
	}

	// Set resident key requirement
	switch c.ResidentKeyRequirement {
	case "required":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementRequired
	case "preferred":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementPreferred
	case "discouraged":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
	}

	// Set authenticator attachment
	switch c.AuthenticatorAttachment {
	case "platform":
		cfg.AuthenticatorSelection.AuthenticatorAttachment = protocol.Platform
	case "cross-platform":
		cfg.AuthenticatorSelection.AuthenticatorAttachment = protocol.CrossPlatform
	}

	return cfg
}
