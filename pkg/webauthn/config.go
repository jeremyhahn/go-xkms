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

package webauthn

import (
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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

	// AllowPublicRegistration controls whether BeginRegistration may create an
	// account for an email it has never seen — that is, whether the relying
	// party accepts open self-service sign-up.
	//
	// Default: false (nil means false). Registration is invite-only unless the
	// operator explicitly opens it, matching the stack-wide registration model
	// (canonical flag iam.self_service_registration.enabled, default off) and
	// the company secure-by-default convention: a setting that can silently
	// produce an open surface is a defect (go-xkms#184, owner ruling
	// 2026-09-01).
	//
	// It remains a *bool rather than a bool so that nil distinguishes "the
	// operator never considered this" from "the operator explicitly chose a
	// policy" — which is what a compliance profile needs in order to flag an
	// explicit open, and what lets a composing host project its own
	// registration flag through without a second default fighting it. When
	// xkms runs as a ServiceModule under a composed host (go-quicbaas), the
	// host-projected value is authoritative: the host writes its
	// iam.self_service_registration decision into this field and the module
	// applies it verbatim.
	//
	// Turning it off does NOT disable enrollment for accounts that already
	// exist: a user provisioned through the authorized CreateUser path still
	// enrolls their first passkey through the same BeginRegistration entry
	// point. Only implicit account creation is withheld. See
	// Service.BeginRegistration.
	AllowPublicRegistration *bool `yaml:"allow_public_registration,omitempty" json:"allow_public_registration,omitempty" mapstructure:"allow_public_registration"`

	// Debug enables debug logging.
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`
}

// PublicRegistrationAllowed reports whether BeginRegistration may create an
// account for an unknown email. An unset AllowPublicRegistration means no:
// registration is closed unless the operator (or the composing host, when
// xkms runs as a ServiceModule) explicitly opens it. A nil Config fails
// closed the same way.
func (c *Config) PublicRegistrationAllowed() bool {
	return c != nil && c.AllowPublicRegistration != nil && *c.AllowPublicRegistration
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.RPID == "" {
		return &errs.Message{Msg: "RPID is required"}
	}
	if c.RPDisplayName == "" {
		return &errs.Message{Msg: "RPDisplayName is required"}
	}
	if len(c.RPOrigins) == 0 {
		return &errs.Message{Msg: "at least one RPOrigin is required"}
	}

	// Validate user verification
	switch c.UserVerification {
	case "", "required", "preferred", "discouraged":
		// Valid
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid user verification: %s", c.UserVerification)}
	}

	// Validate attestation preference
	switch c.AttestationPreference {
	case "", "none", "indirect", "direct", "enterprise":
		// Valid
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid attestation preference: %s", c.AttestationPreference)}
	}

	// Validate resident key requirement
	switch c.ResidentKeyRequirement {
	case "", "required", "preferred", "discouraged":
		// Valid
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid resident key requirement: %s", c.ResidentKeyRequirement)}
	}

	// Validate authenticator attachment
	switch c.AuthenticatorAttachment {
	case "", "platform", "cross-platform":
		// Valid
	default:
		return &errs.Message{Msg: fmt.Sprintf("invalid authenticator attachment: %s", c.AuthenticatorAttachment)}
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

	// Set resident key requirement.
	// Both ResidentKey and RequireResidentKey must be set for full compatibility.
	// The legacy RequireResidentKey (*bool) field is needed because some browsers
	// and authenticators rely on it when ResidentKey is omitted from JSON due to
	// omitempty. This mirrors the go-webauthn library's WithResidentKeyRequirement()
	// helper which explicitly sets both fields.
	switch c.ResidentKeyRequirement {
	case "required":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementRequired
		cfg.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyRequired()
	case "preferred":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementPreferred
		cfg.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
	case "discouraged":
		cfg.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
		cfg.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
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
