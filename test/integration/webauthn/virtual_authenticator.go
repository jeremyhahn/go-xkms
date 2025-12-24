//go:build integration

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
	"context"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// VirtualAuthenticatorConfig configures a virtual WebAuthn authenticator.
type VirtualAuthenticatorConfig struct {
	// Protocol is the authenticator protocol (ctap2 or u2f).
	Protocol webauthn.AuthenticatorProtocol

	// Transport is the authenticator transport (usb, ble, nfc, internal).
	Transport webauthn.AuthenticatorTransport

	// HasResidentKey indicates if the authenticator supports resident keys.
	HasResidentKey bool

	// HasUserVerification indicates if the authenticator supports user verification.
	HasUserVerification bool

	// HasLargeBlob indicates if the authenticator supports large blob storage.
	HasLargeBlob bool

	// HasCredBlob indicates if the authenticator supports credential blob.
	HasCredBlob bool

	// HasMinPinLength indicates if the authenticator supports min PIN length.
	HasMinPinLength bool

	// HasPrf indicates if the authenticator supports PRF extension.
	HasPrf bool

	// AutomaticPresenceSimulation automatically simulates user presence.
	AutomaticPresenceSimulation bool

	// IsUserVerified indicates if user verification should succeed.
	IsUserVerified bool
}

// DefaultVirtualAuthenticatorConfig returns a sensible default configuration
// for a virtual authenticator that simulates a USB security key.
func DefaultVirtualAuthenticatorConfig() VirtualAuthenticatorConfig {
	return VirtualAuthenticatorConfig{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Transport:                   webauthn.AuthenticatorTransportUsb,
		HasResidentKey:              true,
		HasUserVerification:         true,
		HasLargeBlob:                false,
		HasCredBlob:                 false,
		HasMinPinLength:             false,
		HasPrf:                      false,
		AutomaticPresenceSimulation: true,
		IsUserVerified:              true,
	}
}

// PlatformAuthenticatorConfig returns a configuration for a platform authenticator
// (like Windows Hello, Touch ID, or Face ID).
// Note: CTAP 2.1 features (HasLargeBlob, HasCredBlob, HasPrf) are disabled for
// compatibility with Chrome's Virtual Authenticator. Use CTAP21PlatformAuthenticatorConfig
// for testing CTAP 2.1 features when supported.
func PlatformAuthenticatorConfig() VirtualAuthenticatorConfig {
	return VirtualAuthenticatorConfig{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Transport:                   webauthn.AuthenticatorTransportInternal,
		HasResidentKey:              true,
		HasUserVerification:         true,
		HasLargeBlob:                false, // CTAP 2.1 feature, not supported by Chrome virtual authenticator
		HasCredBlob:                 false, // CTAP 2.1 feature, not supported by Chrome virtual authenticator
		HasMinPinLength:             false,
		HasPrf:                      false, // CTAP 2.1 feature, not supported by Chrome virtual authenticator
		AutomaticPresenceSimulation: true,
		IsUserVerified:              true,
	}
}

// CTAP21PlatformAuthenticatorConfig returns a configuration for a platform authenticator
// with CTAP 2.1 features enabled. Note: This may not be supported by all versions of
// Chrome's Virtual Authenticator.
func CTAP21PlatformAuthenticatorConfig() VirtualAuthenticatorConfig {
	return VirtualAuthenticatorConfig{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Transport:                   webauthn.AuthenticatorTransportInternal,
		HasResidentKey:              true,
		HasUserVerification:         true,
		HasLargeBlob:                true,
		HasCredBlob:                 true,
		HasMinPinLength:             false,
		HasPrf:                      true,
		AutomaticPresenceSimulation: true,
		IsUserVerified:              true,
	}
}

// U2FAuthenticatorConfig returns a configuration for a legacy U2F authenticator.
func U2FAuthenticatorConfig() VirtualAuthenticatorConfig {
	return VirtualAuthenticatorConfig{
		Protocol:                    webauthn.AuthenticatorProtocolU2f,
		Transport:                   webauthn.AuthenticatorTransportUsb,
		HasResidentKey:              false,
		HasUserVerification:         false,
		HasLargeBlob:                false,
		HasCredBlob:                 false,
		HasMinPinLength:             false,
		HasPrf:                      false,
		AutomaticPresenceSimulation: true,
		IsUserVerified:              false,
	}
}

// VirtualAuthenticator represents a virtual WebAuthn authenticator managed via CDP.
type VirtualAuthenticator struct {
	id     webauthn.AuthenticatorID
	config VirtualAuthenticatorConfig
}

// ID returns the authenticator ID.
func (v *VirtualAuthenticator) ID() webauthn.AuthenticatorID {
	return v.id
}

// EnableWebAuthn enables the WebAuthn domain in Chrome DevTools Protocol.
// This must be called before creating virtual authenticators.
func EnableWebAuthn(enableUI bool) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		return webauthn.Enable().WithEnableUI(enableUI).Do(ctx)
	})
}

// DisableWebAuthn disables the WebAuthn domain.
func DisableWebAuthn() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		return webauthn.Disable().Do(ctx)
	})
}

// AddVirtualAuthenticator creates a virtual authenticator and returns its ID.
func AddVirtualAuthenticator(config VirtualAuthenticatorConfig) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		options := webauthn.VirtualAuthenticatorOptions{
			Protocol:                    config.Protocol,
			Transport:                   config.Transport,
			HasResidentKey:              config.HasResidentKey,
			HasUserVerification:         config.HasUserVerification,
			HasLargeBlob:                config.HasLargeBlob,
			HasCredBlob:                 config.HasCredBlob,
			HasMinPinLength:             config.HasMinPinLength,
			HasPrf:                      config.HasPrf,
			AutomaticPresenceSimulation: config.AutomaticPresenceSimulation,
			IsUserVerified:              config.IsUserVerified,
		}

		_, err := webauthn.AddVirtualAuthenticator(&options).Do(ctx)
		return err
	}
}

// AddVirtualAuthenticatorWithID creates a virtual authenticator and stores its ID.
func AddVirtualAuthenticatorWithID(config VirtualAuthenticatorConfig, authID *webauthn.AuthenticatorID) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		options := webauthn.VirtualAuthenticatorOptions{
			Protocol:                    config.Protocol,
			Transport:                   config.Transport,
			HasResidentKey:              config.HasResidentKey,
			HasUserVerification:         config.HasUserVerification,
			HasLargeBlob:                config.HasLargeBlob,
			HasCredBlob:                 config.HasCredBlob,
			HasMinPinLength:             config.HasMinPinLength,
			HasPrf:                      config.HasPrf,
			AutomaticPresenceSimulation: config.AutomaticPresenceSimulation,
			IsUserVerified:              config.IsUserVerified,
		}

		id, err := webauthn.AddVirtualAuthenticator(&options).Do(ctx)
		if err != nil {
			return err
		}
		*authID = id
		return nil
	}
}

// RemoveVirtualAuthenticator removes a virtual authenticator.
func RemoveVirtualAuthenticator(authID webauthn.AuthenticatorID) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		return webauthn.RemoveVirtualAuthenticator(authID).Do(ctx)
	}
}

// SetUserVerified sets whether user verification should succeed.
func SetUserVerified(authID webauthn.AuthenticatorID, isVerified bool) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		return webauthn.SetUserVerified(authID, isVerified).Do(ctx)
	}
}

// GetCredentials retrieves all credentials from a virtual authenticator.
func GetCredentials(authID webauthn.AuthenticatorID, creds *[]*webauthn.Credential) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		result, err := webauthn.GetCredentials(authID).Do(ctx)
		if err != nil {
			return err
		}
		*creds = result
		return nil
	}
}

// ClearCredentials removes all credentials from a virtual authenticator.
func ClearCredentials(authID webauthn.AuthenticatorID) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		return webauthn.ClearCredentials(authID).Do(ctx)
	}
}

// SetAutomaticPresenceSimulation enables or disables automatic presence simulation.
func SetAutomaticPresenceSimulation(authID webauthn.AuthenticatorID, enabled bool) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		return webauthn.SetAutomaticPresenceSimulation(authID, enabled).Do(ctx)
	}
}
