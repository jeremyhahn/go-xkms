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

package cmd

import (
	"context"
	"errors"
	"time"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
)

// This file is the client ("browser") half of the WebAuthn ceremonies the
// xkey CLI drives. The server half travels over the SDK transport
// (BeginRegistration / FinishRegistration, BeginAuthentication /
// FinishAuthentication); the authenticator half is driven by
// webauthnclient.HardwareAdapter, the SDK re-export of the single canonical
// WebAuthn ceremony driver (pkg/webauthn/client), which speaks to whichever
// FIDO2 HID device is attached - including the virtual authenticator that
// "xkey fido2" exposes.

// webauthnCeremonyTimeout bounds a single ceremony, including the user
// presence touch, when the relying party states no timeout of its own.
const webauthnCeremonyTimeout = 60 * time.Second

// WebAuthn ceremony errors.
var (
	// ErrWebAuthnAuthenticatorUnavailable indicates no CTAP2 authenticator
	// could be opened for the ceremony.
	ErrWebAuthnAuthenticatorUnavailable = errors.New("webauthn: no FIDO2 authenticator available; " +
		"attach a security key or start the xkey virtual authenticator with 'xkey fido2'")

	// ErrWebAuthnRegistrationFailed indicates the authenticator refused or
	// failed the registration (MakeCredential) ceremony.
	ErrWebAuthnRegistrationFailed = errors.New("webauthn: the authenticator failed the registration ceremony")

	// ErrWebAuthnAssertionFailed indicates the authenticator refused or
	// failed the authentication (GetAssertion) ceremony.
	ErrWebAuthnAssertionFailed = errors.New("webauthn: the authenticator failed the authentication ceremony")

	// ErrWebAuthnPINRequired indicates the authenticator refused the ceremony
	// because it has a PIN set and none was supplied.
	//
	// It replaces the raw CTAP2_ERR_PIN_REQUIRED, which names neither the PIN
	// nor the way to supply it: a security key configured by the xKey setup
	// wizard has a PIN by default, so this is the FIRST thing an operator
	// meets on a default install, and "fido2: PIN required" reads as a device
	// fault rather than as missing input.
	// The flag names are composed from the same constants addPINFlags
	// declares, so a rename cannot leave this message naming a flag that no
	// longer exists.
	ErrWebAuthnPINRequired = errors.New("webauthn: this authenticator requires a PIN; supply it with --" +
		pinFlagStdin + " (preferred) or the " + pinEnvVar + " environment variable")

	// ErrWebAuthnPINSealFailed indicates a resolved PIN could not be sealed
	// into protected memory before it was carried into a CeremonyRequest.
	ErrWebAuthnPINSealFailed = errors.New("webauthn: failed to seal the PIN into protected memory")
)

// sealCeremonyPIN seals a resolved PIN string into protected memory for a
// CeremonyRequest. An empty pin returns nil, the zero value for "no PIN
// configured" — the ceremony itself decides whether that is acceptable.
func sealCeremonyPIN(pin string) (*secure.Secret, error) {
	if pin == "" {
		return nil, nil
	}
	secret, err := secure.NewSecret([]byte(pin))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnPINSealFailed, Cause: err}
	}
	return secret, nil
}

// CeremonyRequest carries one ceremony's inputs: the relying party's
// server-issued options plus the two things a browser would supply from
// outside them — the origin, which it takes from its security context, and the
// authenticator's CTAP2 PIN, which it prompts the user for.
//
// The fields are named rather than positional because Origin and PIN are both
// strings: a positional signature carrying the two adjacent would let a
// transposition send the PIN to the relying party as an origin.
type CeremonyRequest struct {
	// OptionsJSON is the relying party's BeginRegistration or
	// BeginAuthentication output.
	OptionsJSON []byte

	// Origin is the WebAuthn origin to bind into clientDataJSON. Empty
	// selects the WebAuthn same-origin default "https://<rpId>".
	Origin string

	// PIN is the authenticator's CTAP2 PIN, resolved by resolvePINInput. Nil
	// is correct for an authenticator with no PIN configured; against one
	// that has a PIN set the ceremony fails with ErrWebAuthnPINRequired.
	PIN *secure.Secret
}

// WebAuthnCeremony is the local authenticator half of a WebAuthn ceremony.
// Register turns a relying party's creation options into a
// PublicKeyCredential attestation document; Assert turns its request options
// into a PublicKeyCredential assertion document. Both documents are exactly
// what the server parses in the corresponding finish call.
type WebAuthnCeremony interface {
	// Register performs the registration (navigator.credentials.create)
	// ceremony and returns the attestation JSON.
	Register(ctx context.Context, req CeremonyRequest) ([]byte, error)

	// Assert performs the authentication (navigator.credentials.get)
	// ceremony and returns the assertion JSON.
	Assert(ctx context.Context, req CeremonyRequest) ([]byte, error)

	// Close releases the authenticator.
	Close() error
}

// webauthnCeremonyFactory constructs the ceremony driver. It is a
// package-level variable so tests can substitute an in-process authenticator
// for the attached hardware.
var webauthnCeremonyFactory = newFIDO2Ceremony

// webauthnEnumeratorFactory enumerates the host's CTAP2 HID devices. It is a
// package-level variable so tests can drive the device-discovery paths
// without depending on hardware being attached to the machine.
var webauthnEnumeratorFactory = fido2.NewDefaultEnumerator

// fido2Ceremony drives a CTAP2 authenticator over HID through
// webauthnclient.HardwareAdapter, the SDK re-export of the single canonical
// WebAuthn ceremony driver's hardware authenticator adapter.
type fido2Ceremony struct {
	adapter *webauthnclient.HardwareAdapter
}

// fido2Ceremony satisfies the ceremony contract.
var _ WebAuthnCeremony = (*fido2Ceremony)(nil)

// newFIDO2Ceremony opens the local CTAP2 authenticator. It fails closed when
// no authenticator can be enumerated, so a caller never mistakes a missing
// security key for a completed ceremony.
func newFIDO2Ceremony() (WebAuthnCeremony, error) {
	cfg := fido2.DefaultConfig
	cfg.Timeout = webauthnCeremonyTimeout
	cfg.UserPresenceTimeout = webauthnCeremonyTimeout

	adapter, err := webauthnclient.NewHardwareAdapter(&cfg, webauthnEnumeratorFactory())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnAuthenticatorUnavailable, Cause: err}
	}

	return &fido2Ceremony{adapter: adapter}, nil
}

// Register drives the authenticator through authenticatorMakeCredential and
// assembles the PublicKeyCredential attestation document.
func (c *fido2Ceremony) Register(ctx context.Context, req CeremonyRequest) ([]byte, error) {
	attestation, err := c.adapter.MakeCredential(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: req.OptionsJSON,
		Origin:      req.Origin,
		PIN:         req.PIN,
	})
	if err != nil {
		return nil, ceremonyFailure(ErrWebAuthnRegistrationFailed, req.PIN, err)
	}
	return attestation, nil
}

// Assert drives the authenticator through authenticatorGetAssertion and
// assembles the PublicKeyCredential assertion document.
func (c *fido2Ceremony) Assert(ctx context.Context, req CeremonyRequest) ([]byte, error) {
	assertion, err := c.adapter.GetAssertion(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: req.OptionsJSON,
		Origin:      req.Origin,
		PIN:         req.PIN,
	})
	if err != nil {
		return nil, ceremonyFailure(ErrWebAuthnAssertionFailed, req.PIN, err)
	}
	return assertion, nil
}

// ceremonyFailure classifies an authenticator failure before it reaches the
// operator. An authenticator that answers CTAP2_ERR_PIN_REQUIRED when no PIN
// was supplied is reporting missing INPUT, so it is named as such and the
// flags that supply it are printed; the raw CTAP error is kept as the cause so
// nothing is lost.
//
// The same status when a PIN WAS supplied is not a missing-input problem — it
// means the authenticator rejected an authorization that was attempted — and
// is reported verbatim rather than sending the operator to re-enter a PIN they
// already gave.
func ceremonyFailure(sentinel error, pin *secure.Secret, cause error) error {
	if pin == nil && errors.Is(cause, fido2.ErrPINRequired) {
		return &SentinelCauseError{Sentinel: ErrWebAuthnPINRequired, Cause: cause}
	}
	return &SentinelCauseError{Sentinel: sentinel, Cause: cause}
}

// Close releases the authenticator handle.
func (c *fido2Ceremony) Close() error {
	if c.adapter == nil {
		return nil
	}
	return c.adapter.Close()
}
