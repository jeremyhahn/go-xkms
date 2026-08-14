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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
)

// This file is the client ("browser") half of the WebAuthn ceremonies the
// xkey CLI drives. The server half travels over the SDK transport
// (BeginRegistration / FinishRegistration, BeginAuthentication /
// FinishAuthentication); the authenticator half is the canonical CTAP2
// implementation re-exported at sdk/go/fido2, which speaks to whichever
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

	// ErrWebAuthnOptionsInvalid indicates the relying party's ceremony
	// options could not be parsed.
	ErrWebAuthnOptionsInvalid = errors.New("webauthn: relying party ceremony options are invalid")

	// ErrWebAuthnChallengeMissing indicates the ceremony options carried no
	// challenge.
	ErrWebAuthnChallengeMissing = errors.New("webauthn: relying party ceremony options carry no challenge")

	// ErrWebAuthnRPIDMissing indicates the ceremony options carried no
	// relying party ID.
	ErrWebAuthnRPIDMissing = errors.New("webauthn: relying party ceremony options carry no relying party ID")

	// ErrWebAuthnRegistrationFailed indicates the authenticator refused or
	// failed the registration (MakeCredential) ceremony.
	ErrWebAuthnRegistrationFailed = errors.New("webauthn: the authenticator failed the registration ceremony")

	// ErrWebAuthnAssertionFailed indicates the authenticator refused or
	// failed the authentication (GetAssertion) ceremony.
	ErrWebAuthnAssertionFailed = errors.New("webauthn: the authenticator failed the authentication ceremony")
)

// WebAuthnCeremony is the local authenticator half of a WebAuthn ceremony.
// Register turns a relying party's creation options into a
// PublicKeyCredential attestation document; Assert turns its request options
// into a PublicKeyCredential assertion document. Both documents are exactly
// what the server parses in the corresponding finish call.
type WebAuthnCeremony interface {
	// Register performs the registration (navigator.credentials.create)
	// ceremony and returns the attestation JSON.
	Register(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error)

	// Assert performs the authentication (navigator.credentials.get)
	// ceremony and returns the assertion JSON.
	Assert(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error)

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

// fido2Ceremony drives a CTAP2 authenticator over HID through the canonical
// FIDO2 implementation re-exported by the SDK.
type fido2Ceremony struct {
	handler *fido2.FIDO2Handler
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

	handler, err := fido2.NewHandler(&cfg, webauthnEnumeratorFactory())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnAuthenticatorUnavailable, Cause: err}
	}

	devices, err := handler.ListDevices()
	if err != nil {
		_ = handler.Close()
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnAuthenticatorUnavailable, Cause: err}
	}
	if len(devices) == 0 {
		_ = handler.Close()
		return nil, ErrWebAuthnAuthenticatorUnavailable
	}

	return &fido2Ceremony{handler: handler}, nil
}

// Register drives the authenticator through authenticatorMakeCredential and
// assembles the PublicKeyCredential attestation document.
func (c *fido2Ceremony) Register(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opts, err := parseCreationOptions(optionsJSON, origin)
	if err != nil {
		return nil, err
	}

	attestation, err := c.handler.RegisterWebAuthn(opts)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnRegistrationFailed, Cause: err}
	}
	return attestation.PublicKeyCredentialJSON, nil
}

// Assert drives the authenticator through authenticatorGetAssertion and
// assembles the PublicKeyCredential assertion document.
func (c *fido2Ceremony) Assert(ctx context.Context, optionsJSON []byte, origin string) ([]byte, error) {
	assertion, err := c.handler.AssertWithOptionsAndOrigin(ctx, optionsJSON, origin)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnAssertionFailed, Cause: err}
	}
	return assertion, nil
}

// Close releases the authenticator handler.
func (c *fido2Ceremony) Close() error {
	return c.handler.Close()
}

// creationOptionsDocument is the browser-shaped registration options
// document ({"publicKey": {...}}) a relying party serves for
// navigator.credentials.create().
type creationOptionsDocument struct {
	PublicKey *publicKeyCreationOptions `json:"publicKey"`
}

// publicKeyCreationOptions is the subset of
// PublicKeyCredentialCreationOptions a CTAP2 authenticatorMakeCredential
// call needs. Fields the authenticator does not consume (attestation
// preference, excludeCredentials, extensions) are deliberately not decoded.
type publicKeyCreationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	AuthenticatorSelection struct {
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Timeout int `json:"timeout"`
}

// parseCreationOptions decodes a relying party's registration options into
// the structured form the CTAP2 registration ceremony consumes. Both the
// browser-shaped wrapped document ({"publicKey": {...}}) and the bare
// PublicKeyCredentialCreationOptions object are accepted, mirroring the
// assertion path in the canonical FIDO2 package.
//
// The origin is not carried in the options - a browser supplies it from its
// security context - so the caller provides it. An empty origin falls back to
// the WebAuthn same-origin default "https://<rpId>".
func parseCreationOptions(optionsJSON []byte, origin string) (fido2.WebAuthnRegistrationOptions, error) {
	var zero fido2.WebAuthnRegistrationOptions

	if len(optionsJSON) == 0 {
		return zero, &DetailError{Err: ErrWebAuthnOptionsInvalid, Detail: ": options are empty"}
	}

	var wrapped creationOptionsDocument
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		return zero, &SentinelCauseError{Sentinel: ErrWebAuthnOptionsInvalid, Cause: err}
	}

	opts := wrapped.PublicKey
	if opts == nil {
		// No publicKey wrapper: the document is a bare creation-options object.
		opts = &publicKeyCreationOptions{}
		if err := json.Unmarshal(optionsJSON, opts); err != nil {
			return zero, &SentinelCauseError{Sentinel: ErrWebAuthnOptionsInvalid, Cause: err}
		}
	}

	challenge, err := decodeWebAuthnBase64(opts.Challenge)
	if err != nil {
		return zero, &SentinelCauseError{Sentinel: ErrWebAuthnOptionsInvalid, Cause: err}
	}
	if len(challenge) == 0 {
		return zero, ErrWebAuthnChallengeMissing
	}
	if opts.RP.ID == "" {
		return zero, ErrWebAuthnRPIDMissing
	}

	userID, err := decodeWebAuthnBase64(opts.User.ID)
	if err != nil {
		return zero, &SentinelCauseError{Sentinel: ErrWebAuthnOptionsInvalid, Cause: err}
	}

	resolvedOrigin := origin
	if resolvedOrigin == "" {
		resolvedOrigin = "https://" + opts.RP.ID
	}

	return fido2.WebAuthnRegistrationOptions{
		Challenge:               challenge,
		Origin:                  resolvedOrigin,
		RPID:                    opts.RP.ID,
		RPName:                  opts.RP.Name,
		UserID:                  userID,
		UserName:                opts.User.Name,
		UserDisplayName:         opts.User.DisplayName,
		RequireUserVerification: opts.AuthenticatorSelection.UserVerification == "required",
		Timeout:                 time.Duration(opts.Timeout) * time.Millisecond,
	}, nil
}

// decodeWebAuthnBase64 decodes a WebAuthn binary JSON field. WebAuthn
// documents use unpadded base64url, but relying parties have been observed
// emitting the padded form, so both are accepted.
func decodeWebAuthnBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
}

// webauthnOrigin derives the WebAuthn origin from a server URL: the scheme
// and authority with no path, which is what a browser would report. An
// unparsable or scheme-less URL yields an empty string, letting the caller
// fall back to the same-origin default.
func webauthnOrigin(serverURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
