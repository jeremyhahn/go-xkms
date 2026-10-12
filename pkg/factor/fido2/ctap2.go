// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package fido2

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// This file adds the LOCAL half of FIDO2 enrollment: driving an attached
// authenticator over CTAP2 to produce the credential that Factor.Enroll then
// stores.
//
// Factor.Enroll already accepts a finished credential (cose_public_key,
// credential_id, aaguid) because in the normal case a browser ran the
// ceremony. At init there is no browser, and xkms owns the canonical CTAP2
// implementation in this stack — so the same factor can produce that input
// itself. This is a feeder for the existing seam, not a second one: the
// credential still lands through Factor.Enroll, stored the same way, verified
// the same way at login.

// deviceLister enumerates attached FIDO2 authenticators.
// *pkgfido2.FIDO2Handler satisfies it.
type deviceLister interface {
	ListDevices() ([]pkgfido2.Device, error)
}

// ctap2Ceremony runs the authenticator half of a WebAuthn registration.
// *pkgfido2.FIDO2Handler satisfies it.
type ctap2Ceremony interface {
	RegisterWebAuthn(opts pkgfido2.WebAuthnRegistrationOptions) (*pkgfido2.WebAuthnAttestation, error)
}

// deviceBinder narrows an authenticator ceremony to one device path.
//
// It exists because the FIDO2 handler performs its OWN device selection from
// its configuration. Without binding, this driver would resolve the operator's
// --passkey-device hint, report that device, and then let the handler enroll
// against a different one — the exact mis-enrollment the ambiguity guard is
// meant to prevent.
type deviceBinder interface {
	BindDevice(path string)
}

// LocalCeremony is the attached-authenticator driver. Wire it into a Factor
// with NewWithLocalCeremony to enable browser-free enrollment at init.
type LocalCeremony struct {
	devices   deviceLister
	ceremony  ctap2Ceremony
	timeout   time.Duration
	userVerif bool
}

// NewLocalCeremony builds the driver over a FIDO2 handler.
//
// timeout bounds the user-presence wait; 0 selects 60s, long enough to find
// and touch a key and short enough that an unattended init fails instead of
// hanging a boot.
//
// A nil handler yields a ceremony that reports itself unavailable and refuses
// to enroll. It must not be stored in the interfaces as a typed nil, which
// would compare non-nil and dereference the handler on first use.
func NewLocalCeremony(handler *pkgfido2.FIDO2Handler, timeout time.Duration) *LocalCeremony {
	if handler == nil {
		return newLocalCeremony(nil, nil, timeout)
	}
	return newLocalCeremony(handler, handler, timeout)
}

// newLocalCeremony is the seam-injecting constructor used by tests.
func newLocalCeremony(devices deviceLister, ceremony ctap2Ceremony, timeout time.Duration) *LocalCeremony {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &LocalCeremony{
		devices:   devices,
		ceremony:  ceremony,
		timeout:   timeout,
		userVerif: true,
	}
}

// Available reports whether an authenticator is attached, satisfying the
// ceremony's optional availability probe so a missing key fails the init
// preflight before any state changes.
func (c *LocalCeremony) Available(_ context.Context) (bool, string) {
	if c == nil || c.devices == nil || c.ceremony == nil {
		return false, NoHandlerReason
	}
	found, err := c.devices.ListDevices()
	if err != nil {
		return false, "enumerating FIDO2 authenticators failed: " + err.Error()
	}
	if len(found) == 0 {
		return false, "no FIDO2 authenticator detected; attach a security key and retry"
	}
	return true, ""
}

// LocalEnrollRequest describes the credential to create on the attached
// authenticator.
type LocalEnrollRequest struct {
	// Challenge is the relying party's credential-creation challenge. It
	// MUST come from the RP so the resulting credential is bound to a session
	// the server will accept.
	Challenge []byte

	// UserID is the WebAuthn user handle issued by the relying party.
	UserID []byte

	// Username and DisplayName identify the administrator to the
	// authenticator's own UI.
	Username    string
	DisplayName string

	// RPID is the WebAuthn relying-party ID — the registrable domain the
	// console is served from.
	RPID string

	// RPName is the human-readable relying-party name. Falls back to RPID.
	RPName string

	// DeviceHint selects one authenticator when several are attached: an
	// exact device path, or a case-insensitive substring of the product,
	// manufacturer, or serial number.
	DeviceHint string

	// PIN is the authenticator's CTAP2 PIN. Required when the key has one
	// set, because there is no browser at init to prompt for it. Nil is
	// correct for a key with no PIN configured.
	PIN *secure.Secret
}

// LocalEnrollResult carries the credential produced by the authenticator, in
// the shape Factor.Enroll consumes.
type LocalEnrollResult struct {
	// MethodParams is ready to pass as AuthFactorEnrollParams.MethodParams.
	MethodParams map[string]any

	// Device is a human-readable description of the authenticator used, for
	// the ceremony's operator-facing output.
	Device string

	// CredentialID is the raw credential identifier.
	CredentialID []byte
}

// Enroll drives the attached authenticator and returns the enrollment inputs
// for Factor.Enroll.
func (c *LocalCeremony) Enroll(_ context.Context, req LocalEnrollRequest) (*LocalEnrollResult, error) {
	if c == nil || c.devices == nil || c.ceremony == nil {
		return nil, ErrLocalCeremonyUnavailable
	}
	if req.RPID == "" {
		return nil, ErrLocalRPIDRequired
	}
	if len(req.Challenge) == 0 {
		return nil, ErrLocalChallengeRequired
	}

	device, err := c.selectDevice(req.DeviceHint)
	if err != nil {
		return nil, err
	}

	rpName := req.RPName
	if rpName == "" {
		rpName = req.RPID
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// Bind the ceremony to the device this driver resolved, so the handler's
	// own selection cannot pick a different authenticator.
	if binder, ok := c.ceremony.(deviceBinder); ok {
		binder.BindDevice(device.Path)
	}

	attestation, err := c.ceremony.RegisterWebAuthn(pkgfido2.WebAuthnRegistrationOptions{
		Challenge: req.Challenge,
		// Origin must match what a browser will send at login, which for a
		// TLS console is https://<rp id>. A mismatch produces a credential
		// that enrolls cleanly and fails every subsequent login.
		Origin:                  "https://" + req.RPID,
		RPID:                    req.RPID,
		RPName:                  rpName,
		UserID:                  req.UserID,
		UserName:                req.Username,
		UserDisplayName:         displayName,
		RequireUserVerification: c.userVerif,
		Timeout:                 c.timeout,
		PIN:                     req.PIN,
	})
	if err != nil {
		return nil, &LocalCeremonyError{Stage: "authenticator", Err: err}
	}

	cose, aaguid, err := credentialFromAttestation(attestation)
	if err != nil {
		return nil, &LocalCeremonyError{Stage: "parse", Err: err}
	}

	params := map[string]any{
		"cose_public_key": cose,
		"credential_id":   base64.RawURLEncoding.EncodeToString(attestation.CredentialID),
		"rp_id":           req.RPID,
		// The same origin the ceremony above presented to the authenticator
		// (https://<rp id>), recorded explicitly rather than left to
		// Factor.Enroll's default so the enrollment can never drift from what
		// was actually attested.
		"origins": []string{"https://" + req.RPID},
		// The same user-verification requirement passed to the ceremony
		// above (RequireUserVerification), recorded explicitly for the same
		// reason.
		"require_user_verification": c.userVerif,
	}
	if len(aaguid) > 0 {
		params["aaguid"] = base64.RawURLEncoding.EncodeToString(aaguid)
	}

	return &LocalEnrollResult{
		MethodParams: params,
		Device:       describeDevice(device),
		CredentialID: attestation.CredentialID,
	}, nil
}

// selectDevice resolves which authenticator to use.
//
// With no hint and exactly one attached, that one is used. With no hint and
// several attached, this is an error rather than an arbitrary pick: enrolling
// the admin credential onto the wrong token is not discoverable until first
// login, and by then the right token is the one that does not work.
func (c *LocalCeremony) selectDevice(hint string) (pkgfido2.Device, error) {
	found, err := c.devices.ListDevices()
	if err != nil {
		return pkgfido2.Device{}, &LocalCeremonyError{Stage: "enumerate", Err: err}
	}
	if len(found) == 0 {
		return pkgfido2.Device{}, ErrNoAuthenticator
	}

	if hint == "" {
		if len(found) > 1 {
			return pkgfido2.Device{}, &AmbiguousAuthenticatorError{Candidates: describeDevices(found)}
		}
		return found[0], nil
	}

	var matches []pkgfido2.Device
	for _, d := range found {
		if matchesHint(d, hint) {
			matches = append(matches, d)
		}
	}
	switch len(matches) {
	case 0:
		return pkgfido2.Device{}, &AuthenticatorNotFoundError{Hint: hint, Candidates: describeDevices(found)}
	case 1:
		return matches[0], nil
	default:
		return pkgfido2.Device{}, &AmbiguousAuthenticatorError{Candidates: describeDevices(matches)}
	}
}

// matchesHint reports whether the device matches an operator-supplied
// selector.
func matchesHint(d pkgfido2.Device, hint string) bool {
	if d.Path == hint {
		return true
	}
	needle := strings.ToLower(hint)
	for _, field := range []string{d.Product, d.Manufacturer, d.SerialNumber} {
		if field != "" && strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

// describeDevice renders an authenticator for operator-facing output.
func describeDevice(d pkgfido2.Device) string {
	name := strings.TrimSpace(d.Manufacturer + " " + d.Product)
	if name == "" {
		name = d.Path
	}
	if d.SerialNumber != "" {
		return name + " (" + d.SerialNumber + ")"
	}
	return name
}

// describeDevices renders a candidate list for an error message.
func describeDevices(devices []pkgfido2.Device) []string {
	out := make([]string, 0, len(devices))
	for _, d := range devices {
		out = append(out, describeDevice(d))
	}
	return out
}

// credentialFromAttestation extracts the COSE public key and AAGUID from the
// WebAuthn PublicKeyCredential document the authenticator produced.
//
// It parses with the same go-webauthn routine the browser path uses
// (protocol.ParseCredentialCreationResponseBody), so a credential enrolled at
// init is validated exactly as one enrolled from a browser. Reaching into the
// CBOR by hand here would be a second, divergent parser for the same bytes.
func credentialFromAttestation(att *pkgfido2.WebAuthnAttestation) (cose, aaguid []byte, err error) {
	parsed, perr := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(att.PublicKeyCredentialJSON),
	)
	if perr != nil {
		return nil, nil, perr
	}
	attData := parsed.Response.AttestationObject.AuthData.AttData
	return attData.CredentialPublicKey, attData.AAGUID, nil
}
