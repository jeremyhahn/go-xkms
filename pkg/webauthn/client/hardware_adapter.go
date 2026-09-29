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

package client

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// HardwareAdapter implements AuthenticatorAdapter against a real CTAP2
// authenticator reachable over HID: a physical security key, or xkey's
// virtual authenticator ("xkey fido2"), which exposes a uhid kernel device
// that enumerates indistinguishably from real hardware. It drives the
// authenticator through the canonical FIDO2 CTAP2 implementation in
// pkg/fido2 — the same pkg/fido2.FIDO2Handler every other hardware-backed
// ceremony in the stack uses.
type HardwareAdapter struct {
	handler *fido2.FIDO2Handler
}

var _ AuthenticatorAdapter = (*HardwareAdapter)(nil)

// NewHardwareAdapter opens the local CTAP2 authenticator. It fails closed
// when no authenticator can be enumerated, so a caller never mistakes a
// missing security key for a completed ceremony.
//
// A nil config uses fido2.DefaultConfig; a nil enumerator uses
// fido2.NewDefaultEnumerator(), the platform HID enumerator that also
// discovers xkey's virtual uhid authenticator.
func NewHardwareAdapter(config *fido2.Config, enumerator fido2.HIDDeviceEnumerator) (*HardwareAdapter, error) {
	cfg := fido2.DefaultConfig
	if config != nil {
		cfg = *config
	}

	handler, err := fido2.NewHandler(&cfg, hidEnumerator(enumerator))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAuthenticatorNotFound, Cause: err}
	}

	devices, err := handler.ListDevices()
	if err != nil {
		return nil, errors.Join(&errs.Joined{Lead: ErrAuthenticatorNotFound, Cause: err}, handler.Close())
	}
	if len(devices) == 0 {
		return nil, errors.Join(ErrAuthenticatorNotFound, handler.Close())
	}

	return &HardwareAdapter{handler: handler}, nil
}

// hidEnumerator returns enumerator, or the platform HID enumerator
// (fido2.NewDefaultEnumerator) when enumerator is nil.
func hidEnumerator(enumerator fido2.HIDDeviceEnumerator) fido2.HIDDeviceEnumerator {
	if enumerator == nil {
		return fido2.NewDefaultEnumerator()
	}
	return enumerator
}

// Available reports whether the authenticator handle is open.
func (a *HardwareAdapter) Available() bool {
	return a.handler != nil
}

// MakeCredential drives the authenticator through authenticatorMakeCredential
// and returns the WebAuthn PublicKeyCredential attestation document.
func (a *HardwareAdapter) MakeCredential(ctx context.Context, opts *CeremonyOptions) ([]byte, error) {
	if opts == nil {
		return nil, ErrNilRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	regOpts, err := fido2.ParseWebAuthnRegistrationOptions(opts.OptionsJSON, opts.Origin)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidServerResponse, Cause: err}
	}
	regOpts.PIN = opts.PIN

	attestation, err := a.handler.RegisterWebAuthn(regOpts)
	if err != nil {
		return nil, hardwareCeremonyFailure(opts.PIN, err)
	}
	return attestation.PublicKeyCredentialJSON, nil
}

// GetAssertion drives the authenticator through authenticatorGetAssertion
// and returns the WebAuthn PublicKeyCredential assertion document.
func (a *HardwareAdapter) GetAssertion(ctx context.Context, opts *CeremonyOptions) ([]byte, error) {
	if opts == nil {
		return nil, ErrNilRequest
	}

	assertion, err := a.handler.Assert(ctx, fido2.WebAuthnAssertionRequest{
		OptionsJSON: opts.OptionsJSON,
		Origin:      opts.Origin,
		PIN:         opts.PIN,
	})
	if err != nil {
		return nil, hardwareCeremonyFailure(opts.PIN, err)
	}
	return assertion, nil
}

// Close releases the authenticator handle. Callers that construct a
// HardwareAdapter own its lifecycle and should defer Close once the
// ceremony (or ceremonies) it drives are done.
func (a *HardwareAdapter) Close() error {
	if a.handler == nil {
		return nil
	}
	return a.handler.Close()
}

// hardwareCeremonyFailure classifies an authenticator failure before it
// reaches the caller. An authenticator that answers CTAP2_ERR_PIN_REQUIRED
// when no PIN was supplied is reporting missing INPUT, so it is named as
// such (ErrPINRequired) rather than folded into the generic CTAP failure;
// the raw CTAP error is kept as the cause so nothing is lost.
//
// The same status when a PIN WAS supplied is not a missing-input problem —
// it means the authenticator rejected an authorization that was attempted —
// and is reported as a plain CTAP operation failure rather than sending the
// caller back to resupply a PIN it already gave.
func hardwareCeremonyFailure(pin *secure.Secret, cause error) error {
	if pin == nil && errors.Is(cause, fido2.ErrPINRequired) {
		return &errs.Joined{Lead: ErrPINRequired, Cause: cause}
	}
	return &errs.Joined{Lead: ErrCTAPOperationFailed, Cause: cause}
}
