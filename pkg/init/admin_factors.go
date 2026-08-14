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

package initialize

import (
	"context"
	"crypto/rand"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsfido2 "github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
)

// This file connects the ceremony's factor plan to the hardware that performs
// it. qrdb decides WHICH factors are enrolled and in what order; go-xkms owns
// the CTAP2 and PIV implementations, so it supplies the per-factor inputs.

// AdminEnrollmentContext carries what the hardware ceremonies need beyond the
// factor plan itself.
type AdminEnrollmentContext struct {
	// Username identifies the administrator to an authenticator's own UI.
	Username string

	// DisplayName is the human-readable name shown during the ceremony.
	// Falls back to Username.
	DisplayName string

	// RelyingPartyID is the WebAuthn RP ID the passkey is scoped to — the
	// registrable domain the console is served from. Required when the plan
	// includes the FIDO2 factor.
	RelyingPartyID string

	// RelyingPartyName is the human-readable RP name. Falls back to
	// RelyingPartyID.
	RelyingPartyName string

	// PasskeyDevice selects one authenticator when several are attached
	// (--passkey-device).
	PasskeyDevice string

	// PasskeyPIN is the CTAP2 PIN of the authenticator being enrolled. An
	// authenticator with a PIN set refuses credential creation without it,
	// and at init there is no browser to prompt. Read it from stdin or the
	// environment; never from a command-line flag, where it would be visible
	// in /proc to every process on the host.
	PasskeyPIN string

	// LocalCeremony drives an attached FIDO2 authenticator. Nil when this
	// build has no FIDO2 support, which makes a planned fido2 factor fail at
	// preflight rather than midway.
	LocalCeremony *xkmsfido2.LocalCeremony

	// AdminCertPEM is the administrator's client certificate, as issued by
	// the ceremony that just ran. The mTLS factor binds to it, which is what
	// makes the certificate in the admin bundle an actual login credential
	// rather than just a file on disk.
	AdminCertPEM []byte
}

// NewAdminEnrollmentParams returns the per-factor input provider for
// EnrollAdminFactors.
//
// mTLS binds to the administrator certificate the ceremony just issued. The
// FIDO2 branch runs the CTAP2 ceremony against the attached authenticator and
// returns the credential in the shape the canonical fido2 Factor.Enroll
// already consumes. PIV needs no extra inputs here: the factor reads its slot
// from its own configuration.
func NewAdminEnrollmentParams(ec AdminEnrollmentContext) qrdbsdk.AdminEnrollmentParams {
	return func(ctx context.Context, factor qrdbsdk.AdminFactor) (map[string]any, error) {
		if factor == qrdbsdk.FactorMTLS {
			if len(ec.AdminCertPEM) == 0 {
				return nil, ErrAdminCertRequired
			}
			return map[string]any{"cert_pem": string(ec.AdminCertPEM)}, nil
		}
		if factor != qrdbsdk.FactorFIDO2 {
			return nil, nil
		}
		if ec.LocalCeremony == nil {
			return nil, ErrNoLocalFIDO2Ceremony
		}
		if ec.RelyingPartyID == "" {
			return nil, ErrPasskeyRPIDRequired
		}

		// The challenge and user handle are generated here rather than by an
		// HTTP relying party because at init there is no server listening yet.
		// They are still bound to this credential: the fido2 factor records
		// the credential ID and COSE key, and login challenges are issued by
		// the running server against that record.
		challenge, err := randomBytes(32)
		if err != nil {
			return nil, err
		}
		userHandle, err := randomBytes(32)
		if err != nil {
			return nil, err
		}

		result, err := ec.LocalCeremony.Enroll(ctx, xkmsfido2.LocalEnrollRequest{
			Challenge:   challenge,
			UserID:      userHandle,
			Username:    ec.Username,
			DisplayName: ec.DisplayName,
			RPID:        ec.RelyingPartyID,
			RPName:      ec.RelyingPartyName,
			DeviceHint:  ec.PasskeyDevice,
			PIN:         ec.PasskeyPIN,
		})
		if err != nil {
			return nil, err
		}
		return result.MethodParams, nil
	}
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, &RandomSourceError{Err: err}
	}
	return buf, nil
}
