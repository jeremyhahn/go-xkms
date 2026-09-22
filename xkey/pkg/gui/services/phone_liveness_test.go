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

package services

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// The GUI's half of the #129 enforcement (go-xkms#130).
//
// Until the verifier was relocated into pkg/attestation this package could not
// reach the decision at all — pkg/gui/services cannot import the command
// package — so the GUI published a session straight after the Noise handshake
// and a device recorded as protocol v2 was admitted on a copied Noise key
// alone. These tests pin the gate itself: whether the proof is DEMANDED, and
// whether failing to obtain one refuses the connection. Whether the evidence
// is judged correctly is covered where the decision lives.

// TestProveDeviceLivenessRefusesALegacyRecord covers the pairing that
// predates #129 (BREAKING, go-xkms compat cleanup PR5: the #129/#130 grace
// period for an absent/version-1 record is removed).
//
// Such a record has no attested key registered, so there is nothing to prove
// possession of, and it is refused rather than admitted -- the operator must
// re-pair. It must refuse before touching a trust store or a session -- this
// passes nil for both, so anything that reached for either would panic.
func TestProveDeviceLivenessRefusesALegacyRecord(t *testing.T) {
	svc := &PhoneService{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	legacy := &phoneConfigDevice{
		Name:              "legacy",
		DeviceFingerprint: "aa",
	}

	err := svc.proveDeviceLiveness(context.Background(), nil, nil, legacy)
	require.Error(t, err)
	assert.ErrorIs(t, err, xkeyAttestation.ErrDeviceAttestationVersionUnsupported)
}

// TestProveDeviceLivenessRefusesWithoutATrustStore is the fail-closed case.
//
// A record that REQUIRES the proof, on a service with nothing to judge the
// evidence against, must be refused rather than admitted unchecked. Absent
// authorization material must never be less restrictive than the policy it
// implements — the same rule that makes a malformed stored fingerprint a
// refusal instead of "no fingerprint configured".
func TestProveDeviceLivenessRefusesWithoutATrustStore(t *testing.T) {
	svc := &PhoneService{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	require.Nil(t, svc.trustStore)

	bound := &phoneConfigDevice{
		Name:                       "bound",
		DeviceFingerprint:          strings.Repeat("bb", pairing.AttestFingerprintSize), // well-formed, so Validate passes and the trust-store check is what's under test
		AttestationProtocolVersion: pairing.AttestProtocolV2,
	}

	err := svc.proveDeviceLiveness(context.Background(), nil, nil, bound)

	require.Error(t, err, "a required proof with nothing to judge it against must refuse")
	require.ErrorIs(t, err, ErrPhoneAttestationRequired)
}

// TestAttestationBindingReadsTheRecordNotThePeer pins where the requirement
// comes from.
//
// The GUI mirrors devices.yaml in its own struct, and that mirror silently
// lacked attestation_protocol_version — so a CLI-paired v2 device read as
// unbound and the requirement evaporated. The field is carried now, and this
// asserts the projection the verifier consumes actually reflects it.
func TestAttestationBindingReadsTheRecordNotThePeer(t *testing.T) {
	fp := strings.Repeat("cc", pairing.AttestFingerprintSize)
	bound := &phoneConfigDevice{
		DeviceFingerprint:          fp,
		AttestationProtocolVersion: pairing.AttestProtocolV2,
	}
	legacy := &phoneConfigDevice{DeviceFingerprint: fp}

	assert.NoError(t, xkeyAttestation.DeviceBindingFor(*bound).Validate(),
		"a v2 record must validate in the GUI exactly as it does in the CLI")
	assert.Equal(t, fp, xkeyAttestation.DeviceBindingFor(*bound).Fingerprint)

	assert.ErrorIs(t, xkeyAttestation.DeviceBindingFor(*legacy).Validate(),
		xkeyAttestation.ErrDeviceAttestationVersionUnsupported)
}
