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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// TestProveDeviceLivenessSkipsALegacyRecord covers the pairing that predates
// #129.
//
// Such a record has no attested key registered, so there is nothing to prove
// possession of and demanding a proof would refuse every legacy device rather
// than protect it. It must skip before touching a trust store or a session —
// this passes nil for both, so anything that reached for either would panic.
func TestProveDeviceLivenessSkipsALegacyRecord(t *testing.T) {
	svc := &PhoneService{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	legacy := &phoneConfigDevice{
		Name:              "legacy",
		DeviceFingerprint: "aa",
	}

	require.NoError(t, svc.proveDeviceLiveness(context.Background(), nil, nil, legacy))
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
		DeviceFingerprint:          "bb",
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
	bound := &phoneConfigDevice{
		DeviceFingerprint:          "cc",
		AttestationProtocolVersion: pairing.AttestProtocolV2,
	}
	legacy := &phoneConfigDevice{DeviceFingerprint: "cc"}

	assert.True(t, bound.attestationBinding().RequiresLiveAttestation(),
		"a v2 record must demand the proof in the GUI exactly as it does in the CLI")
	assert.Equal(t, "cc", bound.attestationBinding().Fingerprint)

	assert.False(t, legacy.attestationBinding().RequiresLiveAttestation())
}
