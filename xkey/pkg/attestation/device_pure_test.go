// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package attestation_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// TestDeviceBindingFor pins the projection from the persisted record onto the
// two fields the verifier actually reads (#130).
func TestDeviceBindingFor(t *testing.T) {
	record := pairing.PairedDevice{
		DeviceFingerprint:          "abc123",
		AttestationProtocolVersion: pairingproto.AttestProtocolV2,
	}

	binding := attestation.DeviceBindingFor(record)

	assert.Equal(t, "abc123", binding.Fingerprint)
	assert.Equal(t, pairingproto.AttestProtocolV2, binding.ProtocolVersion)
}

// TestApplyVerifiedAttestation_PopulatesEveryField pins that every field a
// verified result carries is written to the record, not a subset.
func TestApplyVerifiedAttestation_PopulatesEveryField(t *testing.T) {
	now := time.Now().UTC()
	result := &attestation.Result{
		AttestationTime:   now,
		SecurityLevel:     "strongbox",
		BootStateVerified: true,
		BootHashHex:       "deadbeef",
		DeviceFingerprint: "cafef00d",
		ProtocolVersion:   pairingproto.AttestProtocolV2,
	}
	record := &pairing.PairedDevice{}

	attestation.ApplyVerifiedAttestation(record, result)

	assert.Equal(t, now, record.LastDeviceAttestationTime)
	assert.Equal(t, "strongbox", record.SecurityLevel)
	assert.True(t, record.BootStateVerified)
	assert.Equal(t, "deadbeef", record.DeviceBootHashHex)
	assert.Equal(t, "cafef00d", record.DeviceFingerprint)
	assert.Equal(t, pairingproto.AttestProtocolV2, record.AttestationProtocolVersion)
}

// TestApplyVerifiedAttestation_NeverDowngradesTheProtocolVersion is the
// anti-downgrade term (#129): the recorded version only ever moves up.
func TestApplyVerifiedAttestation_NeverDowngradesTheProtocolVersion(t *testing.T) {
	record := &pairing.PairedDevice{AttestationProtocolVersion: pairingproto.AttestProtocolV2}

	// A result claiming a version lower than what is already on record must
	// not walk the record's version back down.
	attestation.ApplyVerifiedAttestation(record, &attestation.Result{ProtocolVersion: pairingproto.AttestProtocolV1})

	assert.Equal(t, pairingproto.AttestProtocolV2, record.AttestationProtocolVersion,
		"the version an attacker could lower is not an anti-downgrade term")
}

// TestChallenge_Params pins that the challenge's wire params never carry the
// channel binding (see the note on Challenge.Params in device.go).
func TestChallenge_Params(t *testing.T) {
	challenge := &attestation.Challenge{
		Purpose:        pairingproto.AttestPurposePair,
		Nonce:          attesttest.FixedBytes(0x42, pairingproto.AttestNonceSize),
		ChannelBinding: attesttest.FixedBytes(0x43, pairingproto.AttestChannelBindingSize),
	}

	params := challenge.Params()

	require.NotNil(t, params)
	assert.Equal(t, pairingproto.AttestProtocolV2, params.ProtocolVersion)
	assert.Equal(t, challenge.Nonce, params.Nonce)
	assert.Equal(t, pairingproto.AttestPurposePair, params.Purpose)
}

// TestFormatTrustAnchor covers every branch of the display fallback: nil,
// common name present, organization present with no common name, and
// neither present.
func TestFormatTrustAnchor(t *testing.T) {
	assert.Equal(t, "unknown", attestation.FormatTrustAnchor(nil))

	withCN := &x509.Certificate{Subject: pkix.Name{CommonName: "Google Hardware Attestation Root"}}
	assert.Equal(t, "Google Hardware Attestation Root", attestation.FormatTrustAnchor(withCN))

	withOrgOnly := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Example Corp"}}}
	assert.Equal(t, "Example Corp", attestation.FormatTrustAnchor(withOrgOnly))

	withNeither := &x509.Certificate{Subject: pkix.Name{Country: []string{"US"}}}
	assert.Equal(t, withNeither.Subject.String(), attestation.FormatTrustAnchor(withNeither))
}

// TestVerifiedTrustAnchor_EmptyChain pins the guard against a chain with
// nothing in it, before any verification is attempted.
func TestVerifiedTrustAnchor_EmptyChain(t *testing.T) {
	anchor, err := attestation.VerifiedTrustAnchor(nil, x509.NewCertPool())

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.Nil(t, anchor)
}

// TestValidateAttestedKeyMatch_IdentityChanged pins the comparison branch
// itself, isolated from the incompleteness checks device_test.go already
// covers: a complete, well-formed binding whose stored fingerprint simply
// does not match the fresh one must be refused as a changed identity, not an
// incomplete record.
func TestValidateAttestedKeyMatch_IdentityChanged(t *testing.T) {
	stored := attesttest.FixedBytes(0x01, pairingproto.AttestFingerprintSize)
	fresh := attesttest.FixedBytes(0x02, pairingproto.AttestFingerprintSize)

	binding := attestation.DeviceBinding{
		Fingerprint:     hex.EncodeToString(stored),
		ProtocolVersion: pairingproto.AttestProtocolV2,
	}

	err := binding.ValidateAttestedKeyMatch(hex.EncodeToString(fresh))

	require.Error(t, err)
	assert.ErrorIs(t, err, attestation.ErrDeviceIdentityChanged)
}

// TestValidateAttestedKeyMatch_SameKeyMatches is the accept path beside the
// refusal above, so a change to the comparison itself cannot make both pass.
func TestValidateAttestedKeyMatch_SameKeyMatches(t *testing.T) {
	fp := hex.EncodeToString(attesttest.FixedBytes(0x09, pairingproto.AttestFingerprintSize))
	binding := attestation.DeviceBinding{Fingerprint: fp, ProtocolVersion: pairingproto.AttestProtocolV2}

	assert.NoError(t, binding.ValidateAttestedKeyMatch(fp))
}
