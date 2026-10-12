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

package rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestPIVAttestLevelConstants_MatchSharedVocabulary pins the REST-local
// constants to the exact strings types.AttestLevel uses, so a token minted
// before this change and one minted after carry the identical claim value —
// the whole point of moving these onto the one shared vocabulary rather than
// re-declaring it.
func TestPIVAttestLevelConstants_MatchSharedVocabulary(t *testing.T) {
	assert.Equal(t, "hardware", PIVAttestLevelHardware)
	assert.Equal(t, string(types.AttestLevelHardware), PIVAttestLevelHardware)
	assert.Equal(t, "unattested", PIVAttestLevelUnattested)
	assert.Equal(t, string(types.AttestLevelUnattested), PIVAttestLevelUnattested)
}

// testLoginPeers returns a single self-signed leaf certificate, standing in
// for r.TLS.PeerCertificates. With no AttestationRoots configured,
// attestationLevel never examines the chain, so these precedence tests need
// nothing more.
func testLoginPeers(t *testing.T) []*x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return []*x509.Certificate{generateTestCertificate(t, key)}
}

// TestAttestationLevel_RecordedHardware_AcceptedWithoutAnchor proves a
// recorded types.AttestLevelHardware is accepted when no AttestationRoots is
// configured — the no-record path here would refuse outright (see
// TestPIVLogin_NoAnchorRefusesUnlessUnattestedIsAllowed). With roots
// configured a recorded level is never evidence (TestPIVLogin_StrictAttestation).
func TestAttestationLevel_RecordedHardware_AcceptedWithoutAnchor(t *testing.T) {
	opts := &PIVLoginOptions{
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			return types.AttestLevelHardware, true
		},
	}

	level, refusal := opts.attestationLevel(testLoginPeers(t))
	assert.Equal(t, PIVAttestLevelHardware, level)
	assert.Nil(t, refusal)
}

// TestAttestationLevel_RecordedUnattested_RefusedWithoutAllowUnattested
// proves a recorded non-hardware level still passes through the same
// admission policy as an unrecorded one: RecordedLevel decides WHAT the key
// is, not whether a non-hardware key may log in.
func TestAttestationLevel_RecordedUnattested_RefusedWithoutAllowUnattested(t *testing.T) {
	opts := &PIVLoginOptions{
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			return types.AttestLevelUnattested, true
		},
	}

	level, refusal := opts.attestationLevel(testLoginPeers(t))
	assert.Empty(t, level)
	require.NotNil(t, refusal)
	assert.Equal(t, PIVRefusalRecordedNotHardware, refusal.Reason)
}

// TestAttestationLevel_RecordedSoftware_AcceptedWhenUnattestedAllowed proves
// a recorded types.AttestLevelSoftware is accepted, and its own name reaches
// the claim, once AllowUnattested opts the deployment into non-hardware
// logins — it is never silently upgraded to "hardware" nor collapsed onto
// PIVAttestLevelUnattested.
func TestAttestationLevel_RecordedSoftware_AcceptedWhenUnattestedAllowed(t *testing.T) {
	opts := &PIVLoginOptions{
		AllowUnattested: true,
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			return types.AttestLevelSoftware, true
		},
	}

	level, refusal := opts.attestationLevel(testLoginPeers(t))
	assert.Equal(t, types.AttestLevelSoftware.String(), level)
	assert.Nil(t, refusal)
}

// TestAttestationLevel_RecordedNotFound_FallsBackToUnattested proves
// RecordedLevel reporting found=false — not a level, a "no record" answer —
// is decided exactly as if RecordedLevel were nil.
func TestAttestationLevel_RecordedNotFound_FallsBackToUnattested(t *testing.T) {
	called := false
	opts := &PIVLoginOptions{
		AllowUnattested: true,
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			called = true
			return "", false
		},
	}

	level, refusal := opts.attestationLevel(testLoginPeers(t))
	assert.True(t, called, "RecordedLevel must be consulted before falling back")
	assert.Equal(t, PIVAttestLevelUnattested, level, "no anchor configured falls back to unattested")
	assert.Nil(t, refusal)
}

// TestAttestationLevel_NoAnchorNoRecord_Refused proves that with neither an
// anchor, a record, nor the opt-out, nothing can vouch for the key.
func TestAttestationLevel_NoAnchorNoRecord_Refused(t *testing.T) {
	opts := &PIVLoginOptions{}

	level, refusal := opts.attestationLevel(testLoginPeers(t))
	assert.Empty(t, level)
	require.NotNil(t, refusal)
	assert.Equal(t, PIVRefusalNoAnchor, refusal.Reason)
}
