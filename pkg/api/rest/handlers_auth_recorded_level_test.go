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
// for r.TLS.PeerCertificates. attestationLevel only reads peers[0]'s SPKI in
// the chain-derived fallback, which these precedence tests never reach.
func testLoginPeers(t *testing.T) []*x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return []*x509.Certificate{generateTestCertificate(t, key)}
}

// TestAttestationLevel_RecordedHardware_NeverDowngradedByMissingChain proves
// a recorded types.AttestLevelHardware is accepted even though no
// AttestationRoots is configured at all — the chain path here would refuse
// outright (see TestPIVLogin_NoAnchorRefusesUnlessUnattestedIsAllowed), but
// RecordedLevel answers first and the chain is never consulted.
func TestAttestationLevel_RecordedHardware_NeverDowngradedByMissingChain(t *testing.T) {
	opts := &PIVLoginOptions{
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			return types.AttestLevelHardware, true
		},
	}

	level, reason := opts.attestationLevel(testLoginPeers(t))
	assert.Equal(t, PIVAttestLevelHardware, level)
	assert.Empty(t, reason)
}

// TestAttestationLevel_RecordedUnattested_RefusedWithoutAllowUnattested
// proves a recorded non-hardware level still passes through the same
// admission policy as a chain-derived one: RecordedLevel decides WHAT the
// key is, not whether a non-hardware key may log in.
func TestAttestationLevel_RecordedUnattested_RefusedWithoutAllowUnattested(t *testing.T) {
	opts := &PIVLoginOptions{
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			return types.AttestLevelUnattested, true
		},
	}

	level, reason := opts.attestationLevel(testLoginPeers(t))
	assert.Empty(t, level)
	assert.NotEmpty(t, reason)
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

	level, reason := opts.attestationLevel(testLoginPeers(t))
	assert.Equal(t, types.AttestLevelSoftware.String(), level)
	assert.Empty(t, reason)
}

// TestAttestationLevel_RecordedNotFound_FallsBackToChain proves RecordedLevel
// reporting found=false — not a level, a "no record" answer — defers to the
// certificate-chain decision exactly as if RecordedLevel were nil.
func TestAttestationLevel_RecordedNotFound_FallsBackToChain(t *testing.T) {
	called := false
	opts := &PIVLoginOptions{
		AllowUnattested: true,
		RecordedLevel: func(*x509.Certificate) (types.AttestLevel, bool) {
			called = true
			return "", false
		},
	}

	level, reason := opts.attestationLevel(testLoginPeers(t))
	assert.True(t, called, "RecordedLevel must be consulted before falling back")
	assert.Equal(t, PIVAttestLevelUnattested, level, "no anchor configured falls back to the unattested chain path")
	assert.Empty(t, reason)
}

// TestAttestationLevel_NilRecordedLevel_UsesChainOnly proves a nil
// RecordedLevel reproduces the pre-RecordedLevel behavior exactly: every
// login is decided from the certificate chain alone.
func TestAttestationLevel_NilRecordedLevel_UsesChainOnly(t *testing.T) {
	opts := &PIVLoginOptions{}

	level, reason := opts.attestationLevel(testLoginPeers(t))
	assert.Empty(t, level)
	assert.Equal(t, "no attestation anchor is configured and unattested logins are not allowed", reason)
}
