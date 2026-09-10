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

//go:build fips

package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Under the fips build tag go-truststrap compiles out its X25519 DH, so
// these are the claims a FIPS build must satisfy WITHOUT any injected
// availability answer: the real probe, the real client, a real listener.
// Before this change the same configuration failed at the handshake with
// "noise: X25519 is unavailable in FIPS build" -- observed, not inferred.

// A FIPS client provisioned with both keys must skip Noise_NK and complete
// the approved handshake. This is go-xkms#269's client-side acceptance
// criterion: an executed P-256 bootstrap, not a compile check.
func TestFetch_Noise_FIPSClientCompletesApprovedSuite(t *testing.T) {
	require.False(t, noiseRunnable(t), "a fips build must not be able to run Noise_NK")

	l := startListener(t, true)
	require.Empty(t, l.noiseHex, "a fips listener cannot hold a Noise key")

	bundle, err := fetchNoiseFrom(t, l, &NoiseConfig{
		ServerStaticKey:     placeholderNoiseKey,
		ServerP256StaticKey: l.p256Hex,
	})
	require.NoError(t, err, "a FIPS client with a P-256 key must bootstrap")
	requireBundle(t, l, bundle)
}

// A FIPS client with only the legacy Curve25519 key gets the typed refusal
// naming the build as the constraint -- before it opens a connection.
func TestFetch_Noise_FIPSClientNoiseOnlyIsTypedRefusal(t *testing.T) {
	l := startListener(t, false)

	_, err := fetchNoiseFrom(t, l, &NoiseConfig{ServerStaticKey: placeholderNoiseKey})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFetch)
	assert.ErrorIs(t, err, ErrNoSuite)
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
	assert.Contains(t, err.Error(), "SuiteP256AESGCM",
		"the refusal must name the approved alternative, or it is not actionable")
}

// Pinning Noise_NK under FIPS is refused even though a P-256 key is present:
// the caller asked for a suite this build cannot run, and must not be handed
// a different one.
func TestFetch_Noise_FIPSClientPinnedNoiseIsRefused(t *testing.T) {
	l := startListener(t, false)

	_, err := fetchNoiseFrom(t, l, &NoiseConfig{
		ServerStaticKey:     placeholderNoiseKey,
		ServerP256StaticKey: l.p256Hex,
		Suite:               SuiteNoiseNK,
	})
	require.Error(t, err)
	var se *SuiteError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, SuiteNoiseNK, se.Suite)
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
}
