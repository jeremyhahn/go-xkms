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

package pairing

import (
	"regexp"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sasFormatPattern = regexp.MustCompile(`^\d{4}-\d{4}-\d{4}$`)

// TestFormatShortAuthString_FixedVector pins the exact wire format against a
// fixed 32-byte binding, the same way attest_vectors_test.go pins
// ComputeAttestChannelBinding: a conformance vector any future
// implementation (including xkey-android's) can be checked against
// independently of a live handshake.
func TestFormatShortAuthString_FixedVector(t *testing.T) {
	binding := make([]byte, 32)
	for i := range binding {
		binding[i] = byte(i)
	}
	// bytes 0..5 = 0x00,0x01, 0x02,0x03, 0x04,0x05
	// group1 = 0x0001 % 10000 = 1     -> "0001"
	// group2 = 0x0203 % 10000 = 515   -> "0515"
	// group3 = 0x0405 % 10000 = 1029  -> "1029"
	assert.Equal(t, "0001-0515-1029", formatShortAuthString(binding))
}

// TestShortAuthString_BothPeersComputeTheSameCode proves the code is
// symmetric: the initiator and the responder derive the identical string
// from their own completed sessions, which is what lets an operator compare
// one device's screen against the other's.
func TestShortAuthString_BothPeersComputeTheSameCode(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	initiator, responder := newHandshakenSessionPairForTest(t)

	initiatorCode, err := ShortAuthString(initiator)
	require.NoError(t, err)
	responderCode, err := ShortAuthString(responder)
	require.NoError(t, err)

	assert.Equal(t, initiatorCode, responderCode)
	assert.Regexp(t, sasFormatPattern, initiatorCode)
}

// TestShortAuthString_DiffersForDifferentPeers proves the code is sensitive
// to identity: pairing with a different device produces a different code,
// which is what makes an active MITM substituting its own static key
// visible as a mismatch rather than as a fixed, always-matching string.
func TestShortAuthString_DiffersForDifferentPeers(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	initiatorA, _ := newHandshakenSessionPairForTest(t)
	initiatorB, _ := newHandshakenSessionPairForTest(t)

	codeA, err := ShortAuthString(initiatorA)
	require.NoError(t, err)
	codeB, err := ShortAuthString(initiatorB)
	require.NoError(t, err)

	assert.NotEqual(t, codeA, codeB)
}

// TestShortAuthString_RefusesBeforeHandshakeCompletes mirrors
// AttestChannelBinding's own precondition: there is no authenticated peer
// static key to bind to before the handshake finishes.
func TestShortAuthString_RefusesBeforeHandshakeCompletes(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	key, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{LocalStaticKey: key, IsInitiator: true})
	require.NoError(t, err)

	_, err = ShortAuthString(session)
	require.Error(t, err)
}

// newHandshakenSessionPairForTest runs a complete Noise XX handshake
// in-memory and returns the initiator and responder sessions, each as it
// would exist immediately after PerformHandshake on either side of a real
// connection.
func newHandshakenSessionPairForTest(t *testing.T) (initiator, responder *bootstrap.NoiseSession) {
	t.Helper()

	initiatorKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	t.Cleanup(initiatorKey.Destroy)
	responderKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	t.Cleanup(responderKey.Destroy)

	initiator, err = bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{LocalStaticKey: initiatorKey, IsInitiator: true})
	require.NoError(t, err)
	responder, err = bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{LocalStaticKey: responderKey, IsInitiator: false})
	require.NoError(t, err)

	require.NoError(t, initiator.InitHandshake())
	require.NoError(t, responder.InitHandshake())

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	return initiator, responder
}
