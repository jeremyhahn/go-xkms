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

package peergate_test

import (
	"context"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// TestVerifier_AnchorSourceIsConsultedOnEachVerification: a verifier given
// an anchor source and no fixed anchors reads the source on every
// verification, so a root withdrawn from it (quarantined, removed) refuses
// the very next peer.
func TestVerifier_AnchorSourceIsConsultedOnEachVerification(t *testing.T) {
	h := newHarness(t, device{}, device{})
	h.submit(t, h.honest(t))

	var current atomic.Pointer[x509.CertPool]
	current.Store(h.pki.pool)
	policy := h.policy()
	policy.Anchors = nil
	v, err := peergate.NewVerifier(peergate.VerifierConfig{
		Store:   h.store,
		Policy:  policy,
		Anchors: func(context.Context) (*x509.CertPool, error) { return current.Load(), nil },
	}, peergate.WithClock(h.clock.Now))
	require.NoError(t, err)

	verdict := h.verify(t, v)
	assert.True(t, verdict.Passed, "reason: %s", verdict.Reason)

	current.Store(x509.NewCertPool())
	verdict = h.verify(t, v)
	assert.False(t, verdict.Passed, "a withdrawn root no longer anchors the peer")
}

// TestVerifier_AnchorSourceErrorIsUndecided: a source that cannot answer
// leaves the verifier unable to decide; it never passes the peer.
func TestVerifier_AnchorSourceErrorIsUndecided(t *testing.T) {
	h := newHarness(t, device{}, device{})
	h.submit(t, h.honest(t))

	policy := h.policy()
	policy.Anchors = nil
	failure := errors.New("store down")
	v, err := peergate.NewVerifier(peergate.VerifierConfig{
		Store:   h.store,
		Policy:  policy,
		Anchors: func(context.Context) (*x509.CertPool, error) { return nil, failure },
	}, peergate.WithClock(h.clock.Now))
	require.NoError(t, err)

	verdict, err := v.VerifyPeer(context.Background(), h.attested())
	require.ErrorIs(t, err, failure)
	assert.Nil(t, verdict)
}
