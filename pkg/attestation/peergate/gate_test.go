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

package peergate_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

var errNoDatastoreYet = errors.New("the datastore is not open yet")

func memoryDAOs() (*qrdbsdk.DAOFactory, error) { return testutil.NewMemoryDAOFactory(), nil }

func gatePolicy(h *harness, mode peergate.Mode) peergate.GatePolicy {
	return peergate.GatePolicy{
		Mode:           mode,
		Quote:          h.policy(),
		Permissions:    []qrdbsdk.Permission{qrdbsdk.PermissionAdminStatus},
		MaxEvidenceAge: time.Minute,
	}
}

func newGate(t *testing.T, h *harness, mode peergate.Mode, daos peergate.DAOResolver) *peergate.Gate {
	t.Helper()
	gate, err := peergate.NewGate(peergate.GateConfig{Policy: gatePolicy(h, mode), DAOs: daos}, peergate.WithClock(h.clock.Now))
	require.NoError(t, err)
	return gate
}

// submitTo answers a challenge from the gate's own collector.
func submitTo(t *testing.T, h *harness, gate *peergate.Gate, build func(nonce []byte) peer.Evidence) error {
	t.Helper()
	challenge, err := gate.Collector().Challenge(context.Background(), h.conn.server)
	require.NoError(t, err)
	return gate.Collector().Submit(context.Background(), h.conn.server, build(challenge.Nonce))
}

func offBaseline(t *testing.T, h *harness) func([]byte) peer.Evidence {
	return func(nonce []byte) peer.Evidence {
		swapped := goldenPCRs()
		swapped[10] = fill(0xee)
		return h.ak.evidence(t, h.conn, nonce, swapped)
	}
}

func TestParseMode(t *testing.T) {
	valid := map[string]peergate.Mode{
		"":           peergate.ModeOff,
		"off":        peergate.ModeOff,
		" Optional ": peergate.ModeOptional,
		"REQUIRED":   peergate.ModeRequired,
	}
	for value, want := range valid {
		mode, err := peergate.ParseMode(value)
		require.NoError(t, err, "%q", value)
		assert.Equal(t, want, mode, "%q", value)
	}

	for _, value := range []string{"on", "enforce", "required!"} {
		_, err := peergate.ParseMode(value)
		var modeErr *peergate.ModeError
		require.ErrorAs(t, err, &modeErr, "%q", value)
		assert.Equal(t, value, modeErr.Value)
		assert.Contains(t, err.Error(), "optional or required")
	}
}

func TestGate_RequiredRefusesAnUnattestedPeer(t *testing.T) {
	h := newHarness(t, device{}, device{})
	gate := newGate(t, h, "", memoryDAOs)

	assert.Equal(t, peergate.ModeRequired, gate.Mode(), "an unset mode fails closed")
	verdict := h.verify(t, gate.Verifier())
	assert.False(t, verdict.Passed)
	assert.Equal(t, qrdbsdk.PeerAttestationFailureAbsence, verdict.Failure)
	assert.True(t, verdict.CollectedAt.IsZero(), "go-qrdb refuses a verdict with no collection time as no evidence")

	require.NoError(t, submitTo(t, h, gate, h.honest(t)))
	verdict = h.verify(t, gate.Verifier())
	assert.True(t, verdict.Passed, "reason: %s", verdict.Reason)
	assert.Equal(t, h.clock.now, verdict.CollectedAt)
}

func TestGate_OptionalAdmitsOnlyAnAbsentPeer(t *testing.T) {
	h := newHarness(t, device{}, device{})
	gate := newGate(t, h, peergate.ModeOptional, memoryDAOs)

	verdict := h.verify(t, gate.Verifier())
	assert.True(t, verdict.Passed)
	assert.Equal(t, qrdbsdk.PeerAttestationFailureNone, verdict.Failure)
	assert.Equal(t, h.clock.now, verdict.CollectedAt, "fresh, so go-qrdb's evidence age bound holds")
	assert.Contains(t, verdict.Reason, "unattested")

	require.NoError(t, submitTo(t, h, gate, offBaseline(t, h)))
	verdict = h.verify(t, gate.Verifier())
	assert.False(t, verdict.Passed, "evidence on record is judged, whatever the mode")
	assert.Equal(t, qrdbsdk.PeerAttestationFailureCryptographic, verdict.Failure)
}

func TestGate_GatesThePolicyPermissionsOnly(t *testing.T) {
	h := newHarness(t, device{}, device{})
	gate := newGate(t, h, peergate.ModeRequired, memoryDAOs)

	assert.True(t, gate.PeerAttestationGate().Gates(qrdbsdk.PermissionAdminStatus))
	for _, exempt := range peergate.ExemptPermissions() {
		assert.False(t, gate.PeerAttestationGate().Gates(exempt), "%s", exempt)
	}
}

func TestGate_FailsClosedUntilItsStorageExists(t *testing.T) {
	h := newHarness(t, device{}, device{})
	daos := testutil.NewMemoryDAOFactory()
	var open atomic.Bool
	var resolved atomic.Int32
	gate := newGate(t, h, peergate.ModeOptional, func() (*qrdbsdk.DAOFactory, error) {
		resolved.Add(1)
		if !open.Load() {
			return nil, errNoDatastoreYet
		}
		return daos, nil
	})

	// Optional mode would admit an absent peer, but with no store there is
	// no telling absent from attested-and-failing: the verifier errors and
	// go-qrdb refuses.
	_, err := gate.Verifier().VerifyPeer(context.Background(), h.attested())
	var storeErr *peergate.StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.ErrorIs(t, err, errNoDatastoreYet)
	err = submitTo(t, h, gate, h.honest(t))
	require.ErrorAs(t, err, &storeErr)

	open.Store(true)
	require.NoError(t, submitTo(t, h, gate, h.honest(t)))
	verdict := h.verify(t, gate.Verifier())
	assert.True(t, verdict.Passed, "reason: %s", verdict.Reason)
	assert.NotContains(t, verdict.Reason, "unattested", "the stored evidence was judged")

	before := resolved.Load()
	h.verify(t, gate.Verifier())
	assert.Equal(t, before, resolved.Load(), "the store binds once")
}

func TestNewGate_RefusesAPolicyThatDescribesNoGate(t *testing.T) {
	h := newHarness(t, device{}, device{})
	cases := map[string]struct {
		mutate func(*peergate.GateConfig)
		field  string
	}{
		"mode off":           {func(c *peergate.GateConfig) { c.Policy.Mode = peergate.ModeOff }, "Policy.Mode"},
		"unknown mode":       {func(c *peergate.GateConfig) { c.Policy.Mode = "enforce" }, "Policy.Mode"},
		"no storage":         {func(c *peergate.GateConfig) { c.DAOs = nil }, "DAOs"},
		"no quote anchors":   {func(c *peergate.GateConfig) { c.Policy.Quote.Anchors = nil }, "Policy.Anchors"},
		"no gated operation": {func(c *peergate.GateConfig) { c.Policy.Permissions = nil }, "Policy"},
		"no evidence age":    {func(c *peergate.GateConfig) { c.Policy.MaxEvidenceAge = 0 }, "Policy"},
		"negative challenge TTL": {
			func(c *peergate.GateConfig) { c.Challenges.ChallengeTTL = -time.Second }, "ChallengeTTL"},
		"gates the challenge": {func(c *peergate.GateConfig) {
			c.Policy.Permissions = append(c.Policy.Permissions, peergate.ExemptPermissions()[0])
		}, "Policy.Permissions"},
		"gates the submission": {func(c *peergate.GateConfig) {
			c.Policy.Permissions = append(c.Policy.Permissions, peergate.ExemptPermissions()[1])
		}, "Policy.Permissions"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := peergate.GateConfig{Policy: gatePolicy(h, peergate.ModeRequired), DAOs: memoryDAOs}
			tc.mutate(&cfg)
			gate, err := peergate.NewGate(cfg)
			assert.Nil(t, gate)
			var configErr *peergate.ConfigError
			require.ErrorAs(t, err, &configErr)
			assert.Equal(t, tc.field, configErr.Field)
		})
	}
}
