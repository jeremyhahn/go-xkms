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

package apimodule

import (
	"context"
	"crypto/x509"
	"sync/atomic"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testAttestedCallerPolicy returns a policy gating one permission. Its PCR
// baseline stands in for the embedder's reference values.
func testAttestedCallerPolicy() peergate.GatePolicy {
	return peergate.GatePolicy{
		Mode: peergate.ModeRequired,
		Quote: peer.Policy{
			Anchors:  x509.NewCertPool(),
			Baseline: map[int][]byte{0: make([]byte, 32)},
		},
		Permissions:    []qrdbsdk.Permission{qrdbsdk.PermissionAdminStatus},
		MaxEvidenceAge: time.Minute,
	}
}

// mutualTLSContext returns a context carrying the server's view of an mTLS
// connection, as go-qrdb's transports put it there.
func mutualTLSContext(t *testing.T) context.Context {
	t.Helper()
	state, err := testutil.MutualTLSState()
	require.NoError(t, err)
	return auth.WithTLSState(context.Background(), state)
}

// TestWithAttestedCallerGate_BuildsTheGate proves the option yields the
// go-qrdb gate the host installs, gating the policy's permissions, and that
// a module without the option has none.
func TestWithAttestedCallerGate_BuildsTheGate(t *testing.T) {
	client := newHostNodeClient(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	require.NoError(t, err)
	require.NotNil(t, m.PeerAttestationGate())
	assert.True(t, m.PeerAttestationGate().Gates(qrdbsdk.PermissionAdminStatus))

	plain, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)
	assert.Nil(t, plain.PeerAttestationGate())
}

// TestWithAttestedCallerGate_RefusesAGateItCannotBuild proves construction
// fails without the host's client to keep evidence in, and on a policy the
// gate rejects.
func TestWithAttestedCallerGate_RefusesAGateItCannotBuild(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil },
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	var clientErr *AttestedCallerClientError
	require.ErrorAs(t, err, &clientErr)

	policy := testAttestedCallerPolicy()
	policy.Permissions = nil
	_, err = NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(func() *qrdbsdk.Client { return nil }),
		WithAttestedCallerGate(policy))
	var configErr *peergate.ConfigError
	assert.ErrorAs(t, err, &configErr)
}

// TestWithAttestedCallerGate_KeepsItsOwnPermissions proves a policy the
// embedder changes after passing it does not change the gate.
func TestWithAttestedCallerGate_KeepsItsOwnPermissions(t *testing.T) {
	policy := testAttestedCallerPolicy()
	m := &Module{}
	WithAttestedCallerGate(policy)(m)
	policy.Permissions[0] = qrdbsdk.Permission("other:thing")
	assert.Equal(t, qrdbsdk.PermissionAdminStatus, m.attestedCallerPolicy.Permissions[0])
}

// TestWithAttestedCallerGate_ServesTheVerbs proves the gate's collector
// reaches the service once it resolves: before, the verbs are unconfigured;
// after a transport's first use, a challenge is answered and the evidence
// lands in the host's datastore.
func TestWithAttestedCallerGate_ServesTheVerbs(t *testing.T) {
	client := newHostNodeClient(t)
	var resolved atomic.Pointer[xkms.XKMSService]
	m, err := NewModule(resolved.Load,
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	require.NoError(t, err)

	m.wirePeerEvidenceCollector()
	assert.False(t, m.peerGateWired.Load(), "nothing to wire while the service composes")

	svc := &xkms.XKMSService{}
	resolved.Store(svc)
	_, err = m.keystore()
	require.NoError(t, err)
	require.True(t, m.peerGateWired.Load())

	ctx := mutualTLSContext(t)
	challenge, err := svc.PeerAttestationChallenge(ctx)
	require.NoError(t, err)
	require.NoError(t, svc.SubmitPeerAttestation(ctx, &transport.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.Nonce,
		PCRs:             map[int][]byte{0: make([]byte, 32)},
		AKCertificatePEM: []byte("ak"),
	}))
}

// TestWithAttestedCallerGate_RunsOnTheServiceContext proves the gate's
// evidence storage runs as the host node's service principal
// (WithServiceContext): on a node that enforces authentication, the
// datastore initialises and the Submit verb persists its evidence.
func TestWithAttestedCallerGate_RunsOnTheServiceContext(t *testing.T) {
	node := barriertest.NewPrincipalNode(t)
	svc := &xkms.XKMSService{}
	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithQRDBClient(node.Client),
		WithServiceContext(node.ServiceContext),
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	require.NoError(t, err)

	_, err = m.peerEvidenceStorage()
	require.NoError(t, err)

	_, err = m.keystore()
	require.NoError(t, err)
	ctx := mutualTLSContext(t)
	challenge, err := svc.PeerAttestationChallenge(ctx)
	require.NoError(t, err)
	require.NoError(t, svc.SubmitPeerAttestation(ctx, &transport.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.Nonce,
		PCRs:             map[int][]byte{0: make([]byte, 32)},
		AKCertificatePEM: []byte("ak"),
	}))
}

// TestWithAttestedCallerGate_UnboundIsUnauthenticated proves why the binder
// is needed: without WithServiceContext the same node refuses the evidence
// storage.
func TestWithAttestedCallerGate_UnboundIsUnauthenticated(t *testing.T) {
	node := barriertest.NewPrincipalNode(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(node.Client),
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	require.NoError(t, err)

	_, err = m.peerEvidenceStorage()
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// TestWithAttestedCallerGate_StorageComposing proves evidence storage is
// refused, as composing, until the host's client resolves.
func TestWithAttestedCallerGate_StorageComposing(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(func() *qrdbsdk.Client { return nil }),
		WithAttestedCallerGate(testAttestedCallerPolicy()))
	require.NoError(t, err)

	_, err = m.peerEvidenceStorage()
	var composing *SurfaceComposingError
	require.ErrorAs(t, err, &composing)
	assert.Equal(t, attestedCallerStorage, composing.Surface)
}
