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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testAttestedCallerPolicy describes a gate; no quote can pass it, which
// these tests never need.
func testAttestedCallerPolicy() peergate.GatePolicy {
	return peergate.GatePolicy{
		Quote: peer.Policy{
			Anchors:  x509.NewCertPool(),
			Baseline: map[int][]byte{0: make([]byte, 32)},
		},
		Permissions:    []qrdbsdk.Permission{qrdbsdk.PermissionAdminStatus},
		MaxEvidenceAge: time.Minute,
	}
}

func newPeerGateTestServer(t *testing.T, attestation *config.AttestationConfig, opts ...Option) *Server {
	t.Helper()
	s := &Server{
		config: &config.Config{
			Datastore:   config.DatastoreConfig{Path: t.TempDir()},
			Attestation: attestation,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctx:    context.Background(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// testPeer is a connection certificate's identity as go-qrdb hands it to
// the verifier.
func testPeer(t *testing.T) qrdbsdk.AttestedPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return qrdbsdk.AttestedPeer{Certificate: cert, Thumbprint: qrdbsdk.ComputeSPKIThumbprint(cert)}
}

func TestAttestedCallerNodeOptions_OffInstallsNothing(t *testing.T) {
	sections := map[string]*config.AttestationConfig{
		"no attestation section": nil,
		"unset":                  {},
		"off":                    {PeerGate: "off"},
	}
	for name, section := range sections {
		t.Run(name, func(t *testing.T) {
			s := newPeerGateTestServer(t, section)
			opts, err := s.attestedCallerNodeOptions()
			require.NoError(t, err, "no gate needs no policy")
			assert.Empty(t, opts)
			assert.Nil(t, s.peerGate)
			assert.NoError(t, s.bindPeerEvidenceStorage(), "no gate, nothing to bind")
		})
	}
}

func TestAttestedCallerNodeOptions_InstallsTheConfiguredMode(t *testing.T) {
	for _, mode := range []peergate.Mode{peergate.ModeOptional, peergate.ModeRequired} {
		t.Run(string(mode), func(t *testing.T) {
			policy := testAttestedCallerPolicy()
			policy.Mode = peergate.ModeRequired
			if mode == peergate.ModeRequired {
				policy.Mode = peergate.ModeOptional
			}
			s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: string(mode)}, WithAttestedCallerPolicy(policy))

			opts, err := s.attestedCallerNodeOptions()
			require.NoError(t, err)
			assert.Len(t, opts, 1)
			require.NotNil(t, s.peerGate)
			assert.Equal(t, mode, s.peerGate.Mode(), "attestation.peer_gate wins over the policy's mode")
			assert.True(t, s.peerGate.PeerAttestationGate().Gates(qrdbsdk.PermissionAdminStatus))
		})
	}
}

// TestWirePeerEvidenceCollector_ServesTheVerbsOnlyWithAGate proves the peer
// attestation verbs reach the installed gate's collector, and stay
// unconfigured on a server whose node runs no gate.
func TestWirePeerEvidenceCollector_ServesTheVerbsOnlyWithAGate(t *testing.T) {
	state, err := testutil.MutualTLSState()
	require.NoError(t, err)
	ctx := auth.WithTLSState(context.Background(), state)

	t.Run("gate installed", func(t *testing.T) {
		s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "required"}, WithAttestedCallerPolicy(testAttestedCallerPolicy()))
		_, err := s.attestedCallerNodeOptions()
		require.NoError(t, err)
		svc := &xkms.XKMSService{}
		s.wirePeerEvidenceCollector(svc)

		challenge, err := svc.PeerAttestationChallenge(ctx)
		require.NoError(t, err)
		assert.Len(t, challenge.Nonce, peergate.NonceLength)
	})

	t.Run("no gate", func(t *testing.T) {
		s := newPeerGateTestServer(t, nil)
		svc := &xkms.XKMSService{}
		s.wirePeerEvidenceCollector(svc)

		_, err := svc.PeerAttestationChallenge(ctx)
		assert.ErrorIs(t, err, xkms.ErrNotConfigured)
	})
}

func TestAttestedCallerNodeOptions_RefusesAGateItCannotBuild(t *testing.T) {
	s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "required"})
	_, err := s.attestedCallerNodeOptions()
	assert.ErrorIs(t, err, ErrAttestedCallerPolicyMissing, "go-xkms ships no reference values")
	assert.Nil(t, s.peerGate)

	s = newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "enforce"}, WithAttestedCallerPolicy(testAttestedCallerPolicy()))
	_, err = s.attestedCallerNodeOptions()
	var modeErr *peergate.ModeError
	assert.ErrorAs(t, err, &modeErr)

	broken := testAttestedCallerPolicy()
	broken.Permissions = peergate.ExemptPermissions()
	s = newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "optional"}, WithAttestedCallerPolicy(broken))
	_, err = s.attestedCallerNodeOptions()
	var configErr *peergate.ConfigError
	assert.ErrorAs(t, err, &configErr)
	assert.Nil(t, s.peerGate)
}

func TestWithAttestedCallerPolicy_KeepsItsOwnPermissions(t *testing.T) {
	policy := testAttestedCallerPolicy()
	s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "required"}, WithAttestedCallerPolicy(policy))
	policy.Permissions[0] = peergate.ExemptPermissions()[0]

	_, err := s.attestedCallerNodeOptions()
	require.NoError(t, err, "the caller's later edit must not reach the server")
	assert.True(t, s.peerGate.PeerAttestationGate().Gates(qrdbsdk.PermissionAdminStatus))
}

func TestAttestedCallerGate_FailsClosedUntilTheDatastoreOpens(t *testing.T) {
	s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "optional"}, WithAttestedCallerPolicy(testAttestedCallerPolicy()))
	_, err := s.attestedCallerNodeOptions()
	require.NoError(t, err)

	// Optional mode admits an absent peer, but without the datastore the
	// gate cannot tell absent from failing, so the verifier errors.
	_, err = s.peerGate.Verifier().VerifyPeer(context.Background(), testPeer(t))
	var storeErr *peergate.StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.ErrorIs(t, err, ErrNoDatastore)

	err = s.bindPeerEvidenceStorage()
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	assert.ErrorIs(t, err, ErrNoDatastore)
}

func TestAttestedCallerGate_BindsToTheNodeDatastore(t *testing.T) {
	cases := map[string]struct {
		mode    string
		passed  bool
		failure qrdbsdk.PeerAttestationFailure
	}{
		"required refuses an unattested peer": {"required", false, qrdbsdk.PeerAttestationFailureAbsence},
		"optional admits an unattested peer":  {"optional", true, qrdbsdk.PeerAttestationFailureNone},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: tc.mode}, WithAttestedCallerPolicy(testAttestedCallerPolicy()))
			require.NoError(t, s.initializeQRDBStorage())
			t.Cleanup(func() { assert.NoError(t, s.closeQRDBStorage()) })

			require.NotNil(t, s.peerGate, "initEmbeddedQRDBNode installs the gate")
			daos, err := s.peerEvidenceStorage()
			require.NoError(t, err)
			assert.NotNil(t, daos)

			verdict, err := s.peerGate.Verifier().VerifyPeer(context.Background(), testPeer(t))
			require.NoError(t, err, "the evidence store reads the node's datastore")
			assert.Equal(t, tc.passed, verdict.Passed, "reason: %s", verdict.Reason)
			assert.Equal(t, tc.failure, verdict.Failure)
		})
	}
}
