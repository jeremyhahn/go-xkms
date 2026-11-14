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
	"crypto/x509"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// harness is one peer, the PKI that issued its credentials, and a collector
// and verifier sharing one store.
type harness struct {
	pki       *pki
	conn      connection
	leaf      *x509.Certificate
	ak        attestationKey
	clock     *clock
	store     *peergate.DAOStore
	collector *peergate.Collector
}

func newHarness(t *testing.T, peerDevice, akDevice device) *harness {
	t.Helper()
	p := newPKI(t)
	client, leaf := p.clientCert(t, peerDevice)
	c := newClock()
	store := newStore(t, peergate.WithClock(c.Now))
	return &harness{
		pki:       p,
		conn:      p.connect(t, client),
		leaf:      leaf,
		ak:        p.newAK(t, akDevice),
		clock:     c,
		store:     store,
		collector: newCollector(t, store, c),
	}
}

func (h *harness) policy() peer.Policy {
	return peer.Policy{Anchors: h.pki.pool, Baseline: goldenPCRs(), RequiredPCRs: []int{10}}
}

func (h *harness) verifier(t *testing.T, cfg peergate.VerifierConfig) *peergate.Verifier {
	t.Helper()
	cfg.Store = h.store
	if cfg.Policy.Anchors == nil {
		cfg.Policy = h.policy()
	}
	v, err := peergate.NewVerifier(cfg, peergate.WithClock(h.clock.Now))
	require.NoError(t, err)
	return v
}

// submit challenges the peer and submits the evidence build makes from the
// nonce.
func (h *harness) submit(t *testing.T, build func(nonce []byte) peer.Evidence) {
	t.Helper()
	challenge, err := h.collector.Challenge(context.Background(), h.conn.server)
	require.NoError(t, err)
	require.NoError(t, h.collector.Submit(context.Background(), h.conn.server, build(challenge.Nonce)))
}

func (h *harness) honest(t *testing.T) func([]byte) peer.Evidence {
	return func(nonce []byte) peer.Evidence { return h.ak.evidence(t, h.conn, nonce, goldenPCRs()) }
}

func (h *harness) attested() qrdbsdk.AttestedPeer {
	return qrdbsdk.AttestedPeer{Certificate: h.leaf, Thumbprint: qrdbsdk.ComputeSPKIThumbprint(h.leaf)}
}

func (h *harness) verify(t *testing.T, v *peergate.Verifier) *qrdbsdk.PeerAttestation {
	t.Helper()
	verdict, err := v.VerifyPeer(context.Background(), h.attested())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	return verdict
}

// Each case is evidence that is present and wrong: the verdict must refuse it
// as a cryptographic failure, the class go-qrdb's gate audits as a security
// event.
func TestVerifier_RefusesWrongEvidenceAsCryptographic(t *testing.T) {
	cases := map[string]func(t *testing.T, h *harness) func([]byte) peer.Evidence{
		"quote bound to another connection": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			other, _ := h.pki.clientCert(t, device{})
			elsewhere := h.pki.connect(t, other)
			return func(nonce []byte) peer.Evidence { return h.ak.evidence(t, elsewhere, nonce, goldenPCRs()) }
		},
		"quote over the bare nonce": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			return func(nonce []byte) peer.Evidence {
				attest, signature := h.ak.quote(t, nonce, goldenPCRs())
				return peer.Evidence{Quote: attest, Signature: signature, Nonce: nonce, PCRs: goldenPCRs(), AKCertificatePEM: h.ak.pem}
			}
		},
		"forged signature": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			forger := h.pki.newAK(t, device{})
			return func(nonce []byte) peer.Evidence {
				evidence := forger.evidence(t, h.conn, nonce, goldenPCRs())
				evidence.AKCertificatePEM = h.ak.pem // claims the genuine key
				return evidence
			}
		},
		"attestation key from an untrusted CA": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			rogue := newPKI(t).newAK(t, device{})
			return func(nonce []byte) peer.Evidence { return rogue.evidence(t, h.conn, nonce, goldenPCRs()) }
		},
		"measured state off the baseline": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			return func(nonce []byte) peer.Evidence {
				swapped := goldenPCRs()
				swapped[10] = fill(0xee)
				return h.ak.evidence(t, h.conn, nonce, swapped)
			}
		},
		"reported values that are not the quoted ones": func(t *testing.T, h *harness) func([]byte) peer.Evidence {
			return func(nonce []byte) peer.Evidence {
				evidence := h.ak.evidence(t, h.conn, nonce, goldenPCRs())
				evidence.PCRs = map[int][]byte{0: fill(0x10), 7: fill(0x17), 10: fill(0x99)}
				return evidence
			}
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, device{}, device{})
			h.submit(t, build(t, h))

			verdict := h.verify(t, h.verifier(t, peergate.VerifierConfig{}))
			assert.False(t, verdict.Passed)
			assert.Equal(t, qrdbsdk.PeerAttestationFailureCryptographic, verdict.Failure, "reason: %s", verdict.Reason)
			assert.NotEmpty(t, verdict.Reason)
			assert.Equal(t, h.clock.now, verdict.CollectedAt)
		})
	}
}

func TestVerifier_StaleEvidenceIsAnAbsence(t *testing.T) {
	h := newHarness(t, device{}, device{})
	h.submit(t, h.honest(t))
	policy := h.policy()
	policy.MaxEvidenceAge = time.Minute
	v := h.verifier(t, peergate.VerifierConfig{Policy: policy})

	require.True(t, h.verify(t, v).Passed)
	h.clock.now = h.clock.now.Add(2 * time.Minute)

	verdict := h.verify(t, v)
	assert.False(t, verdict.Passed)
	assert.Equal(t, qrdbsdk.PeerAttestationFailureAbsence, verdict.Failure, "reason: %s", verdict.Reason)
}

// The latest evidence wins: a peer that submits a bad quote cannot keep
// presenting the good one it submitted before.
func TestVerifier_JudgesTheLatestEvidence(t *testing.T) {
	h := newHarness(t, device{}, device{})
	v := h.verifier(t, peergate.VerifierConfig{})
	h.submit(t, h.honest(t))
	require.True(t, h.verify(t, v).Passed)

	h.submit(t, func(nonce []byte) peer.Evidence {
		swapped := goldenPCRs()
		swapped[10] = fill(0xee)
		return h.ak.evidence(t, h.conn, nonce, swapped)
	})
	assert.False(t, h.verify(t, v).Passed)

	require.NoError(t, h.store.Delete(context.Background(), h.attested().Thumbprint))
	assert.Equal(t, qrdbsdk.PeerAttestationFailureAbsence, h.verify(t, v).Failure, "withdrawn evidence is an absence")
}

func TestVerifier_DeviceIdentityBinding(t *testing.T) {
	tpmA := device{serial: "IFX:0a0b:0c0d", permID: "a1a1a1a1"}
	tpmB := device{serial: "IFX:ffff:eeee", permID: "b2b2b2b2"}
	cases := map[string]struct {
		peerDevice, akDevice device
		passed               bool
		failure              qrdbsdk.PeerAttestationFailure
	}{
		"IDevID and IAK of one TPM":           {tpmA, tpmA, true, qrdbsdk.PeerAttestationFailureNone},
		"IAK of a different TPM":              {tpmA, tpmB, false, qrdbsdk.PeerAttestationFailureCryptographic},
		"connection certificate not a DevID":  {device{}, tpmA, false, qrdbsdk.PeerAttestationFailureAbsence},
		"attestation key names no TPM at all": {tpmA, device{}, false, qrdbsdk.PeerAttestationFailureAbsence},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tc.peerDevice, tc.akDevice)
			h.submit(t, h.honest(t))
			v := h.verifier(t, peergate.VerifierConfig{DeviceIdentity: &peer.DevIDPolicy{Anchors: h.pki.pool}})

			verdict := h.verify(t, v)
			assert.Equal(t, tc.passed, verdict.Passed, "reason: %s", verdict.Reason)
			assert.Equal(t, tc.failure, verdict.Failure, "reason: %s", verdict.Reason)
		})
	}
}

// With device binding on, an attestation key certificate the binding cannot
// read adds a "not evaluated" absence to the verdict and never a pass. The
// verdict's class stays whatever the quote checks made it: a missing
// certificate is an absence there too, a malformed one is evidence that is
// present and wrong.
func TestVerifier_DeviceBindingWithoutAReadableAKCertificate(t *testing.T) {
	tpm := device{serial: "IFX:0a0b:0c0d", permID: "a1a1a1a1"}
	cases := map[string]struct {
		akPEM   []byte
		failure qrdbsdk.PeerAttestationFailure
	}{
		"no certificate":             {nil, qrdbsdk.PeerAttestationFailureAbsence},
		"certificate does not parse": {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), qrdbsdk.PeerAttestationFailureCryptographic},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tpm, tpm)
			h.submit(t, func(nonce []byte) peer.Evidence {
				evidence := h.ak.evidence(t, h.conn, nonce, goldenPCRs())
				evidence.AKCertificatePEM = tc.akPEM
				return evidence
			})
			v := h.verifier(t, peergate.VerifierConfig{DeviceIdentity: &peer.DevIDPolicy{Anchors: h.pki.pool}})

			verdict := h.verify(t, v)
			assert.False(t, verdict.Passed)
			assert.Equal(t, tc.failure, verdict.Failure, "reason: %s", verdict.Reason)
			assert.Contains(t, verdict.Reason, "device binding not evaluated")
		})
	}
}

func TestVerifier_ReturnsAnErrorWhenItCannotDecide(t *testing.T) {
	h := newHarness(t, device{}, device{})
	v := h.verifier(t, peergate.VerifierConfig{})
	_, otherLeaf := h.pki.clientCert(t, device{})

	t.Run("no certificate", func(t *testing.T) {
		_, err := v.VerifyPeer(context.Background(), qrdbsdk.AttestedPeer{Thumbprint: "x"})
		var peerErr *peergate.AttestedPeerError
		require.True(t, errors.As(err, &peerErr), "VerifyPeer = %v", err)
	})
	t.Run("thumbprint of another certificate", func(t *testing.T) {
		_, err := v.VerifyPeer(context.Background(), qrdbsdk.AttestedPeer{
			Certificate: h.leaf,
			Thumbprint:  qrdbsdk.ComputeSPKIThumbprint(otherLeaf),
		})
		var peerErr *peergate.AttestedPeerError
		require.True(t, errors.As(err, &peerErr), "VerifyPeer = %v", err)
	})
	t.Run("store down", func(t *testing.T) {
		down, err := peergate.NewVerifier(peergate.VerifierConfig{Store: failingStore{}, Policy: h.policy()})
		require.NoError(t, err)
		_, err = down.VerifyPeer(context.Background(), h.attested())
		var storeErr *peergate.StoreError
		require.True(t, errors.As(err, &storeErr), "VerifyPeer = %v", err)
		assert.Equal(t, "get", storeErr.Op)
	})
	t.Run("done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := v.VerifyPeer(ctx, h.attested())
		var ctxErr *peer.ContextError
		require.True(t, errors.As(err, &ctxErr), "VerifyPeer = %v", err)
	})
}

// recordStore answers every lookup with one fixed record, standing in for a
// foreign store that returns what it should not.
type recordStore struct{ record peergate.Record }

func (s recordStore) Put(context.Context, peergate.Record) error { return nil }
func (s recordStore) Get(context.Context, string) (peergate.Record, bool, error) {
	return s.record, true, nil
}
func (s recordStore) Delete(context.Context, string) error { return nil }

func TestVerifier_DistrustsWhatAStoreReturns(t *testing.T) {
	h := newHarness(t, device{}, device{})
	h.submit(t, h.honest(t))
	record, ok, err := h.store.Get(context.Background(), h.attested().Thumbprint)
	require.NoError(t, err)
	require.True(t, ok)

	t.Run("record without a channel binding", func(t *testing.T) {
		unbound := record
		unbound.ChannelBinding = nil
		v, err := peergate.NewVerifier(peergate.VerifierConfig{Store: recordStore{unbound}, Policy: h.policy()}, peergate.WithClock(h.clock.Now))
		require.NoError(t, err)
		verdict := h.verify(t, v)
		assert.False(t, verdict.Passed, "an unbound record must never verify under an unbound policy")
		assert.Equal(t, qrdbsdk.PeerAttestationFailureAbsence, verdict.Failure)
	})
	t.Run("another peer's record", func(t *testing.T) {
		foreign := record
		foreign.Thumbprint = "another-peer"
		v, err := peergate.NewVerifier(peergate.VerifierConfig{Store: recordStore{foreign}, Policy: h.policy()}, peergate.WithClock(h.clock.Now))
		require.NoError(t, err)
		verdict := h.verify(t, v)
		assert.Equal(t, "another-peer", verdict.PeerThumbprint, "the verdict names whose evidence it judged, so the gate can refuse the mismatch")
	})
}

func TestNewVerifier_RefusesAnUnusableConfiguration(t *testing.T) {
	h := newHarness(t, device{}, device{})
	good := h.policy()
	noAnchors := good
	noAnchors.Anchors = nil
	noBaseline := good
	noBaseline.Baseline = nil
	bound := good
	bound.ChannelBinding = make([]byte, peer.ChannelBindingLength)
	negativeAge := good
	negativeAge.MaxEvidenceAge = -time.Second

	cases := map[string]struct {
		cfg   peergate.VerifierConfig
		field string
	}{
		"no store":                    {peergate.VerifierConfig{Policy: good}, "Store"},
		"no anchors":                  {peergate.VerifierConfig{Store: h.store, Policy: noAnchors}, "Policy.Anchors"},
		"no baseline":                 {peergate.VerifierConfig{Store: h.store, Policy: noBaseline}, "Policy.Baseline"},
		"fixed channel binding":       {peergate.VerifierConfig{Store: h.store, Policy: bound}, "Policy.ChannelBinding"},
		"policy that cannot evaluate": {peergate.VerifierConfig{Store: h.store, Policy: negativeAge}, "Policy"},
		"device policy without anchors": {
			peergate.VerifierConfig{Store: h.store, Policy: good, DeviceIdentity: &peer.DevIDPolicy{}},
			"DeviceIdentity.Anchors",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := peergate.NewVerifier(tc.cfg)
			var cfgErr *peergate.ConfigError
			require.True(t, errors.As(err, &cfgErr), "NewVerifier = %v", err)
			assert.Equal(t, tc.field, cfgErr.Field)
		})
	}
}
