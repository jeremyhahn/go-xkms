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

package peergate

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	evid "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
)

// VerifierConfig is what a Verifier demands of a peer. Like peer.Policy it is
// provisioned by the relying party and never learned from the peer.
type VerifierConfig struct {
	// Store is where the Collector put the evidence. Required.
	Store EvidenceStore

	// Policy is the quote policy: attestation key anchors, the PCR baseline,
	// required registers and, optionally, a maximum evidence age of its own
	// (go-qrdb's gate enforces its own bound regardless). Anchors and a
	// non-empty Baseline are required, since without either no peer could
	// ever pass. ChannelBinding must be empty: each record's evidence is
	// verified under the binding of the connection it arrived on, never under
	// one fixed value.
	Policy peer.Policy

	// DeviceIdentity, when set, additionally requires the certificate on the
	// gated connection to be a TCG device identity credential (IDevID or
	// LDevID) under this policy, naming the same TPM as the attestation key
	// that signed the quote (peer.VerifySameDevice). This closes the relay a
	// channel binding alone cannot: a host with a valid client certificate
	// quoting with another machine's attestation key. Nil leaves the
	// connection certificate to authentication.
	DeviceIdentity *peer.DevIDPolicy
}

// Verifier is go-xkms's go-qrdb PeerAttestationVerifier: it judges the
// evidence the Collector stored for the peer on a gated connection.
type Verifier struct {
	store  EvidenceStore
	policy peer.Policy
	device *peer.DevIDPolicy
	engine peer.Verifier
}

// Compile-time check that Verifier satisfies go-qrdb's attested-caller seam.
var _ qrdbsdk.PeerAttestationVerifier = (*Verifier)(nil)

// NewVerifier returns a Verifier over cfg.Store. It returns *ConfigError for
// a missing store, a policy with no anchors or no baseline, a policy carrying
// a fixed channel binding, a policy peer.Verify cannot evaluate, or a device
// identity policy with no anchors.
func NewVerifier(cfg VerifierConfig, opts ...Option) (*Verifier, error) {
	if cfg.Store == nil {
		return nil, &ConfigError{Field: "Store", Reason: "an evidence store is required"}
	}
	if cfg.Policy.Anchors == nil {
		return nil, &ConfigError{Field: "Policy.Anchors", Reason: "no attestation key anchors; no quote could ever verify"}
	}
	if len(cfg.Policy.Baseline) == 0 {
		return nil, &ConfigError{Field: "Policy.Baseline", Reason: "no PCR baseline; no measured state could ever pass"}
	}
	if len(cfg.Policy.ChannelBinding) != 0 {
		return nil, &ConfigError{Field: "Policy.ChannelBinding", Reason: "must be empty; each record is verified under its own connection's binding"}
	}
	if cfg.DeviceIdentity != nil && cfg.DeviceIdentity.Anchors == nil {
		return nil, &ConfigError{Field: "DeviceIdentity.Anchors", Reason: "no device identity anchors; no connection certificate could ever verify"}
	}

	settings := newSettings(opts)
	engine := peer.NewVerifier(peer.WithClock(settings.now))
	// peer.Verify reports an unusable policy as an error and everything else
	// in the verdict, so verifying no evidence at all is exactly a policy
	// check -- made here, once, instead of on the first gated request.
	if _, err := engine.Verify(context.Background(), peer.Evidence{}, cfg.Policy); err != nil {
		return nil, &ConfigError{Field: "Policy", Reason: "cannot be evaluated", Cause: err}
	}

	v := &Verifier{store: cfg.Store, policy: cfg.Policy, engine: engine}
	if cfg.DeviceIdentity != nil {
		device := *cfg.DeviceIdentity
		v.device = &device
	}
	return v, nil
}

// judgment accumulates a verdict across the quote and the device checks, with
// the same rule peer.Verify applies: cryptographic dominates absence.
type judgment struct {
	passed        bool
	cryptographic bool
	reasons       []string
}

func (j *judgment) fail(class peer.FailureClass, reason string) {
	j.passed = false
	if class == peer.FailureCryptographic {
		j.cryptographic = true
	}
	j.reasons = append(j.reasons, reason)
}

func (j *judgment) failure() qrdbsdk.PeerAttestationFailure {
	switch {
	case j.passed:
		return qrdbsdk.PeerAttestationFailureNone
	case j.cryptographic:
		return qrdbsdk.PeerAttestationFailureCryptographic
	default:
		return qrdbsdk.PeerAttestationFailureAbsence
	}
}

// VerifyPeer implements go-qrdb's PeerAttestationVerifier.
//
// The peer is looked up by the SPKI thumbprint of the certificate
// authentication verified, and nothing the request carries. The stored
// evidence is verified afresh, under the provisioned policy bound to the
// connection the evidence arrived on, so a policy change or an expiring
// attestation key certificate takes effect on the next request.
//
// A peer with no evidence, or evidence that does not pass, gets a refusing
// verdict naming every failed check. An error is returned only when no
// verdict can be rendered: a peer description that does not describe its
// certificate (*AttestedPeerError), a store failure (*StoreError), a done
// context (*peer.ContextError), or a device policy that cannot be evaluated
// (*peer.DevIDPolicyError). The gate refuses on an error too.
func (v *Verifier) VerifyPeer(ctx context.Context, attested qrdbsdk.AttestedPeer) (*qrdbsdk.PeerAttestation, error) {
	if err := ctx.Err(); err != nil {
		return nil, &peer.ContextError{Cause: err}
	}
	if attested.Certificate == nil {
		return nil, &AttestedPeerError{Reason: "no certificate"}
	}
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(attested.Certificate)
	if attested.Thumbprint != thumbprint {
		return nil, &AttestedPeerError{Reason: "the thumbprint is not the certificate's SPKI thumbprint"}
	}

	record, ok, err := v.store.Get(ctx, thumbprint)
	if err != nil {
		return nil, &StoreError{Op: "get", Cause: err}
	}
	if !ok {
		return &qrdbsdk.PeerAttestation{
			PeerThumbprint: thumbprint,
			Failure:        qrdbsdk.PeerAttestationFailureAbsence,
			Reason:         "no attestation evidence has been collected from this peer",
		}, nil
	}
	if len(record.ChannelBinding) != peer.ChannelBindingLength {
		// An unbound record would verify under an unbound policy and accept a
		// relayed quote. The Collector never writes one; a foreign store might.
		return &qrdbsdk.PeerAttestation{
			PeerThumbprint: record.Thumbprint,
			CollectedAt:    record.Evidence.CollectedAt,
			Failure:        qrdbsdk.PeerAttestationFailureAbsence,
			Reason:         "the stored evidence carries no channel binding",
		}, nil
	}

	policy := v.policy
	policy.ChannelBinding = record.ChannelBinding
	verdict, err := v.engine.Verify(ctx, record.Evidence, policy)
	if err != nil {
		return nil, err
	}
	j := &judgment{passed: verdict.Passed}
	if !verdict.Passed {
		j.fail(verdict.Failure, verdict.Reason)
	}
	if v.device != nil {
		if err := v.checkDevice(ctx, attested.Certificate, record.Evidence.AKCertificatePEM, j); err != nil {
			return nil, err
		}
	}

	return &qrdbsdk.PeerAttestation{
		// The record's own key, not the lookup key: a store that answered with
		// another peer's record is caught by the gate as a peer mismatch.
		PeerThumbprint: record.Thumbprint,
		CollectedAt:    record.Evidence.CollectedAt,
		Passed:         j.passed,
		Failure:        j.failure(),
		Reason:         strings.Join(j.reasons, "; "),
	}, nil
}

// checkDevice holds the connection certificate to the device identity policy
// and to the attestation key's TPM. A connection certificate that is not a
// device credential, or an attestation key certificate that names no TPM, is
// an absence; two well-formed credentials naming different TPMs is the relay
// this check exists for, and is cryptographic. It returns an error only when
// the device policy cannot be evaluated or the context is done.
func (v *Verifier) checkDevice(ctx context.Context, connection *x509.Certificate, akPEM []byte, j *judgment) error {
	if err := peer.VerifyIDevID(ctx, connection, *v.device); err != nil {
		var credential *peer.DevIDError
		if !errors.As(err, &credential) {
			return err
		}
		j.fail(peer.FailureAbsence, "the connection certificate is not a usable device identity credential: "+credential.Reason)
		return nil
	}
	if len(akPEM) == 0 {
		j.fail(peer.FailureAbsence, "device binding not evaluated: no attestation key certificate")
		return nil
	}
	ak, _, err := evid.ParseCertificatesPEM(akPEM)
	if err != nil {
		j.fail(peer.FailureAbsence, "device binding not evaluated: the attestation key certificate does not parse")
		return nil
	}

	err = peer.VerifySameDevice(connection, ak)
	var mismatch *peer.DeviceMismatchError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &mismatch):
		j.fail(peer.FailureCryptographic, "the attestation key belongs to a different TPM than the connection's device identity: "+mismatch.Field+" differs")
	default:
		j.fail(peer.FailureAbsence, "device binding not evaluated: "+err.Error())
	}
	return nil
}
