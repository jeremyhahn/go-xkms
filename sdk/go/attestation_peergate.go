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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// The attested-caller gate, go-xkms's side. go-qrdb owns the gate
// (sdk.NewPeerAttestationGate, node.WithPeerAttestationGate) and the seam it
// calls; pkg/attestation/peergate implements that seam over the verification
// primitive above, with the evidence cache it reads and the collector that
// fills it. A host hosting the xkms module builds it with one option and
// installs it on its node:
//
//	module, _ := xkms.NewServiceModule(resolve,
//		xkms.WithServiceModuleQRDBClient(client),
//		xkms.WithAttestedCallerGate(policy))
//	node, _ := qrdbnode.NewStandaloneNode(ctx, cfg, serverOpts,
//		qrdbnode.WithPeerAttestationGate(module.PeerAttestationGate()))
//
// The module serves the Challenge/Submit verbs on every transport and keeps
// the evidence in the host's datastore. A peer answers a challenge with
// PeerQuoteEvidence. The policy's PCR values are the host's; go-xkms ships
// none.

// AttestedCallerPolicy is the policy WithAttestedCallerGate builds the gate
// from: its mode, the quote policy each peer's evidence is verified under,
// the gated permissions and the oldest evidence accepted.
type AttestedCallerPolicy = peergate.GatePolicy

const (
	// AttestedCallerOptional admits a peer without evidence and refuses one
	// whose evidence fails.
	AttestedCallerOptional = peergate.ModeOptional
	// AttestedCallerRequired refuses every gated call from a peer that is
	// not currently attested. It is the policy's zero value.
	AttestedCallerRequired = peergate.ModeRequired
)

// PeerGateVerifier is go-qrdb's PeerAttestationVerifier: VerifyPeer judges the
// evidence collected from the peer on a gated connection, from the cache, on
// every call.
type PeerGateVerifier = peergate.Verifier

// PeerGateVerifierConfig is the store, the quote policy and the optional
// device identity policy a PeerGateVerifier demands.
type PeerGateVerifierConfig = peergate.VerifierConfig

// NewPeerGateVerifier constructs a PeerGateVerifier. It refuses a
// configuration under which no peer could ever pass with *PeerGateConfigError.
var NewPeerGateVerifier = peergate.NewVerifier

// PeerEvidenceCollector issues single-use challenges to authenticated peers
// and stores the evidence they answer with, bound to the connection it
// arrived on and stamped with its receipt time.
type PeerEvidenceCollector = peergate.Collector

// PeerEvidenceCollectorConfig is the store, challenge lifetime and
// outstanding-challenge bound of a PeerEvidenceCollector.
type PeerEvidenceCollectorConfig = peergate.CollectorConfig

// NewPeerEvidenceCollector constructs a PeerEvidenceCollector.
var NewPeerEvidenceCollector = peergate.NewCollector

// PeerChallenge is a nonce issued to one peer and its expiry.
type PeerChallenge = peergate.Challenge

// PeerEvidenceStore holds the latest evidence per peer, keyed by the SPKI
// thumbprint of its verified client certificate.
type PeerEvidenceStore = peergate.EvidenceStore

// PeerEvidenceRecord is one peer's stored evidence and channel binding.
type PeerEvidenceRecord = peergate.Record

// PeerDAOEvidenceStore is the PeerEvidenceStore persisted through a qrdb DAO.
type PeerDAOEvidenceStore = peergate.DAOStore

// PeerDAOEvidenceStoreConfig is the DAO factory and bounds of a
// PeerDAOEvidenceStore.
type PeerDAOEvidenceStoreConfig = peergate.DAOStoreConfig

// NewPeerDAOEvidenceStore constructs a PeerDAOEvidenceStore.
var NewPeerDAOEvidenceStore = peergate.NewDAOStore

// PeerEvidenceDatabase is the qrdb database a PeerDAOEvidenceStore persists
// in; the host ensures it on its datastore first.
const PeerEvidenceDatabase = peergate.DatabaseName

// PeerGateOption configures a collector, verifier or evidence store.
type PeerGateOption = peergate.Option

// WithPeerGateClock pins the clock of a collector, verifier or evidence store.
var WithPeerGateClock = peergate.WithClock

// PeerQuoter produces a TPM 2.0 quote; the TPM2 keystore is one.
type PeerQuoter = peergate.Quoter

// PeerQuoteEvidence is the quoting side of a challenge: it binds the nonce to
// the connection, quotes, and assembles the evidence to submit.
var PeerQuoteEvidence = peergate.QuoteEvidence

// PeerVerifySameDevice reports whether a device identity credential and an
// attestation key credential name the same TPM (TCG DevID §8.1 hardware module
// name and permanent identifier).
var PeerVerifySameDevice = peer.VerifySameDevice

// PeerDeviceMismatchError reports a device identity credential and an
// attestation key credential that name different TPMs.
type PeerDeviceMismatchError = peer.DeviceMismatchError

// The attested-caller gate's typed errors.
type (
	// PeerGateConfigError reports an unusable collector, verifier or store
	// configuration.
	PeerGateConfigError = peergate.ConfigError
	// PeerCertificateError reports a connection with no verified client
	// certificate.
	PeerCertificateError = peergate.PeerCertificateError
	// PeerChallengeError reports evidence that answers no outstanding
	// challenge.
	PeerChallengeError = peergate.ChallengeError
	// PeerGateAttestedPeerError reports a go-qrdb AttestedPeer the verifier
	// cannot judge.
	PeerGateAttestedPeerError = peergate.AttestedPeerError
	// PeerGateCapacityError reports a store or collector at its peer bound.
	PeerGateCapacityError = peergate.CapacityError
	// PeerEvidenceStoreError reports a failed evidence store operation.
	PeerEvidenceStoreError = peergate.StoreError
	// PeerQuoteError reports a quote that could not become evidence.
	PeerQuoteError = peergate.QuoteError
	// PeerNonceError reports a challenge nonce the random source could not
	// produce.
	PeerNonceError = peergate.NonceError
)

const (
	// PeerChallengeNonceLength is the length of a challenge nonce in bytes.
	PeerChallengeNonceLength = peergate.NonceLength
	// DefaultPeerChallengeTTL is a challenge's lifetime when none is set.
	DefaultPeerChallengeTTL = peergate.DefaultChallengeTTL
	// DefaultPeerGateMaxPeers bounds a store and the outstanding challenges
	// when no bound is set.
	DefaultPeerGateMaxPeers = peergate.DefaultMaxPeers
	// DefaultPeerEvidenceRetention is how long an evidence store keeps evidence
	// before it may evict it for a new peer, when none is set.
	DefaultPeerEvidenceRetention = peergate.DefaultRetention
)
