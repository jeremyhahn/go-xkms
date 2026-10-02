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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
)

// NonceLength is the length in bytes of a challenge nonce.
const NonceLength = 32

// DefaultChallengeTTL is how long a challenge may be answered when the
// configuration leaves ChallengeTTL zero. A TPM quote takes well under a
// second; the margin covers a slow TPM and the round trip.
const DefaultChallengeTTL = time.Minute

// CollectorConfig configures a Collector.
type CollectorConfig struct {
	// Store receives the evidence. Required; the Verifier reads the same
	// store.
	Store EvidenceStore

	// ChallengeTTL is how long an issued nonce may be answered. Zero means
	// DefaultChallengeTTL; negative is invalid.
	ChallengeTTL time.Duration

	// MaxPendingChallenges bounds the outstanding challenges, one per peer.
	// Zero means DefaultMaxPeers; negative is invalid.
	MaxPendingChallenges int
}

// Challenge is a nonce issued to one peer.
type Challenge struct {
	// Nonce is the value the peer must quote over, bound to its connection
	// (QuoteEvidence, or peer.QualifyingDataFromTLS).
	Nonce []byte

	// ExpiresAt is the last instant the evidence answering it is accepted.
	ExpiresAt time.Time
}

// pending is an outstanding challenge.
type pending struct {
	nonce     []byte
	expiresAt time.Time
}

// Collector issues challenges to authenticated peers and stores the evidence
// they answer with. It is the only writer of evidence: a record exists only
// for a peer that answered a nonce this collector issued to it, over a
// connection authenticated as that peer, with a quote bound to that
// connection.
type Collector struct {
	store      EvidenceStore
	ttl        time.Duration
	maxPending int
	now        func() time.Time

	mu      sync.Mutex
	pending map[string]pending
}

// NewCollector returns a Collector writing to cfg.Store. It returns
// *ConfigError for a missing store or a negative bound.
func NewCollector(cfg CollectorConfig, opts ...Option) (*Collector, error) {
	if cfg.Store == nil {
		return nil, &ConfigError{Field: "Store", Reason: "an evidence store is required"}
	}
	if cfg.ChallengeTTL < 0 {
		return nil, &ConfigError{Field: "ChallengeTTL", Reason: "must not be negative"}
	}
	if cfg.MaxPendingChallenges < 0 {
		return nil, &ConfigError{Field: "MaxPendingChallenges", Reason: "must not be negative"}
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = DefaultChallengeTTL
	}
	if cfg.MaxPendingChallenges == 0 {
		cfg.MaxPendingChallenges = DefaultMaxPeers
	}
	return &Collector{
		store:      cfg.Store,
		ttl:        cfg.ChallengeTTL,
		maxPending: cfg.MaxPendingChallenges,
		now:        newSettings(opts).now,
		pending:    make(map[string]pending),
	}, nil
}

// Challenge issues a fresh nonce to the peer authenticated on state. A peer
// holds at most one outstanding challenge: a new one replaces the last.
//
// It returns *PeerCertificateError when the connection has no verified client
// certificate, *CapacityError when MaxPendingChallenges unexpired challenges
// are outstanding for other peers, and *peer.ContextError for a done context.
func (c *Collector) Challenge(ctx context.Context, state *tls.ConnectionState) (Challenge, error) {
	if err := ctx.Err(); err != nil {
		return Challenge{}, &peer.ContextError{Cause: err}
	}
	_, thumbprint, err := verifiedPeer(state)
	if err != nil {
		return Challenge{}, err
	}
	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, &NonceError{Cause: err}
	}
	now := c.now()
	issued := pending{nonce: nonce, expiresAt: now.Add(c.ttl)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.pending[thumbprint]; !exists && len(c.pending) >= c.maxPending {
		c.expireLocked(now)
		if len(c.pending) >= c.maxPending {
			return Challenge{}, &CapacityError{What: "challenges", Limit: c.maxPending}
		}
	}
	c.pending[thumbprint] = issued
	return Challenge{Nonce: bytes.Clone(nonce), ExpiresAt: issued.expiresAt}, nil
}

// expireLocked drops every challenge past its expiry. The caller holds c.mu.
func (c *Collector) expireLocked(now time.Time) {
	for thumbprint, p := range c.pending {
		if now.After(p.expiresAt) {
			delete(c.pending, thumbprint)
		}
	}
}

// take removes and returns the outstanding challenge for thumbprint. A
// challenge is consumed by any submission, accepted or not, so a nonce can be
// answered at most once.
func (c *Collector) take(thumbprint string) (pending, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[thumbprint]
	if ok {
		delete(c.pending, thumbprint)
	}
	return p, ok
}

// Submit stores the evidence the peer authenticated on state reported in
// answer to its outstanding challenge.
//
// The peer is the verified client certificate on state, and the evidence is
// bound to state's TLS exporter value; CollectedAt is the receipt time,
// whatever the peer reported. Submit does not judge the quote: the Verifier
// does, on every gated request, so a submission whose quote is wrong is stored
// and refused there as a cryptographic failure rather than silently dropped.
//
// It returns *PeerCertificateError for a connection with no verified client
// certificate, *ChallengeError when the evidence does not answer an unexpired
// challenge issued to this peer, *peer.ChannelBindingError when the connection
// cannot export keying material, *StoreError when the store refuses the
// record, and *peer.ContextError for a done context. Nothing is stored on an
// error.
func (c *Collector) Submit(ctx context.Context, state *tls.ConnectionState, reported peer.Evidence) error {
	if err := ctx.Err(); err != nil {
		return &peer.ContextError{Cause: err}
	}
	_, thumbprint, err := verifiedPeer(state)
	if err != nil {
		return err
	}
	challenge, ok := c.take(thumbprint)
	if !ok {
		return &ChallengeError{Reason: "no challenge is outstanding for this peer"}
	}
	now := c.now()
	if now.After(challenge.expiresAt) {
		return &ChallengeError{Reason: "the challenge expired at " + challenge.expiresAt.UTC().Format(time.RFC3339)}
	}
	if subtle.ConstantTimeCompare(challenge.nonce, reported.Nonce) != 1 {
		return &ChallengeError{Reason: "the evidence carries a nonce this peer was not issued"}
	}

	bound, err := peer.EvidenceFromTLS(state, reported)
	if err != nil {
		return err
	}
	bound.Evidence.CollectedAt = now
	if err := c.store.Put(ctx, Record{
		Thumbprint:     thumbprint,
		Evidence:       bound.Evidence,
		ChannelBinding: bound.ChannelBinding,
	}); err != nil {
		return &StoreError{Op: "put", Cause: err}
	}
	return nil
}
