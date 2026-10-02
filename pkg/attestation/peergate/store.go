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
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
)

// DefaultMaxPeers bounds a MemoryStore, and a Collector's outstanding
// challenges, when the configuration leaves the limit zero.
const DefaultMaxPeers = 100_000

// DefaultRetention is how long a MemoryStore keeps evidence it may evict to
// make room for a new peer, when the configuration leaves it zero. Evidence
// this old is far past any sensible maximum evidence age, so evicting it
// changes no verdict: the gate would refuse it as stale anyway.
const DefaultRetention = 24 * time.Hour

// Record is the latest evidence one peer submitted.
type Record struct {
	// Thumbprint is the canonical SPKI thumbprint of the verified client
	// certificate the evidence arrived under. It is the record's key.
	Thumbprint string

	// Evidence is the evidence as the collector stored it, CollectedAt
	// stamped with the receipt time.
	Evidence peer.Evidence

	// ChannelBinding is the TLS exporter value of the connection the evidence
	// arrived on. The quote's qualifying data must be bound to it.
	ChannelBinding []byte
}

// clone returns a deep copy, so a record handed out never aliases a stored one.
func (r Record) clone() Record {
	pcrs := make(map[int][]byte, len(r.Evidence.PCRs))
	for idx, value := range r.Evidence.PCRs {
		pcrs[idx] = bytes.Clone(value)
	}
	return Record{
		Thumbprint: r.Thumbprint,
		Evidence: peer.Evidence{
			Quote:            bytes.Clone(r.Evidence.Quote),
			Signature:        bytes.Clone(r.Evidence.Signature),
			Nonce:            bytes.Clone(r.Evidence.Nonce),
			PCRs:             pcrs,
			AKCertificatePEM: bytes.Clone(r.Evidence.AKCertificatePEM),
			CollectedAt:      r.Evidence.CollectedAt,
		},
		ChannelBinding: bytes.Clone(r.ChannelBinding),
	}
}

// EvidenceStore holds the latest evidence per peer, keyed by SPKI thumbprint.
// The Collector writes it and the Verifier reads it. Implementations are safe
// for concurrent use.
type EvidenceStore interface {
	// Put stores r, replacing any earlier record for r.Thumbprint. The latest
	// evidence always wins, so a peer whose state turned bad cannot keep
	// presenting an older passing quote once it has submitted a new one.
	Put(ctx context.Context, r Record) error

	// Get returns the record for thumbprint. ok is false when the peer has
	// none; err is reserved for a store that could not answer.
	Get(ctx context.Context, thumbprint string) (r Record, ok bool, err error)

	// Delete withdraws the record for thumbprint, so the peer is refused until
	// it submits again. Deleting an absent record is not an error.
	Delete(ctx context.Context, thumbprint string) error
}

// MemoryStoreConfig bounds a MemoryStore.
type MemoryStoreConfig struct {
	// MaxPeers is the most peers the store holds evidence for. Zero means
	// DefaultMaxPeers; negative is invalid.
	MaxPeers int

	// Retention is the age past which a record may be evicted to admit a new
	// peer when the store is full. Zero means DefaultRetention; negative is
	// invalid. A record is never evicted while the store has room.
	Retention time.Duration
}

// MemoryStore is the in-process EvidenceStore. Evidence collected on one node
// is visible only to that node's verifier; a host that load-balances peers
// across nodes routes submissions to every node or supplies a shared
// EvidenceStore.
type MemoryStore struct {
	mu        sync.RWMutex
	records   map[string]Record
	maxPeers  int
	retention time.Duration
	now       func() time.Time
}

// Compile-time check that MemoryStore is an EvidenceStore.
var _ EvidenceStore = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore. It returns *ConfigError for a
// negative bound.
func NewMemoryStore(cfg MemoryStoreConfig, opts ...Option) (*MemoryStore, error) {
	if cfg.MaxPeers < 0 {
		return nil, &ConfigError{Field: "MaxPeers", Reason: "must not be negative"}
	}
	if cfg.Retention < 0 {
		return nil, &ConfigError{Field: "Retention", Reason: "must not be negative"}
	}
	if cfg.MaxPeers == 0 {
		cfg.MaxPeers = DefaultMaxPeers
	}
	if cfg.Retention == 0 {
		cfg.Retention = DefaultRetention
	}
	return &MemoryStore{
		records:   make(map[string]Record),
		maxPeers:  cfg.MaxPeers,
		retention: cfg.Retention,
		now:       newSettings(opts).now,
	}, nil
}

// Put implements EvidenceStore. A new peer beyond MaxPeers first evicts
// records older than Retention; if none is that old it is refused with
// *CapacityError and every existing record is kept.
func (s *MemoryStore) Put(ctx context.Context, r Record) error {
	if err := ctx.Err(); err != nil {
		return &peer.ContextError{Cause: err}
	}
	stored := r.clone()

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[r.Thumbprint]; !exists && len(s.records) >= s.maxPeers {
		s.evictExpiredLocked()
		if len(s.records) >= s.maxPeers {
			return &CapacityError{What: "evidence", Limit: s.maxPeers}
		}
	}
	s.records[r.Thumbprint] = stored
	return nil
}

// evictExpiredLocked drops every record older than the retention window. The
// caller holds the write lock.
func (s *MemoryStore) evictExpiredLocked() {
	cutoff := s.now().Add(-s.retention)
	for thumbprint, r := range s.records {
		if r.Evidence.CollectedAt.Before(cutoff) {
			delete(s.records, thumbprint)
		}
	}
}

// Get implements EvidenceStore.
func (s *MemoryStore) Get(ctx context.Context, thumbprint string) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, &peer.ContextError{Cause: err}
	}
	s.mu.RLock()
	r, ok := s.records[thumbprint]
	s.mu.RUnlock()
	if !ok {
		return Record{}, false, nil
	}
	return r.clone(), true, nil
}

// Delete implements EvidenceStore.
func (s *MemoryStore) Delete(ctx context.Context, thumbprint string) error {
	if err := ctx.Err(); err != nil {
		return &peer.ContextError{Cause: err}
	}
	s.mu.Lock()
	delete(s.records, thumbprint)
	s.mu.Unlock()
	return nil
}

// Len reports how many peers the store holds evidence for.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}
