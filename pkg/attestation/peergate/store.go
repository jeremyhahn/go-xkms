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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// DefaultMaxPeers bounds a DAOStore, and a Collector's outstanding
// challenges, when the configuration leaves the limit zero.
const DefaultMaxPeers = 100_000

// DefaultRetention is how long a DAOStore keeps a peer's evidence before it
// may be evicted to make room, when the configuration leaves it zero. It is a
// capacity policy, not a freshness one: the gate judges freshness itself.
const DefaultRetention = 24 * time.Hour

// DatabaseName is the qrdb database the evidence store persists in. A host
// ensures it on its datastore before handing the DAO factory to NewDAOStore.
const DatabaseName = "peergate"

const (
	entityType = "peer_evidence"

	// evictPageSize is how many records one eviction scan reads at a time.
	evictPageSize = 500
)

// Record is one peer's latest evidence, keyed by its certificate thumbprint.
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

// EvidenceStore holds the latest evidence per peer. Implementations must be
// safe for concurrent use.
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

// DAOStoreConfig configures a DAOStore.
type DAOStoreConfig struct {
	// DAOs is the qrdb DAO factory the store persists through. DatabaseName
	// must already be ensured on it. Required.
	DAOs *qrdbsdk.DAOFactory

	// MaxPeers is the most peers the store holds evidence for. Zero means
	// DefaultMaxPeers; negative is invalid.
	MaxPeers int

	// Retention is the age past which a record may be evicted to admit a new
	// peer when the store is full. Zero means DefaultRetention; negative is
	// invalid. A record is never evicted while the store has room.
	Retention time.Duration
}

// DAOStore is the EvidenceStore persisted through a qrdb DAO, so every node
// sharing the datastore sees the same evidence and it survives a restart.
//
// MaxPeers is enforced per Put: two first submissions racing at the limit
// may both be admitted, so the bound can be exceeded by the number of
// concurrent first submissions, never by a single peer resubmitting.
type DAOStore struct {
	records   qrdbsdk.GenericDAO[*evidenceEntity]
	maxPeers  int
	retention time.Duration
	now       func() time.Time
}

var _ EvidenceStore = (*DAOStore)(nil)

// NewDAOStore returns a DAOStore over cfg.DAOs. Zero bounds select the
// defaults; a missing factory or a negative bound is a *ConfigError.
func NewDAOStore(cfg DAOStoreConfig, opts ...Option) (*DAOStore, error) {
	if cfg.DAOs == nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "is required"}
	}
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
	records, err := dao.New(cfg.DAOs, DatabaseName, entityType, newEvidenceEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Thumbprint")))
	if err != nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "cannot open the evidence DAO", Cause: err}
	}
	return &DAOStore{
		records:   records,
		maxPeers:  cfg.MaxPeers,
		retention: cfg.Retention,
		now:       newSettings(opts).now,
	}, nil
}

// Put stores r as the peer's latest evidence. When r is a new peer and the
// store is full, records older than the retention are evicted first; a store
// still full afterwards refuses r with a *CapacityError.
func (s *DAOStore) Put(ctx context.Context, r Record) error {
	if err := ctx.Err(); err != nil {
		return &peer.ContextError{Cause: err}
	}
	_, exists, err := s.load(ctx, r.Thumbprint)
	if err != nil {
		return err
	}
	if !exists {
		if err := s.makeRoom(ctx); err != nil {
			return err
		}
	}
	return s.records.Save(ctx, entityFromRecord(r))
}

// makeRoom evicts expired records when the store is at its limit and
// reports a *CapacityError when eviction freed nothing.
func (s *DAOStore) makeRoom(ctx context.Context) error {
	count, err := s.records.Count(ctx)
	if err != nil {
		return err
	}
	if count < s.maxPeers {
		return nil
	}
	evicted, err := s.evictExpired(ctx)
	if err != nil {
		return err
	}
	if count-evicted >= s.maxPeers {
		return &CapacityError{What: "evidence", Limit: s.maxPeers}
	}
	return nil
}

// evictExpired deletes every record collected before the retention cutoff
// and returns how many it deleted. The scan completes before any delete, so
// removing records cannot shift the pages still to be read.
func (s *DAOStore) evictExpired(ctx context.Context) (int, error) {
	cutoff := s.now().Add(-s.retention)
	var expired []*evidenceEntity
	query := qrdbsdk.PageQuery{Page: 1, PageSize: evictPageSize, SortOrder: qrdbsdk.DAOSortAscending}
	err := s.records.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[*evidenceEntity]) error {
		for _, e := range page.Entities {
			if e.CollectedAt.Before(cutoff) {
				expired = append(expired, e)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// A peer may refresh its evidence between the scan and the delete, so
	// each delete is conditional on the record still being the one scanned,
	// and only records actually removed make room.
	evicted := 0
	for _, e := range expired {
		deleted, err := s.records.DeleteIfMatch(ctx, e)
		if err != nil {
			return 0, err
		}
		if deleted {
			evicted++
		}
	}
	return evicted, nil
}

// Get returns the peer's latest evidence.
func (s *DAOStore) Get(ctx context.Context, thumbprint string) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, &peer.ContextError{Cause: err}
	}
	e, ok, err := s.load(ctx, thumbprint)
	if err != nil || !ok {
		return Record{}, false, err
	}
	return e.record(), true, nil
}

// Delete withdraws the peer's evidence. An absent record is not an error.
func (s *DAOStore) Delete(ctx context.Context, thumbprint string) error {
	if err := ctx.Err(); err != nil {
		return &peer.ContextError{Cause: err}
	}
	e, ok, err := s.load(ctx, thumbprint)
	if err != nil || !ok {
		return err
	}
	return s.records.Delete(ctx, e)
}

func (s *DAOStore) load(ctx context.Context, thumbprint string) (*evidenceEntity, bool, error) {
	e, err := s.records.GetByNaturalKey(ctx, thumbprint)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return e, true, nil
}
