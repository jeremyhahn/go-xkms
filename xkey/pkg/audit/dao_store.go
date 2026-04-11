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

package audit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const (
	daoEntityType = "audit_entries"
)

// Option configures a DAOAuditStore.
type Option func(*daoConfig)

type daoConfig struct {
	maxEntries int
	logger     *slog.Logger
}

// WithMaxEntries sets the maximum number of entries held in the in-memory
// ring buffer cache. When the cache is full, the oldest entry is evicted.
// Defaults to 10000.
func WithMaxEntries(n int) Option {
	return func(c *daoConfig) {
		if n > 0 {
			c.maxEntries = n
		}
	}
}

// WithLogger configures an slog.Logger for structured audit log output.
// When set, all logged entries are also forwarded to the slog logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *daoConfig) {
		c.logger = logger
	}
}

// DAOAuditStore implements both Store and Logger interfaces using a
// go-qrdb GenericDAO for persistence and an in-memory ring buffer
// cache for fast queries.
type DAOAuditStore struct {
	mu      sync.RWMutex
	slog    *SlogLogger
	dao     qrdbsdk.GenericDAO[*AuditEntryEntity]
	cache   []Entry
	maxSize int
	seq     atomic.Uint64
	closed  atomic.Bool
}

// Compile-time interface satisfaction checks.
var _ Store = (*DAOAuditStore)(nil)

// NewDAOAuditStore creates a new DAO-backed audit store. Existing entries
// are loaded from the DAO into the in-memory ring buffer cache on creation.
func NewDAOAuditStore(kvStore qrdbsdk.KVStore, opts ...Option) (*DAOAuditStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	cfg := &daoConfig{
		maxEntries: defaultMaxSize,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	auditDAO, err := qrdbsdk.NewDAO[*AuditEntryEntity](
		kvStore,
		daoEntityType,
		func() *AuditEntryEntity { return &AuditEntryEntity{} },
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	s := &DAOAuditStore{
		dao:     auditDAO,
		cache:   make([]Entry, 0, cfg.maxEntries),
		maxSize: cfg.maxEntries,
	}
	if cfg.logger != nil {
		s.slog = NewSlogLogger(cfg.logger)
	}

	if loadErr := s.loadFromDAO(); loadErr != nil {
		return nil, loadErr
	}

	return s, nil
}

// Log persists an audit entry to the DAO and appends it to the in-memory
// cache. When the cache is full, the oldest entry is evicted. If an slog
// logger is configured, the entry is also forwarded to it.
func (s *DAOAuditStore) Log(entry Entry) {
	if s.closed.Load() {
		return
	}

	entity := entryToEntity(entry)
	ctx := context.Background()
	_ = s.dao.Save(ctx, entity)

	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.cache = s.cache[1:]
	}
	s.cache = append(s.cache, entry)
	s.mu.Unlock()

	if s.slog != nil {
		s.slog.Log(entry)
	}
}

// LogKeyOperation logs a key-related operation.
func (s *DAOAuditStore) LogKeyOperation(op OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		Backend:    backend,
		KeyID:      keyID,
		Success:    success,
		Error:      errStr,
		DurationMs: durationMs,
	})
}

// LogCryptoOperation logs a cryptographic operation.
func (s *DAOAuditStore) LogCryptoOperation(op OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		Backend:    backend,
		KeyID:      keyID,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		Success:    success,
		Error:      errStr,
		DurationMs: durationMs,
	})
}

// LogConnectionEvent logs a connection-related event.
func (s *DAOAuditStore) LogConnectionEvent(op OperationType, deviceID, deviceName string, details map[string]any) {
	s.Log(Entry{
		Timestamp:  time.Now(),
		Operation:  op,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		Success:    true,
		Details:    details,
	})
}

// LogServiceEvent logs a service lifecycle event.
func (s *DAOAuditStore) LogServiceEvent(op OperationType, details map[string]any) {
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   true,
		Details:   details,
	})
}

// LogPINOperation logs a PIN-related operation (verify, change, lock).
func (s *DAOAuditStore) LogPINOperation(op OperationType, backend string, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Backend:   backend,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogTPMOperation logs a TPM-related operation (provision, auth, seal).
func (s *DAOAuditStore) LogTPMOperation(op OperationType, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Backend:   "tpm2",
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogPasswordStoreOperation logs a password store operation (unlock, access, autofill).
func (s *DAOAuditStore) LogPasswordStoreOperation(op OperationType, source string, success bool, err error, details map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	if details == nil {
		details = make(map[string]any)
	}
	details["source"] = source
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}

// LogUserPresenceEvent logs a user presence/touch event.
func (s *DAOAuditStore) LogUserPresenceEvent(op OperationType, source string, success bool, details map[string]any) {
	if details == nil {
		details = make(map[string]any)
	}
	details["source"] = source
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Details:   details,
	})
}

// Query returns audit entries matching the provided filter from the in-memory
// ring buffer cache. All non-zero filter fields are applied conjunctively.
// Results are returned in insertion order (oldest first), with Offset and
// Limit applied after filtering.
func (s *DAOAuditStore) Query(filter QueryFilter) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []Entry
	skipped := 0

	for i := range s.cache {
		e := &s.cache[i]

		if filter.Operation != "" && e.Operation != filter.Operation {
			continue
		}
		if filter.Backend != "" && e.Backend != filter.Backend {
			continue
		}
		if filter.KeyID != "" && e.KeyID != filter.KeyID {
			continue
		}
		if filter.DeviceID != "" && e.DeviceID != filter.DeviceID {
			continue
		}
		if filter.Success != nil && e.Success != *filter.Success {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && e.Timestamp.After(filter.Until) {
			continue
		}

		if filter.Offset > 0 && skipped < filter.Offset {
			skipped++
			continue
		}

		matched = append(matched, *e)

		if filter.Limit > 0 && len(matched) >= filter.Limit {
			break
		}
	}

	return matched
}

// Count returns the number of entries currently held in the cache.
func (s *DAOAuditStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// Page retrieves a paginated set of audit entry entities from the DAO.
func (s *DAOAuditStore) Page(ctx context.Context, q qrdbsdk.PageQuery) (qrdbsdk.PageResult[*AuditEntryEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*AuditEntryEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, q)
}

// Close marks the store as closed. Subsequent Log calls are silently
// dropped and Page calls return ErrStoreClosed.
func (s *DAOAuditStore) Close() error {
	s.closed.Store(true)
	return nil
}

// loadFromDAO loads all existing entries from the DAO into the in-memory
// ring buffer cache, sorted chronologically by timestamp, respecting
// maxSize.
func (s *DAOAuditStore) loadFromDAO() error {
	ctx := context.Background()

	var entities []*AuditEntryEntity
	loadErr := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*AuditEntryEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if loadErr != nil {
		return loadErr
	}

	if len(entities) == 0 {
		return nil
	}

	// Sort entities chronologically by timestamp.
	sortEntitiesByTimestamp(entities)

	// If more entities exist than maxSize, keep only the most recent.
	if len(entities) > s.maxSize {
		entities = entities[len(entities)-s.maxSize:]
	}

	entries := make([]Entry, 0, len(entities))
	for _, entity := range entities {
		entries = append(entries, entityToEntry(entity))
	}

	s.cache = entries
	s.seq.Store(uint64(len(entries)))

	return nil
}

// sortEntitiesByTimestamp sorts entities in ascending chronological order.
func sortEntitiesByTimestamp(entities []*AuditEntryEntity) {
	n := len(entities)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && entities[j].Timestamp.Before(entities[j-1].Timestamp); j-- {
			entities[j], entities[j-1] = entities[j-1], entities[j]
		}
	}
}

// entryToEntity converts an Entry to an AuditEntryEntity for DAO persistence.
func entryToEntity(e Entry) *AuditEntryEntity {
	return &AuditEntryEntity{
		Timestamp:  e.Timestamp,
		Operation:  e.Operation,
		Backend:    e.Backend,
		KeyID:      e.KeyID,
		DeviceID:   e.DeviceID,
		DeviceName: e.DeviceName,
		Success:    e.Success,
		Error:      e.Error,
		DurationMs: e.DurationMs,
		Details:    e.Details,
	}
}

// entityToEntry converts an AuditEntryEntity back to an Entry.
func entityToEntry(e *AuditEntryEntity) Entry {
	return Entry{
		Timestamp:  e.Timestamp,
		Operation:  e.Operation,
		Backend:    e.Backend,
		KeyID:      e.KeyID,
		DeviceID:   e.DeviceID,
		DeviceName: e.DeviceName,
		Success:    e.Success,
		Error:      e.Error,
		DurationMs: e.DurationMs,
		Details:    e.Details,
	}
}
