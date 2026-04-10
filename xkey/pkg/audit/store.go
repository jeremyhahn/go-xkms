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
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	defaultMaxSize = 10000
	keyPrefix      = "audit/"
)

// Store extends Logger with queryable audit entry retrieval.
type Store interface {
	Logger
	Query(filter QueryFilter) []Entry
	Count() int
}

// QueryFilter specifies criteria for filtering audit entries.
type QueryFilter struct {
	Operation OperationType
	Backend   string
	KeyID     string
	DeviceID  string
	Success   *bool
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// BackendStore is a thread-safe audit store that persists entries to a
// storage.Backend and maintains an in-memory cache (ring buffer) for
// fast queries.
type BackendStore struct {
	mu      sync.RWMutex
	slog    *SlogLogger
	backend storage.Backend
	prefix  string
	cache   []Entry
	maxSize int
	seq     atomic.Uint64
}

// NewBackendStore creates a new persistent audit store backed by the provided
// storage.Backend. Existing entries are loaded from the backend into the
// in-memory cache on creation. If maxSize is <= 0, it defaults to 10000.
// When a non-nil slog.Logger is provided, all logged entries are also
// forwarded to it for structured log output.
func NewBackendStore(backend storage.Backend, maxSize int, logger *slog.Logger) (*BackendStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}

	s := &BackendStore{
		backend: backend,
		prefix:  keyPrefix,
		cache:   make([]Entry, 0, maxSize),
		maxSize: maxSize,
	}
	if logger != nil {
		s.slog = NewSlogLogger(logger)
	}

	if err := s.loadFromBackend(); err != nil {
		return nil, err
	}

	return s, nil
}

// Log persists an audit entry to the storage backend and appends it to the
// in-memory cache. When the cache is full, the oldest entry is evicted.
// If an slog logger is configured, the entry is also forwarded to it.
func (s *BackendStore) Log(entry Entry) {
	key := s.entryKey(entry)

	data, err := json.Marshal(entry)
	if err == nil {
		_ = s.backend.Put(context.Background(), key, data)
	}

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
func (s *BackendStore) LogKeyOperation(op OperationType, backend, keyID string, success bool, err error, durationMs int64) {
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
func (s *BackendStore) LogCryptoOperation(op OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
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
func (s *BackendStore) LogConnectionEvent(op OperationType, deviceID, deviceName string, details map[string]any) {
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
func (s *BackendStore) LogServiceEvent(op OperationType, details map[string]any) {
	s.Log(Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   true,
		Details:   details,
	})
}

// LogPINOperation logs a PIN-related operation (verify, change, lock).
func (s *BackendStore) LogPINOperation(op OperationType, backend string, success bool, err error, details map[string]any) {
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
func (s *BackendStore) LogTPMOperation(op OperationType, success bool, err error, details map[string]any) {
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
func (s *BackendStore) LogPasswordStoreOperation(op OperationType, source string, success bool, err error, details map[string]any) {
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
func (s *BackendStore) LogUserPresenceEvent(op OperationType, source string, success bool, details map[string]any) {
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

// Query returns audit entries matching the provided filter. All non-zero
// filter fields are applied conjunctively. Results are returned in
// insertion order (oldest first), with Offset and Limit applied after
// filtering.
func (s *BackendStore) Query(filter QueryFilter) []Entry {
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
func (s *BackendStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// MigrateBackend transfers all entries from the current backend to a new
// backend via Scan/Put, then swaps the backend reference. This supports
// transitioning from an in-memory backend to barrier-encrypted storage
// after unseal.
func (s *BackendStore) MigrateBackend(newBackend storage.Backend) error {
	if newBackend == nil {
		return ErrNilBackend
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()

	if err := s.backend.Scan(ctx, s.prefix, func(key string, value []byte) error {
		if putErr := newBackend.Put(ctx, key, value); putErr != nil {
			return fmt.Errorf("audit: put during migration key=%s: %w", key, putErr)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("audit: scan during migration: %w", err)
	}

	s.backend = newBackend
	return nil
}

// entryKey generates a deterministic, lexicographically sortable storage
// key for the given entry. The format is "audit/<unix_nano>-<seq>.json"
// where seq is zero-padded to 12 digits.
func (s *BackendStore) entryKey(entry Entry) string {
	seq := s.seq.Add(1) - 1
	return fmt.Sprintf("%s%d-%012d.json", s.prefix, entry.Timestamp.UnixNano(), seq)
}

// loadFromBackend scans all entries from the backend, unmarshals them,
// sorts by key (which is chronological due to the key format), and
// populates the in-memory cache respecting maxSize.
func (s *BackendStore) loadFromBackend() error {
	ctx := context.Background()

	raw := make(map[string][]byte)
	if err := s.backend.Scan(ctx, s.prefix, func(key string, value []byte) error {
		raw[key] = value
		return nil
	}); err != nil {
		return fmt.Errorf("audit: load from backend: %w", err)
	}

	if len(raw) == 0 {
		return nil
	}

	// Sort keys lexicographically to maintain chronological order.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// If more entries exist than maxSize, keep only the most recent.
	if len(keys) > s.maxSize {
		keys = keys[len(keys)-s.maxSize:]
	}

	entries := make([]Entry, 0, len(keys))
	for _, k := range keys {
		var entry Entry
		if unmarshalErr := json.Unmarshal(raw[k], &entry); unmarshalErr != nil {
			return fmt.Errorf("audit: unmarshal entry key=%s: %w", k, unmarshalErr)
		}
		entries = append(entries, entry)
	}

	s.cache = entries

	// Set sequence counter past any loaded entries to avoid key collisions.
	s.seq.Store(uint64(len(entries)))

	return nil
}

// Compile-time interface satisfaction check.
var _ Store = (*BackendStore)(nil)
