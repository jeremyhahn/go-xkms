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

package token

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// refreshPrefix namespaces refresh-token records in the KV store.
const refreshPrefix = "auth/refresh/"

// Record tracks one issued refresh token. Records are keyed by
// (family, jti): the family groups every token descended from one login so a
// stolen-then-replayed token revokes the entire session lineage at once.
type Record struct {
	// JTI is the refresh token's unique identifier claim.
	JTI string `json:"jti"`

	// Family groups all refresh tokens descended from a single login.
	Family string `json:"family"`

	// Subject is the identity the token refreshes.
	Subject string `json:"subject"`

	// ExpiresAt is the refresh token's absolute expiry (Unix seconds).
	ExpiresAt int64 `json:"expires_at"`

	// Rotated marks a token that was already exchanged for a successor.
	// Presenting a rotated token again is reuse — the family is revoked.
	Rotated bool `json:"rotated"`
}

// RefreshStore persists refresh-token records. Implementations must treat a
// missing record as revoked (fail closed).
type RefreshStore interface {
	// Save stores a record.
	Save(ctx context.Context, rec *Record) error

	// Get returns the record for (family, jti), or nil when absent.
	Get(ctx context.Context, family, jti string) (*Record, error)

	// MarkRotated flags the record as rotated.
	MarkRotated(ctx context.Context, family, jti string) error

	// RevokeFamily removes every record in the family.
	RevokeFamily(ctx context.Context, family string) error
}

// refreshKey builds the KV key for a record.
func refreshKey(family, jti string) string {
	return refreshPrefix + family + "/" + jti
}

// ---------------------------------------------------------------------------
// In-memory store (non-qrdb storage modes, tests, loopback desktop mode).
// ---------------------------------------------------------------------------

// MemoryRefreshStore is a concurrency-safe in-process RefreshStore. Expired
// records are dropped lazily on read and opportunistically on write.
type MemoryRefreshStore struct {
	mu      sync.Mutex
	records map[string]*Record
}

// NewMemoryRefreshStore constructs an empty MemoryRefreshStore.
func NewMemoryRefreshStore() *MemoryRefreshStore {
	return &MemoryRefreshStore{records: make(map[string]*Record)}
}

// Save implements RefreshStore.
func (s *MemoryRefreshStore) Save(_ context.Context, rec *Record) error {
	if rec == nil {
		return &NilInputError{Field: "record"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	cp := *rec
	s.records[refreshKey(rec.Family, rec.JTI)] = &cp
	return nil
}

// Get implements RefreshStore.
func (s *MemoryRefreshStore) Get(_ context.Context, family, jti string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[refreshKey(family, jti)]
	if !ok || expired(rec) {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

// MarkRotated implements RefreshStore.
func (s *MemoryRefreshStore) MarkRotated(_ context.Context, family, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.records[refreshKey(family, jti)]; ok {
		rec.Rotated = true
	}
	return nil
}

// RevokeFamily implements RefreshStore.
func (s *MemoryRefreshStore) RevokeFamily(_ context.Context, family string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := refreshPrefix + family + "/"
	for k := range s.records {
		if strings.HasPrefix(k, prefix) {
			delete(s.records, k)
		}
	}
	return nil
}

// sweepLocked drops expired records. Callers hold the mutex.
func (s *MemoryRefreshStore) sweepLocked() {
	for k, rec := range s.records {
		if expired(rec) {
			delete(s.records, k)
		}
	}
}

// expired reports whether the record's refresh window has passed.
func expired(rec *Record) bool {
	return time.Now().Unix() >= rec.ExpiresAt
}

// ---------------------------------------------------------------------------
// qrdb-KV store (the production identity plane).
// ---------------------------------------------------------------------------

// QRDBRefreshStore persists refresh-token records on the embedded qrdb node's
// KV plane under auth/refresh/. The KV store has no native TTL, so expiry is
// carried in the record and enforced on read; expired records are deleted
// opportunistically.
type QRDBRefreshStore struct {
	kv qrdbtransport.KVClient
}

// NewQRDBRefreshStore constructs a store over the given KV client.
func NewQRDBRefreshStore(kv qrdbtransport.KVClient) (*QRDBRefreshStore, error) {
	if kv == nil {
		return nil, &NilInputError{Field: "kv"}
	}
	return &QRDBRefreshStore{kv: kv}, nil
}

// Save implements RefreshStore.
func (s *QRDBRefreshStore) Save(ctx context.Context, rec *Record) error {
	if rec == nil {
		return &NilInputError{Field: "record"}
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return &StoreError{Op: "encode", Err: err}
	}
	if err := s.kv.Put(ctx, refreshKey(rec.Family, rec.JTI), data); err != nil {
		return &StoreError{Op: "put", Err: err}
	}
	return nil
}

// Get implements RefreshStore.
func (s *QRDBRefreshStore) Get(ctx context.Context, family, jti string) (*Record, error) {
	data, err := s.kv.Get(ctx, refreshKey(family, jti))
	if err != nil {
		// A missing key is "revoked or never issued", not a store failure.
		// The qrdb SDK returns a typed KeyNotFoundError; any error on Get is
		// treated as absence only when the payload is empty, otherwise it is
		// surfaced so an outage cannot silently revoke sessions.
		if isNotFound(err) {
			return nil, nil
		}
		return nil, &StoreError{Op: "get", Err: err}
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, &StoreError{Op: "decode", Err: err}
	}
	if expired(&rec) {
		// Lazy TTL: drop the tombstone; deletion failure is non-fatal.
		_ = s.kv.Delete(ctx, refreshKey(family, jti)) //nolint:errcheck // best-effort cleanup of an already-expired record
		return nil, nil
	}
	return &rec, nil
}

// MarkRotated implements RefreshStore.
func (s *QRDBRefreshStore) MarkRotated(ctx context.Context, family, jti string) error {
	rec, err := s.Get(ctx, family, jti)
	if err != nil {
		return err
	}
	if rec == nil {
		return nil
	}
	rec.Rotated = true
	return s.Save(ctx, rec)
}

// RevokeFamily implements RefreshStore.
func (s *QRDBRefreshStore) RevokeFamily(ctx context.Context, family string) error {
	prefix := refreshPrefix + family + "/"
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return &StoreError{Op: "list", Err: err}
	}
	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil {
			return &StoreError{Op: "delete", Err: err}
		}
	}
	return nil
}

// isNotFound reports whether the KV error indicates a missing key. The qrdb
// SDK's typed not-found error implements interface{ NotFound() bool } on some
// transports and carries "not found" text on the rest; both are matched so a
// transport change cannot turn absence into an outage.
func isNotFound(err error) bool {
	type notFound interface{ NotFound() bool }
	var nf notFound
	if errors.As(err, &nf) && nf.NotFound() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
