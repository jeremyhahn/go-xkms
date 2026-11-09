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
	"fmt"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

const (
	// refreshPrefix namespaces refresh-token records in the KV store.
	refreshPrefix = "auth/refresh/"

	// revokedPrefix namespaces family revocation tombstones. It is a sibling
	// of refreshPrefix rather than a key inside the family's own range, so
	// RevokeFamily's prefix sweep cannot delete the tombstone it just wrote.
	revokedPrefix = "auth/refresh-revoked/"
)

// RevocationTombstoneTTL is how long a family revocation tombstone is kept.
// The tombstone is what stops a refresh that is already in flight from
// committing a successor into a family that was revoked underneath it, so it
// must outlive every refresh token the issuer can mint; NewIssuer enforces
// that by rejecting a longer RefreshTTL. Once no token of the family can still
// be presented the tombstone is dead weight and is swept.
const RevocationTombstoneTTL = 24 * time.Hour

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

	// Tenant is the holder's tenant, normalized at mint so the system
	// tenant is never stored as "". A subject is unique only within its
	// tenant, so RevokeBySubject matches on both.
	Tenant string `json:"tenant"`

	// ExpiresAt is the refresh token's absolute expiry (Unix seconds).
	ExpiresAt int64 `json:"expires_at"`

	// Rotated marks a token that was already exchanged for a successor.
	// Presenting a rotated token again is reuse — the family is revoked.
	Rotated bool `json:"rotated"`
}

// holds reports whether r belongs to subject in tenant. tenant is
// normalized as Mint normalizes it; a record stored without a tenant never
// matches.
func (r *Record) holds(tenant, subject string) bool {
	return r.Tenant != "" && r.Tenant == qrdbsdk.NormalizeTenantID(tenant) && r.Subject == subject
}

// revocation is the tombstone written when a family is revoked.
type revocation struct {
	// Family is the revoked lineage.
	Family string `json:"family"`

	// ExpiresAt is when the tombstone may be swept (Unix seconds).
	ExpiresAt int64 `json:"expires_at"`
}

// RefreshStore persists refresh-token records. Implementations must treat a
// missing record as revoked (fail closed).
//
// Rotation is a race, not a sequence: a stolen refresh token is presented at
// the same moment as the legitimate one, so the store — not the caller — has
// to arbitrate. Implementations must therefore make MarkRotated and Save
// atomic with respect to each other and to RevokeFamily. An implementation
// that cannot do so must fail at construction rather than serve a weaker
// guarantee.
type RefreshStore interface {
	// Save stores a record. It returns *FamilyRevokedError when the record's
	// family carries a revocation tombstone, so a successor minted by a
	// refresh that raced a logout is never committed.
	Save(ctx context.Context, rec *Record) error

	// Get returns the record for (family, jti), or nil when absent.
	Get(ctx context.Context, family, jti string) (*Record, error)

	// MarkRotated atomically flags the record as rotated, and is the point at
	// which concurrent refreshes of one token are arbitrated: exactly one
	// caller may observe a nil error. It returns *RefreshRaceLostError when
	// the record was already rotated (or changed underneath the caller) and
	// *RefreshRevokedError when it is missing or expired.
	MarkRotated(ctx context.Context, family, jti string) error

	// RevokeFamily writes a revocation tombstone and removes every record in
	// the family. The tombstone is written first so a refresh in flight cannot
	// slip a successor past the sweep.
	RevokeFamily(ctx context.Context, family string) error

	// RevokeBySubject revokes every family whose Record.Tenant and
	// Record.Subject equal tenant and subject, exactly as RevokeFamily
	// revokes one -- so a user-lifecycle change (disable, delete) ends every
	// session the account holds, no matter which login flow minted it, and
	// no session of a same-named account in another tenant. tenant is
	// normalized as at mint; a record without a tenant never matches. It is
	// idempotent: a subject with no live family is a no-op success, matching
	// RevokeFamily's own logout semantics.
	RevokeBySubject(ctx context.Context, tenant, subject string) error
}

// refreshKey builds the KV key for a record.
func refreshKey(family, jti string) string {
	return refreshPrefix + family + "/" + jti
}

// familyPrefix builds the KV key prefix covering a family's records.
func familyPrefix(family string) string {
	return refreshPrefix + family + "/"
}

// revokedKey builds the KV key for a family's revocation tombstone.
func revokedKey(family string) string {
	return revokedPrefix + family
}

// ---------------------------------------------------------------------------
// In-memory store (non-qrdb storage modes, tests, loopback desktop mode).
// ---------------------------------------------------------------------------

// MemoryRefreshStore is a concurrency-safe in-process RefreshStore. Expired
// records are dropped lazily on read and opportunistically on write.
//
// Every operation completes under one mutex, which is what makes the
// check-and-set in MarkRotated and the tombstone check in Save atomic: in a
// single process the mutex is the state machine.
type MemoryRefreshStore struct {
	mu      sync.Mutex
	records map[string]*Record

	// revoked maps a family to its tombstone expiry (Unix seconds).
	revoked map[string]int64
}

// NewMemoryRefreshStore constructs an empty MemoryRefreshStore.
func NewMemoryRefreshStore() *MemoryRefreshStore {
	return &MemoryRefreshStore{
		records: make(map[string]*Record),
		revoked: make(map[string]int64),
	}
}

// Save implements RefreshStore.
func (s *MemoryRefreshStore) Save(_ context.Context, rec *Record) error {
	if rec == nil {
		return &NilInputError{Field: "record"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if _, revoked := s.revoked[rec.Family]; revoked {
		return &FamilyRevokedError{Family: rec.Family}
	}
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

	rec, ok := s.records[refreshKey(family, jti)]
	if !ok || expired(rec) {
		return &RefreshRevokedError{}
	}
	if rec.Rotated {
		return &RefreshRaceLostError{Family: family, JTI: jti}
	}
	rec.Rotated = true
	return nil
}

// RevokeFamily implements RefreshStore.
func (s *MemoryRefreshStore) RevokeFamily(_ context.Context, family string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family)
	return nil
}

// RevokeBySubject implements RefreshStore.
func (s *MemoryRefreshStore) RevokeBySubject(_ context.Context, tenant, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	families := make(map[string]struct{})
	for _, rec := range s.records {
		if rec.holds(tenant, subject) {
			families[rec.Family] = struct{}{}
		}
	}
	for family := range families {
		s.revokeFamilyLocked(family)
	}
	return nil
}

// revokeFamilyLocked writes family's revocation tombstone and removes every
// record in it. Callers hold s.mu.
func (s *MemoryRefreshStore) revokeFamilyLocked(family string) {
	if _, ok := s.revoked[family]; !ok {
		s.revoked[family] = time.Now().Add(RevocationTombstoneTTL).Unix()
	}
	prefix := familyPrefix(family)
	for k := range s.records {
		if strings.HasPrefix(k, prefix) {
			delete(s.records, k)
		}
	}
}

// sweepLocked drops expired records and tombstones. Callers hold the mutex.
func (s *MemoryRefreshStore) sweepLocked() {
	for k, rec := range s.records {
		if expired(rec) {
			delete(s.records, k)
		}
	}
	now := time.Now().Unix()
	for family, exp := range s.revoked {
		if now >= exp {
			delete(s.revoked, family)
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
//
// It holds the GUARDED KV client, not the plain one: rotation is decided with
// CompareAndSwap and revocation with PutIfAbsent, both evaluated inside the
// Raft state machine, so two nodes cannot both win.
type QRDBRefreshStore struct {
	kv qrdbtransport.GuardedKVClient
}

// NewQRDBRefreshStore constructs a store over the given KV client.
//
// The client must implement transport.GuardedKVClient. That capability is
// detected by type assertion, exactly as the qrdb SDK prescribes, because a
// transport carries the conditional-write verbs only once its wire contract
// does. Without them, rotation would have to be a read-then-write that a
// second refresh can slip between — so construction fails instead. There is
// deliberately no degraded non-atomic path: a refresh store that cannot
// arbitrate a race is a refresh store that mints two live successors.
func NewQRDBRefreshStore(kv qrdbtransport.KVClient, opts ...QRDBRefreshStoreOption) (*QRDBRefreshStore, error) {
	if kv == nil {
		return nil, &NilInputError{Field: "kv"}
	}
	guarded, ok := kv.(qrdbtransport.GuardedKVClient)
	if !ok {
		return nil, &GuardedKVUnsupportedError{ClientType: fmt.Sprintf("%T", kv)}
	}
	var o qrdbRefreshStoreOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.callContext != nil {
		guarded = boundGuardedKV{GuardedKVClient: guarded, bind: o.callContext}
	}
	return &QRDBRefreshStore{kv: guarded}, nil
}

// QRDBRefreshStoreOption configures a QRDBRefreshStore.
type QRDBRefreshStoreOption func(*qrdbRefreshStoreOptions)

type qrdbRefreshStoreOptions struct {
	callContext func(ctx context.Context) (context.Context, error)
}

// WithCallContext derives the context every qrdb call of the store runs on
// from the caller's. xkmsd binds the embedded node's service principal
// (Node.ServiceContext): the store persists refresh-token records on its own
// behalf, often for an anonymous request such as a WebAuthn registration
// finish that mints the first token pair, whose context carries no qrdb
// principal and is refused as unauthenticated.
func WithCallContext(bind func(ctx context.Context) (context.Context, error)) QRDBRefreshStoreOption {
	return func(o *qrdbRefreshStoreOptions) { o.callContext = bind }
}

// boundGuardedKV runs every KV call on the context bind derives from the
// caller's; a bind error fails the call.
type boundGuardedKV struct {
	qrdbtransport.GuardedKVClient
	bind func(ctx context.Context) (context.Context, error)
}

func (c boundGuardedKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	ctx, err := c.bind(ctx)
	if err != nil {
		return err
	}
	return c.GuardedKVClient.Put(ctx, key, value, opts...)
}

func (c boundGuardedKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return nil, err
	}
	return c.GuardedKVClient.Get(ctx, key, opts...)
}

func (c boundGuardedKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	ctx, err := c.bind(ctx)
	if err != nil {
		return err
	}
	return c.GuardedKVClient.Delete(ctx, key, opts...)
}

func (c boundGuardedKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return nil, err
	}
	return c.GuardedKVClient.List(ctx, prefix, opts...)
}

func (c boundGuardedKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return nil, err
	}
	return c.GuardedKVClient.Scan(ctx, prefix, opts...)
}

func (c boundGuardedKV) Exists(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) (bool, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return false, err
	}
	return c.GuardedKVClient.Exists(ctx, key, opts...)
}

func (c boundGuardedKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return false, err
	}
	return c.GuardedKVClient.PutIfAbsent(ctx, key, value)
}

func (c boundGuardedKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return false, err
	}
	return c.GuardedKVClient.CompareAndDelete(ctx, key, expected)
}

func (c boundGuardedKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	ctx, err := c.bind(ctx)
	if err != nil {
		return false, err
	}
	return c.GuardedKVClient.CompareAndSwap(ctx, key, expected, next)
}

// Save implements RefreshStore.
//
// The tombstone is read AFTER the record is written. That ordering is what
// closes the revoke race: a RevokeFamily either wrote its tombstone before
// this read — in which case it is seen here and the record is withdrawn — or
// it wrote the tombstone after, which means its sweep runs after this Put and
// removes the record. No interleaving leaves a usable successor behind.
func (s *QRDBRefreshStore) Save(ctx context.Context, rec *Record) error {
	if rec == nil {
		return &NilInputError{Field: "record"}
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return &StoreError{Op: "encode", Err: err}
	}

	key := refreshKey(rec.Family, rec.JTI)
	if err := s.kv.Put(ctx, key, data); err != nil {
		return &StoreError{Op: "put", Err: err}
	}

	revoked, err := s.familyRevoked(ctx, rec.Family)
	if err != nil {
		return err
	}
	if revoked {
		// Withdraw exactly the bytes this call wrote. An unguarded delete could
		// remove a record another writer put here in the meantime.
		if _, delErr := s.kv.CompareAndDelete(ctx, key, data); delErr != nil {
			return &StoreError{Op: "compare-and-delete", Err: delErr}
		}
		return &FamilyRevokedError{Family: rec.Family}
	}
	return nil
}

// Get implements RefreshStore.
func (s *QRDBRefreshStore) Get(ctx context.Context, family, jti string) (*Record, error) {
	rec, _, err := s.load(ctx, family, jti)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// load reads a record and returns it together with the exact stored bytes,
// which are the compare operand for a guarded write. It returns a nil record
// when the key is absent or the record has expired.
func (s *QRDBRefreshStore) load(ctx context.Context, family, jti string) (*Record, []byte, error) {
	data, err := s.kv.Get(ctx, refreshKey(family, jti))
	if err != nil {
		// A missing key is "revoked or never issued", not a store failure.
		// The qrdb SDK returns a typed KeyNotFoundError; any other error is
		// surfaced so an outage cannot silently revoke sessions.
		if isNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, &StoreError{Op: "get", Err: err}
	}

	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, nil, &StoreError{Op: "decode", Err: err}
	}
	if expired(&rec) {
		// Lazy TTL: drop the tombstone; deletion failure is non-fatal because
		// the record is already treated as absent by every reader.
		_ = s.kv.Delete(ctx, refreshKey(family, jti)) // best-effort cleanup of an already-expired record; the explicit `_ =` already satisfies errcheck
		return nil, nil, nil
	}
	return &rec, data, nil
}

// MarkRotated implements RefreshStore.
func (s *QRDBRefreshStore) MarkRotated(ctx context.Context, family, jti string) error {
	rec, current, err := s.load(ctx, family, jti)
	if err != nil {
		return err
	}
	if rec == nil {
		return &RefreshRevokedError{}
	}
	if rec.Rotated {
		return &RefreshRaceLostError{Family: family, JTI: jti}
	}

	rec.Rotated = true
	next, err := json.Marshal(rec)
	if err != nil {
		return &StoreError{Op: "encode", Err: err}
	}

	swapped, err := s.kv.CompareAndSwap(ctx, refreshKey(family, jti), current, next)
	if err != nil {
		return &StoreError{Op: "compare-and-swap", Err: err}
	}
	if !swapped {
		// The stored bytes changed between the read and the swap: another
		// refresh rotated this record, or a revoke removed it, first.
		return &RefreshRaceLostError{Family: family, JTI: jti}
	}
	return nil
}

// RevokeFamily implements RefreshStore.
func (s *QRDBRefreshStore) RevokeFamily(ctx context.Context, family string) error {
	tombstone, err := json.Marshal(&revocation{
		Family:    family,
		ExpiresAt: time.Now().Add(RevocationTombstoneTTL).Unix(),
	})
	if err != nil {
		return &StoreError{Op: "encode revocation", Err: err}
	}

	// PutIfAbsent, not Put: the first revoker's tombstone stands, so two
	// concurrent revokes cannot write divergent expiries. A false result means
	// the family was already revoked, which is a success — logout is
	// idempotent.
	if _, err := s.kv.PutIfAbsent(ctx, revokedKey(family), tombstone); err != nil {
		return &StoreError{Op: "put-if-absent", Err: err}
	}

	keys, err := s.kv.List(ctx, familyPrefix(family))
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

// RevokeBySubject implements RefreshStore.
//
// The store keeps no secondary index from subject to family, so this scans
// every live refresh record under refreshPrefix once to collect the
// families subject owns, then revokes each exactly as RevokeFamily does.
// That scan is the store's only way to answer "every session this account
// holds": the alternative -- indexing by subject on every Save -- would
// have to stay consistent with RevokeFamily's own delete-by-prefix sweep,
// and a lifecycle change is rare enough next to a refresh that the scan's
// cost is the right place to pay it.
func (s *QRDBRefreshStore) RevokeBySubject(ctx context.Context, tenant, subject string) error {
	entries, err := s.kv.Scan(ctx, refreshPrefix)
	if err != nil {
		return &StoreError{Op: "scan", Err: err}
	}

	families := make(map[string]struct{})
	for _, data := range entries {
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			return &StoreError{Op: "decode", Err: err}
		}
		if rec.holds(tenant, subject) {
			families[rec.Family] = struct{}{}
		}
	}
	for family := range families {
		if err := s.RevokeFamily(ctx, family); err != nil {
			return err
		}
	}
	return nil
}

// familyRevoked reports whether a live revocation tombstone covers the family.
func (s *QRDBRefreshStore) familyRevoked(ctx context.Context, family string) (bool, error) {
	data, err := s.kv.Get(ctx, revokedKey(family))
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, &StoreError{Op: "get revocation", Err: err}
	}

	var rev revocation
	if err := json.Unmarshal(data, &rev); err != nil {
		return false, &StoreError{Op: "decode revocation", Err: err}
	}
	if time.Now().Unix() >= rev.ExpiresAt {
		// No token of this family can still be presented, so the tombstone has
		// nothing left to guard. Cleanup failure is non-fatal.
		_ = s.kv.Delete(ctx, revokedKey(family)) // best-effort cleanup of an already-expired tombstone; the explicit `_ =` already satisfies errcheck
		return false, nil
	}
	return true, nil
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
