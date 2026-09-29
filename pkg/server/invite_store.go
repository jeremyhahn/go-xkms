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

package server

import (
	"context"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// defaultInviteStoreTenant is the key segment an empty tenant ID is stored
// under. Empty is a valid, common tenantID (the default/system tenant), and
// a key namespace built by concatenating an empty segment loses the
// separation it exists to provide — "" + "/" + token would otherwise
// collide with a literal tenant named to match whatever placeholder segment
// was chosen. A colon is not: storage.ValidateTenantID refuses any tenant ID
// containing one, so no real tenant can ever be routed to this segment by
// its own name.
const defaultInviteStoreTenant = ":empty-tenant:"

// tenantPrefixedInviteStore is THE enrollment-invitation store (go-xkms#1294
// part B). There is exactly one wiring path — no preferred-plus-fallback
// pair (per the owner's standing "never use fallbacks without approval"
// rule) — built unconditionally over the same createStorage seam every
// other xkmsd subsystem's persistent metadata uses (see
// initializePKCS11StateStore for the precedent this mirrors), never a
// second, independent storage path. Invitations move in lockstep with
// whatever storage.backend is configured, exactly as pkg/pkcs11state's
// records do — and, once go-xkms#1363 lands, with the one shared qrdb
// datastore createStorage becomes a prefixed, barrier-protected, replicated
// view over.
//
// It is ONE store shared by every tenant: records are separated only by a
// "<tenant>/" key prefix (storage.NewPrefixBackend), never by routing to a
// different underlying backend or a different tenant's barrier key. The
// qrdb SDK's InviteDAOStore (qrdbsdk.NewInviteStore) owns every invitation
// semantic — token generation, digesting, expiry, and single-use redemption
// — this type only routes each tenant to its own namespaced instance of it
// and caches that instance; it is not a parallel implementation.
//
// Guarded writes (PutIfAbsent — the primitive single-use redemption
// requires) are backed by a genuine atomic primitive for every configured
// storage.backend: memory, file and pebble all delegate to a go-qrdb
// embedded engine that implements it natively, and the qrdb backend option
// is qrdb's own storage. The storage.Backend-to-kvstore.KVStore bridge is
// pkg/storage/kvadapter (already in this codebase; do not add a second
// one) — it discovers atomicity from the wrapped backend's own
// storage.GuardedWritesUsable report rather than assuming it, so a future
// backend that cannot serialise guarded writes fails at construction, not
// on the first redemption.
type tenantPrefixedInviteStore struct {
	base storage.Backend

	mu     sync.Mutex
	stores map[string]*qrdbsdk.InviteDAOStore
}

// newTenantPrefixedInviteStore builds a tenantPrefixedInviteStore over base,
// the Backend createStorage("invites") returns.
func newTenantPrefixedInviteStore(base storage.Backend) *tenantPrefixedInviteStore {
	return &tenantPrefixedInviteStore{base: base, stores: map[string]*qrdbsdk.InviteDAOStore{}}
}

// Compile-time check: tenantPrefixedInviteStore satisfies xkms.InviteStore.
var _ xkms.InviteStore = (*tenantPrefixedInviteStore)(nil)

// Create issues an invitation for userID in tenantID.
func (s *tenantPrefixedInviteStore) Create(ctx context.Context, userID, tenantID string, ttl time.Duration) (string, *qrdbsdk.InviteEntity, error) {
	store, err := s.storeFor(tenantID)
	if err != nil {
		return "", nil, err
	}
	return store.Create(ctx, userID, tenantID, ttl)
}

// Lookup resolves a token within tenantID without consuming it.
func (s *tenantPrefixedInviteStore) Lookup(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error) {
	store, err := s.storeFor(tenantID)
	if err != nil {
		return nil, err
	}
	return store.Lookup(ctx, token)
}

// Redeem consumes a token within tenantID exactly once.
func (s *tenantPrefixedInviteStore) Redeem(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error) {
	store, err := s.storeFor(tenantID)
	if err != nil {
		return nil, err
	}
	return store.Redeem(ctx, token)
}

// storeFor returns the cached per-tenant invite DAO store, building and
// caching one on first use. Caching avoids re-registering the store's
// entity ID generator on every call — cheap here (invite.Entity has no
// secondary indexes to register), but the same reasoning
// qrdbsdk.TenantStore's own cache documents, and it keeps one
// *qrdbsdk.InviteDAOStore instance per tenant for the lifetime of the
// process rather than one per request.
func (s *tenantPrefixedInviteStore) storeFor(tenantID string) (*qrdbsdk.InviteDAOStore, error) {
	segment := tenantID
	if segment == "" {
		segment = defaultInviteStoreTenant
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if store, ok := s.stores[segment]; ok {
		return store, nil
	}

	prefixed, err := storage.NewPrefixBackend(s.base, segment+"/")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "invite storage (tenant " + segment + ")", Err: err}
	}
	kv, err := kvadapter.New(prefixed)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "invite storage (tenant " + segment + ")", Err: err}
	}
	store, err := qrdbsdk.NewInviteStore(kv)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "invite storage (tenant " + segment + ")", Err: err}
	}
	s.stores[segment] = store
	return store, nil
}
