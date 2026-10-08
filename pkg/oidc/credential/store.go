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

package credential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// recordSuffix ends every credential record key, so a listing under a
// scope root separates records from any other key.
const recordSuffix = ".json"

// Backend is the barrier a tenant's credentials are sealed on. The guarded
// writes (PutIfAbsent, CompareAndSwap, CompareAndDelete) compare decrypted
// values, so a read-modify-write is atomic without the caller holding the
// key. *seal.Barrier (a qrdb StorageBarrier) satisfies it.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error)
	CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
	CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

// Barriers resolves the barrier holding each tenant's credentials.
type Barriers interface {
	// Barrier returns tenantID's barrier (scope.SystemTenant: the system
	// barrier). It fails for an unknown tenant; a sealed barrier fails on
	// use.
	Barrier(tenantID string) (Backend, error)

	// Tenants returns every tenant with a barrier, the system tenant
	// included.
	Tenants() []string
}

// registryBarriers resolves barriers from a tenant barrier registry.
type registryBarriers struct {
	registry *seal.BarrierRegistry
}

// RegistryBarriers returns the Barriers of a tenant barrier registry: the
// system barrier for the system tenant, each registered tenant's barrier
// for the rest.
func RegistryBarriers(registry *seal.BarrierRegistry) Barriers {
	return &registryBarriers{registry: registry}
}

func (r *registryBarriers) Barrier(tenantID string) (Backend, error) {
	if scope.IsSystem(tenantID) {
		system := r.registry.SystemBarrier()
		if system == nil {
			return nil, seal.ErrNilSystemBarrier
		}
		return system, nil
	}
	tb, err := r.registry.Tenant(scope.TenantName(tenantID))
	if err != nil {
		return nil, err
	}
	return tb.Barrier(), nil
}

func (r *registryBarriers) Tenants() []string {
	tenants := r.registry.ListTenants()
	out := make([]string, 0, len(tenants)+1)
	out = append(out, scope.SystemTenant)
	for _, t := range tenants {
		if !scope.IsSystem(t) {
			out = append(out, t)
		}
	}
	return out
}

// record is a credential as stored on the barrier.
type record struct {
	Ref         Ref                       `json:"ref"`
	Config      Config                    `json:"config"`
	Tokens      *oidc.TokenResponse       `json:"tokens,omitempty"`
	Status      Status                    `json:"status"`
	Reason      string                    `json:"reason,omitempty"`
	Device      *oidc.DeviceAuthorization `json:"device,omitempty"`
	LastRefresh time.Time                 `json:"last_refresh,omitempty"`
	LastError   string                    `json:"last_error,omitempty"`
	Revision    uint64                    `json:"revision"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
	CreatedBy   string                    `json:"created_by,omitempty"`
}

// refreshable reports whether the server can redeem the login's refresh
// token.
func (r *record) refreshable() bool {
	return !r.Config.NoRefresh && r.Tokens != nil && r.Tokens.RefreshToken != ""
}

// expiresAt returns the current access token's expiry (zero: unknown).
func (r *record) expiresAt() time.Time {
	if r.Tokens == nil {
		return time.Time{}
	}
	return r.Tokens.ExpiresAt()
}

// refreshDue reports whether an active, refreshable login should be
// refreshed at now: its access token is inside the refresh margin, or, with
// no known expiry, it is older than unknownExpiryRefreshAge.
func (r *record) refreshDue(now time.Time) bool {
	if r.Status != StatusActive || !r.refreshable() {
		return false
	}
	exp := r.expiresAt()
	if exp.IsZero() {
		return r.LastRefresh.IsZero() || now.Sub(r.LastRefresh) >= unknownExpiryRefreshAge
	}
	return !now.Add(r.Config.margin()).Before(exp)
}

// expired reports whether the access token has expired at now.
func (r *record) expired(now time.Time) bool {
	exp := r.expiresAt()
	return !exp.IsZero() && !now.Before(exp)
}

// view returns the public view of the record.
func (r *record) view() *Credential {
	cfg := r.Config
	cfg.ClientSecret = ""
	cfg.Scopes = append([]string(nil), r.Config.Scopes...)
	c := &Credential{
		Ref:          r.Ref,
		Config:       cfg,
		Status:       r.Status,
		StatusReason: r.Reason,
		ExpiresAt:    r.expiresAt(),
		Refreshable:  r.refreshable(),
		LastRefresh:  r.LastRefresh,
		LastError:    r.LastError,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
		CreatedBy:    r.CreatedBy,
	}
	if r.Device != nil {
		c.DeviceLogin = &DeviceLogin{
			UserCode:                r.Device.UserCode,
			VerificationURI:         r.Device.VerificationURI,
			VerificationURIComplete: r.Device.VerificationURIComplete,
			Interval:                r.Device.Interval,
			ExpiresAt:               r.Device.ExpiresAt,
		}
	}
	return c
}

// recordKey returns the barrier key of ref, whose tenant, scope and owner
// are already resolved.
func recordKey(ref Ref) (string, error) {
	prefix, err := scope.Prefix(ref.TenantID, Feature, ref.Scope, ref.Owner)
	if err != nil {
		return "", err
	}
	return prefix + ref.Name + recordSuffix, nil
}

// stored is a record together with the exact bytes it was read from, the
// expectation of the compare-and-swap that replaces it.
type stored struct {
	rec  *record
	raw  []byte
	key  string
	back Backend
}

// load reads the record at key.
func load(ctx context.Context, back Backend, key string) (*stored, error) {
	raw, err := back.Get(ctx, key)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, &RecordError{Key: key, Err: err}
	}
	return &stored{rec: &rec, raw: raw, key: key, back: back}, nil
}

// create stores rec at key, refusing an existing key.
func create(ctx context.Context, back Backend, key string, rec *record) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return &RecordError{Key: key, Err: err}
	}
	ok, err := back.PutIfAbsent(ctx, key, raw)
	if err != nil {
		return err
	}
	if !ok {
		return ErrExists
	}
	return nil
}

// replace writes next over s with compare-and-swap, bumping the revision.
// It returns ErrConcurrentUpdate when the record changed since s was read.
func (s *stored) replace(ctx context.Context, next *record, now time.Time) (*stored, error) {
	next.Revision = s.rec.Revision + 1
	next.UpdatedAt = now
	raw, err := json.Marshal(next)
	if err != nil {
		return nil, &RecordError{Key: s.key, Err: err}
	}
	ok, err := s.back.CompareAndSwap(ctx, s.key, s.raw, raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrConcurrentUpdate
	}
	return &stored{rec: next, raw: raw, key: s.key, back: s.back}, nil
}

// remove deletes s with compare-and-delete.
func (s *stored) remove(ctx context.Context) error {
	ok, err := s.back.CompareAndDelete(ctx, s.key, s.raw)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConcurrentUpdate
	}
	return nil
}

// clone returns a deep copy of the record, safe to modify.
func (r *record) clone() *record {
	c := *r
	c.Config.Scopes = append([]string(nil), r.Config.Scopes...)
	if r.Tokens != nil {
		t := *r.Tokens
		c.Tokens = &t
	}
	if r.Device != nil {
		d := *r.Device
		c.Device = &d
	}
	return &c
}

// isNotFound reports whether err is a barrier's missing-key error.
func isNotFound(err error) bool {
	return errors.Is(err, seal.ErrSecretNotFound) || errors.Is(err, storage.ErrNotFound)
}

// isRecordKey reports whether a listed key is a credential record.
func isRecordKey(key string) bool {
	return strings.HasSuffix(key, recordSuffix)
}

// RecordError reports a record that could not be encoded or decoded.
type RecordError struct {
	Key string
	Err error
}

// Error implements error.
func (e *RecordError) Error() string {
	return ErrCorruptRecord.Error() + ": " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns ErrCorruptRecord and the cause.
func (e *RecordError) Unwrap() []error { return []error{ErrCorruptRecord, e.Err} }
