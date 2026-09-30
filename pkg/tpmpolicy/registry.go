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

package tpmpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"

	xscope "github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Registry key layout, under each tenant's prefix
// "<tenant>/tpm-policies/shared/":
//
//	scope                             the tenant's Scope record
//	policies/<name>                   a named Policy and its current approval
//	objects/<objectID>                an object's Assignment (authoritative)
//	by-policy/<name>/<objectID>       the policy -> object index (derived)
//
// The object record is the authority on which policy an object uses. The
// by-policy entry is an index written before it and removed after it, so an
// interrupted write can leave a dangling index entry but never an object the
// index does not list; readers of the index skip (and remove) entries with no
// object record behind them.
const (
	scopeKey        = "scope"
	policiesPrefix  = "policies/"
	objectsPrefix   = "objects/"
	byPolicyPrefix  = "by-policy/"
	registryFeature = "tpm-policies"
)

// Registry persists scopes, named policies and object assignments. A TPM
// cannot report the policy an object was created under, so this is the
// record of it, queryable in both directions.
//
// Mutations of one tenant's registry are serialized in-process. TPM objects
// are bound to the node whose TPM holds them, so the registry is stored with
// that node's TPM key blobs and has one writer.
type Registry struct {
	store storage.Backend

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// NewRegistry returns a Registry over store.
func NewRegistry(store storage.Backend) (*Registry, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	return &Registry{store: store, locks: make(map[string]*sync.Mutex)}, nil
}

// lock returns the mutex serializing tenant's registry mutations.
func (r *Registry) lock(tenant string) *sync.Mutex {
	r.locksMu.Lock()
	defer r.locksMu.Unlock()
	mu, ok := r.locks[tenant]
	if !ok {
		mu = &sync.Mutex{}
		r.locks[tenant] = mu
	}
	return mu
}

// key returns the storage key of a registry entry for tenant: the entry lives
// in the tenant's shared keyspace of the tpm-policies feature (pkg/scope).
func key(tenant, suffix string) (string, error) {
	prefix, err := xscope.SharedPrefix(tenant, registryFeature)
	if err != nil {
		return "", &InvalidTenantError{Tenant: tenant, Err: err}
	}
	return prefix + suffix, nil
}

// validName refuses names that cannot be a single key segment.
func validName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return &InvalidNameError{Name: name}
	}
	return nil
}

// validObjectID accepts "<kind>/<name>" for a known ObjectKind, where name
// may itself contain '/' but no empty, "." or ".." segment and no NUL.
func validObjectID(id string) error {
	kind, name, ok := strings.Cut(id, "/")
	if !ok || name == "" || strings.ContainsRune(id, 0) {
		return &InvalidNameError{Name: id}
	}
	if ObjectKind(kind) != ObjectKey && ObjectKind(kind) != ObjectSealed {
		return &InvalidNameError{Name: id}
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return &InvalidNameError{Name: id}
		}
	}
	return nil
}

// ObjectID returns the registry ID of a TPM object of kind named name.
func ObjectID(kind ObjectKind, name string) string {
	return string(kind) + "/" + name
}

// getJSON loads and decodes one record, reporting found=false when absent.
func (r *Registry) getJSON(ctx context.Context, k string, v any) (bool, error) {
	data, err := r.store.Get(ctx, k)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, &StoreError{Op: "get", Key: k, Err: err}
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, &StoreError{Op: "decode", Key: k, Err: err}
	}
	return true, nil
}

// putJSON encodes and stores one record.
func (r *Registry) putJSON(ctx context.Context, k string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return &StoreError{Op: "encode", Key: k, Err: err}
	}
	if err := r.store.Put(ctx, k, data); err != nil {
		return &StoreError{Op: "put", Key: k, Err: err}
	}
	return nil
}

// deleteKey removes one record; an absent record is not an error.
func (r *Registry) deleteKey(ctx context.Context, k string) error {
	if err := r.store.Delete(ctx, k); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &StoreError{Op: "delete", Key: k, Err: err}
	}
	return nil
}

// Scope returns tenant's scope record, or ErrScopeNotFound.
func (r *Registry) Scope(ctx context.Context, tenant string) (*Scope, error) {
	k, err := key(tenant, scopeKey)
	if err != nil {
		return nil, err
	}
	var s Scope
	found, err := r.getJSON(ctx, k, &s)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrScopeNotFound
	}
	return &s, nil
}

// PutScope stores tenant's scope record.
func (r *Registry) PutScope(ctx context.Context, s *Scope) error {
	if s == nil {
		return ErrNilScope
	}
	k, err := key(s.Tenant, scopeKey)
	if err != nil {
		return err
	}
	return r.putJSON(ctx, k, s)
}

// DeleteScope removes tenant's scope record. It refuses while the tenant has
// any object or named policy: TPM objects cannot leave their TPM.
func (r *Registry) DeleteScope(ctx context.Context, tenant string) error {
	mu := r.lock(xscope.TenantName(tenant))
	mu.Lock()
	defer mu.Unlock()

	if err := r.refuseIfPopulated(ctx, tenant); err != nil {
		return err
	}
	k, err := key(tenant, scopeKey)
	if err != nil {
		return err
	}
	return r.deleteKey(ctx, k)
}

// refuseIfPopulated returns *ScopeInUseError when tenant has objects or
// named policies.
func (r *Registry) refuseIfPopulated(ctx context.Context, tenant string) error {
	objects, err := r.listObjectIDs(ctx, tenant)
	if err != nil {
		return err
	}
	policies, err := r.ListPolicies(ctx, tenant)
	if err != nil {
		return err
	}
	if len(objects) == 0 && len(policies) == 0 {
		return nil
	}
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, p.Name)
	}
	return &ScopeInUseError{Tenant: xscope.TenantName(tenant), Objects: objects, Policies: names}
}

// CreatePolicy stores a new named policy. It refuses a name that already
// exists (ErrPolicyExists) and the reserved built-in name.
func (r *Registry) CreatePolicy(ctx context.Context, tenant string, p *Policy) error {
	if p == nil {
		return ErrNilPolicy
	}
	if err := validName(p.Name); err != nil {
		return err
	}
	if p.Name == PlatformPolicy {
		return ErrReservedPolicy
	}
	k, err := key(tenant, policiesPrefix+p.Name)
	if err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return &StoreError{Op: "encode", Key: k, Err: err}
	}
	stored, err := r.store.PutIfAbsent(ctx, k, data)
	if err != nil {
		return &StoreError{Op: "put", Key: k, Err: err}
	}
	if !stored {
		return ErrPolicyExists
	}
	return nil
}

// UpdatePolicy replaces an existing named policy's record (new approvals,
// re-captured PCR values or a new description). The name must already exist.
func (r *Registry) UpdatePolicy(ctx context.Context, tenant string, p *Policy) error {
	if p == nil {
		return ErrNilPolicy
	}
	if _, err := r.Policy(ctx, tenant, p.Name); err != nil {
		return err
	}
	k, err := key(tenant, policiesPrefix+p.Name)
	if err != nil {
		return err
	}
	return r.putJSON(ctx, k, p)
}

// Policy returns tenant's named policy, or ErrPolicyNotFound.
func (r *Registry) Policy(ctx context.Context, tenant, name string) (*Policy, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	k, err := key(tenant, policiesPrefix+name)
	if err != nil {
		return nil, err
	}
	var p Policy
	found, err := r.getJSON(ctx, k, &p)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPolicyNotFound
	}
	return &p, nil
}

// ListPolicies returns tenant's named policies, sorted by name.
func (r *Registry) ListPolicies(ctx context.Context, tenant string) ([]*Policy, error) {
	prefix, err := key(tenant, policiesPrefix)
	if err != nil {
		return nil, err
	}
	var out []*Policy
	err = r.store.Scan(ctx, prefix, func(k string, v []byte) error {
		var p Policy
		if err := json.Unmarshal(v, &p); err != nil {
			return &StoreError{Op: "decode", Key: k, Err: err}
		}
		out = append(out, &p)
		return nil
	})
	if err != nil {
		var storeErr *StoreError
		if errors.As(err, &storeErr) {
			return nil, err
		}
		return nil, &StoreError{Op: "scan", Key: prefix, Err: err}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeletePolicy removes tenant's named policy. It refuses with
// *PolicyInUseError, listing the objects, while any object uses it.
func (r *Registry) DeletePolicy(ctx context.Context, tenant, name string) error {
	if name == PlatformPolicy {
		return ErrReservedPolicy
	}
	mu := r.lock(xscope.TenantName(tenant))
	mu.Lock()
	defer mu.Unlock()

	if _, err := r.Policy(ctx, tenant, name); err != nil {
		return err
	}
	objects, err := r.objectsOf(ctx, tenant, name)
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		return &PolicyInUseError{Policy: name, Objects: objects}
	}
	k, err := key(tenant, policiesPrefix+name)
	if err != nil {
		return err
	}
	return r.deleteKey(ctx, k)
}

// Assign records that object a.ObjectID uses policy a.Policy. The named
// policy must exist (the built-in platform policy always does).
func (r *Registry) Assign(ctx context.Context, tenant string, a *Assignment) error {
	if a == nil {
		return ErrNilAssignment
	}
	if err := validObjectID(a.ObjectID); err != nil {
		return err
	}
	mu := r.lock(xscope.TenantName(tenant))
	mu.Lock()
	defer mu.Unlock()

	if a.Policy != PlatformPolicy {
		if _, err := r.Policy(ctx, tenant, a.Policy); err != nil {
			return err
		}
	}
	indexKey, err := key(tenant, byPolicyPrefix+a.Policy+"/"+a.ObjectID)
	if err != nil {
		return err
	}
	if err := r.store.Put(ctx, indexKey, indexMarker); err != nil {
		return &StoreError{Op: "put", Key: indexKey, Err: err}
	}
	objectKey, err := key(tenant, objectsPrefix+a.ObjectID)
	if err != nil {
		return err
	}
	return r.putJSON(ctx, objectKey, a)
}

// Unassign removes object objectID's assignment. An object with none is not
// an error: deletion paths call this unconditionally.
func (r *Registry) Unassign(ctx context.Context, tenant, objectID string) error {
	if err := validObjectID(objectID); err != nil {
		return err
	}
	mu := r.lock(xscope.TenantName(tenant))
	mu.Lock()
	defer mu.Unlock()

	a, err := r.PolicyOf(ctx, tenant, objectID)
	if errors.Is(err, ErrNotAssigned) {
		return nil
	}
	if err != nil {
		return err
	}
	objectKey, err := key(tenant, objectsPrefix+objectID)
	if err != nil {
		return err
	}
	if err := r.deleteKey(ctx, objectKey); err != nil {
		return err
	}
	indexKey, err := key(tenant, byPolicyPrefix+a.Policy+"/"+objectID)
	if err != nil {
		return err
	}
	return r.deleteKey(ctx, indexKey)
}

// PolicyOf returns object objectID's assignment, or ErrNotAssigned.
func (r *Registry) PolicyOf(ctx context.Context, tenant, objectID string) (*Assignment, error) {
	if err := validObjectID(objectID); err != nil {
		return nil, err
	}
	k, err := key(tenant, objectsPrefix+objectID)
	if err != nil {
		return nil, err
	}
	var a Assignment
	found, err := r.getJSON(ctx, k, &a)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotAssigned
	}
	return &a, nil
}

// ObjectsOf returns the IDs of the objects using policy name, sorted.
func (r *Registry) ObjectsOf(ctx context.Context, tenant, name string) ([]string, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	mu := r.lock(xscope.TenantName(tenant))
	mu.Lock()
	defer mu.Unlock()
	return r.objectsOf(ctx, tenant, name)
}

// objectsOf lists name's objects through the by-policy index, dropping index
// entries an interrupted write left without an object record (or whose
// object has since moved to another policy). The caller holds the lock.
func (r *Registry) objectsOf(ctx context.Context, tenant, name string) ([]string, error) {
	prefix, err := key(tenant, byPolicyPrefix+name+"/")
	if err != nil {
		return nil, err
	}
	keys, err := r.store.List(ctx, prefix)
	if err != nil {
		return nil, &StoreError{Op: "list", Key: prefix, Err: err}
	}
	var out []string
	for _, k := range keys {
		objectID := strings.TrimPrefix(k, prefix)
		a, err := r.PolicyOf(ctx, tenant, objectID)
		switch {
		case errors.Is(err, ErrNotAssigned) || (err == nil && a.Policy != name):
			if err := r.deleteKey(ctx, k); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		default:
			out = append(out, objectID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// listObjectIDs returns every object with an assignment in tenant's scope.
func (r *Registry) listObjectIDs(ctx context.Context, tenant string) ([]string, error) {
	prefix, err := key(tenant, objectsPrefix)
	if err != nil {
		return nil, err
	}
	keys, err := r.store.List(ctx, prefix)
	if err != nil {
		return nil, &StoreError{Op: "list", Key: prefix, Err: err}
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, prefix))
	}
	sort.Strings(out)
	return out, nil
}
