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

package policy

import (
	"context"
	"sort"
	"strings"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	xscope "github.com/jeremyhahn/go-xkms/pkg/scope"
)

// listPageSize is the page size the registry lists its entities with.
const listPageSize = 500

// Registry persists scopes, named policies and object assignments as go-qrdb
// DAO entities in DatabaseName. A TPM cannot report the policy an object was
// created under, so this is the record of it, queryable in both directions.
//
// Every entity's ID derives from its natural key, which starts with the
// tenant's root ("<tenant>/"), so one tenant's records never answer for
// another's. An object's assignment entity is the one record of which policy
// it uses; the policy -> objects direction is a scan of the tenant's
// assignments.
//
// Mutations of one tenant's registry are serialized in-process. TPM objects
// are bound to the node whose TPM holds them, so the registry has one writer.
type Registry struct {
	scopes      qrdbsdk.GenericDAO[*scopeEntity]
	policies    qrdbsdk.GenericDAO[*policyEntity]
	assignments qrdbsdk.GenericDAO[*assignmentEntity]

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// NewRegistry returns a Registry whose DAOs daos builds in DatabaseName. The
// factory must already serve that database; the errors are pkg/dao's.
func NewRegistry(daos *qrdbsdk.DAOFactory) (*Registry, error) {
	scopes, err := newDAO(daos, scopeEntityType, func() *scopeEntity { return &scopeEntity{} })
	if err != nil {
		return nil, err
	}
	policies, err := newDAO(daos, policyEntityType, func() *policyEntity { return &policyEntity{} })
	if err != nil {
		return nil, err
	}
	assignments, err := newDAO(daos, assignmentEntityType, func() *assignmentEntity { return &assignmentEntity{} })
	if err != nil {
		return nil, err
	}
	return &Registry{
		scopes:      scopes,
		policies:    policies,
		assignments: assignments,
		locks:       make(map[string]*sync.Mutex),
	}, nil
}

// newDAO builds the DAO of one registry entity type, its IDs derived from
// the entity's natural key with a collision-resistant hash.
func newDAO[E qrdbsdk.Entity](daos *qrdbsdk.DAOFactory, entityType string, newEntity func() E) (qrdbsdk.GenericDAO[E], error) {
	return dao.New(daos, DatabaseName, entityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator(naturalKeyField)))
}

// load returns the entity whose natural key is key, reporting found=false
// when there is none.
func load[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], key string) (E, bool, error) {
	entity, err := d.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		var zero E
		return zero, false, nil
	}
	if err != nil {
		var zero E
		return zero, false, &StoreError{Op: "get", Key: key, Err: err}
	}
	return entity, true, nil
}

// save stores entity under its natural key, replacing the record there.
func save[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], key string, entity E) error {
	if err := d.Save(ctx, entity); err != nil {
		return &StoreError{Op: "put", Key: key, Err: err}
	}
	return nil
}

// remove deletes the entity whose natural key is key; an absent entity is
// not an error.
func remove[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], key string) error {
	entity, found, err := load(ctx, d, key)
	if err != nil || !found {
		return err
	}
	if err := d.Delete(ctx, entity); err != nil {
		return &StoreError{Op: "delete", Key: key, Err: err}
	}
	return nil
}

// list returns every entity of d that keep accepts, in storage order.
func list[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], entityType string, keep func(E) bool) ([]E, error) {
	var out []E
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize}
	err := d.ForEachPage(ctx, query, func(page qrdbsdk.PageResult[E]) error {
		for _, entity := range page.Entities {
			if keep(entity) {
				out = append(out, entity)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Key: entityType, Err: err}
	}
	return out, nil
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

// tenantRoot returns tenant's root ("<tenant>/"), the prefix of the natural
// key of each of its records, and its normalized name.
func tenantRoot(tenant string) (root, name string, err error) {
	root, err = xscope.TenantRoot(tenant)
	if err != nil {
		return "", "", &InvalidTenantError{Tenant: tenant, Err: err}
	}
	return root, xscope.TenantName(tenant), nil
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

// Scope returns tenant's scope record, or ErrScopeNotFound.
func (r *Registry) Scope(ctx context.Context, tenant string) (*Scope, error) {
	root, _, err := tenantRoot(tenant)
	if err != nil {
		return nil, err
	}
	entity, found, err := load(ctx, r.scopes, root)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrScopeNotFound
	}
	return &entity.Scope, nil
}

// PutScope stores tenant's scope record.
func (r *Registry) PutScope(ctx context.Context, s *Scope) error {
	if s == nil {
		return ErrNilScope
	}
	root, name, err := tenantRoot(s.Tenant)
	if err != nil {
		return err
	}
	return save(ctx, r.scopes, root, &scopeEntity{Key: root, Tenant: name, Scope: *s})
}

// DeleteScope removes tenant's scope record. It refuses while the tenant has
// any object or named policy: TPM objects cannot leave their TPM.
func (r *Registry) DeleteScope(ctx context.Context, tenant string) error {
	root, name, err := tenantRoot(tenant)
	if err != nil {
		return err
	}
	mu := r.lock(name)
	mu.Lock()
	defer mu.Unlock()

	if err := r.refuseIfPopulated(ctx, tenant); err != nil {
		return err
	}
	return remove(ctx, r.scopes, root)
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

// policyKey returns the natural key of tenant's policy name, and the
// tenant's normalized name.
func policyKey(tenant, name string) (key, tenantName string, err error) {
	if err := validName(name); err != nil {
		return "", "", err
	}
	root, tenantName, err := tenantRoot(tenant)
	if err != nil {
		return "", "", err
	}
	return root + name, tenantName, nil
}

// CreatePolicy stores a new named policy. It refuses a name that already
// exists (ErrPolicyExists) and the reserved built-in name.
func (r *Registry) CreatePolicy(ctx context.Context, tenant string, p *Policy) error {
	if p == nil {
		return ErrNilPolicy
	}
	if p.Name == PlatformPolicy {
		return ErrReservedPolicy
	}
	k, name, err := policyKey(tenant, p.Name)
	if err != nil {
		return err
	}
	stored, err := r.policies.SaveIfAbsent(ctx, &policyEntity{Key: k, Tenant: name, Policy: *p})
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
	k, name, err := policyKey(tenant, p.Name)
	if err != nil {
		return err
	}
	return save(ctx, r.policies, k, &policyEntity{Key: k, Tenant: name, Policy: *p})
}

// Policy returns tenant's named policy, or ErrPolicyNotFound.
func (r *Registry) Policy(ctx context.Context, tenant, name string) (*Policy, error) {
	k, _, err := policyKey(tenant, name)
	if err != nil {
		return nil, err
	}
	entity, found, err := load(ctx, r.policies, k)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPolicyNotFound
	}
	return &entity.Policy, nil
}

// ListPolicies returns tenant's named policies, sorted by name.
func (r *Registry) ListPolicies(ctx context.Context, tenant string) ([]*Policy, error) {
	_, name, err := tenantRoot(tenant)
	if err != nil {
		return nil, err
	}
	entities, err := list(ctx, r.policies, policyEntityType, func(e *policyEntity) bool { return e.Tenant == name })
	if err != nil {
		return nil, err
	}
	out := make([]*Policy, 0, len(entities))
	for _, entity := range entities {
		out = append(out, &entity.Policy)
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
	k, tenantName, err := policyKey(tenant, name)
	if err != nil {
		return err
	}
	mu := r.lock(tenantName)
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
	return remove(ctx, r.policies, k)
}

// assignmentKey returns the natural key of tenant's object objectID's
// assignment, and the tenant's normalized name.
func assignmentKey(tenant, objectID string) (key, tenantName string, err error) {
	if err := validObjectID(objectID); err != nil {
		return "", "", err
	}
	root, tenantName, err := tenantRoot(tenant)
	if err != nil {
		return "", "", err
	}
	return root + objectID, tenantName, nil
}

// Assign records that object a.ObjectID uses policy a.Policy. The named
// policy must exist (the built-in platform policy always does).
func (r *Registry) Assign(ctx context.Context, tenant string, a *Assignment) error {
	if a == nil {
		return ErrNilAssignment
	}
	k, name, err := assignmentKey(tenant, a.ObjectID)
	if err != nil {
		return err
	}
	mu := r.lock(name)
	mu.Lock()
	defer mu.Unlock()

	if a.Policy != PlatformPolicy {
		if _, err := r.Policy(ctx, tenant, a.Policy); err != nil {
			return err
		}
	}
	return save(ctx, r.assignments, k, &assignmentEntity{Key: k, Tenant: name, Assignment: *a})
}

// Unassign removes object objectID's assignment. An object with none is not
// an error: deletion paths call this unconditionally.
func (r *Registry) Unassign(ctx context.Context, tenant, objectID string) error {
	k, name, err := assignmentKey(tenant, objectID)
	if err != nil {
		return err
	}
	mu := r.lock(name)
	mu.Lock()
	defer mu.Unlock()
	return remove(ctx, r.assignments, k)
}

// PolicyOf returns object objectID's assignment, or ErrNotAssigned.
func (r *Registry) PolicyOf(ctx context.Context, tenant, objectID string) (*Assignment, error) {
	k, _, err := assignmentKey(tenant, objectID)
	if err != nil {
		return nil, err
	}
	entity, found, err := load(ctx, r.assignments, k)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotAssigned
	}
	return &entity.Assignment, nil
}

// ObjectsOf returns the IDs of the objects using policy name, sorted.
func (r *Registry) ObjectsOf(ctx context.Context, tenant, name string) ([]string, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	_, tenantName, err := tenantRoot(tenant)
	if err != nil {
		return nil, err
	}
	mu := r.lock(tenantName)
	mu.Lock()
	defer mu.Unlock()
	return r.objectsOf(ctx, tenant, name)
}

// objectsOf returns the IDs of tenant's objects assigned to policy name,
// sorted. The caller holds the lock.
func (r *Registry) objectsOf(ctx context.Context, tenant, name string) ([]string, error) {
	assignments, err := r.Assignments(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range assignments {
		if a.Policy == name {
			out = append(out, a.ObjectID)
		}
	}
	return out, nil
}

// listObjectIDs returns every object with an assignment in tenant's scope,
// sorted.
func (r *Registry) listObjectIDs(ctx context.Context, tenant string) ([]string, error) {
	assignments, err := r.Assignments(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(assignments))
	for _, a := range assignments {
		out = append(out, a.ObjectID)
	}
	return out, nil
}

// Scopes returns the names of every scope with a scope record, sorted.
func (r *Registry) Scopes(ctx context.Context) ([]string, error) {
	entities, err := list(ctx, r.scopes, scopeEntityType, func(*scopeEntity) bool { return true })
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entities))
	for _, entity := range entities {
		out = append(out, entity.Tenant)
	}
	sort.Strings(out)
	return out, nil
}

// Assignments returns every assignment recorded in tenant's scope, sorted by
// object ID.
func (r *Registry) Assignments(ctx context.Context, tenant string) ([]*Assignment, error) {
	_, name, err := tenantRoot(tenant)
	if err != nil {
		return nil, err
	}
	entities, err := list(ctx, r.assignments, assignmentEntityType, func(e *assignmentEntity) bool { return e.Tenant == name })
	if err != nil {
		return nil, err
	}
	out := make([]*Assignment, 0, len(entities))
	for _, entity := range entities {
		out = append(out, &entity.Assignment)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObjectID < out[j].ObjectID })
	return out, nil
}
