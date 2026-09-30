// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package tenancy is the server-side SSH service: the sdkssh.Client every
// xkmsd transport (REST, gRPC, MCP, QUIC, the Unix socket) is wired with. It
// binds each request's scope and owner to the authenticated caller and
// serves it from that caller's tenant partition, so the (scope, owner, name)
// address a request carries can never reach another tenant's or another
// user's SSH assets.
//
// # Owner binding
//
// The transports' RBAC gate cannot do this: auth.Authorizer binds the
// caller's own tenant as the target, so ssh:read / ssh:write / ssh:delete,
// which a tenant Admin holds, admit any address. The binding is therefore
// enforced here, once, for every transport, by the xkms scope rule
// (scope.Principal.Authorize):
//
//   - scope=tenant is owned by the tenant whose ID is the owner, and every
//     user of that tenant may address it;
//   - scope=user is owned by the principal whose subject is the owner, in
//     the caller's tenant, and only that principal may address it -- a
//     platform caller included;
//   - scope=service is owned by a workload in the caller's tenant, and only
//     a caller holding the explicit ssh:service permission may address it
//     (Options.Permissions; with none wired the scope is closed).
//
// A platform caller (auth.IsCrossTenant: no identity, or the system tenant)
// may also address any tenant's scope=tenant assets. A refusal is an
// *OwnerBindingError that answers exactly as a missing asset does; a listing
// silently omits what the caller may not see.
//
// # Partitions
//
// A subject is unique only within its tenant -- the mTLS authenticator uses
// the username -- so user- and service-scoped assets of equal subjects in two
// tenants would share an address in one flat store. Every tenant therefore
// has its own storage partition, rooted at the tenant root "{tenant}/"
// (scope.TenantRoot) of the shared SSH storage view, and its own backend-key
// namespace (the backend KeyProvider sees the tenant in
// types.KeyAttributes.TenantID, exactly as a xkms.TenantScopedBackend scopes
// it). The platform is the ordinary tenant "system": its partition is
// "system/". The stores key records by the xkms scope layout inside the
// partition, so every asset lands at
//
//	{tenant}/ssh/shared/<kind>/<name>             scope=tenant
//	{tenant}/ssh/users/{subject}/<kind>/<name>    scope=user
//	{tenant}/ssh/services/{owner}/<kind>/<name>   scope=service
//
// A tenant-scoped caller is always served from its own tenant's partition. A
// platform caller is served from the partition of the tenant a scope=tenant
// owner names, and from the platform partition otherwise.
package tenancy

import (
	"context"
	"errors"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Options configures New.
type Options struct {
	// Storage is the SSH storage view shared by every partition. Required.
	// The Client owns it and closes it on Close.
	Storage storage.Backend

	// Resolver resolves a crypto backend's KeyProvider by backend ID,
	// unscoped. The Client narrows it to each partition's tenant. Optional:
	// when nil only software keys (sealed in the SSH store) are available and
	// a request naming a backend is refused by the SDK.
	Resolver sshbackend.Resolver

	// Permissions answers whether the caller holds ssh:service, the explicit
	// permission a service-scoped address requires. *xkms.XKMSService
	// satisfies it. Optional: when nil the service scope is closed to every
	// caller.
	Permissions PermissionChecker
}

// PermissionChecker reports whether the identity on ctx holds
// resource:action, returning nil when it does.
type PermissionChecker interface {
	AuthorizeCaller(ctx context.Context, resource, action string) error
}

// client is the tenant-binding sdkssh.Client.
type client struct {
	storage     storage.Backend
	resolver    sshbackend.Resolver
	permissions PermissionChecker

	// empty is a partition over storage nothing is ever written to: it
	// serves only refusals, which read, delete and look up through it, and
	// Emit, which reads no store. Its answer to any address is therefore the
	// answer for an asset that does not exist.
	empty sdkssh.Client

	closeOnce sync.Once
	closeErr  error
}

var _ sdkssh.Client = (*client)(nil)

// New returns the tenant-binding SSH client over opts.Storage. Returns
// *NilInputError when opts.Storage is nil.
func New(opts Options) (sdkssh.Client, error) {
	if opts.Storage == nil {
		return nil, &NilInputError{Field: "Storage"}
	}
	nothing, err := storage.NewMemoryBackend()
	if err != nil {
		return nil, err
	}
	empty, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: nothing})
	if err != nil {
		return nil, err
	}
	return &client{storage: opts.Storage, resolver: opts.Resolver, permissions: opts.Permissions, empty: empty}, nil
}

// Keys implements sdkssh.Client.
func (c *client) Keys() sdkssh.KeysClient { return &keysClient{c: c} }

// KnownHosts implements sdkssh.Client.
func (c *client) KnownHosts() sdkssh.KnownHostsClient { return &knownHostsClient{c: c} }

// AuthorizedKeys implements sdkssh.Client.
func (c *client) AuthorizedKeys() sdkssh.AuthorizedKeysClient { return &authorizedKeysClient{c: c} }

// Session implements sdkssh.Client.
func (c *client) Session() sdkssh.SessionClient { return &sessionClient{c: c} }

// Console implements sdkssh.Client. The authentication key and the host-key
// pins are both addressed by (KeyScope, KeyOwner), so one binding covers
// both.
func (c *client) Console(ctx context.Context, req sdkssh.ConsoleConnectRequest, cfg sdkssh.ConsoleConfig) (sdkssh.ConsoleSession, error) {
	p, err := c.serve(ctx, req.KeyScope, req.KeyOwner)
	if err != nil {
		return nil, err
	}
	session, err := p.client.Console(ctx, req, cfg)
	if err != nil {
		return nil, c.wrapRefusal(ctx, p, "console", req.KeyScope, req.KeyOwner, err)
	}
	return session, nil
}

// Close closes the shared storage view. Idempotent.
func (c *client) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = errors.Join(c.empty.Close(), c.storage.Close())
	})
	return c.closeErr
}

// ------------------------------------------------------------------
// Binding.
// ------------------------------------------------------------------

// caller is the authenticated principal a request is bound to.
type caller struct {
	identity  *auth.Identity
	principal scope.Principal
}

// callerOf returns the principal ctx carries.
func callerOf(ctx context.Context) caller {
	identity := auth.GetIdentity(ctx)
	return caller{identity: identity, principal: scope.PrincipalOf(identity)}
}

// platform reports whether the caller is platform-scoped.
func (a caller) platform() bool { return a.principal.Platform }

// target returns the owner a request addressing (sc, owner) names: a
// scope=tenant owner is the tenant itself; a user or service owner lives in
// the caller's own tenant.
func (a caller) target(sc pkgscope.Scope, owner string) scope.Target {
	if sc == pkgscope.Tenant {
		return scope.Target{TenantID: owner, Scope: sc}
	}
	return scope.Target{TenantID: a.principal.TenantID, Scope: sc, Owner: owner}
}

// authorize applies the xkms scope rule (scope.Principal.Authorize) to a
// request addressing (sc, owner). The service-scope permission is resolved
// only for a service-scoped address, so no other request pays for the check.
func (c *client) authorize(ctx context.Context, who caller, sc pkgscope.Scope, owner string) error {
	p := who.principal
	if sc == pkgscope.Service {
		p.ServiceAccess = c.serviceAccess(ctx)
	}
	return p.Authorize(who.target(sc, owner))
}

// serviceAccess reports whether the caller holds ssh:service. Without a
// permission checker the service scope is closed to everyone.
func (c *client) serviceAccess(ctx context.Context) bool {
	if c.permissions == nil {
		return false
	}
	return c.permissions.AuthorizeCaller(ctx, auth.ResourceSSH, auth.ActionService) == nil
}

// visibility returns the listing filter for the caller: whether an asset of
// owner in scope belongs in its listing. The service-scope permission is
// resolved at most once per listing.
func (c *client) visibility(ctx context.Context, who caller) func(scope, owner string) bool {
	var service *bool
	return func(rawScope, owner string) bool {
		sc := pkgscope.Scope(rawScope)
		p := who.principal
		if sc == pkgscope.Service {
			if service == nil {
				granted := c.serviceAccess(ctx)
				service = &granted
			}
			p.ServiceAccess = *service
		}
		return p.Authorize(who.target(sc, owner)) == nil
	}
}

// partition is where one request is served: a tenant's partition, the
// platform partition (tenantID "", the "system" tenant), or -- when the caller may not make the
// request -- the empty partition, with refusal holding why.
type partition struct {
	client   sdkssh.Client
	tenantID string
	allowed  bool
	refusal  error
}

// serve binds a request addressing (rawScope, owner) to the caller and opens
// the partition that serves it. An unrecognized scope is answered as the SDK
// answers it for every caller.
func (c *client) serve(ctx context.Context, rawScope, owner string) (partition, error) {
	sc, err := pkgscope.Parse(rawScope)
	if err != nil {
		return partition{}, &sdkssh.InvalidScopeError{Value: rawScope}
	}
	b, err := c.bind(ctx, sc, owner)
	if err != nil {
		return partition{}, err
	}
	if b.refusal != nil {
		return partition{client: c.empty, refusal: b.refusal}, nil
	}
	p, err := c.open(b.tenantID)
	if err != nil {
		return partition{}, err
	}
	return partition{client: p, tenantID: b.tenantID, allowed: true}, nil
}

// binding is the outcome of binding a request to its caller: the partition
// tenant that serves it, or the refusal of a caller that may not make it.
type binding struct {
	tenantID string
	refusal  error
}

// bind resolves the binding of a request addressing (sc, owner).
func (c *client) bind(ctx context.Context, sc pkgscope.Scope, owner string) (binding, error) {
	who := callerOf(ctx)
	if refusal := c.authorize(ctx, who, sc, owner); refusal != nil {
		return binding{refusal: refusal}, nil
	}
	if !who.platform() {
		if err := validatePartitionTenant(who.identity.TenantID); err != nil {
			return binding{}, err
		}
		return binding{tenantID: who.identity.TenantID}, nil
	}
	if sc != pkgscope.Tenant || qrdbsdk.IsSystemTenant(owner) {
		return binding{}, nil
	}
	if err := storage.ValidateTenantID(owner); err != nil {
		// No tenant can have this ID, so it has no partition and no assets.
		return binding{refusal: &scope.InvalidSegmentError{Field: "tenant", Value: owner, Err: err}}, nil
	}
	return binding{tenantID: owner}, nil
}

// listPartition opens the partition a listing filtered by (rawScope, owner)
// reads, and the filter that keeps what the caller may see. Either filter may
// be empty. A tenant-scoped caller always reads its own partition.
func (c *client) listPartition(ctx context.Context, rawScope, owner string) (sdkssh.Client, func(scope, owner string) bool, error) {
	who := callerOf(ctx)
	visible := c.visibility(ctx, who)
	var sc pkgscope.Scope
	if rawScope != "" {
		parsed, err := pkgscope.Parse(rawScope)
		if err != nil {
			return nil, nil, &sdkssh.InvalidScopeError{Value: rawScope}
		}
		sc = parsed
	}
	if !who.platform() {
		if err := validatePartitionTenant(who.identity.TenantID); err != nil {
			return nil, nil, err
		}
		p, err := c.open(who.identity.TenantID)
		return p, visible, err
	}
	if sc != pkgscope.Tenant || owner == "" || qrdbsdk.IsSystemTenant(owner) {
		p, err := c.open("")
		return p, visible, err
	}
	if storage.ValidateTenantID(owner) != nil {
		return c.empty, visible, nil
	}
	p, err := c.open(owner)
	return p, visible, err
}

// validatePartitionTenant checks a tenant-scoped caller's tenant can root a
// partition. auth.IsCrossTenant already classed an empty tenant as the
// platform, so tenantID is never empty here.
func validatePartitionTenant(tenantID string) error {
	if err := storage.ValidateTenantID(tenantID); err != nil {
		return &CallerTenantError{TenantID: tenantID, Err: err}
	}
	return nil
}

// open returns the embedded client over tenantID's partition ("" is the
// platform partition, rooted at "system/"). A partition is a view -- the
// tenant root (scope.TenantRoot) as a key prefix over the shared storage and
// a tenant-narrowed backend resolver -- so opening one allocates no
// resources that need releasing.
func (c *client) open(tenantID string) (sdkssh.Client, error) {
	root, err := scope.TenantRoot(tenantID)
	if err != nil {
		return nil, err
	}
	view, err := storage.NewPrefixBackend(c.storage, root)
	if err != nil {
		return nil, err
	}
	opts := sdkssh.EmbeddedOptions{Backend: view}
	if c.resolver != nil {
		provider, err := sshbackend.New(c.tenantResolver(tenantID))
		if err != nil {
			return nil, err
		}
		opts.BackendProvider = provider
	}
	return sdkssh.NewEmbedded(opts)
}

// tenantResolver narrows the unscoped resolver to tenantID: every key the
// returned resolver's providers generate, sign with or delete is addressed in
// that tenant's namespace. The platform partition keeps the unscoped view.
func (c *client) tenantResolver(tenantID string) sshbackend.Resolver {
	if tenantID == "" {
		return c.resolver
	}
	return sshbackend.ResolverFunc(func(ctx context.Context, backendID string) (types.KeyProvider, error) {
		kp, err := c.resolver.ResolveKeyProvider(ctx, backendID)
		if err != nil {
			return nil, err
		}
		if kp == nil {
			return nil, &sshbackend.BackendNotFoundError{BackendID: backendID}
		}
		return &tenantKeyProvider{base: kp, tenantID: tenantID}, nil
	})
}

// wrapRefusal marks err as the refusal it is when p is the empty partition
// serving a refused request, and returns err unchanged otherwise.
func (c *client) wrapRefusal(ctx context.Context, p partition, op, scope, owner string, err error) error {
	if p.allowed {
		return err
	}
	return newOwnerBindingError(ctx, op, scope, owner, p.refusal, err)
}

// newOwnerBindingError builds the refusal carrying miss, the genuine-miss
// answer, and cause, the scope rule's reason. The empty partition holds
// nothing, so it always has a miss; a nil miss means something wrote to it,
// and the refusal becomes an internal error rather than a success.
func newOwnerBindingError(ctx context.Context, op, scope, owner string, cause, miss error) error {
	if miss == nil {
		miss = &EmptyPartitionError{Op: op}
	}
	who := callerOf(ctx)
	refusal := &OwnerBindingError{Op: op, Scope: scope, Owner: owner, Cause: cause, Err: miss}
	if who.identity != nil {
		refusal.CallerTenantID = who.identity.TenantID
		refusal.CallerSubject = who.identity.Subject
	}
	return refusal
}
