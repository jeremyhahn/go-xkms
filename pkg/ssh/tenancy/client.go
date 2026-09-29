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
// enforced here, once, for every transport:
//
//   - scope=tenant is owned by the tenant whose ID is the owner;
//   - scope=user and scope=service are owned by the principal whose subject
//     is the owner.
//
// A tenant-scoped caller may address only what it owns. A platform caller
// (auth.IsCrossTenant: no identity, or the system tenant) may address
// anything. A refusal is an *OwnerBindingError that answers exactly as a
// missing asset does; a listing silently omits what the caller does not own.
//
// # Partitions
//
// A subject is unique only within its tenant -- the mTLS authenticator uses
// the username -- so user- and service-scoped assets of equal subjects in two
// tenants would share an address in one flat store. Every tenant therefore
// has its own storage partition (the "tenants/<tenant-id>/" prefix of the
// shared SSH storage view) and its own backend-key namespace (the backend
// KeyProvider sees the tenant in types.KeyAttributes.TenantID, exactly as a
// xkms.TenantScopedBackend scopes it). A tenant-scoped caller is always
// served from its own tenant's partition. A platform caller is served from
// the partition of the tenant a scope=tenant owner names, and from the
// platform partition -- the unprefixed view -- otherwise.
package tenancy

import (
	"context"
	"errors"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// tenantPartitionPrefix roots every tenant partition in the shared storage
// view. The platform partition's records begin with "ssh/", so no tenant ID
// can make a tenant partition overlap it.
const tenantPartitionPrefix = "tenants/"

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
}

// client is the tenant-binding sdkssh.Client.
type client struct {
	storage  storage.Backend
	resolver sshbackend.Resolver

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
	return &client{storage: opts.Storage, resolver: opts.Resolver, empty: empty}, nil
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
	identity *auth.Identity
	platform bool
}

// callerOf returns the principal ctx carries.
func callerOf(ctx context.Context) caller {
	identity := auth.GetIdentity(ctx)
	return caller{identity: identity, platform: auth.IsCrossTenant(identity)}
}

// owns reports whether the caller may address assets of owner in sc.
func (a caller) owns(sc pkgscope.Scope, owner string) bool {
	if a.platform {
		return true
	}
	switch sc {
	case pkgscope.Tenant:
		return owner == a.identity.TenantID
	case pkgscope.User, pkgscope.Service:
		return owner == a.identity.Subject
	default:
		return false
	}
}

// partition is where one request is served: a tenant's partition, the
// platform partition (tenantID ""), or -- when the caller may not make the
// request -- the empty partition.
type partition struct {
	client   sdkssh.Client
	tenantID string
	allowed  bool
}

// serve binds a request addressing (rawScope, owner) to the caller and opens
// the partition that serves it. An unrecognized scope is answered as the SDK
// answers it for every caller.
func (c *client) serve(ctx context.Context, rawScope, owner string) (partition, error) {
	sc, err := pkgscope.Parse(rawScope)
	if err != nil {
		return partition{}, &sdkssh.InvalidScopeError{Value: rawScope}
	}
	tenantID, allowed, err := c.bind(ctx, sc, owner)
	if err != nil {
		return partition{}, err
	}
	if !allowed {
		return partition{client: c.empty}, nil
	}
	p, err := c.open(tenantID)
	if err != nil {
		return partition{}, err
	}
	return partition{client: p, tenantID: tenantID, allowed: true}, nil
}

// bind resolves the partition tenant of a request addressing (sc, owner),
// and whether the caller may make it.
func (c *client) bind(ctx context.Context, sc pkgscope.Scope, owner string) (string, bool, error) {
	who := callerOf(ctx)
	if !who.owns(sc, owner) {
		return "", false, nil
	}
	if !who.platform {
		if err := validatePartitionTenant(who.identity.TenantID); err != nil {
			return "", false, err
		}
		return who.identity.TenantID, true, nil
	}
	if sc != pkgscope.Tenant || qrdbsdk.IsSystemTenant(owner) {
		return "", true, nil
	}
	if storage.ValidateTenantID(owner) != nil {
		// No tenant can have this ID, so it has no partition and no assets.
		return "", false, nil
	}
	return owner, true, nil
}

// listPartition opens the partition a listing filtered by (rawScope, owner)
// reads. Either filter may be empty. A tenant-scoped caller always reads its
// own partition; the caller filters the result to what it owns.
func (c *client) listPartition(ctx context.Context, rawScope, owner string) (sdkssh.Client, caller, error) {
	who := callerOf(ctx)
	var sc pkgscope.Scope
	if rawScope != "" {
		parsed, err := pkgscope.Parse(rawScope)
		if err != nil {
			return nil, who, &sdkssh.InvalidScopeError{Value: rawScope}
		}
		sc = parsed
	}
	if !who.platform {
		if err := validatePartitionTenant(who.identity.TenantID); err != nil {
			return nil, who, err
		}
		p, err := c.open(who.identity.TenantID)
		return p, who, err
	}
	if sc != pkgscope.Tenant || owner == "" || qrdbsdk.IsSystemTenant(owner) {
		p, err := c.open("")
		return p, who, err
	}
	if storage.ValidateTenantID(owner) != nil {
		return c.empty, who, nil
	}
	p, err := c.open(owner)
	return p, who, err
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
// platform partition). A partition is a view -- a key prefix over the shared
// storage and a tenant-narrowed backend resolver -- so opening one allocates
// no resources that need releasing.
func (c *client) open(tenantID string) (sdkssh.Client, error) {
	view := c.storage
	if tenantID != "" {
		prefixed, err := storage.NewPrefixBackend(c.storage, tenantPartitionPrefix+tenantID+"/")
		if err != nil {
			return nil, err
		}
		view = prefixed
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
	return newOwnerBindingError(ctx, op, scope, owner, err)
}

// newOwnerBindingError builds the refusal carrying miss, the genuine-miss
// answer. The empty partition holds nothing, so it always has one; a nil
// miss means something wrote to it, and the refusal becomes an internal
// error rather than a success.
func newOwnerBindingError(ctx context.Context, op, scope, owner string, miss error) error {
	if miss == nil {
		miss = &EmptyPartitionError{Op: op}
	}
	who := callerOf(ctx)
	refusal := &OwnerBindingError{Op: op, Scope: scope, Owner: owner, Err: miss}
	if who.identity != nil {
		refusal.CallerTenantID = who.identity.TenantID
		refusal.CallerSubject = who.identity.Subject
	}
	return refusal
}

// visible reports whether a listed asset of owner in scope belongs in the
// caller's listing. Listed assets carry the store's canonical scope string.
func (a caller) visible(scope, owner string) bool {
	return a.owns(pkgscope.Scope(scope), owner)
}
