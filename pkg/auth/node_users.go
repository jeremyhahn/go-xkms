// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"time"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// NodeUserSource is the embedded go-qrdb node's user-service accessor
// (*node.Node satisfies it). The service is read at each call: a node
// publishes it only once it has completed boot, which a sealed node does
// after it is unsealed.
type NodeUserSource interface {
	UserService() qrdbsdk.UserServicer
}

// ErrNodeUsersNotServing is returned while the node has not published its
// user service yet (still booting or sealed).
var ErrNodeUsersNotServing = errors.New("auth: qrdb node user service not serving")

// NodeUserClient looks users up through the embedded node's user service,
// the path pkg/server's nodeCertUsers already resolves mTLS certificates
// through. It serves the public (unauthenticated) routes -- WebAuthn
// ceremonies, invite redemption and the refresh re-check -- whose request
// context carries no qrdb credentials, so the datastore client's user calls
// answer "qrdb/auth: unauthenticated" there (ruling 973). The user a call
// acts on comes from server-side state (the ceremony's login key, the invite
// record, the validated refresh token), never from a caller-chosen id.
//
// It speaks the transport shapes of qrdbtransport.UserClient for the
// methods those routes call. A returned User carries the scalar fields,
// role ids, auth methods and attributes; cert and role bindings and factor
// metadata are not carried.
type NodeUserClient struct {
	node NodeUserSource
}

// NewNodeUserClient returns a NodeUserClient over node.
func NewNodeUserClient(node NodeUserSource) *NodeUserClient {
	return &NodeUserClient{node: node}
}

func (c *NodeUserClient) service() (qrdbsdk.UserServicer, error) {
	if c == nil || c.node == nil {
		return nil, ErrNodeUsersNotServing
	}
	users := c.node.UserService()
	if users == nil {
		return nil, ErrNodeUsersNotServing
	}
	return users, nil
}

// GetUser retrieves a user by id.
func (c *NodeUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	return nodeUser(users.GetUser(ctx, id))
}

// GetUserByUsername retrieves a user by tenant-scoped username.
func (c *NodeUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	return nodeUser(users.GetUserByUsername(bindTenant(ctx, tenantID), tenantID, username))
}

// bindTenant binds tenantID on ctx for the node's routing user service,
// which acts on the caller's tenant and, on the anonymous public routes,
// would otherwise default to the system tenant. Callers pass a tenant from
// server-side state (the validated refresh token's claims, the invite
// record, the configured WebAuthn scope), never a caller-chosen one. An
// empty tenantID leaves ctx unchanged.
func bindTenant(ctx context.Context, tenantID string) context.Context {
	if tenantID == "" {
		return ctx
	}
	return qrdbtenant.WithTenantID(ctx, tenantID)
}

// GetUserByEmail retrieves a user by tenant-scoped email login key.
func (c *NodeUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	return nodeUser(users.GetUserByEmail(bindTenant(ctx, tenantID), tenantID, email))
}

// CreateUser creates a passwordless user.
func (c *NodeUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("auth: nil create user request")
	}
	return nodeUser(users.CreateUser(ctx, &qrdbsdk.CreateUserRequest{
		Username:             req.Username,
		Email:                req.Email,
		WithoutEmailLoginKey: req.WithoutEmailLoginKey,
		Name:                 req.Name,
		TenantID:             req.TenantID,
		RoleIDs:              req.RoleIDs,
		Pending:              req.Pending,
		Lifecycle:            qrdbsdk.Lifecycle(req.Lifecycle),
		AuthMethods:          req.AuthMethods,
	}))
}

// UpdateUser applies a partial update. Role bindings are not carried: no
// public route changes them.
func (c *NodeUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("auth: nil update user request")
	}
	if len(req.RoleBindings) > 0 {
		return nil, errors.New("auth: node user client does not update role bindings")
	}
	upd := &qrdbsdk.UpdateUserRequest{
		ID:          req.ID,
		Username:    req.Username,
		Email:       req.Email,
		Name:        req.Name,
		RoleIDs:     req.RoleIDs,
		Attributes:  req.Attributes,
		Lifecycle:   qrdbsdk.Lifecycle(req.Lifecycle),
		AuthMethods: req.AuthMethods,
	}
	if req.LastAuth != "" {
		at, pErr := time.Parse(time.RFC3339Nano, req.LastAuth)
		if pErr != nil {
			return nil, pErr
		}
		upd.LastAuth = &at
	}
	return nodeUser(users.UpdateUser(ctx, upd))
}

// DeleteUser removes a non-system user.
func (c *NodeUserClient) DeleteUser(ctx context.Context, id uint64) error {
	users, err := c.service()
	if err != nil {
		return err
	}
	return users.DeleteUser(ctx, id)
}

// AddCertBinding binds a certificate thumbprint to the user.
func (c *NodeUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	users, err := c.service()
	if err != nil {
		return nil, err
	}
	return nodeUser(users.AddCertBinding(ctx, userID, thumbprint, notAfterUnix))
}

// nodeUser converts the node's user record to the transport shape.
func nodeUser(u *qrdbsdk.User, err error) (*qrdbtransport.User, error) {
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("auth: node user service returned no user")
	}
	out := &qrdbtransport.User{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Name:        u.Name,
		TenantID:    u.TenantID,
		RoleIDs:     u.RoleIDs,
		System:      u.System,
		Lifecycle:   string(u.Lifecycle),
		AuthMethods: u.AuthMethods,
		Attributes:  u.Attributes,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:   u.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if u.LastAuth != nil {
		out.LastAuth = u.LastAuth.UTC().Format(time.RFC3339Nano)
	}
	return out, nil
}
