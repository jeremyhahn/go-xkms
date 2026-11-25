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

package auth

import (
	"context"
	"errors"
	"time"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ErrNodeUsersNotServing is returned while the embedded node has not yet
// published its user service (a sealed node publishes it once unsealed).
var ErrNodeUsersNotServing = errors.New("auth: node user service not serving")

// CeremonyUserService is the slice of the embedded node's user service the
// login and invitation ceremonies read and update accounts through.
type CeremonyUserService interface {
	GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbsdk.User, error)
	GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbsdk.User, error)
	UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error)
	AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbsdk.User, error)
}

// CeremonyUsers is a qrdb user client confined to one tenant for the
// unauthenticated passkey and invitation ceremonies. Account reads, the
// display-name update, activation of a pending account and an invitation's
// certificate binding go through the node user service in that tenant only;
// a user of any other tenant reads as not found. Every other verb, and any
// update touching other fields, goes to the authorized client and keeps its
// authorization.
type CeremonyUsers struct {
	tenantID   string
	node       func() CeremonyUserService
	authorized qrdbtransport.UserClient
}

var _ qrdbtransport.UserClient = (*CeremonyUsers)(nil)

// NewCeremonyUsers confines the node user service node returns to tenantID;
// node is read at each call. authorized serves every other verb.
func NewCeremonyUsers(tenantID string, node func() CeremonyUserService, authorized qrdbtransport.UserClient) *CeremonyUsers {
	return &CeremonyUsers{tenantID: tenantID, node: node, authorized: authorized}
}

func (c *CeremonyUsers) service(ctx context.Context) (context.Context, CeremonyUserService, error) {
	var svc CeremonyUserService
	if c.node != nil {
		svc = c.node()
	}
	if svc == nil {
		return ctx, nil, ErrNodeUsersNotServing
	}
	return qrdbsdk.ContextWithTenant(ctx, c.tenantID), svc, nil
}

// confined returns u when it belongs to the tenant, else a not-found error.
func (c *CeremonyUsers) confined(u *qrdbsdk.User, err error, missing error) (*qrdbsdk.User, error) {
	if err != nil {
		return nil, err
	}
	if u == nil || u.TenantID != c.tenantID {
		return nil, missing
	}
	return u, nil
}

func (c *CeremonyUsers) member(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	ctx, svc, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	u, err := svc.GetUser(ctx, id)
	return c.confined(u, err, &qrdbtransport.UserNotFoundError{ID: id})
}

// GetUser reads a user of the tenant by ID.
func (c *CeremonyUsers) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	u, err := c.member(ctx, id)
	if err != nil {
		return nil, err
	}
	return wireUser(u), nil
}

// GetUserByEmail reads a user of the tenant by email.
func (c *CeremonyUsers) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	missing := &qrdbtransport.UserNotFoundError{Lookup: "email"}
	if tenantID != c.tenantID {
		return nil, missing
	}
	ctx, svc, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	found, err := svc.GetUserByEmail(ctx, tenantID, email)
	u, err := c.confined(found, err, missing)
	if err != nil {
		return nil, err
	}
	return wireUser(u), nil
}

// GetUserByUsername reads a user of the tenant by username.
func (c *CeremonyUsers) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	missing := &qrdbtransport.UserNotFoundError{Lookup: "username"}
	if tenantID != c.tenantID {
		return nil, missing
	}
	ctx, svc, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	found, err := svc.GetUserByUsername(ctx, tenantID, username)
	u, err := c.confined(found, err, missing)
	if err != nil {
		return nil, err
	}
	return wireUser(u), nil
}

// UpdateUser sets a tenant user's display name or activates its pending
// account; any other change goes to the authorized client.
func (c *CeremonyUsers) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if req == nil || !ceremonyUpdate(req) {
		return c.authorized.UpdateUser(ctx, req)
	}
	u, err := c.member(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if req.Lifecycle != "" && u.Lifecycle != qrdbsdk.LifecyclePending {
		return c.authorized.UpdateUser(ctx, req)
	}
	ctx, svc, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	updated, err := svc.UpdateUser(ctx, &qrdbsdk.UpdateUserRequest{
		ID:        req.ID,
		Name:      req.Name,
		Lifecycle: qrdbsdk.Lifecycle(req.Lifecycle),
	})
	if err != nil {
		return nil, err
	}
	return wireUser(updated), nil
}

// ceremonyUpdate reports whether req only sets the display name and/or
// activates the account.
func ceremonyUpdate(req *qrdbtransport.UpdateUserRequest) bool {
	if req.Username != "" || req.Email != "" || len(req.RoleIDs) > 0 || req.AuthMethods != nil ||
		req.LastAuth != "" || req.RoleBindings != nil || req.Attributes != nil {
		return false
	}
	if req.Lifecycle != "" && req.Lifecycle != string(qrdbsdk.LifecycleActive) {
		return false
	}
	return req.Name != "" || req.Lifecycle != ""
}

// AddCertBinding binds an invitation's certificate to a pending tenant user;
// any other binding goes to the authorized client.
func (c *CeremonyUsers) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	u, err := c.member(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.Lifecycle != qrdbsdk.LifecyclePending {
		return c.authorized.AddCertBinding(ctx, userID, thumbprint, notAfterUnix)
	}
	ctx, svc, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	bound, err := svc.AddCertBinding(ctx, userID, thumbprint, notAfterUnix)
	if err != nil {
		return nil, err
	}
	return wireUser(bound), nil
}

// CreateUser keeps the authorized client's authorization.
func (c *CeremonyUsers) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return c.authorized.CreateUser(ctx, req)
}

// GetUserByCertThumbprint keeps the authorized client's authorization.
func (c *CeremonyUsers) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return c.authorized.GetUserByCertThumbprint(ctx, thumbprint)
}

// RemoveCertBinding keeps the authorized client's authorization.
func (c *CeremonyUsers) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return c.authorized.RemoveCertBinding(ctx, userID, thumbprint)
}

// DeleteUser keeps the authorized client's authorization.
func (c *CeremonyUsers) DeleteUser(ctx context.Context, id uint64) error {
	return c.authorized.DeleteUser(ctx, id)
}

// ListUsers keeps the authorized client's authorization.
func (c *CeremonyUsers) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return c.authorized.ListUsers(ctx, req)
}

// EnableUser keeps the authorized client's authorization.
func (c *CeremonyUsers) EnableUser(ctx context.Context, id uint64) error {
	return c.authorized.EnableUser(ctx, id)
}

// DisableUser keeps the authorized client's authorization.
func (c *CeremonyUsers) DisableUser(ctx context.Context, id uint64) error {
	return c.authorized.DisableUser(ctx, id)
}

// SuspendUser keeps the authorized client's authorization.
func (c *CeremonyUsers) SuspendUser(ctx context.Context, id uint64) error {
	return c.authorized.SuspendUser(ctx, id)
}

// UnsuspendUser keeps the authorized client's authorization.
func (c *CeremonyUsers) UnsuspendUser(ctx context.Context, id uint64) error {
	return c.authorized.UnsuspendUser(ctx, id)
}

// wireUser projects a node user onto the client's wire form.
func wireUser(u *qrdbsdk.User) *qrdbtransport.User {
	if u == nil {
		return nil
	}
	out := &qrdbtransport.User{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		Name:         u.Name,
		TenantID:     u.TenantID,
		RoleIDs:      append([]string(nil), u.RoleIDs...),
		System:       u.System,
		Lifecycle:    string(u.Lifecycle),
		AuthMethods:  append([]string(nil), u.AuthMethods...),
		CertBindings: qrdbuser.WireCertBindings(u.CertBindings),
		RoleBindings: qrdbuser.WireRoleBindings(u.RoleBindings),
	}
	if u.LastAuth != nil {
		out.LastAuth = u.LastAuth.UTC().Format(time.RFC3339)
	}
	if len(u.Attributes) > 0 {
		out.Attributes = make(map[string]string, len(u.Attributes))
		for k, v := range u.Attributes {
			out.Attributes[k] = v
		}
	}
	return out
}
