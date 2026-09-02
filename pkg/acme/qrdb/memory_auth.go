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

package qrdb

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

var (
	errRoleNotFound = errors.New("qrdb: role not found")
	errUserNotFound = errors.New("qrdb: user not found")
)

// memoryRoleClient is an in-memory RoleClient implementation.
type memoryRoleClient struct {
	mu     sync.RWMutex
	roles  map[string]*db.Role
	nextID atomic.Uint64
}

func newMemoryRoleClient() *memoryRoleClient {
	return &memoryRoleClient{
		roles: make(map[string]*db.Role),
	}
}

func (c *memoryRoleClient) CreateRole(_ context.Context, req *db.CreateRoleRequest) (*db.Role, error) {
	id := c.nextID.Add(1)
	now := time.Now().UTC().Format(time.RFC3339)
	role := &db.Role{
		ID:          "role-" + strconv.FormatUint(id, 10),
		Name:        req.Name,
		TenantID:    req.TenantID,
		Permissions: req.Permissions,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	c.mu.Lock()
	c.roles[role.ID] = role
	c.mu.Unlock()
	return role, nil
}

func (c *memoryRoleClient) GetRole(_ context.Context, id string) (*db.Role, error) {
	c.mu.RLock()
	role, ok := c.roles[id]
	c.mu.RUnlock()
	if !ok {
		return nil, errRoleNotFound
	}
	return role, nil
}

func (c *memoryRoleClient) UpdateRole(_ context.Context, req *db.UpdateRoleRequest) (*db.Role, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	role, ok := c.roles[req.ID]
	if !ok {
		return nil, errRoleNotFound
	}
	if req.Name != "" {
		role.Name = req.Name
	}
	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}
	role.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return role, nil
}

func (c *memoryRoleClient) DeleteRole(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.roles[id]; !ok {
		return errRoleNotFound
	}
	delete(c.roles, id)
	return nil
}

func (c *memoryRoleClient) ListRoles(_ context.Context, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var roles []*db.Role
	for _, r := range c.roles {
		if req.TenantID == "" || r.TenantID == req.TenantID {
			roles = append(roles, r)
		}
	}
	return &db.ListRolesResponse{
		Roles: roles,
		Total: len(roles),
	}, nil
}

func (c *memoryRoleClient) AssignRole(_ context.Context, _ uint64, _ string) error   { return nil }
func (c *memoryRoleClient) UnassignRole(_ context.Context, _ uint64, _ string) error { return nil }

func (c *memoryRoleClient) ListPermissions(_ context.Context) (*db.ListPermissionsResponse, error) {
	return &db.ListPermissionsResponse{}, nil
}

// memoryUserClient is an in-memory UserClient implementation.
type memoryUserClient struct {
	mu     sync.RWMutex
	users  map[uint64]*db.User
	nextID atomic.Uint64
}

func newMemoryUserClient() *memoryUserClient {
	return &memoryUserClient{
		users: make(map[uint64]*db.User),
	}
}

func (c *memoryUserClient) CreateUser(_ context.Context, req *db.CreateUserRequest) (*db.User, error) {
	id := c.nextID.Add(1)
	now := time.Now().UTC().Format(time.RFC3339)
	user := &db.User{
		ID:        id,
		Username:  req.Username,
		Email:     qrdbsdk.NormalizeEmail(req.Email),
		Name:      req.Name,
		TenantID:  req.TenantID,
		RoleIDs:   req.RoleIDs,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	c.mu.Lock()
	c.users[user.ID] = user
	c.mu.Unlock()
	return user, nil
}

func (c *memoryUserClient) GetUser(_ context.Context, id uint64) (*db.User, error) {
	c.mu.RLock()
	user, ok := c.users[id]
	c.mu.RUnlock()
	if !ok {
		return nil, errUserNotFound
	}
	return user, nil
}

func (c *memoryUserClient) GetUserByUsername(_ context.Context, tenantID, username string) (*db.User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, user := range c.users {
		if user.Username != username {
			continue
		}
		if tenantID != "" && user.TenantID != tenantID {
			continue
		}
		return user, nil
	}
	return nil, errUserNotFound
}

// GetUserByEmail resolves the canonical tenant-scoped login key. It mirrors
// the real store: normalized comparison, and a tenant mismatch is a miss rather
// than a match — a double that skipped either would accept lookups the store
// refuses.
func (c *memoryUserClient) GetUserByEmail(_ context.Context, tenantID, email string) (*db.User, error) {
	normalized := qrdbsdk.NormalizeEmail(email)
	if normalized == "" {
		return nil, errUserNotFound
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, user := range c.users {
		if user.Email != normalized {
			continue
		}
		if tenantID != "" && user.TenantID != tenantID {
			continue
		}
		return user, nil
	}
	return nil, errUserNotFound
}

// GetUserByCertThumbprint satisfies the transport.UserClient contract. This
// in-memory test client does not track mTLS cert bindings (the transport-layer
// User carries no binding data), so it reports no match — the ACME tests that
// use this client authenticate by username, not by cert thumbprint.
func (c *memoryUserClient) GetUserByCertThumbprint(_ context.Context, _ string) (*db.User, error) {
	return nil, errUserNotFound
}

func (c *memoryUserClient) UpdateUser(_ context.Context, req *db.UpdateUserRequest) (*db.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	user, ok := c.users[req.ID]
	if !ok {
		return nil, errUserNotFound
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.RoleIDs != nil {
		user.RoleIDs = req.RoleIDs
	}
	user.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return user, nil
}

func (c *memoryUserClient) DeleteUser(_ context.Context, id uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.users[id]; !ok {
		return errUserNotFound
	}
	delete(c.users, id)
	return nil
}

func (c *memoryUserClient) ListUsers(_ context.Context, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var users []*db.User
	for _, u := range c.users {
		if req.TenantID == "" || u.TenantID == req.TenantID {
			users = append(users, u)
		}
	}
	return &db.ListUsersResponse{
		Users: users,
		Total: len(users),
	}, nil
}

func (c *memoryUserClient) EnableUser(_ context.Context, id uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	user, ok := c.users[id]
	if !ok {
		return errUserNotFound
	}
	user.Enabled = true
	return nil
}

func (c *memoryUserClient) DisableUser(_ context.Context, id uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	user, ok := c.users[id]
	if !ok {
		return errUserNotFound
	}
	user.Enabled = false
	return nil
}

// AddCertBinding satisfies the transport.UserClient contract. This in-memory
// test client does not track mTLS cert bindings (the transport-layer User
// carries no binding data), so it simply returns the resolved user — the ACME
// tests that use this client authenticate by username, not by cert thumbprint.
func (c *memoryUserClient) AddCertBinding(_ context.Context, userID uint64, _ string, _ int64) (*db.User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	user, ok := c.users[userID]
	if !ok {
		return nil, errUserNotFound
	}
	return user, nil
}
