// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const userService = "admin.user"

// UserClient provides tenant user management operations.
type UserClient interface {
	// Create creates a new user within a tenant.
	Create(ctx context.Context, tenantID string, req *CreateUserRequest) (*User, error)

	// Get retrieves a user by tenant ID and user ID.
	Get(ctx context.Context, tenantID, userID string) (*User, error)

	// Update updates an existing user.
	Update(ctx context.Context, tenantID string, req *UpdateUserRequest) (*User, error)

	// Delete deletes a user.
	Delete(ctx context.Context, tenantID, userID string) error

	// List lists users for a tenant.
	List(ctx context.Context, tenantID string, req *ListUsersRequest) (*ListUsersResponse, error)
}

type userClient struct {
	transport transport.Transport
}

func newUserClient(t transport.Transport) UserClient {
	return &userClient{transport: t}
}

// createUserTransportRequest wraps the tenant ID with the create payload.
type createUserTransportRequest struct {
	TenantID string   `json:"tenantId"`
	Username string   `json:"username"`
	RoleIDs  []string `json:"roleIDs,omitempty"`
}

// userIDRequest wraps tenant ID and user ID for transport serialization.
type userIDRequest struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
}

// updateUserTransportRequest wraps the tenant ID with the update payload.
type updateUserTransportRequest struct {
	TenantID string   `json:"tenantId"`
	ID       string   `json:"id"`
	Username string   `json:"username,omitempty"`
	RoleIDs  []string `json:"roleIDs,omitempty"`
}

// listUsersTransportRequest wraps the tenant ID with the list payload.
type listUsersTransportRequest struct {
	TenantID string `json:"tenantId"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

func (c *userClient) Create(ctx context.Context, tenantID string, req *CreateUserRequest) (*User, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.user.Create", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.user.Create", "request cannot be nil")
	}

	transportReq := &createUserTransportRequest{
		TenantID: tenantID,
		Username: req.Username,
		RoleIDs:  req.RoleIDs,
	}

	raw, err := c.transport.Request(ctx, userService, "create", transportReq)
	if err != nil {
		return nil, err
	}

	var result User
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *userClient) Get(ctx context.Context, tenantID, userID string) (*User, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.user.Get", "tenant ID cannot be empty")
	}
	if userID == "" {
		return nil, errors.NewInvalidInput("admin.user.Get", "user ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, userService, "get", &userIDRequest{
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		return nil, err
	}

	var result User
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *userClient) Update(ctx context.Context, tenantID string, req *UpdateUserRequest) (*User, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.user.Update", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.user.Update", "request cannot be nil")
	}

	transportReq := &updateUserTransportRequest{
		TenantID: tenantID,
		ID:       req.ID,
		Username: req.Username,
		RoleIDs:  req.RoleIDs,
	}

	raw, err := c.transport.Request(ctx, userService, "update", transportReq)
	if err != nil {
		return nil, err
	}

	var result User
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *userClient) Delete(ctx context.Context, tenantID, userID string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.user.Delete", "tenant ID cannot be empty")
	}
	if userID == "" {
		return errors.NewInvalidInput("admin.user.Delete", "user ID cannot be empty")
	}

	_, err := c.transport.Request(ctx, userService, "delete", &userIDRequest{
		TenantID: tenantID,
		UserID:   userID,
	})
	return err
}

func (c *userClient) List(ctx context.Context, tenantID string, req *ListUsersRequest) (*ListUsersResponse, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.user.List", "tenant ID cannot be empty")
	}
	if req == nil {
		req = &ListUsersRequest{}
	}

	transportReq := &listUsersTransportRequest{
		TenantID: tenantID,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	raw, err := c.transport.Request(ctx, userService, "list", transportReq)
	if err != nil {
		return nil, err
	}

	var result ListUsersResponse
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
