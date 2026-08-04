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

package admin

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const roleService = "admin.role"

// RoleClient provides tenant role management operations.
type RoleClient interface {
	// Create creates a new role within a tenant.
	Create(ctx context.Context, tenantID string, req *CreateRoleRequest) (*Role, error)

	// Get retrieves a role by tenant ID and role ID.
	Get(ctx context.Context, tenantID, roleID string) (*Role, error)

	// Update updates an existing role.
	Update(ctx context.Context, tenantID string, req *UpdateRoleRequest) (*Role, error)

	// Delete deletes a role.
	Delete(ctx context.Context, tenantID, roleID string) error

	// List lists roles for a tenant.
	List(ctx context.Context, tenantID string, req *ListRolesRequest) (*ListRolesResponse, error)
}

type roleClient struct {
	transport transport.Transport
}

func newRoleClient(t transport.Transport) RoleClient {
	return &roleClient{transport: t}
}

// createRoleTransportRequest wraps the tenant ID with the create payload.
type createRoleTransportRequest struct {
	TenantID    string   `json:"tenantId"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// roleIDRequest wraps tenant ID and role ID for transport serialization.
type roleIDRequest struct {
	TenantID string `json:"tenantId"`
	RoleID   string `json:"roleId"`
}

// updateRoleTransportRequest wraps the tenant ID with the update payload.
type updateRoleTransportRequest struct {
	TenantID    string   `json:"tenantId"`
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// listRolesTransportRequest wraps the tenant ID with the list payload.
type listRolesTransportRequest struct {
	TenantID string `json:"tenantId"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

func (c *roleClient) Create(ctx context.Context, tenantID string, req *CreateRoleRequest) (*Role, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.role.Create", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.role.Create", "request cannot be nil")
	}

	transportReq := &createRoleTransportRequest{
		TenantID:    tenantID,
		Name:        req.Name,
		Permissions: req.Permissions,
	}

	raw, err := c.transport.Request(ctx, roleService, "create", transportReq)
	if err != nil {
		return nil, err
	}

	var result Role
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *roleClient) Get(ctx context.Context, tenantID, roleID string) (*Role, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.role.Get", "tenant ID cannot be empty")
	}
	if roleID == "" {
		return nil, errors.NewInvalidInput("admin.role.Get", "role ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, roleService, "get", &roleIDRequest{
		TenantID: tenantID,
		RoleID:   roleID,
	})
	if err != nil {
		return nil, err
	}

	var result Role
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *roleClient) Update(ctx context.Context, tenantID string, req *UpdateRoleRequest) (*Role, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.role.Update", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.role.Update", "request cannot be nil")
	}

	transportReq := &updateRoleTransportRequest{
		TenantID:    tenantID,
		ID:          req.ID,
		Name:        req.Name,
		Permissions: req.Permissions,
	}

	raw, err := c.transport.Request(ctx, roleService, "update", transportReq)
	if err != nil {
		return nil, err
	}

	var result Role
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *roleClient) Delete(ctx context.Context, tenantID, roleID string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.role.Delete", "tenant ID cannot be empty")
	}
	if roleID == "" {
		return errors.NewInvalidInput("admin.role.Delete", "role ID cannot be empty")
	}

	_, err := c.transport.Request(ctx, roleService, "delete", &roleIDRequest{
		TenantID: tenantID,
		RoleID:   roleID,
	})
	return err
}

func (c *roleClient) List(ctx context.Context, tenantID string, req *ListRolesRequest) (*ListRolesResponse, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.role.List", "tenant ID cannot be empty")
	}
	if req == nil {
		req = &ListRolesRequest{}
	}

	transportReq := &listRolesTransportRequest{
		TenantID: tenantID,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	raw, err := c.transport.Request(ctx, roleService, "list", transportReq)
	if err != nil {
		return nil, err
	}

	var result ListRolesResponse
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
