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

const tenantService = "admin.tenant"

// TenantClient provides tenant management operations.
type TenantClient interface {
	// Create creates a new tenant.
	Create(ctx context.Context, req *CreateTenantRequest) (*TenantInfo, error)

	// Get retrieves a tenant by ID.
	Get(ctx context.Context, tenantID string) (*TenantInfo, error)

	// Update updates an existing tenant.
	Update(ctx context.Context, tenantID string, req *UpdateTenantRequest) (*TenantInfo, error)

	// Delete deletes a tenant.
	Delete(ctx context.Context, tenantID string) error

	// List lists tenants with optional filtering.
	List(ctx context.Context, req *ListTenantsRequest) (*ListTenantsResponse, error)
}

type tenantClient struct {
	transport transport.Transport
}

func newTenantClient(t transport.Transport) TenantClient {
	return &tenantClient{transport: t}
}

// tenantIDRequest wraps a tenant ID for transport serialization.
type tenantIDRequest struct {
	TenantID string `json:"tenantId"`
}

// tenantEnvelope is the core /api/v1/tenants body for one tenant. The HTTP
// transports reach the core routes and get the envelope; gRPC and MCP
// answer with the tenant itself.
type tenantEnvelope struct {
	Tenant *TenantInfo `json:"tenant"`
}

// mapTenantResponse decodes a single-tenant response in either shape.
func mapTenantResponse(raw interface{}) (*TenantInfo, error) {
	var envelope tenantEnvelope
	if err := mapResponse(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Tenant != nil {
		return envelope.Tenant, nil
	}

	var tenant TenantInfo
	if err := mapResponse(raw, &tenant); err != nil {
		return nil, err
	}
	return &tenant, nil
}

// updateTenantTransportRequest wraps the tenant ID with the update payload.
type updateTenantTransportRequest struct {
	TenantID string              `json:"tenantId"`
	Name     string              `json:"name,omitempty"`
	Settings *TenantSettingsInfo `json:"settings,omitempty"`
}

func (c *tenantClient) Create(ctx context.Context, req *CreateTenantRequest) (*TenantInfo, error) {
	if req == nil {
		return nil, errors.NewInvalidInput("admin.tenant.Create", "request cannot be nil")
	}

	raw, err := c.transport.Request(ctx, tenantService, "create", req)
	if err != nil {
		return nil, err
	}
	return mapTenantResponse(raw)
}

func (c *tenantClient) Get(ctx context.Context, tenantID string) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.Get", "tenant ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, tenantService, "get", &tenantIDRequest{TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	return mapTenantResponse(raw)
}

func (c *tenantClient) Update(ctx context.Context, tenantID string, req *UpdateTenantRequest) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.Update", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.tenant.Update", "request cannot be nil")
	}

	transportReq := &updateTenantTransportRequest{
		TenantID: tenantID,
		Name:     req.Name,
		Settings: req.Settings,
	}

	raw, err := c.transport.Request(ctx, tenantService, "update", transportReq)
	if err != nil {
		return nil, err
	}

	var result TenantInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *tenantClient) Delete(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.tenant.Delete", "tenant ID cannot be empty")
	}

	_, err := c.transport.Request(ctx, tenantService, "delete", &tenantIDRequest{TenantID: tenantID})
	return err
}

func (c *tenantClient) List(ctx context.Context, req *ListTenantsRequest) (*ListTenantsResponse, error) {
	if req == nil {
		req = &ListTenantsRequest{}
	}

	raw, err := c.transport.Request(ctx, tenantService, "list", req)
	if err != nil {
		return nil, err
	}

	var tenants []*TenantInfo
	var pagination *Pagination
	if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
		return nil, err
	}

	return &ListTenantsResponse{
		Tenants:    tenants,
		Pagination: pagination,
	}, nil
}
