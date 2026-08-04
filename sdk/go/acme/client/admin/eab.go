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

const eabService = "admin.eab"

// EABClient provides External Account Binding management operations.
type EABClient interface {
	// Create creates a new EAB for a tenant.
	Create(ctx context.Context, tenantID string, req *CreateEABRequest) (*CreateEABResponse, error)

	// Get retrieves an EAB by tenant ID and key ID.
	Get(ctx context.Context, tenantID, kid string) (*EABInfo, error)

	// Delete deletes an EAB.
	Delete(ctx context.Context, tenantID, kid string) error

	// List lists EABs for a tenant with optional filtering.
	List(ctx context.Context, tenantID string, req *ListEABRequest) (*ListEABResponse, error)
}

type eabClient struct {
	transport transport.Transport
}

func newEABClient(t transport.Transport) EABClient {
	return &eabClient{transport: t}
}

// createEABTransportRequest wraps the tenant ID with the create payload.
type createEABTransportRequest struct {
	TenantID          string            `json:"tenantId"`
	Purpose           string            `json:"purpose,omitempty"`
	ExternalAccountID string            `json:"external_account_id,omitempty"`
	DeviceInfo        *EABDeviceInfo    `json:"device_info,omitempty"`
	Contact           []string          `json:"contact,omitempty"`
	ExpiresInDays     int               `json:"expires_in_days,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// eabIDRequest wraps tenant ID and key ID for transport serialization.
type eabIDRequest struct {
	TenantID string `json:"tenantId"`
	KID      string `json:"kid"`
}

// listEABTransportRequest wraps the tenant ID with the list payload.
type listEABTransportRequest struct {
	TenantID string `json:"tenantId"`
	Page     int    `json:"page,omitempty"`
	PerPage  int    `json:"per_page,omitempty"`
	Status   string `json:"status,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
}

func (c *eabClient) Create(ctx context.Context, tenantID string, req *CreateEABRequest) (*CreateEABResponse, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.eab.Create", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.eab.Create", "request cannot be nil")
	}

	transportReq := &createEABTransportRequest{
		TenantID:          tenantID,
		Purpose:           req.Purpose,
		ExternalAccountID: req.ExternalAccountID,
		DeviceInfo:        req.DeviceInfo,
		Contact:           req.Contact,
		ExpiresInDays:     req.ExpiresInDays,
		Metadata:          req.Metadata,
	}

	raw, err := c.transport.Request(ctx, eabService, "create", transportReq)
	if err != nil {
		return nil, err
	}

	var result CreateEABResponse
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *eabClient) Get(ctx context.Context, tenantID, kid string) (*EABInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.eab.Get", "tenant ID cannot be empty")
	}
	if kid == "" {
		return nil, errors.NewInvalidInput("admin.eab.Get", "key ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, eabService, "get", &eabIDRequest{
		TenantID: tenantID,
		KID:      kid,
	})
	if err != nil {
		return nil, err
	}

	var result EABInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *eabClient) Delete(ctx context.Context, tenantID, kid string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.eab.Delete", "tenant ID cannot be empty")
	}
	if kid == "" {
		return errors.NewInvalidInput("admin.eab.Delete", "key ID cannot be empty")
	}

	_, err := c.transport.Request(ctx, eabService, "delete", &eabIDRequest{
		TenantID: tenantID,
		KID:      kid,
	})
	return err
}

func (c *eabClient) List(ctx context.Context, tenantID string, req *ListEABRequest) (*ListEABResponse, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.eab.List", "tenant ID cannot be empty")
	}
	if req == nil {
		req = &ListEABRequest{}
	}

	transportReq := &listEABTransportRequest{
		TenantID: tenantID,
		Page:     req.Page,
		PerPage:  req.PerPage,
		Status:   req.Status,
		Purpose:  req.Purpose,
	}

	raw, err := c.transport.Request(ctx, eabService, "list", transportReq)
	if err != nil {
		return nil, err
	}

	var eabs []*EABInfo
	var pagination *Pagination
	if err := mapListResponse(raw, "eabs", &eabs, &pagination); err != nil {
		return nil, err
	}

	return &ListEABResponse{
		EABs:       eabs,
		Pagination: pagination,
	}, nil
}
