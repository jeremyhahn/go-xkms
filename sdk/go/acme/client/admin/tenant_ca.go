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

const tenantCAService = "admin.tenant.ca"

// TenantCAClient provides tenant CA hierarchy management operations.
type TenantCAClient interface {
	// CreateRootCA creates a root CA for a tenant.
	CreateRootCA(ctx context.Context, tenantID string, req *CreateTenantRootCARequest) (*TenantRootCAInfo, error)

	// CAStatus retrieves the CA status for a tenant.
	CAStatus(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error)

	// CreateIntermediateCA creates an intermediate CA for a tenant.
	CreateIntermediateCA(ctx context.Context, tenantID string, req *CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error)

	// ListIntermediateCAs lists all intermediate CAs for a tenant.
	ListIntermediateCAs(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error)

	// GetIntermediateCA retrieves a specific intermediate CA.
	GetIntermediateCA(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error)

	// UpdateIntermediateCAStatus updates an intermediate CA's status.
	UpdateIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error

	// UpdateTenantStatus is refused with ErrTenantStatusUnsupported, and sends
	// no request, until go-qrdb carries a tenant status (SPEC.md:129).
	UpdateTenantStatus(ctx context.Context, tenantID string, status string) error
}

type tenantCAClient struct {
	transport transport.Transport
}

func newTenantCAClient(t transport.Transport) TenantCAClient {
	return &tenantCAClient{transport: t}
}

// createRootCATransportRequest wraps the tenant ID with the root CA request payload.
type createRootCATransportRequest struct {
	TenantID      string `json:"tenantId"`
	CommonName    string `json:"common_name"`
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
}

// tenantCAStatusRequest wraps a tenant ID for CA status queries.
type tenantCAStatusRequest struct {
	TenantID string `json:"tenantId"`
}

// createIntermediateCATransportRequest wraps the tenant ID with the intermediate CA request payload.
type createIntermediateCATransportRequest struct {
	TenantID      string `json:"tenantId"`
	CommonName    string `json:"common_name"`
	ParentType    string `json:"parent_type"`
	Purpose       string `json:"purpose,omitempty"`
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
	SetAsDefault  bool   `json:"set_as_default,omitempty"`
}

// intermediateCARequest wraps a tenant ID and CA ID for intermediate CA queries.
type intermediateCARequest struct {
	TenantID string `json:"tenantId"`
	CAID     string `json:"caId"`
}

// updateIntermediateCAStatusTransportRequest wraps the tenant ID, CA ID, and status.
type updateIntermediateCAStatusTransportRequest struct {
	TenantID string `json:"tenantId"`
	CAID     string `json:"caId"`
	Status   string `json:"status"`
}

func (c *tenantCAClient) CreateRootCA(ctx context.Context, tenantID string, req *CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.CreateRootCA", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.tenant.ca.CreateRootCA", "request cannot be nil")
	}

	transportReq := &createRootCATransportRequest{
		TenantID:      tenantID,
		CommonName:    req.CommonName,
		KeyAlgorithm:  req.KeyAlgorithm,
		ValidityYears: req.ValidityYears,
	}

	raw, err := c.transport.Request(ctx, tenantCAService, "createRootCA", transportReq)
	if err != nil {
		return nil, err
	}

	var result TenantRootCAInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *tenantCAClient) CAStatus(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.CAStatus", "tenant ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, tenantCAService, "status", &tenantCAStatusRequest{TenantID: tenantID})
	if err != nil {
		return nil, err
	}

	var result TenantCAStatusInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *tenantCAClient) CreateIntermediateCA(ctx context.Context, tenantID string, req *CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.CreateIntermediateCA", "tenant ID cannot be empty")
	}
	if req == nil {
		return nil, errors.NewInvalidInput("admin.tenant.ca.CreateIntermediateCA", "request cannot be nil")
	}

	transportReq := &createIntermediateCATransportRequest{
		TenantID:      tenantID,
		CommonName:    req.CommonName,
		ParentType:    req.ParentType,
		Purpose:       req.Purpose,
		KeyAlgorithm:  req.KeyAlgorithm,
		ValidityYears: req.ValidityYears,
		SetAsDefault:  req.SetAsDefault,
	}

	raw, err := c.transport.Request(ctx, tenantCAService, "createIntermediateCA", transportReq)
	if err != nil {
		return nil, err
	}

	var result TenantIntCAInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *tenantCAClient) ListIntermediateCAs(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.ListIntermediateCAs", "tenant ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, tenantCAService, "listIntermediateCAs", &tenantCAStatusRequest{TenantID: tenantID})
	if err != nil {
		return nil, err
	}

	var cas []*TenantIntCAInfo
	if err := mapListResponse(raw, "intermediate_cas", &cas, nil); err != nil {
		return nil, err
	}
	return cas, nil
}

func (c *tenantCAClient) GetIntermediateCA(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.GetIntermediateCA", "tenant ID cannot be empty")
	}
	if caID == "" {
		return nil, errors.NewInvalidInput("admin.tenant.ca.GetIntermediateCA", "CA ID cannot be empty")
	}

	raw, err := c.transport.Request(ctx, tenantCAService, "getIntermediateCA", &intermediateCARequest{
		TenantID: tenantID,
		CAID:     caID,
	})
	if err != nil {
		return nil, err
	}

	var result TenantIntCAInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *tenantCAClient) UpdateIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.tenant.ca.UpdateIntermediateCAStatus", "tenant ID cannot be empty")
	}
	if caID == "" {
		return errors.NewInvalidInput("admin.tenant.ca.UpdateIntermediateCAStatus", "CA ID cannot be empty")
	}
	if status == "" {
		return errors.NewInvalidInput("admin.tenant.ca.UpdateIntermediateCAStatus", "status cannot be empty")
	}

	_, err := c.transport.Request(ctx, tenantCAService, "updateIntermediateCAStatus", &updateIntermediateCAStatusTransportRequest{
		TenantID: tenantID,
		CAID:     caID,
		Status:   status,
	})
	return err
}

func (c *tenantCAClient) UpdateTenantStatus(_ context.Context, tenantID string, _ string) error {
	if tenantID == "" {
		return errors.NewInvalidInput("admin.tenant.ca.UpdateTenantStatus", "tenant ID cannot be empty")
	}
	return NewTenantStatusUnsupported("admin.tenant.ca.UpdateTenantStatus")
}
