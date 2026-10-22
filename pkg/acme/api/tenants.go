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

package api

import (
	"net/url"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
)

// TenantsPath is the core xkms tenant collection. The core module owns the
// tenant lifecycle (create, list, get, delete) under it; the admin module
// only adds update and status beneath the same prefix (go-xkms#794).
const TenantsPath = "/api/v1/tenants/"

// TenantEnvelope is the core tenant routes' single-tenant body.
type TenantEnvelope struct {
	Tenant admin.TenantInfo `json:"tenant"`
}

// TenantListEnvelope is the core tenant list body.
type TenantListEnvelope struct {
	Tenants    []*admin.TenantInfo `json:"tenants"`
	Pagination TenantListPage      `json:"pagination"`
}

// TenantListPage is the pagination block of a TenantListEnvelope.
type TenantListPage struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// AdminPagination converts the core pagination block to the admin shape.
func (p TenantListPage) AdminPagination() *admin.Pagination {
	return &admin.Pagination{Page: p.Page, PerPage: p.PageSize, Total: p.Total}
}

// TenantPath is the core path of one tenant.
func TenantPath(tenantID string) string {
	return TenantsPath + url.PathEscape(tenantID)
}

// TenantListPath is the core tenant list path for req: page and page_size,
// and the status filter when req names one.
func TenantListPath(req *admin.ListTenantsRequest) string {
	query := url.Values{}
	query.Set("page", strconv.Itoa(req.Page))
	query.Set("page_size", strconv.Itoa(req.PerPage))
	if req.Status != "" {
		query.Set("status", req.Status)
	}
	return TenantsPath + "?" + query.Encode()
}
