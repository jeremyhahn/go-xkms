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
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestMapResponse(t *testing.T) {
	t.Run("success from map", func(t *testing.T) {
		raw := map[string]interface{}{
			"id":     "tenant-1",
			"name":   "Test Tenant",
			"status": "active",
		}

		var result TenantInfo
		if err := mapResponse(raw, &result); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-1" {
			t.Errorf("expected ID tenant-1, got %s", result.ID)
		}
		if result.Name != "Test Tenant" {
			t.Errorf("expected name Test Tenant, got %s", result.Name)
		}
	})

	t.Run("success with Data wrapper", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data": map[string]interface{}{
				"id":     "tenant-2",
				"name":   "Wrapped Tenant",
				"status": "active",
			},
		}

		var result TenantInfo
		if err := mapResponse(raw, &result); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-2" {
			t.Errorf("expected ID tenant-2, got %s", result.ID)
		}
	})

	t.Run("nil raw returns error", func(t *testing.T) {
		var result TenantInfo
		err := mapResponse(nil, &result)
		if err == nil {
			t.Fatal("expected error for nil raw")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})

	t.Run("struct response marshals correctly", func(t *testing.T) {
		type response struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		raw := &response{
			ID:     "tenant-3",
			Name:   "Struct Tenant",
			Status: "active",
		}

		var result TenantInfo
		if err := mapResponse(raw, &result); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-3" {
			t.Errorf("expected ID tenant-3, got %s", result.ID)
		}
	})

	t.Run("Data field as non-map is treated as wrapper", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data":   "not-a-map",
			"id":     "tenant-4",
			"name":   "Non-map Data",
			"status": "active",
		}

		var result TenantInfo
		if err := mapResponse(raw, &result); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-4" {
			t.Errorf("expected ID tenant-4, got %s", result.ID)
		}
	})
}

func TestMapListResponse(t *testing.T) {
	t.Run("success with pagination", func(t *testing.T) {
		raw := map[string]interface{}{
			"tenants": []map[string]interface{}{
				{"id": "t-1", "name": "One", "status": "active"},
				{"id": "t-2", "name": "Two", "status": "active"},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		}

		var tenants []*TenantInfo
		var pagination *Pagination
		if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tenants) != 2 {
			t.Errorf("expected 2 tenants, got %d", len(tenants))
		}
		if pagination == nil {
			t.Fatal("expected pagination to be present")
		}
		if pagination.Total != 2 {
			t.Errorf("expected total 2, got %d", pagination.Total)
		}
	})

	t.Run("success without pagination", func(t *testing.T) {
		raw := map[string]interface{}{
			"tenants": []map[string]interface{}{
				{"id": "t-1", "name": "One", "status": "active"},
			},
		}

		var tenants []*TenantInfo
		var pagination *Pagination
		if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tenants) != 1 {
			t.Errorf("expected 1 tenant, got %d", len(tenants))
		}
		if pagination != nil {
			t.Error("expected nil pagination when not in response")
		}
	})

	t.Run("nil raw returns error", func(t *testing.T) {
		var tenants []*TenantInfo
		var pagination *Pagination
		err := mapListResponse(nil, "tenants", &tenants, &pagination)
		if err == nil {
			t.Fatal("expected error for nil raw")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})

	t.Run("nil pagination pointer is safe", func(t *testing.T) {
		raw := map[string]interface{}{
			"items": []map[string]interface{}{},
		}

		var items []*TenantInfo
		if err := mapListResponse(raw, "items", &items, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing items key returns empty slice", func(t *testing.T) {
		raw := map[string]interface{}{
			"other_key": "value",
		}

		var tenants []*TenantInfo
		if err := mapListResponse(raw, "tenants", &tenants, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tenants != nil {
			t.Errorf("expected nil tenants for missing key, got %v", tenants)
		}
	})

	t.Run("with Data wrapper", func(t *testing.T) {
		raw := map[string]interface{}{
			"Data": map[string]interface{}{
				"tenants": []map[string]interface{}{
					{"id": "t-1", "name": "Wrapped", "status": "active"},
				},
				"pagination": map[string]interface{}{
					"page": 1, "per_page": 10, "total": 1,
				},
			},
		}

		var tenants []*TenantInfo
		var pagination *Pagination
		if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tenants) != 1 {
			t.Errorf("expected 1 tenant, got %d", len(tenants))
		}
		if pagination == nil {
			t.Fatal("expected pagination to be present")
		}
	})

	t.Run("struct response marshals correctly", func(t *testing.T) {
		type listResponse struct {
			Tenants    []map[string]interface{} `json:"tenants"`
			Pagination map[string]interface{}   `json:"pagination"`
		}
		raw := &listResponse{
			Tenants: []map[string]interface{}{
				{"id": "t-1", "name": "Struct List", "status": "active"},
			},
			Pagination: map[string]interface{}{
				"page": 1, "per_page": 10, "total": 1,
			},
		}

		var tenants []*TenantInfo
		var pagination *Pagination
		if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tenants) != 1 {
			t.Errorf("expected 1 tenant, got %d", len(tenants))
		}
	})

	t.Run("nil pagination value in data", func(t *testing.T) {
		raw := map[string]interface{}{
			"tenants":    []map[string]interface{}{},
			"pagination": nil,
		}

		var tenants []*TenantInfo
		var pagination *Pagination
		if err := mapListResponse(raw, "tenants", &tenants, &pagination); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pagination != nil {
			t.Error("expected nil pagination for nil value")
		}
	})
}
