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
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestTenantClient_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":     "tenant-1",
			"name":   "Test Tenant",
			"status": "active",
		})
		c := newTenantClient(mt)

		result, err := c.Create(context.Background(), &CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Test Tenant",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-1" {
			t.Errorf("expected ID tenant-1, got %s", result.ID)
		}
		if result.Name != "Test Tenant" {
			t.Errorf("expected name Test Tenant, got %s", result.Name)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantClient(mt)

		_, err := c.Create(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestConnRefused)
		c := newTenantClient(mt)

		_, err := c.Create(context.Background(), &CreateTenantRequest{
			ID:   "tenant-1",
			Name: "Test Tenant",
		})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestTenantClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":     "tenant-1",
			"name":   "Test Tenant",
			"status": "active",
		})
		c := newTenantClient(mt)

		result, err := c.Get(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "tenant-1" {
			t.Errorf("expected ID tenant-1, got %s", result.ID)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantClient(mt)

		_, err := c.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestNotFound)
		c := newTenantClient(mt)

		_, err := c.Get(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestTenantClient_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":     "tenant-1",
			"name":   "Updated Tenant",
			"status": "active",
		})
		c := newTenantClient(mt)

		result, err := c.Update(context.Background(), "tenant-1", &UpdateTenantRequest{
			Name: "Updated Tenant",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "Updated Tenant" {
			t.Errorf("expected name Updated Tenant, got %s", result.Name)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantClient(mt)

		_, err := c.Update(context.Background(), "", &UpdateTenantRequest{Name: "x"})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantClient(mt)

		_, err := c.Update(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestTenantClient_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newTenantClient(mt)

		err := c.Delete(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantClient(mt)

		err := c.Delete(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestForbidden)
		c := newTenantClient(mt)

		err := c.Delete(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestTenantClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"tenants": []map[string]interface{}{
				{"id": "tenant-1", "name": "Tenant One", "status": "active"},
				{"id": "tenant-2", "name": "Tenant Two", "status": "active"},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		})
		c := newTenantClient(mt)

		result, err := c.List(context.Background(), &ListTenantsRequest{Page: 1, PerPage: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Tenants) != 2 {
			t.Errorf("expected 2 tenants, got %d", len(result.Tenants))
		}
		if result.Pagination == nil {
			t.Fatal("expected pagination to be present")
		}
		if result.Pagination.Total != 2 {
			t.Errorf("expected total 2, got %d", result.Pagination.Total)
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"tenants": []map[string]interface{}{},
		})
		c := newTenantClient(mt)

		result, err := c.List(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Tenants == nil {
			t.Error("expected non-nil tenants slice")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newTenantClient(mt)

		_, err := c.List(context.Background(), &ListTenantsRequest{})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}
