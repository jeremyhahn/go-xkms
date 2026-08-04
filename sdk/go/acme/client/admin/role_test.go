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

func TestRoleClient_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":          "role-1",
			"name":        "admin",
			"tenantID":    "tenant-1",
			"permissions": []string{"read", "write"},
		})
		c := newRoleClient(mt)

		result, err := c.Create(context.Background(), "tenant-1", &CreateRoleRequest{
			Name:        "admin",
			Permissions: []string{"read", "write"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "role-1" {
			t.Errorf("expected ID role-1, got %s", result.ID)
		}
		if result.Name != "admin" {
			t.Errorf("expected name admin, got %s", result.Name)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Create(context.Background(), "", &CreateRoleRequest{Name: "admin"})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestServerError)
		c := newRoleClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", &CreateRoleRequest{Name: "admin"})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestRoleClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":       "role-1",
			"name":     "admin",
			"tenantID": "tenant-1",
		})
		c := newRoleClient(mt)

		result, err := c.Get(context.Background(), "tenant-1", "role-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "role-1" {
			t.Errorf("expected ID role-1, got %s", result.ID)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Get(context.Background(), "", "role-1")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty role ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Get(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty role ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestRoleClient_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":          "role-1",
			"name":        "super-admin",
			"tenantID":    "tenant-1",
			"permissions": []string{"read", "write", "delete"},
		})
		c := newRoleClient(mt)

		result, err := c.Update(context.Background(), "tenant-1", &UpdateRoleRequest{
			ID:          "role-1",
			Name:        "super-admin",
			Permissions: []string{"read", "write", "delete"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "super-admin" {
			t.Errorf("expected name super-admin, got %s", result.Name)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Update(context.Background(), "", &UpdateRoleRequest{ID: "role-1"})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.Update(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestRoleClient_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newRoleClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "role-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		err := c.Delete(context.Background(), "", "role-1")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
	})

	t.Run("empty role ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty role ID")
		}
	})
}

func TestRoleClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"roles": []map[string]interface{}{
				{"id": "role-1", "name": "admin", "tenantID": "tenant-1"},
				{"id": "role-2", "name": "viewer", "tenantID": "tenant-1"},
			},
			"total":   2,
			"hasMore": false,
		})
		c := newRoleClient(mt)

		result, err := c.List(context.Background(), "tenant-1", &ListRolesRequest{Page: 1, PageSize: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(result.Roles))
		}
		if result.Total != 2 {
			t.Errorf("expected total 2, got %d", result.Total)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newRoleClient(mt)

		_, err := c.List(context.Background(), "", &ListRolesRequest{})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"roles":   []map[string]interface{}{},
			"total":   0,
			"hasMore": false,
		})
		c := newRoleClient(mt)

		result, err := c.List(context.Background(), "tenant-1", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Total != 0 {
			t.Errorf("expected total 0, got %d", result.Total)
		}
	})
}
