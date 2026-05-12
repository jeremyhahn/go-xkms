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
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestUserClient_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":       "user-1",
			"username": "alice",
			"tenantID": "tenant-1",
			"enabled":  true,
		})
		c := newUserClient(mt)

		result, err := c.Create(context.Background(), "tenant-1", &CreateUserRequest{
			Username: "alice",
			RoleIDs:  []string{"role-1"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "user-1" {
			t.Errorf("expected ID user-1, got %s", result.ID)
		}
		if result.Username != "alice" {
			t.Errorf("expected username alice, got %s", result.Username)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Create(context.Background(), "", &CreateUserRequest{Username: "alice"})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("conflict"))
		c := newUserClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", &CreateUserRequest{Username: "alice"})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestUserClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":       "user-1",
			"username": "alice",
			"tenantID": "tenant-1",
			"enabled":  true,
		})
		c := newUserClient(mt)

		result, err := c.Get(context.Background(), "tenant-1", "user-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Username != "alice" {
			t.Errorf("expected username alice, got %s", result.Username)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Get(context.Background(), "", "user-1")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Get(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty user ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestUserClient_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":       "user-1",
			"username": "alice-updated",
			"tenantID": "tenant-1",
			"enabled":  true,
		})
		c := newUserClient(mt)

		result, err := c.Update(context.Background(), "tenant-1", &UpdateUserRequest{
			ID:       "user-1",
			Username: "alice-updated",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Username != "alice-updated" {
			t.Errorf("expected username alice-updated, got %s", result.Username)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Update(context.Background(), "", &UpdateUserRequest{ID: "user-1"})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.Update(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestUserClient_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newUserClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "user-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		err := c.Delete(context.Background(), "", "user-1")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
	})

	t.Run("empty user ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty user ID")
		}
	})
}

func TestUserClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"users": []map[string]interface{}{
				{"id": "user-1", "username": "alice", "tenantID": "tenant-1", "enabled": true},
				{"id": "user-2", "username": "bob", "tenantID": "tenant-1", "enabled": true},
			},
			"total":   2,
			"hasMore": false,
		})
		c := newUserClient(mt)

		result, err := c.List(context.Background(), "tenant-1", &ListUsersRequest{Page: 1, PageSize: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Users) != 2 {
			t.Errorf("expected 2 users, got %d", len(result.Users))
		}
		if result.Total != 2 {
			t.Errorf("expected total 2, got %d", result.Total)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newUserClient(mt)

		_, err := c.List(context.Background(), "", &ListUsersRequest{})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"users":   []map[string]interface{}{},
			"total":   0,
			"hasMore": false,
		})
		c := newUserClient(mt)

		result, err := c.List(context.Background(), "tenant-1", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Total != 0 {
			t.Errorf("expected total 0, got %d", result.Total)
		}
	})
}
