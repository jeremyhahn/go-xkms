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

func TestAdminAccountClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"accounts": []map[string]interface{}{
				{"id": 1, "status": "valid", "order_count": 5},
				{"id": 2, "status": "deactivated", "order_count": 0},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		})
		c := newAdminAccountClient(mt)

		result, err := c.List(context.Background(), &ListAccountsRequest{Page: 1, PerPage: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Accounts) != 2 {
			t.Errorf("expected 2 accounts, got %d", len(result.Accounts))
		}
		if result.Pagination == nil {
			t.Fatal("expected pagination to be present")
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"accounts": []map[string]interface{}{},
		})
		c := newAdminAccountClient(mt)

		result, err := c.List(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Accounts == nil {
			t.Error("expected non-nil accounts slice")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newAdminAccountClient(mt)

		_, err := c.List(context.Background(), &ListAccountsRequest{})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestAdminAccountClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":          1,
			"status":      "valid",
			"order_count": 5,
			"orders_url":  "https://ca.example.com/acme/account/1/orders",
		})
		c := newAdminAccountClient(mt)

		result, err := c.Get(context.Background(), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != 1 {
			t.Errorf("expected ID 1, got %d", result.ID)
		}
		if result.Status != "valid" {
			t.Errorf("expected status valid, got %s", result.Status)
		}
	})

	t.Run("zero account ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newAdminAccountClient(mt)

		_, err := c.Get(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error for zero account ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestNotFound)
		c := newAdminAccountClient(mt)

		_, err := c.Get(context.Background(), 1)
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestAdminAccountClient_Disable(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newAdminAccountClient(mt)

		err := c.Disable(context.Background(), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("zero account ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newAdminAccountClient(mt)

		err := c.Disable(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error for zero account ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestForbidden)
		c := newAdminAccountClient(mt)

		err := c.Disable(context.Background(), 1)
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}
