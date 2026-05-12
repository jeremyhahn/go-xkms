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

func TestOrderClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"orders": []map[string]interface{}{
				{"id": float64(1), "account_id": float64(10), "status": "valid"},
				{"id": float64(2), "account_id": float64(10), "status": "pending"},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		})
		c := newOrderClient(mt)

		result, err := c.List(context.Background(), &ListOrdersRequest{
			Page:    1,
			PerPage: 10,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Orders) != 2 {
			t.Errorf("expected 2 orders, got %d", len(result.Orders))
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
			"orders": []map[string]interface{}{},
		})
		c := newOrderClient(mt)

		result, err := c.List(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Orders == nil {
			t.Error("expected non-nil orders slice")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("connection refused"))
		c := newOrderClient(mt)

		_, err := c.List(context.Background(), &ListOrdersRequest{})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newOrderClient(mt)

		_, err := c.List(context.Background(), &ListOrdersRequest{})
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestOrderClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":          float64(42),
			"account_id":  float64(10),
			"status":      "valid",
			"identifiers": []string{"example.com"},
		})
		c := newOrderClient(mt)

		result, err := c.Get(context.Background(), 42)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != 42 {
			t.Errorf("expected ID 42, got %d", result.ID)
		}
		if result.Status != "valid" {
			t.Errorf("expected status valid, got %s", result.Status)
		}
	})

	t.Run("zero order ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newOrderClient(mt)

		_, err := c.Get(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error for zero order ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("not found"))
		c := newOrderClient(mt)

		_, err := c.Get(context.Background(), 1)
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newOrderClient(mt)

		_, err := c.Get(context.Background(), 1)
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}
