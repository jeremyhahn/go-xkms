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

func TestEABClient_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":        "eab-123",
			"mac_key":   "dGVzdGtleQ",
			"algorithm": "HS256",
		})
		c := newEABClient(mt)

		result, err := c.Create(context.Background(), "tenant-1", &CreateEABRequest{
			Purpose: "account-binding",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "eab-123" {
			t.Errorf("expected ID eab-123, got %s", result.ID)
		}
		if result.MACKey != "dGVzdGtleQ" {
			t.Errorf("expected MACKey dGVzdGtleQ, got %s", result.MACKey)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		_, err := c.Create(context.Background(), "", &CreateEABRequest{})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestInternalError)
		c := newEABClient(mt)

		_, err := c.Create(context.Background(), "tenant-1", &CreateEABRequest{})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestEABClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":        "eab-123",
			"tenant_id": "tenant-1",
			"status":    "active",
			"purpose":   "account-binding",
		})
		c := newEABClient(mt)

		result, err := c.Get(context.Background(), "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "eab-123" {
			t.Errorf("expected ID eab-123, got %s", result.ID)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		_, err := c.Get(context.Background(), "", "eab-123")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty kid", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		_, err := c.Get(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty kid")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestEABClient_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newEABClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "eab-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		err := c.Delete(context.Background(), "", "eab-123")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty kid", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		err := c.Delete(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty kid")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})
}

func TestEABClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"eabs": []map[string]interface{}{
				{"id": "eab-1", "status": "active", "purpose": "account-binding"},
				{"id": "eab-2", "status": "used", "purpose": "endorse-01"},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		})
		c := newEABClient(mt)

		result, err := c.List(context.Background(), "tenant-1", &ListEABRequest{Page: 1, PerPage: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.EABs) != 2 {
			t.Errorf("expected 2 EABs, got %d", len(result.EABs))
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newEABClient(mt)

		_, err := c.List(context.Background(), "", &ListEABRequest{})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"eabs": []map[string]interface{}{},
		})
		c := newEABClient(mt)

		result, err := c.List(context.Background(), "tenant-1", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.EABs == nil {
			t.Error("expected non-nil EABs slice")
		}
	})
}
