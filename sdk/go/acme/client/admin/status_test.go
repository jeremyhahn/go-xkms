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
)

func TestStatusClient_Status(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"identity":            "Trusted CA",
			"initialized":         true,
			"version":             "1.0.0",
			"key_algorithm":       "ECDSA-P384",
			"signature_algorithm": "SHA384-ECDSA",
			"root_ca":             "CN=Root CA",
		})
		c := newStatusClient(mt)

		result, err := c.Status(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Identity != "Trusted CA" {
			t.Errorf("expected identity Trusted CA, got %s", result.Identity)
		}
		if !result.Initialized {
			t.Error("expected initialized to be true")
		}
		if result.Version != "1.0.0" {
			t.Errorf("expected version 1.0.0, got %s", result.Version)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newStatusClient(mt)

		_, err := c.Status(context.Background())
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newStatusClient(mt)

		_, err := c.Status(context.Background())
		if err == nil {
			t.Fatal("expected error for nil transport response")
		}
	})
}

func TestStatusClient_Stats(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"total_certificates":   100,
			"valid_certificates":   80,
			"revoked_certificates": 10,
			"expired_certificates": 10,
			"total_accounts":       50,
			"active_accounts":      45,
			"total_orders":         200,
			"pending_orders":       5,
			"completed_orders":     195,
		})
		c := newStatusClient(mt)

		result, err := c.Stats(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TotalCertificates != 100 {
			t.Errorf("expected total certificates 100, got %d", result.TotalCertificates)
		}
		if result.ValidCertificates != 80 {
			t.Errorf("expected valid certificates 80, got %d", result.ValidCertificates)
		}
		if result.TotalAccounts != 50 {
			t.Errorf("expected total accounts 50, got %d", result.TotalAccounts)
		}
		if result.CompletedOrders != 195 {
			t.Errorf("expected completed orders 195, got %d", result.CompletedOrders)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newStatusClient(mt)

		_, err := c.Stats(context.Background())
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newStatusClient(mt)

		_, err := c.Stats(context.Background())
		if err == nil {
			t.Fatal("expected error for nil transport response")
		}
	})
}
