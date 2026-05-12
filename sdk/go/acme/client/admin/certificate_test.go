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

func TestCertificateClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"certificates": []map[string]interface{}{
				{"id": 1, "serial_number": "ABC123", "subject": "CN=test", "status": "valid"},
				{"id": 2, "serial_number": "DEF456", "subject": "CN=test2", "status": "revoked"},
			},
			"pagination": map[string]interface{}{
				"page": 1, "per_page": 10, "total": 2,
			},
		})
		c := newCertificateClient(mt)

		result, err := c.List(context.Background(), &ListCertificatesRequest{Page: 1, PerPage: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Certificates) != 2 {
			t.Errorf("expected 2 certificates, got %d", len(result.Certificates))
		}
		if result.Pagination == nil {
			t.Fatal("expected pagination to be present")
		}
	})

	t.Run("nil request defaults", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"certificates": []map[string]interface{}{},
		})
		c := newCertificateClient(mt)

		result, err := c.List(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Certificates == nil {
			t.Error("expected non-nil certificates slice")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("unavailable"))
		c := newCertificateClient(mt)

		_, err := c.List(context.Background(), &ListCertificatesRequest{})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestCertificateClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":            1,
			"serial_number": "ABC123",
			"subject":       "CN=test",
			"status":        "valid",
		})
		c := newCertificateClient(mt)

		result, err := c.Get(context.Background(), "ABC123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.SerialNumber != "ABC123" {
			t.Errorf("expected serial ABC123, got %s", result.SerialNumber)
		}
	})

	t.Run("empty serial", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newCertificateClient(mt)

		_, err := c.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty serial")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("not found"))
		c := newCertificateClient(mt)

		_, err := c.Get(context.Background(), "ABC123")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestCertificateClient_Revoke(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newCertificateClient(mt)

		err := c.Revoke(context.Background(), "ABC123", "keyCompromise")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty serial", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newCertificateClient(mt)

		err := c.Revoke(context.Background(), "", "keyCompromise")
		if err == nil {
			t.Fatal("expected error for empty serial")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(fmt.Errorf("revocation failed"))
		c := newCertificateClient(mt)

		err := c.Revoke(context.Background(), "ABC123", "keyCompromise")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}
