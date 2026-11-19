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
	stderrors "errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestTenantCAClient_CreateRootCA(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"common_name":   "Test Root CA",
			"key_algorithm": "RSA-4096",
			"status":        "active",
		})
		c := newTenantCAClient(mt)

		result, err := c.CreateRootCA(context.Background(), "tenant-1", &CreateTenantRootCARequest{
			CommonName:    "Test Root CA",
			KeyAlgorithm:  "RSA-4096",
			ValidityYears: 10,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.CommonName != "Test Root CA" {
			t.Errorf("expected common name Test Root CA, got %s", result.CommonName)
		}
		if result.KeyAlgorithm != "RSA-4096" {
			t.Errorf("expected key algorithm RSA-4096, got %s", result.KeyAlgorithm)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.CreateRootCA(context.Background(), "", &CreateTenantRootCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.CreateRootCA(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestConnRefused)
		c := newTenantCAClient(mt)

		_, err := c.CreateRootCA(context.Background(), "tenant-1", &CreateTenantRootCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newTenantCAClient(mt)

		_, err := c.CreateRootCA(context.Background(), "tenant-1", &CreateTenantRootCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestTenantCAClient_CAStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"tenant_id":              "tenant-1",
			"active_ca_count":        float64(2),
			"can_issue_certificates": true,
		})
		c := newTenantCAClient(mt)

		result, err := c.CAStatus(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TenantID != "tenant-1" {
			t.Errorf("expected tenant ID tenant-1, got %s", result.TenantID)
		}
		if result.ActiveCACount != 2 {
			t.Errorf("expected active CA count 2, got %d", result.ActiveCACount)
		}
		if !result.CanIssueCerts {
			t.Error("expected can issue certs to be true")
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.CAStatus(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newTenantCAClient(mt)

		_, err := c.CAStatus(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newTenantCAClient(mt)

		_, err := c.CAStatus(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestTenantCAClient_CreateIntermediateCA(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":            "int-ca-1",
			"common_name":   "Test Intermediate CA",
			"parent_type":   "root",
			"key_algorithm": "ECDSA-P256",
			"status":        "active",
		})
		c := newTenantCAClient(mt)

		result, err := c.CreateIntermediateCA(context.Background(), "tenant-1", &CreateTenantIntermediateCARequest{
			CommonName:    "Test Intermediate CA",
			ParentType:    "root",
			KeyAlgorithm:  "ECDSA-P256",
			ValidityYears: 5,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "int-ca-1" {
			t.Errorf("expected ID int-ca-1, got %s", result.ID)
		}
		if result.CommonName != "Test Intermediate CA" {
			t.Errorf("expected common name, got %s", result.CommonName)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.CreateIntermediateCA(context.Background(), "", &CreateTenantIntermediateCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.CreateIntermediateCA(context.Background(), "tenant-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestConflict)
		c := newTenantCAClient(mt)

		_, err := c.CreateIntermediateCA(context.Background(), "tenant-1", &CreateTenantIntermediateCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newTenantCAClient(mt)

		_, err := c.CreateIntermediateCA(context.Background(), "tenant-1", &CreateTenantIntermediateCARequest{
			CommonName: "Test",
		})
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestTenantCAClient_ListIntermediateCAs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"intermediate_cas": []map[string]interface{}{
				{"id": "int-ca-1", "common_name": "CA One", "status": "active"},
				{"id": "int-ca-2", "common_name": "CA Two", "status": "active"},
			},
		})
		c := newTenantCAClient(mt)

		result, err := c.ListIntermediateCAs(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 intermediate CAs, got %d", len(result))
		}
		if result[0].ID != "int-ca-1" {
			t.Errorf("expected ID int-ca-1, got %s", result[0].ID)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.ListIntermediateCAs(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestUnavailable)
		c := newTenantCAClient(mt)

		_, err := c.ListIntermediateCAs(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newTenantCAClient(mt)

		_, err := c.ListIntermediateCAs(context.Background(), "tenant-1")
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestTenantCAClient_GetIntermediateCA(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{
			"id":            "int-ca-1",
			"common_name":   "Test Intermediate CA",
			"key_algorithm": "RSA-4096",
			"status":        "active",
		})
		c := newTenantCAClient(mt)

		result, err := c.GetIntermediateCA(context.Background(), "tenant-1", "int-ca-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "int-ca-1" {
			t.Errorf("expected ID int-ca-1, got %s", result.ID)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.GetIntermediateCA(context.Background(), "", "int-ca-1")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty CA ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		_, err := c.GetIntermediateCA(context.Background(), "tenant-1", "")
		if err == nil {
			t.Fatal("expected error for empty CA ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestNotFound)
		c := newTenantCAClient(mt)

		_, err := c.GetIntermediateCA(context.Background(), "tenant-1", "int-ca-1")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})

	t.Run("nil transport response", func(t *testing.T) {
		mt := newMockTransportNilResponse()
		c := newTenantCAClient(mt)

		_, err := c.GetIntermediateCA(context.Background(), "tenant-1", "int-ca-1")
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got %v", err)
		}
	})
}

func TestTenantCAClient_UpdateIntermediateCAStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := newMockTransportWithResponse(map[string]interface{}{})
		c := newTenantCAClient(mt)

		err := c.UpdateIntermediateCAStatus(context.Background(), "tenant-1", "int-ca-1", "suspended")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		err := c.UpdateIntermediateCAStatus(context.Background(), "", "int-ca-1", "suspended")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty CA ID", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		err := c.UpdateIntermediateCAStatus(context.Background(), "tenant-1", "", "suspended")
		if err == nil {
			t.Fatal("expected error for empty CA ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty status", func(t *testing.T) {
		mt := newMockTransportWithResponse(nil)
		c := newTenantCAClient(mt)

		err := c.UpdateIntermediateCAStatus(context.Background(), "tenant-1", "int-ca-1", "")
		if err == nil {
			t.Fatal("expected error for empty status")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		mt := newMockTransportWithError(errTestForbidden)
		c := newTenantCAClient(mt)

		err := c.UpdateIntermediateCAStatus(context.Background(), "tenant-1", "int-ca-1", "suspended")
		if err == nil {
			t.Fatal("expected error from transport")
		}
	})
}

func TestTenantCAClient_UpdateTenantStatus(t *testing.T) {
	t.Run("refused without a request", func(t *testing.T) {
		c := newTenantCAClient(refusingTransport(t))

		err := c.UpdateTenantStatus(context.Background(), "tenant-1", "suspended")
		assertTenantStatusRefused(t, err)
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		c := newTenantCAClient(refusingTransport(t))

		err := c.UpdateTenantStatus(context.Background(), "", "disabled")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if !errors.IsInvalidInput(err) {
			t.Errorf("expected invalid input error, got %v", err)
		}
	})

	t.Run("empty status", func(t *testing.T) {
		c := newTenantCAClient(refusingTransport(t))

		err := c.UpdateTenantStatus(context.Background(), "tenant-1", "")
		assertTenantStatusRefused(t, err)
	})
}

// refusingTransport returns a transport that fails the test if any request
// reaches it.
func refusingTransport(t *testing.T) *mockTransport {
	t.Helper()
	return &mockTransport{
		requestFunc: func(_ context.Context, service, method string, _ interface{}) (interface{}, error) {
			t.Fatalf("unexpected request %s.%s", service, method)
			return nil, nil
		},
	}
}

// assertTenantStatusRefused checks err is the typed tenant status refusal.
func assertTenantStatusRefused(t *testing.T, err error) {
	t.Helper()
	if !stderrors.Is(err, ErrTenantStatusUnsupported) {
		t.Fatalf("expected ErrTenantStatusUnsupported, got %v", err)
	}
	var unsupported *TenantStatusUnsupportedError
	if !stderrors.As(err, &unsupported) {
		t.Fatalf("expected *TenantStatusUnsupportedError, got %T", err)
	}
	if unsupported.Field != "status" {
		t.Errorf("expected field status, got %q", unsupported.Field)
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got %v", err)
	}
}
