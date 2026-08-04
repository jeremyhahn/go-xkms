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

package order

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/test/mock"
)

func newMockResponse(data map[string]interface{}, nonce, location string) map[string]interface{} {
	resp := map[string]interface{}{
		"Data": data,
	}
	if nonce != "" {
		resp["Nonce"] = nonce
	}
	if location != "" {
		resp["Location"] = location
	}
	return resp
}

func TestCreate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "order" || method != "create" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status": "pending",
						"identifiers": []interface{}{
							map[string]interface{}{
								"type":  "dns",
								"value": "example.com",
							},
						},
						"authorizations": []interface{}{
							"https://example.com/acme/authz/1",
						},
						"finalize": "https://example.com/acme/order/1/finalize",
					},
					"nonce-create-1",
					"https://example.com/acme/order/1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Create(context.Background(), &CreateRequest{
			Identifiers: []Identifier{{Type: "dns", Value: "example.com"}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Order == nil {
			t.Fatal("expected order in response")
		}
		if resp.Order.Status != StatusPending {
			t.Errorf("expected status 'pending', got %q", resp.Order.Status)
		}
		if resp.Location != "https://example.com/acme/order/1" {
			t.Errorf("expected location URL, got %q", resp.Location)
		}
		if resp.Nonce != "nonce-create-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewUnavailable("test", "server unavailable")
			},
		}

		c := NewClient(mt)
		_, err := c.Create(context.Background(), &CreateRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsUnavailable(err) {
			t.Errorf("expected unavailable error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Create(context.Background(), &CreateRequest{})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return newMockResponse(
					map[string]interface{}{
						"status":      "valid",
						"finalize":    "https://example.com/acme/order/1/finalize",
						"certificate": "https://example.com/acme/cert/1",
					},
					"nonce-get-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			OrderURL: "https://example.com/acme/order/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Order == nil {
			t.Fatal("expected order in response")
		}
		if resp.Order.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Order.Status)
		}
		if resp.Order.Certificate != "https://example.com/acme/cert/1" {
			t.Errorf("expected certificate URL, got %q", resp.Order.Certificate)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewNotFound("test", "order not found")
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			OrderURL: "https://example.com/acme/order/999",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsNotFound(err) {
			t.Errorf("expected not found error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			OrderURL: "https://example.com/acme/order/1",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestList(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return newMockResponse(
					map[string]interface{}{
						"orders": []interface{}{
							"https://example.com/acme/order/1",
							"https://example.com/acme/order/2",
						},
					},
					"nonce-list-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.List(context.Background(), &ListRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Orders) != 2 {
			t.Fatalf("expected 2 orders, got %d", len(resp.Orders))
		}
		if resp.Nonce != "nonce-list-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewUnauthorized("test", "unauthorized")
			},
		}

		c := NewClient(mt)
		_, err := c.List(context.Background(), &ListRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsUnauthorized(err) {
			t.Errorf("expected unauthorized error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.List(context.Background(), &ListRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestFinalize(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if method != "finalize" {
					t.Errorf("expected method 'finalize', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status":      "valid",
						"certificate": "https://example.com/acme/cert/1",
						"finalize":    "https://example.com/acme/order/1/finalize",
					},
					"nonce-finalize-1",
					"https://example.com/acme/order/1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Finalize(context.Background(), &FinalizeRequest{
			FinalizeURL: "https://example.com/acme/order/1/finalize",
			CSR:         "base64url-encoded-csr",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Order == nil {
			t.Fatal("expected order in response")
		}
		if resp.Order.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Order.Status)
		}
		if resp.Location != "https://example.com/acme/order/1" {
			t.Errorf("expected location URL, got %q", resp.Location)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.New(errors.CodeACMEOrderNotReady, "test", "order not ready")
			},
		}

		c := NewClient(mt)
		_, err := c.Finalize(context.Background(), &FinalizeRequest{
			FinalizeURL: "https://example.com/acme/order/1/finalize",
			CSR:         "base64url-encoded-csr",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if errors.Code(err) != errors.CodeACMEOrderNotReady {
			t.Errorf("expected order not ready error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Finalize(context.Background(), &FinalizeRequest{
			FinalizeURL: "https://example.com/acme/order/1/finalize",
			CSR:         "base64url-encoded-csr",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestURLExtractors(t *testing.T) {
	t.Run("get_request", func(t *testing.T) {
		r := &GetRequest{OrderURL: "https://example.com/acme/order/1"}
		if r.ExtractURL() != "https://example.com/acme/order/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("list_request", func(t *testing.T) {
		r := &ListRequest{AccountURL: "https://example.com/acme/acct/1"}
		if r.ExtractURL() != "https://example.com/acme/acct/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("finalize_request", func(t *testing.T) {
		r := &FinalizeRequest{FinalizeURL: "https://example.com/acme/order/1/finalize"}
		if r.ExtractURL() != "https://example.com/acme/order/1/finalize" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})
}
