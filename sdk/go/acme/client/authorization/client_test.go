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

package authorization

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/test/mock"
)

func newMockResponse(data map[string]interface{}, nonce string) map[string]interface{} {
	resp := map[string]interface{}{
		"Data": data,
	}
	if nonce != "" {
		resp["Nonce"] = nonce
	}
	return resp
}

func TestGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "authorization" || method != "get" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status": "pending",
						"identifier": map[string]interface{}{
							"type":  "dns",
							"value": "example.com",
						},
						"challenges": []interface{}{
							map[string]interface{}{
								"type":   "http-01",
								"url":    "https://example.com/acme/chall/1",
								"status": "pending",
								"token":  "abc123",
							},
						},
					},
					"nonce-get-1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			AuthorizationURL: "https://example.com/acme/authz/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Authorization == nil {
			t.Fatal("expected authorization in response")
		}
		if resp.Authorization.Status != StatusPending {
			t.Errorf("expected status 'pending', got %q", resp.Authorization.Status)
		}
		if resp.Authorization.Identifier.Type != "dns" {
			t.Errorf("expected identifier type 'dns', got %q", resp.Authorization.Identifier.Type)
		}
		if len(resp.Authorization.Challenges) != 1 {
			t.Fatalf("expected 1 challenge, got %d", len(resp.Authorization.Challenges))
		}
		if resp.Nonce != "nonce-get-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewNotFound("test", "authorization not found")
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			AuthorizationURL: "https://example.com/acme/authz/999",
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
			AuthorizationURL: "https://example.com/acme/authz/1",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestDeactivate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if method != "deactivate" {
					t.Errorf("expected method 'deactivate', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status": "deactivated",
						"identifier": map[string]interface{}{
							"type":  "dns",
							"value": "example.com",
						},
						"challenges": []interface{}{},
					},
					"nonce-deactivate-1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Deactivate(context.Background(), &DeactivateRequest{
			AuthorizationURL: "https://example.com/acme/authz/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Authorization == nil {
			t.Fatal("expected authorization in response")
		}
		if resp.Authorization.Status != StatusDeactivated {
			t.Errorf("expected status 'deactivated', got %q", resp.Authorization.Status)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewForbidden("test", "forbidden")
			},
		}

		c := NewClient(mt)
		_, err := c.Deactivate(context.Background(), &DeactivateRequest{
			AuthorizationURL: "https://example.com/acme/authz/1",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsForbidden(err) {
			t.Errorf("expected forbidden error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Deactivate(context.Background(), &DeactivateRequest{
			AuthorizationURL: "https://example.com/acme/authz/1",
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
		r := &GetRequest{AuthorizationURL: "https://example.com/acme/authz/1"}
		if r.ExtractURL() != "https://example.com/acme/authz/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("deactivate_request", func(t *testing.T) {
		r := &DeactivateRequest{AuthorizationURL: "https://example.com/acme/authz/2"}
		if r.ExtractURL() != "https://example.com/acme/authz/2" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})
}
