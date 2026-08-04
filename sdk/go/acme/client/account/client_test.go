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

package account

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
				if service != "account" || method != "create" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status":  "valid",
						"contact": []interface{}{"mailto:test@example.com"},
						"orders":  "https://example.com/acme/orders/1",
					},
					"nonce-create-1",
					"https://example.com/acme/acct/1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Create(context.Background(), &CreateRequest{
			Contact:              []string{"mailto:test@example.com"},
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Account == nil {
			t.Fatal("expected account in response")
		}
		if resp.Account.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Account.Status)
		}
		if resp.Location != "https://example.com/acme/acct/1" {
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
				if method != "get" {
					t.Errorf("expected method 'get', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status":  "valid",
						"contact": []interface{}{"mailto:admin@example.com"},
					},
					"nonce-get-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Account == nil {
			t.Fatal("expected account in response")
		}
		if resp.Account.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Account.Status)
		}
		if resp.Nonce != "nonce-get-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewNotFound("test", "account not found")
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			AccountURL: "https://example.com/acme/acct/999",
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

func TestUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if method != "update" {
					t.Errorf("expected method 'update', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status":  "valid",
						"contact": []interface{}{"mailto:new@example.com"},
					},
					"nonce-update-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Update(context.Background(), &UpdateRequest{
			AccountURL: "https://example.com/acme/acct/1",
			Contact:    []string{"mailto:new@example.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Account == nil {
			t.Fatal("expected account in response")
		}
		if len(resp.Account.Contact) != 1 || resp.Account.Contact[0] != "mailto:new@example.com" {
			t.Errorf("unexpected contact: %v", resp.Account.Contact)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewUnauthorized("test", "unauthorized")
			},
		}

		c := NewClient(mt)
		_, err := c.Update(context.Background(), &UpdateRequest{
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
		_, err := c.Update(context.Background(), &UpdateRequest{
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
					},
					"nonce-deactivate-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Deactivate(context.Background(), &DeactivateRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Account == nil {
			t.Fatal("expected account in response")
		}
		if resp.Account.Status != StatusDeactivated {
			t.Errorf("expected status 'deactivated', got %q", resp.Account.Status)
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
			AccountURL: "https://example.com/acme/acct/1",
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

func TestKeyChange(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if method != "keychange" {
					t.Errorf("expected method 'keychange', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"status": "valid",
					},
					"nonce-keychange-1",
					"",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.KeyChange(context.Background(), &KeyChangeRequest{
			AccountURL: "https://example.com/acme/acct/1",
			OldKey:     map[string]interface{}{"kty": "RSA"},
			NewKey:     map[string]interface{}{"kty": "RSA"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Account == nil {
			t.Fatal("expected account in response")
		}
		if resp.Account.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Account.Status)
		}
		if resp.Nonce != "nonce-keychange-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewConflict("test", "key conflict")
			},
		}

		c := NewClient(mt)
		_, err := c.KeyChange(context.Background(), &KeyChangeRequest{
			AccountURL: "https://example.com/acme/acct/1",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsConflict(err) {
			t.Errorf("expected conflict error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.KeyChange(context.Background(), &KeyChangeRequest{
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

func TestURLExtractors(t *testing.T) {
	t.Run("get_request", func(t *testing.T) {
		r := &GetRequest{AccountURL: "https://example.com/acme/acct/1"}
		if r.ExtractURL() != "https://example.com/acme/acct/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("update_request", func(t *testing.T) {
		r := &UpdateRequest{AccountURL: "https://example.com/acme/acct/2"}
		if r.ExtractURL() != "https://example.com/acme/acct/2" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("deactivate_request", func(t *testing.T) {
		r := &DeactivateRequest{AccountURL: "https://example.com/acme/acct/3"}
		if r.ExtractURL() != "https://example.com/acme/acct/3" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})
}
