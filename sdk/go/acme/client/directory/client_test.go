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

package directory

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/test/mock"
)

func TestGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "directory" || method != "get" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return map[string]interface{}{
					"Data": map[string]interface{}{
						"newNonce":   "https://example.com/acme/new-nonce",
						"newAccount": "https://example.com/acme/new-acct",
						"newOrder":   "https://example.com/acme/new-order",
						"revokeCert": "https://example.com/acme/revoke-cert",
						"keyChange":  "https://example.com/acme/key-change",
						"meta": map[string]interface{}{
							"termsOfService":          "https://example.com/terms",
							"website":                 "https://example.com",
							"externalAccountRequired": false,
						},
					},
					"Nonce": "nonce-dir-1",
				}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Directory == nil {
			t.Fatal("expected directory in response")
		}
		if resp.Directory.NewNonce != "https://example.com/acme/new-nonce" {
			t.Errorf("expected newNonce URL, got %q", resp.Directory.NewNonce)
		}
		if resp.Directory.NewAccount != "https://example.com/acme/new-acct" {
			t.Errorf("expected newAccount URL, got %q", resp.Directory.NewAccount)
		}
		if resp.Directory.NewOrder != "https://example.com/acme/new-order" {
			t.Errorf("expected newOrder URL, got %q", resp.Directory.NewOrder)
		}
		if resp.Directory.RevokeCert != "https://example.com/acme/revoke-cert" {
			t.Errorf("expected revokeCert URL, got %q", resp.Directory.RevokeCert)
		}
		if resp.Directory.KeyChange != "https://example.com/acme/key-change" {
			t.Errorf("expected keyChange URL, got %q", resp.Directory.KeyChange)
		}
		if resp.Directory.Meta == nil {
			t.Fatal("expected meta in directory")
		}
		if resp.Directory.Meta.TermsOfService != "https://example.com/terms" {
			t.Errorf("expected terms of service URL, got %q", resp.Directory.Meta.TermsOfService)
		}
		if resp.Nonce != "nonce-dir-1" {
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
		_, err := c.Get(context.Background(), &GetRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsUnavailable(err) {
			t.Errorf("expected unavailable error, got: %v", err)
		}
	})

	t.Run("nil_response_from_transport", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, nil
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{})
		if err == nil {
			t.Fatal("expected error for nil response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}
