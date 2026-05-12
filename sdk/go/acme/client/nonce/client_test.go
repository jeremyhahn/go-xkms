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

package nonce

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/test/mock"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "nonce" || method != "new" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return map[string]interface{}{
					"Nonce": "fresh-nonce-abc123",
				}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.New(context.Background(), &NewRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Nonce != "fresh-nonce-abc123" {
			t.Errorf("expected nonce 'fresh-nonce-abc123', got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewUnavailable("test", "server unavailable")
			},
		}

		c := NewClient(mt)
		_, err := c.New(context.Background(), &NewRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsUnavailable(err) {
			t.Errorf("expected unavailable error, got: %v", err)
		}
	})

	t.Run("empty_nonce_from_transport", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return map[string]interface{}{}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.New(context.Background(), &NewRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Nonce != "" {
			t.Errorf("expected empty nonce, got %q", resp.Nonce)
		}
	})
}
