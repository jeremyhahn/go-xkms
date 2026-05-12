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

package challenge

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
				if service != "challenge" || method != "get" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return newMockResponse(
					map[string]interface{}{
						"type":   "http-01",
						"url":    "https://example.com/acme/chall/1",
						"status": "pending",
						"token":  "token-abc-123",
					},
					"nonce-get-1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			ChallengeURL: "https://example.com/acme/chall/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Challenge == nil {
			t.Fatal("expected challenge in response")
		}
		if resp.Challenge.Type != TypeHTTP01 {
			t.Errorf("expected type 'http-01', got %q", resp.Challenge.Type)
		}
		if resp.Challenge.Status != StatusPending {
			t.Errorf("expected status 'pending', got %q", resp.Challenge.Status)
		}
		if resp.Challenge.Token != "token-abc-123" {
			t.Errorf("expected token, got %q", resp.Challenge.Token)
		}
		if resp.Nonce != "nonce-get-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewNotFound("test", "challenge not found")
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			ChallengeURL: "https://example.com/acme/chall/999",
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
			ChallengeURL: "https://example.com/acme/chall/1",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestRespond(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if method != "respond" {
					t.Errorf("expected method 'respond', got %q", method)
				}
				return newMockResponse(
					map[string]interface{}{
						"type":   "http-01",
						"url":    "https://example.com/acme/chall/1",
						"status": "processing",
						"token":  "token-abc-123",
					},
					"nonce-respond-1",
				), nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Respond(context.Background(), &RespondRequest{
			ChallengeURL: "https://example.com/acme/chall/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Challenge == nil {
			t.Fatal("expected challenge in response")
		}
		if resp.Challenge.Status != StatusProcessing {
			t.Errorf("expected status 'processing', got %q", resp.Challenge.Status)
		}
		if resp.Nonce != "nonce-respond-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.New(errors.CodeACMEUnauthorized, "test", "unauthorized challenge response")
			},
		}

		c := NewClient(mt)
		_, err := c.Respond(context.Background(), &RespondRequest{
			ChallengeURL: "https://example.com/acme/chall/1",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if errors.Code(err) != errors.CodeACMEUnauthorized {
			t.Errorf("expected ACME unauthorized error, got: %v", err)
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Respond(context.Background(), &RespondRequest{
			ChallengeURL: "https://example.com/acme/chall/1",
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
		r := &GetRequest{ChallengeURL: "https://example.com/acme/chall/1"}
		if r.ExtractURL() != "https://example.com/acme/chall/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})

	t.Run("respond_request", func(t *testing.T) {
		r := &RespondRequest{ChallengeURL: "https://example.com/acme/chall/2"}
		if r.ExtractURL() != "https://example.com/acme/chall/2" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})
}
