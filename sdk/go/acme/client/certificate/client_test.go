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

package certificate

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/test/mock"
)

const testPEMChain = `-----BEGIN CERTIFICATE-----
MIIBkDCB+gIUTest...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBkDCB+gIURoot...
-----END CERTIFICATE-----`

func TestGet(t *testing.T) {
	t.Run("success_pem_response", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "certificate" || method != "get" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return map[string]interface{}{
					"IsPEM": true,
					"Body":  testPEMChain,
					"Nonce": "nonce-cert-1",
				}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			CertificateURL: "https://example.com/acme/cert/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Chain != testPEMChain {
			t.Errorf("expected PEM chain, got %q", resp.Chain)
		}
		if resp.Nonce != "nonce-cert-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("success_json_response", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return map[string]interface{}{
					"Data": map[string]interface{}{
						"url":          "https://example.com/acme/cert/1",
						"status":       "valid",
						"serialNumber": "AABBCCDD",
					},
					"Nonce": "nonce-cert-2",
					"Headers": map[string]interface{}{
						"Link": []interface{}{
							`<https://example.com/acme/cert/1/alt>; rel="alternate"`,
						},
					},
				}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Get(context.Background(), &GetRequest{
			CertificateURL: "https://example.com/acme/cert/1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Certificate == nil {
			t.Fatal("expected certificate in response")
		}
		if resp.Certificate.Status != StatusValid {
			t.Errorf("expected status 'valid', got %q", resp.Certificate.Status)
		}
		if resp.Certificate.SerialNumber != "AABBCCDD" {
			t.Errorf("expected serial number, got %q", resp.Certificate.SerialNumber)
		}
		if len(resp.AlternateLinks) != 1 {
			t.Fatalf("expected 1 alternate link, got %d", len(resp.AlternateLinks))
		}
		if resp.AlternateLinks[0] != "https://example.com/acme/cert/1/alt" {
			t.Errorf("expected alternate link URL, got %q", resp.AlternateLinks[0])
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.NewNotFound("test", "certificate not found")
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			CertificateURL: "https://example.com/acme/cert/999",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.IsNotFound(err) {
			t.Errorf("expected not found error, got: %v", err)
		}
	})

	t.Run("decode_error_json_path", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				// Not a PEM response, but response can't be decoded to Certificate
				return "not-a-map", nil
			},
		}

		c := NewClient(mt)
		_, err := c.Get(context.Background(), &GetRequest{
			CertificateURL: "https://example.com/acme/cert/1",
		})
		if err == nil {
			t.Fatal("expected error for undecodable response")
		}
		if !errors.IsInternal(err) {
			t.Errorf("expected internal error, got: %v", err)
		}
	})
}

func TestRevoke(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				if service != "certificate" || method != "revoke" {
					t.Errorf("unexpected route: %s/%s", service, method)
				}
				return map[string]interface{}{
					"Nonce": "nonce-revoke-1",
				}, nil
			},
		}

		c := NewClient(mt)
		resp, err := c.Revoke(context.Background(), &RevokeRequest{
			Certificate: "base64url-encoded-der-cert",
			Reason:      ReasonKeyCompromise,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Nonce != "nonce-revoke-1" {
			t.Errorf("expected nonce, got %q", resp.Nonce)
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		mt := &mock.Transport{
			RequestFunc: func(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
				return nil, errors.New(errors.CodeACMEAlreadyRevoked, "test", "already revoked")
			},
		}

		c := NewClient(mt)
		_, err := c.Revoke(context.Background(), &RevokeRequest{
			Certificate: "base64url-encoded-der-cert",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if errors.Code(err) != errors.CodeACMEAlreadyRevoked {
			t.Errorf("expected already revoked error, got: %v", err)
		}
	})
}

func TestURLExtractor(t *testing.T) {
	t.Run("get_request", func(t *testing.T) {
		r := &GetRequest{CertificateURL: "https://example.com/acme/cert/1"}
		if r.ExtractURL() != "https://example.com/acme/cert/1" {
			t.Errorf("unexpected URL: %q", r.ExtractURL())
		}
	})
}
