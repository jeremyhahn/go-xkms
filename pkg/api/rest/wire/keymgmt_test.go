// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package wire

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// keyManagementCall is one KeyManagementClient method bound to its request;
// a nil request exercises the client's nil check.
type keyManagementCall func(c KeyManagementClient, withRequest bool) error

// keyManagementRoute is one KeyManagementClient method with the method and
// path its request must produce; body marks a route that carries the request
// in its body.
type keyManagementRoute struct {
	name   string
	call   keyManagementCall
	method string
	path   string
	body   bool
}

// keyManagementCalls returns the route of every KeyManagementClient method.
func keyManagementCalls(ctx context.Context) []keyManagementRoute {
	key := &transport.KeyManagementRequest{Backend: "software", KeyID: "a b"}
	backend := &transport.BackendRequest{Backend: "software"}
	pick := func(withRequest bool, req *transport.KeyManagementRequest) *transport.KeyManagementRequest {
		if withRequest {
			return req
		}
		return nil
	}
	return []keyManagementRoute{
		{"public-key", func(c KeyManagementClient, with bool) error {
			req := &transport.GetPublicKeyRequest{Backend: "software", KeyID: "a b", Version: 2}
			if !with {
				req = nil
			}
			_, err := c.GetPublicKey(ctx, req)
			return err
		}, http.MethodGet, "/api/v1/keys/a%20b/public-key?backend=software&version=2", false},
		{"revoke", func(c KeyManagementClient, with bool) error {
			req := &transport.RevokeKeyRequest{Backend: "software", KeyID: "a b", Reason: "lost"}
			if !with {
				req = nil
			}
			_, err := c.RevokeKey(ctx, req)
			return err
		}, http.MethodPost, "/api/v1/keys/a%20b/revoke", true},
		{"status", func(c KeyManagementClient, with bool) error {
			req := &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "a b", Status: transport.KeyStatusDisabled}
			if !with {
				req = nil
			}
			_, err := c.UpdateKeyStatus(ctx, req)
			return err
		}, http.MethodPost, "/api/v1/keys/a%20b/status", true},
		{"get-metadata", func(c KeyManagementClient, with bool) error {
			_, err := c.GetKeyMetadata(ctx, pick(with, key))
			return err
		}, http.MethodGet, "/api/v1/keys/a%20b/metadata?backend=software", false},
		{"update-metadata", func(c KeyManagementClient, with bool) error {
			req := &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "a b", Name: "n"}
			if !with {
				req = nil
			}
			_, err := c.UpdateKeyMetadata(ctx, req)
			return err
		}, http.MethodPut, "/api/v1/keys/a%20b/metadata", true},
		{"set-policy", func(c KeyManagementClient, with bool) error {
			req := &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "a b", Policy: &transport.KeyPolicy{}}
			if !with {
				req = nil
			}
			_, err := c.SetKeyPolicy(ctx, req)
			return err
		}, http.MethodPut, "/api/v1/keys/a%20b/policy", true},
		{"get-policy", func(c KeyManagementClient, with bool) error {
			_, err := c.GetKeyPolicy(ctx, pick(with, key))
			return err
		}, http.MethodGet, "/api/v1/keys/a%20b/policy?backend=software", false},
		{"delete-policy", func(c KeyManagementClient, with bool) error {
			_, err := c.DeleteKeyPolicy(ctx, pick(with, key))
			return err
		}, http.MethodDelete, "/api/v1/keys/a%20b/policy?backend=software", false},
		{"set-rotation-policy", func(c KeyManagementClient, with bool) error {
			req := &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "a b", Policy: &transport.RotationPolicy{}}
			if !with {
				req = nil
			}
			_, err := c.SetKeyRotationPolicy(ctx, req)
			return err
		}, http.MethodPut, "/api/v1/keys/a%20b/rotation-policy", true},
		{"get-rotation-policy", func(c KeyManagementClient, with bool) error {
			_, err := c.GetKeyRotationPolicy(ctx, pick(with, key))
			return err
		}, http.MethodGet, "/api/v1/keys/a%20b/rotation-policy?backend=software", false},
		{"delete-rotation-policy", func(c KeyManagementClient, with bool) error {
			_, err := c.DeleteKeyRotationPolicy(ctx, pick(with, key))
			return err
		}, http.MethodDelete, "/api/v1/keys/a%20b/rotation-policy?backend=software", false},
		{"algorithms", func(c KeyManagementClient, with bool) error {
			req := backend
			if !with {
				req = nil
			}
			_, err := c.GetSupportedAlgorithms(ctx, req)
			return err
		}, http.MethodGet, "/api/v1/backend/algorithms?backend=software", false},
		{"backend-status", func(c KeyManagementClient, with bool) error {
			req := backend
			if !with {
				req = nil
			}
			_, err := c.BackendStatus(ctx, req)
			return err
		}, http.MethodGet, "/api/v1/backend/status?backend=software", false},
		{"backend-test", func(c KeyManagementClient, with bool) error {
			req := backend
			if !with {
				req = nil
			}
			_, err := c.BackendTest(ctx, req)
			return err
		}, http.MethodPost, "/api/v1/backend/test", true},
		{"set-safety", func(c KeyManagementClient, with bool) error {
			req := &transport.SetKeySafetyRequest{Backend: "software", KeyID: "a b", MaxOperations: 10}
			if !with {
				req = nil
			}
			_, err := c.SetKeySafety(ctx, req)
			return err
		}, http.MethodPut, "/api/v1/keys/a%20b/safety", true},
		{"clear-safety", func(c KeyManagementClient, with bool) error {
			_, err := c.ClearKeySafety(ctx, pick(with, key))
			return err
		}, http.MethodDelete, "/api/v1/keys/a%20b/safety?backend=software", false},
		{"safety-check", func(c KeyManagementClient, with bool) error {
			req := &transport.SafetyCheckRequest{}
			if !with {
				req = nil
			}
			_, err := c.SafetyCheck(ctx, req)
			return err
		}, http.MethodGet, "/api/v1/safety/check", false},
		{"safety-report", func(c KeyManagementClient, with bool) error {
			req := &transport.SafetyReportRequest{Format: "table"}
			if !with {
				req = nil
			}
			_, err := c.SafetyReport(ctx, req)
			return err
		}, http.MethodGet, "/api/v1/safety/report?format=table", false},
	}
}

// TestKeyManagementClient_Routes proves each method reaches the route the
// REST server serves it on, with the request in the body only where the
// route takes one.
func TestKeyManagementClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := KeyManagementClient{Do: rec.do}
	for _, tt := range keyManagementCalls(context.Background()) {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call(c, true))
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
			if tt.body {
				assert.NotEmpty(t, got.body)
			} else {
				assert.Nil(t, got.body)
			}
		})
	}
}

// TestKeyManagementClient_Errors proves each method refuses a nil request
// and surfaces a failed request and an undecodable response.
func TestKeyManagementClient_Errors(t *testing.T) {
	failing := KeyManagementClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	garbled := KeyManagementClient{Do: (&recordingRequester{response: `{not json`}).do}
	for _, tt := range keyManagementCalls(context.Background()) {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(failing, false), ErrNilRequest)
			assert.ErrorIs(t, tt.call(failing, true), errRequestFailed)
			var decodeErr *DecodeError
			assert.ErrorAs(t, tt.call(garbled, true), &decodeErr)
		})
	}
}
