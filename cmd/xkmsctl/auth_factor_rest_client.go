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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// authFactorRESTClient satisfies the qrdb SDK UserAuthFactorClient interface
// by calling xkmsd's auth-factor endpoints.
//
// The CLI reaches identity through the same server it already uses for keys,
// rather than opening a second connection to the qrdb node. xkmsd holds the
// node and proxies these calls; factor state stays qrdb's.
//
// Implementing qrdb's interface rather than a local one keeps every existing
// auth-factor command unchanged: the handlers were already written against
// this contract, they were simply never given a client.
type authFactorRESTClient struct {
	http    *http.Client
	baseURL string
}

// compile-time check that the REST client satisfies the SDK contract.
var _ qrdbtransport.UserAuthFactorClient = (*authFactorRESTClient)(nil)

// newAuthFactorRESTClient builds a client against the configured server.
func newAuthFactorRESTClient(cfg *Config) (*authFactorRESTClient, error) {
	if cfg.Server == "" {
		return nil, ErrServerRequired
	}

	httpClient, err := createInitHTTPClient(cfg, false)
	if err != nil {
		return nil, err
	}

	return &authFactorRESTClient{http: httpClient, baseURL: cfg.Server}, nil
}

// AddAuthFactor persists a new factor for a user.
func (c *authFactorRESTClient) AddAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	var resp qrdbtransport.AuthFactorAddResponse
	if err := c.call(ctx, http.MethodPost, "/api/v1/factors", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAuthFactors returns every factor owned by a user.
func (c *authFactorRESTClient) ListAuthFactors(ctx context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	var resp qrdbtransport.AuthFactorListResponse
	path := fmt.Sprintf("/api/v1/factors?user_id=%d", req.UserID)
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAuthFactor returns a single factor by ID.
func (c *authFactorRESTClient) GetAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	var resp qrdbtransport.AuthFactorGetResponse
	path := "/api/v1/factors/" + url.PathEscape(req.FactorID)
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RemoveAuthFactor soft-deletes a factor.
func (c *authFactorRESTClient) RemoveAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	var resp qrdbtransport.AuthFactorRemoveResponse
	path := "/api/v1/factors/" + url.PathEscape(req.FactorID)
	if req.Force {
		path += "?force=true"
	}
	if err := c.call(ctx, http.MethodDelete, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RotateAuthFactor adds a replacement factor and revokes the old one.
func (c *authFactorRESTClient) RotateAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	var resp qrdbtransport.AuthFactorRotateResponse
	path := "/api/v1/factors/" + url.PathEscape(req.OldFactorID) + "/rotate"
	if err := c.call(ctx, http.MethodPost, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RelabelAuthFactor updates a factor's display label.
func (c *authFactorRESTClient) RelabelAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	var resp qrdbtransport.AuthFactorRelabelResponse
	path := "/api/v1/factors/" + url.PathEscape(req.FactorID)
	if err := c.call(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LoginAuthFactor resolves a (type, lookup key) pair to a principal. The
// hardware proof is verified by the caller, not by this call.
func (c *authFactorRESTClient) LoginAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	var resp qrdbtransport.AuthFactorLoginResponse
	if err := c.call(ctx, http.MethodPost, "/api/v1/factors/login", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// call issues one request and decodes the reply. A response with no body
// (204) leaves out untouched rather than failing to decode.
func (c *authFactorRESTClient) call(ctx context.Context, method, path string, body, out any) error {
	resp, err := doInitRequestContext(ctx, c.http, method, c.baseURL+path, body)
	if err != nil {
		return err
	}

	payload, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	if len(payload) == 0 || out == nil {
		return nil
	}

	if err := json.Unmarshal(payload, out); err != nil {
		return &WrappedDetailError{
			Sentinel: ErrHTTPRequestFailed,
			Detail:   "failed to parse auth factor response",
			Err:      err,
		}
	}
	return nil
}
