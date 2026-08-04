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

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "certificate"
)

// Client provides ACME certificate operations as defined in RFC 8555.
type Client interface {
	// Get retrieves a certificate from the ACME server.
	// RFC 8555 Section 7.4.2.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

	// Revoke revokes a certificate.
	// RFC 8555 Section 7.6.
	Revoke(ctx context.Context, req *RevokeRequest) (*RevokeResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new certificate client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Get retrieves a certificate from the ACME server.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	resp := &GetResponse{
		Nonce:          client.ExtractNonce(raw),
		AlternateLinks: client.ExtractLinks(raw),
	}

	// PEM responses contain the certificate chain as raw body
	if client.IsPEMResponse(raw) {
		body := client.ExtractBody(raw)
		if body != nil {
			resp.Chain = string(body)
		}
		return resp, nil
	}

	// JSON responses contain certificate metadata
	cert := &Certificate{}
	if err := client.MapResponse(raw, cert); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "certificate.Get",
			"failed to decode certificate response")
	}
	resp.Certificate = cert

	return resp, nil
}

// Revoke revokes a certificate.
func (c *acmeClient) Revoke(ctx context.Context, req *RevokeRequest) (*RevokeResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "revoke", req)
	if err != nil {
		return nil, err
	}

	return &RevokeResponse{
		Nonce: client.ExtractNonce(raw),
	}, nil
}
