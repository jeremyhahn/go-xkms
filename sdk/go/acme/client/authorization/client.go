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

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "authorization"
)

// Client provides ACME authorization operations as defined in RFC 8555.
type Client interface {
	// Get retrieves an existing ACME authorization.
	// RFC 8555 Section 7.5.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

	// Deactivate deactivates an authorization.
	// RFC 8555 Section 7.5.2.
	Deactivate(ctx context.Context, req *DeactivateRequest) (*DeactivateResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new authorization client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Get retrieves an existing ACME authorization.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	authz := &Authorization{}
	if err := client.MapResponse(raw, authz); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "authorization.Get",
			"failed to decode authorization response")
	}

	return &GetResponse{
		Authorization: authz,
		Nonce:         client.ExtractNonce(raw),
	}, nil
}

// Deactivate deactivates an authorization.
func (c *acmeClient) Deactivate(ctx context.Context, req *DeactivateRequest) (*DeactivateResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "deactivate", req)
	if err != nil {
		return nil, err
	}

	authz := &Authorization{}
	if err := client.MapResponse(raw, authz); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "authorization.Deactivate",
			"failed to decode authorization response")
	}

	return &DeactivateResponse{
		Authorization: authz,
		Nonce:         client.ExtractNonce(raw),
	}, nil
}
