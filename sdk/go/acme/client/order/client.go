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

package order

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "order"
)

// Client provides ACME order operations as defined in RFC 8555.
type Client interface {
	// Create creates a new ACME order for certificate issuance.
	// RFC 8555 Section 7.4.
	Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error)

	// Get retrieves an existing ACME order.
	// RFC 8555 Section 7.4.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

	// List retrieves a list of orders for an account.
	// RFC 8555 Section 7.1.2.1.
	List(ctx context.Context, req *ListRequest) (*ListResponse, error)

	// Finalize finalizes an order by submitting a CSR.
	// RFC 8555 Section 7.4.
	Finalize(ctx context.Context, req *FinalizeRequest) (*FinalizeResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new order client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Create creates a new ACME order for certificate issuance.
func (c *acmeClient) Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "create", req)
	if err != nil {
		return nil, err
	}

	ord := &Order{}
	if err := client.MapResponse(raw, ord); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "order.Create",
			"failed to decode order response")
	}

	return &CreateResponse{
		Order:    ord,
		Location: client.ExtractLocation(raw),
		Nonce:    client.ExtractNonce(raw),
	}, nil
}

// Get retrieves an existing ACME order.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	ord := &Order{}
	if err := client.MapResponse(raw, ord); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "order.Get",
			"failed to decode order response")
	}

	return &GetResponse{
		Order: ord,
		Nonce: client.ExtractNonce(raw),
	}, nil
}

// List retrieves a list of orders for an account.
func (c *acmeClient) List(ctx context.Context, req *ListRequest) (*ListResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "list", req)
	if err != nil {
		return nil, err
	}

	resp := &ListResponse{}
	if err := client.MapResponse(raw, resp); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "order.List",
			"failed to decode order list response")
	}

	resp.Nonce = client.ExtractNonce(raw)
	return resp, nil
}

// Finalize finalizes an order by submitting a CSR.
func (c *acmeClient) Finalize(ctx context.Context, req *FinalizeRequest) (*FinalizeResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "finalize", req)
	if err != nil {
		return nil, err
	}

	ord := &Order{}
	if err := client.MapResponse(raw, ord); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "order.Finalize",
			"failed to decode order response")
	}

	return &FinalizeResponse{
		Order:    ord,
		Location: client.ExtractLocation(raw),
		Nonce:    client.ExtractNonce(raw),
	}, nil
}
