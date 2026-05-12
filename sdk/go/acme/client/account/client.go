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

package account

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "account"
)

// Client provides ACME account operations as defined in RFC 8555.
type Client interface {
	// Create creates a new ACME account or returns an existing one.
	// RFC 8555 Section 7.3.
	Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error)

	// Get retrieves an existing ACME account.
	// RFC 8555 Section 7.3.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

	// Update updates an existing ACME account.
	// RFC 8555 Section 7.3.2.
	Update(ctx context.Context, req *UpdateRequest) (*UpdateResponse, error)

	// Deactivate deactivates an ACME account.
	// RFC 8555 Section 7.3.6.
	Deactivate(ctx context.Context, req *DeactivateRequest) (*DeactivateResponse, error)

	// KeyChange changes the public key associated with an account.
	// RFC 8555 Section 7.3.5.
	KeyChange(ctx context.Context, req *KeyChangeRequest) (*KeyChangeResponse, error)
}

// client implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new account client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Create creates a new ACME account or returns an existing one.
func (c *acmeClient) Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "create", req)
	if err != nil {
		return nil, err
	}

	acct := &Account{}
	if err := client.MapResponse(raw, acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "account.Create",
			"failed to decode account response")
	}

	return &CreateResponse{
		Account:  acct,
		Location: client.ExtractLocation(raw),
		Nonce:    client.ExtractNonce(raw),
	}, nil
}

// Get retrieves an existing ACME account.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	acct := &Account{}
	if err := client.MapResponse(raw, acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "account.Get",
			"failed to decode account response")
	}

	return &GetResponse{
		Account: acct,
		Nonce:   client.ExtractNonce(raw),
	}, nil
}

// Update updates an existing ACME account.
func (c *acmeClient) Update(ctx context.Context, req *UpdateRequest) (*UpdateResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "update", req)
	if err != nil {
		return nil, err
	}

	acct := &Account{}
	if err := client.MapResponse(raw, acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "account.Update",
			"failed to decode account response")
	}

	return &UpdateResponse{
		Account: acct,
		Nonce:   client.ExtractNonce(raw),
	}, nil
}

// Deactivate deactivates an ACME account.
func (c *acmeClient) Deactivate(ctx context.Context, req *DeactivateRequest) (*DeactivateResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "deactivate", req)
	if err != nil {
		return nil, err
	}

	acct := &Account{}
	if err := client.MapResponse(raw, acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "account.Deactivate",
			"failed to decode account response")
	}

	return &DeactivateResponse{
		Account: acct,
		Nonce:   client.ExtractNonce(raw),
	}, nil
}

// KeyChange changes the public key associated with an account.
func (c *acmeClient) KeyChange(ctx context.Context, req *KeyChangeRequest) (*KeyChangeResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "keychange", req)
	if err != nil {
		return nil, err
	}

	acct := &Account{}
	if err := client.MapResponse(raw, acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "account.KeyChange",
			"failed to decode account response")
	}

	return &KeyChangeResponse{
		Account: acct,
		Nonce:   client.ExtractNonce(raw),
	}, nil
}
