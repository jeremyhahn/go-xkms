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

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "challenge"
)

// Client provides ACME challenge operations as defined in RFC 8555.
type Client interface {
	// Get retrieves an existing ACME challenge.
	// RFC 8555 Section 7.5.1.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

	// Respond responds to a challenge to trigger validation.
	// RFC 8555 Section 7.5.1.
	Respond(ctx context.Context, req *RespondRequest) (*RespondResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new challenge client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Get retrieves an existing ACME challenge.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	ch := &Challenge{}
	if err := client.MapResponse(raw, ch); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "challenge.Get",
			"failed to decode challenge response")
	}

	return &GetResponse{
		Challenge: ch,
		Nonce:     client.ExtractNonce(raw),
	}, nil
}

// Respond responds to a challenge to trigger validation.
func (c *acmeClient) Respond(ctx context.Context, req *RespondRequest) (*RespondResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "respond", req)
	if err != nil {
		return nil, err
	}

	ch := &Challenge{}
	if err := client.MapResponse(raw, ch); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "challenge.Respond",
			"failed to decode challenge response")
	}

	return &RespondResponse{
		Challenge: ch,
		Nonce:     client.ExtractNonce(raw),
	}, nil
}
