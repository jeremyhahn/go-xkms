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

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "nonce"
)

// Client provides ACME nonce operations as defined in RFC 8555.
type Client interface {
	// New retrieves a new nonce from the ACME server.
	// RFC 8555 Section 7.2.
	New(ctx context.Context, req *NewRequest) (*NewResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new nonce client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// New retrieves a new nonce from the ACME server.
func (c *acmeClient) New(ctx context.Context, req *NewRequest) (*NewResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "new", req)
	if err != nil {
		return nil, err
	}

	return &NewResponse{
		Nonce: client.ExtractNonce(raw),
	}, nil
}
