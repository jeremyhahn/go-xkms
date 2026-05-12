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

package directory

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	serviceName = "directory"
)

// Client provides ACME directory operations as defined in RFC 8555.
type Client interface {
	// Get retrieves the ACME directory resource.
	// RFC 8555 Section 7.1.1.
	Get(ctx context.Context, req *GetRequest) (*GetResponse, error)
}

// acmeClient implements the Client interface.
type acmeClient struct {
	transport transport.Transport
}

// NewClient creates a new directory client with the given transport.
func NewClient(t transport.Transport) Client {
	return &acmeClient{transport: t}
}

// Get retrieves the ACME directory resource.
func (c *acmeClient) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
	raw, err := c.transport.Request(ctx, serviceName, "get", req)
	if err != nil {
		return nil, err
	}

	dir := &Directory{}
	if err := client.MapResponse(raw, dir); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "directory.Get",
			"failed to decode directory response")
	}

	return &GetResponse{
		Directory: dir,
		Nonce:     client.ExtractNonce(raw),
	}, nil
}
