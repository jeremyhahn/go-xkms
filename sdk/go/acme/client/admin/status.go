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

package admin

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const statusService = "admin.status"

// StatusClient provides CA status and statistics operations.
type StatusClient interface {
	// Status returns the current CA status.
	Status(ctx context.Context) (*CAStatus, error)

	// Stats returns CA statistics.
	Stats(ctx context.Context) (*CAStats, error)
}

type statusClient struct {
	transport transport.Transport
}

func newStatusClient(t transport.Transport) StatusClient {
	return &statusClient{transport: t}
}

func (c *statusClient) Status(ctx context.Context) (*CAStatus, error) {
	raw, err := c.transport.Request(ctx, statusService, "status", nil)
	if err != nil {
		return nil, err
	}

	var result CAStatus
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *statusClient) Stats(ctx context.Context) (*CAStats, error) {
	raw, err := c.transport.Request(ctx, statusService, "stats", nil)
	if err != nil {
		return nil, err
	}

	var result CAStats
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
