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

package admin

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const orderService = "admin.order"

// OrderClient provides admin order management operations.
type OrderClient interface {
	// List lists orders with optional filtering.
	List(ctx context.Context, req *ListOrdersRequest) (*ListOrdersResponse, error)

	// Get retrieves an order by ID.
	Get(ctx context.Context, orderID uint64) (*OrderInfo, error)
}

type orderClient struct {
	transport transport.Transport
}

func newOrderClient(t transport.Transport) OrderClient {
	return &orderClient{transport: t}
}

// orderIDRequest wraps an order ID for transport serialization.
type orderIDRequest struct {
	OrderID uint64 `json:"orderId"`
}

func (c *orderClient) List(ctx context.Context, req *ListOrdersRequest) (*ListOrdersResponse, error) {
	if req == nil {
		req = &ListOrdersRequest{}
	}

	raw, err := c.transport.Request(ctx, orderService, "list", req)
	if err != nil {
		return nil, err
	}

	var orders []*OrderInfo
	var pagination *Pagination
	if err := mapListResponse(raw, "orders", &orders, &pagination); err != nil {
		return nil, err
	}

	return &ListOrdersResponse{
		Orders:     orders,
		Pagination: pagination,
	}, nil
}

func (c *orderClient) Get(ctx context.Context, orderID uint64) (*OrderInfo, error) {
	if orderID == 0 {
		return nil, errors.NewInvalidInput("admin.order.Get", "order ID cannot be zero")
	}

	raw, err := c.transport.Request(ctx, orderService, "get", &orderIDRequest{OrderID: orderID})
	if err != nil {
		return nil, err
	}

	var result OrderInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
