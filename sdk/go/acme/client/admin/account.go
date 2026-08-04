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

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const accountService = "admin.account"

// AdminAccountClient provides admin ACME account management operations.
type AdminAccountClient interface {
	// List lists ACME accounts with optional filtering.
	List(ctx context.Context, req *ListAccountsRequest) (*ListAccountsResponse, error)

	// Get retrieves an ACME account by ID.
	Get(ctx context.Context, accountID uint64) (*AccountInfo, error)

	// Disable disables an ACME account.
	Disable(ctx context.Context, accountID uint64) error
}

type adminAccountClient struct {
	transport transport.Transport
}

func newAdminAccountClient(t transport.Transport) AdminAccountClient {
	return &adminAccountClient{transport: t}
}

// accountIDRequest wraps an account ID for transport serialization.
type accountIDRequest struct {
	AccountID uint64 `json:"accountId"`
}

func (c *adminAccountClient) List(ctx context.Context, req *ListAccountsRequest) (*ListAccountsResponse, error) {
	if req == nil {
		req = &ListAccountsRequest{}
	}

	raw, err := c.transport.Request(ctx, accountService, "list", req)
	if err != nil {
		return nil, err
	}

	var accounts []*AccountInfo
	var pagination *Pagination
	if err := mapListResponse(raw, "accounts", &accounts, &pagination); err != nil {
		return nil, err
	}

	return &ListAccountsResponse{
		Accounts:   accounts,
		Pagination: pagination,
	}, nil
}

func (c *adminAccountClient) Get(ctx context.Context, accountID uint64) (*AccountInfo, error) {
	if accountID == 0 {
		return nil, errors.NewInvalidInput("admin.account.Get", "account ID cannot be zero")
	}

	raw, err := c.transport.Request(ctx, accountService, "get", &accountIDRequest{AccountID: accountID})
	if err != nil {
		return nil, err
	}

	var result AccountInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *adminAccountClient) Disable(ctx context.Context, accountID uint64) error {
	if accountID == 0 {
		return errors.NewInvalidInput("admin.account.Disable", "account ID cannot be zero")
	}

	_, err := c.transport.Request(ctx, accountService, "disable", &accountIDRequest{AccountID: accountID})
	return err
}
