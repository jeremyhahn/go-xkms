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

package workflow

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// Register creates a new ACME account or retrieves an existing one.
func (w *workflow) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	const op = "workflow.Register"

	if req == nil {
		return nil, errors.NewInvalidInput(op, "register request cannot be nil")
	}
	if req.Email == "" {
		return nil, errors.NewInvalidInput(op, "email is required")
	}

	contact := []string{fmt.Sprintf("mailto:%s", req.Email)}

	resp, err := w.client.Account().Create(ctx, &account.CreateRequest{
		Contact:              contact,
		TermsOfServiceAgreed: req.TermsOfServiceAgreed,
	})
	if err != nil {
		return nil, WrapRegistrationError(err, op, "failed to create account")
	}

	if resp.Account == nil {
		return nil, NewRegistrationError(op, "server returned nil account")
	}

	return &RegisterResponse{
		AccountURL: resp.Location,
		Status:     string(resp.Account.Status),
		Contact:    resp.Account.Contact,
	}, nil
}
