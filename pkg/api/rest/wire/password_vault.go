// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package wire

import (
	"context"
	"net/http"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Personal-vault REST paths. The server's route table (pkg/api/rest/routes.go)
// registers the same paths, with an {id} placeholder for a factor.
const (
	// PasswordVaultPath is the caller's vault status.
	PasswordVaultPath = "/api/v1/password-vault"

	// PasswordVaultFactorsPath enrolls a factor.
	PasswordVaultFactorsPath = PasswordVaultPath + "/factors"

	// PasswordVaultRecoverPath recovers the vault with the recovery code.
	PasswordVaultRecoverPath = PasswordVaultPath + "/recover"
)

// PasswordVaultFactorPath returns the path of one of the caller's factors.
func PasswordVaultFactorPath(id string) string {
	return PasswordVaultFactorsPath + "/" + url.PathEscape(id)
}

// PasswordVaultClient serves the personal-vault methods of
// transport.PasswordService over the REST routes. The REST and QUIC
// transports (QUIC serves the same router over HTTP/3) delegate to it with
// their own Requester. Every call acts on the caller's own vault, which the
// server takes from the authenticated identity.
type PasswordVaultClient struct {
	// Do performs the requests.
	Do Requester
}

// PasswordVaultStatus describes the caller's personal vault.
func (c PasswordVaultClient) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	var resp transport.PasswordVaultStatusResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, PasswordVaultPath, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordVaultEnroll enrolls a passphrase or passkey on the caller's vault.
func (c PasswordVaultClient) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.PasswordVaultEnrollResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, PasswordVaultFactorsPath, req.PasswordVaultCredential, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordVaultRotate replaces the secret of one of the caller's factors.
func (c PasswordVaultClient) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.PasswordVaultEnrollResponse
	if err := callJSON(ctx, c.Do, http.MethodPut, PasswordVaultFactorPath(req.FactorID), req.PasswordVaultCredential, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordVaultRemoveFactor removes one of the caller's factors.
func (c PasswordVaultClient) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, PasswordVaultFactorPath(req.FactorID), nil, nil)
}

// PasswordVaultRecover uses the caller's recovery code to enroll a new factor.
func (c PasswordVaultClient) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.PasswordVaultEnrollResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, PasswordVaultRecoverPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
