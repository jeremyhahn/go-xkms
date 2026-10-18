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

package xkms

import (
	"context"
	"encoding/base64"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// SubmitCredential submits a credential for manual mode.
// Returns ErrNotConfigured if the credential service is not wired.
//
// Submitted credentials are the platform's backend credentials (a PKCS#11
// PIN, a cloud KMS secret), sealed into the platform store, so only a
// system-tenant caller may submit one (qrdbsdk.IdentityIsSystemTenant, go-xkms#1226):
// a tenant-scoped caller is refused with a *TenantBindingError that reads as
// not-found.
func (s *XKMSService) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	credentialService := s.credentialService.load()
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, "submit credential", "")
	}
	if credentialService == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	if err := credentialService.SubmitCredential(ctx, req.Name, value); err != nil {
		return nil, err
	}

	return &transport.CredentialSubmitResponse{
		Status: "accepted",
	}, nil
}

// GetCredentialStrategy returns the configured credential strategy.
// Returns ErrNotConfigured if the credential service is not wired.
func (s *XKMSService) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	credentialService := s.credentialService.load()
	if credentialService == nil {
		return nil, ErrNotConfigured
	}

	return &transport.CredentialStrategyResponse{
		Strategy:   credentialService.Strategy(),
		AutoUnseal: credentialService.AutoUnsealAvailable(),
	}, nil
}

// ListCredentials returns the names of the platform's stored backend
// credentials. Values are never returned. Like SubmitCredential it is
// platform-scoped: the names describe the platform's own backends.
func (s *XKMSService) ListCredentials(ctx context.Context) ([]string, error) {
	credentialService := s.credentialService.load()
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, "list credentials", "")
	}
	if credentialService == nil {
		return nil, ErrNotConfigured
	}
	return credentialService.ListCredentials(ctx)
}
