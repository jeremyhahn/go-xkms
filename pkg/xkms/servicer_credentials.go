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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// SubmitCredential submits a credential for manual mode.
// Returns ErrNotConfigured if the credential service is not wired.
func (s *XKMSService) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if s.credentialService == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	if err := s.credentialService.SubmitCredential(ctx, req.Name, value); err != nil {
		return nil, err
	}

	return &transport.CredentialSubmitResponse{
		Status: "accepted",
	}, nil
}

// GetCredentialStrategy returns the configured credential strategy.
// Returns ErrNotConfigured if the credential service is not wired.
func (s *XKMSService) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	if s.credentialService == nil {
		return nil, ErrNotConfigured
	}

	return &transport.CredentialStrategyResponse{
		Strategy:   s.credentialService.Strategy(),
		AutoUnseal: s.credentialService.AutoUnsealAvailable(),
	}, nil
}
