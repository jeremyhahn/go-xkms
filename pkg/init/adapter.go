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

package initialize

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// CeremonyAdapter wraps *CeremonyService and implements transport.InitCeremonyService.
// This adapter breaks the import cycle between pkg/xkms and pkg/init by
// converting CeremonyService types to transport types at the boundary.
type CeremonyAdapter struct {
	cs *CeremonyService
}

// NewCeremonyAdapter creates a new adapter wrapping the given CeremonyService.
func NewCeremonyAdapter(cs *CeremonyService) *CeremonyAdapter {
	return &CeremonyAdapter{cs: cs}
}

// GetInitStatus returns the current init ceremony state.
func (a *CeremonyAdapter) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	return &transport.InitStatusResponse{
		State: string(a.cs.State()),
	}, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (a *CeremonyAdapter) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	challenge, err := a.cs.BeginClaimCert(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	return &transport.ClaimCertBeginResponse{
		Nonce:     hex.EncodeToString(challenge.Nonce),
		Username:  challenge.Username,
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's
// signature over the challenge nonce.
func (a *CeremonyAdapter) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, ErrChallengeVerificationFailed
	}

	result, err := a.cs.CompleteClaimCert(ctx, req.Username, req.Nonce, signature)
	if err != nil {
		return nil, err
	}

	return &transport.ClaimCertCompleteResponse{
		CertPEM:   string(result.CertPEM),
		CACertPEM: string(result.CACertPEM),
	}, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (a *CeremonyAdapter) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	shareJSON, err := a.cs.ClaimShare(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	return &transport.ClaimShareResponse{
		Share: json.RawMessage(shareJSON),
	}, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
// It validates the request, verifies the SO PIN, parses the CSR, and
// delegates to the CeremonyService to sign via the CA.
func (a *CeremonyAdapter) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	result, err := a.cs.SignCSRInit(ctx, req.Username, req.SOPin, req.CSRPEM, req.Role)
	if err != nil {
		return nil, err
	}

	return &transport.SignCSRInitResponse{
		CertPEM: string(result.CertPEM),
	}, nil
}
