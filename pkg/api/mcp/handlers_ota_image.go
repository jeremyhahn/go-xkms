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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// OTAImageKeyParams names a trusted-firmware board's OTA image-signing key
// for xkms.createOTAImageKey and xkms.rotateOTAImageKey.
type OTAImageKeyParams struct {
	BoardID string `json:"board_id"`
	Backend string `json:"backend"`
	// Algorithm is "ES256" or empty; any other value is refused.
	Algorithm string `json:"algorithm,omitempty"`
}

// OTAImageSignParams represents parameters for xkms.signOTAImage.
type OTAImageSignParams struct {
	BoardID string `json:"board_id"`
	Backend string `json:"backend"`
	Data    []byte `json:"data"`
	// DataIsDigest states that Data is already the SHA-256 digest.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
}

// handleCreateOTAImageKey creates the ES256 OTA image-signing key of one
// trusted-firmware board.
func (s *Server) handleCreateOTAImageKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params OTAImageKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{
		Backend:   params.Backend,
		BoardID:   params.BoardID,
		Algorithm: params.Algorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return GenerateKeyResult{KeyID: resp.KeyID, PublicKeyPEM: resp.PublicKeyPEM}, nil
}

// handleRotateOTAImageKey creates the next version of a board's OTA
// image-signing key and makes it current; earlier versions keep verifying.
func (s *Server) handleRotateOTAImageKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params OTAImageKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{
		Backend:   params.Backend,
		BoardID:   params.BoardID,
		Algorithm: params.Algorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return RotateKeyResult{
		KeyID:                      resp.KeyID,
		PublicKeyPEM:               resp.PublicKeyPEM,
		KeyType:                    resp.KeyType,
		KeyVersion:                 resp.KeyVersion,
		CertificateReissueRequired: resp.CertificateReissueRequired,
	}, nil
}

// handleSignOTAImage signs an OTA image with the current version of its
// board's key, which the result's key_version names.
func (s *Server) handleSignOTAImage(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params OTAImageSignParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend:      params.Backend,
		BoardID:      params.BoardID,
		Data:         params.Data,
		DataIsDigest: params.DataIsDigest,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return SignResult{Signature: resp.Signature, Algorithm: resp.Algorithm, KeyVersion: resp.KeyVersion}, nil
}
