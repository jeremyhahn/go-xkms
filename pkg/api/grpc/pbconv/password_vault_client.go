// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package pbconv

import (
	"context"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// PasswordVaultClient serves the personal-vault methods of
// transport.PasswordService over a generated xkms.v1 client. The gRPC and
// Unix-socket transports, which both speak the generated protocol, delegate
// to it once they hold a connection. Errors are the server's gRPC status
// errors, unchanged. Every call acts on the caller's own vault, which the
// server takes from the authenticated identity.
type PasswordVaultClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// PasswordVaultStatus describes the caller's personal vault.
func (c PasswordVaultClient) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	resp, err := c.Client.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	if err != nil {
		return nil, err
	}
	return VaultStatusFromPB(resp), nil
}

// PasswordVaultEnroll enrolls a passphrase or passkey on the caller's vault.
func (c PasswordVaultClient) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{
		Credential: VaultCredentialToPB(req.PasswordVaultCredential),
	})
	if err != nil {
		return nil, err
	}
	return VaultEnrollResponseFromPB(resp), nil
}

// PasswordVaultRotate replaces the secret of one of the caller's factors.
func (c PasswordVaultClient) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{
		FactorId:   req.FactorID,
		Credential: VaultCredentialToPB(req.PasswordVaultCredential),
	})
	if err != nil {
		return nil, err
	}
	return VaultEnrollResponseFromPB(resp), nil
}

// PasswordVaultRemoveFactor removes one of the caller's factors.
func (c PasswordVaultClient) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: req.FactorID})
	return err
}

// PasswordVaultRecover uses the caller's recovery code to enroll a new
// factor.
func (c PasswordVaultClient) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.PasswordVaultRecover(ctx, &pb.PasswordVaultRecoverRequest{
		RecoveryCode: req.RecoveryCode,
		Credential:   VaultCredentialToPB(req.PasswordVaultCredential),
	})
	if err != nil {
		return nil, err
	}
	return VaultEnrollResponseFromPB(resp), nil
}
