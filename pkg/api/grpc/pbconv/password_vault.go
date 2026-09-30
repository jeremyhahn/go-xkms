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

package pbconv

import (
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// VaultCredentialToPB converts a personal-vault credential to the wire.
func VaultCredentialToPB(c transport.PasswordVaultCredential) *pb.PasswordVaultCredential {
	return &pb.PasswordVaultCredential{
		Factor:       c.Factor,
		Passphrase:   c.Passphrase,
		CredentialId: c.CredentialID,
		PrfSalt:      c.PRFSalt,
		Secret:       c.Secret,
		Label:        c.Label,
	}
}

// VaultCredentialFromPB converts a personal-vault credential from the wire.
// A nil credential is the zero credential, which the service refuses.
func VaultCredentialFromPB(c *pb.PasswordVaultCredential) transport.PasswordVaultCredential {
	if c == nil {
		return transport.PasswordVaultCredential{}
	}
	return transport.PasswordVaultCredential{
		Factor:       c.GetFactor(),
		Passphrase:   c.GetPassphrase(),
		CredentialID: c.GetCredentialId(),
		PRFSalt:      c.GetPrfSalt(),
		Secret:       c.GetSecret(),
		Label:        c.GetLabel(),
	}
}

// VaultFactorToPB converts an enrolled-factor description to the wire.
func VaultFactorToPB(f transport.PasswordVaultFactor) *pb.PasswordVaultFactor {
	return &pb.PasswordVaultFactor{
		Id:           f.ID,
		Factor:       f.Factor,
		Label:        f.Label,
		CreatedAt:    f.CreatedAt,
		CredentialId: f.CredentialID,
		PrfSalt:      f.PRFSalt,
	}
}

// VaultFactorFromPB converts an enrolled-factor description from the wire.
func VaultFactorFromPB(f *pb.PasswordVaultFactor) transport.PasswordVaultFactor {
	if f == nil {
		return transport.PasswordVaultFactor{}
	}
	return transport.PasswordVaultFactor{
		ID:           f.GetId(),
		Factor:       f.GetFactor(),
		Label:        f.GetLabel(),
		CreatedAt:    f.GetCreatedAt(),
		CredentialID: f.GetCredentialId(),
		PRFSalt:      f.GetPrfSalt(),
	}
}

// VaultStatusToPB converts a vault status to the wire.
func VaultStatusToPB(s *transport.PasswordVaultStatusResponse) *pb.PasswordVaultStatusResponse {
	factors := make([]*pb.PasswordVaultFactor, 0, len(s.Factors))
	for _, f := range s.Factors {
		factors = append(factors, VaultFactorToPB(f))
	}
	return &pb.PasswordVaultStatusResponse{
		Initialized: s.Initialized,
		Unlocked:    s.Unlocked,
		Factors:     factors,
	}
}

// VaultStatusFromPB converts a vault status from the wire.
func VaultStatusFromPB(s *pb.PasswordVaultStatusResponse) *transport.PasswordVaultStatusResponse {
	factors := make([]transport.PasswordVaultFactor, 0, len(s.GetFactors()))
	for _, f := range s.GetFactors() {
		factors = append(factors, VaultFactorFromPB(f))
	}
	return &transport.PasswordVaultStatusResponse{
		Initialized: s.GetInitialized(),
		Unlocked:    s.GetUnlocked(),
		Factors:     factors,
	}
}

// VaultEnrollResponseToPB converts an enrollment result to the wire.
func VaultEnrollResponseToPB(r *transport.PasswordVaultEnrollResponse) *pb.PasswordVaultEnrollResponse {
	return &pb.PasswordVaultEnrollResponse{
		Factor:       VaultFactorToPB(r.Factor),
		RecoveryCode: r.RecoveryCode,
	}
}

// VaultEnrollResponseFromPB converts an enrollment result from the wire.
func VaultEnrollResponseFromPB(r *pb.PasswordVaultEnrollResponse) *transport.PasswordVaultEnrollResponse {
	return &transport.PasswordVaultEnrollResponse{
		Factor:       VaultFactorFromPB(r.GetFactor()),
		RecoveryCode: r.GetRecoveryCode(),
	}
}
