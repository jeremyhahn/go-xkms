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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// BarrierServicer defines operations for managing the encryption barrier
// that protects sensitive data at rest.
type BarrierServicer interface {
	BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error
	BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error
	BarrierSeal(ctx context.Context) error
	BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error)
	BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error)
	BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error)
	BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error
	BarrierShamirListShares(ctx context.Context) (*transport.BarrierShamirSharesResponse, error)
	BarrierShamirDeleteShare(ctx context.Context, req *transport.BarrierShamirDeleteShareRequest) error
	BarrierShamirDeleteAllShares(ctx context.Context) error
	BarrierShamirVerify(ctx context.Context) error
	BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error)
	BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error)
	BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error
	BarrierDeleteRecoveryKeys(ctx context.Context) error
	BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error)
	BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error)
}

// BarrierInitialize initializes the encryption barrier with a secret.
func (s *XKMSService) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.Initialize(ctx, seal.Credentials{Secret: req.Secret})
}

// BarrierUnseal unseals the encryption barrier using a secret.
func (s *XKMSService) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.Unseal(ctx, seal.Credentials{Secret: req.Secret})
}

// BarrierSeal seals the encryption barrier, re-encrypting all data at rest.
func (s *XKMSService) BarrierSeal(ctx context.Context) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	return s.barrier.Seal()
}

// BarrierStatus returns the current barrier status including seal state and strategy.
func (s *XKMSService) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	status := s.barrier.Status()
	return &transport.BarrierStatusResponse{
		Sealed:         status.Sealed,
		Strategy:       string(status.Strategy),
		HardwareBacked: status.HardwareBacked,
		InitializedAt:  status.InitializedAt.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

// BarrierInitializeShamir initializes the barrier with Shamir secret sharing.
// The request's threshold and total shares are applied to the barrier's Shamir
// configuration before initialization.
func (s *XKMSService) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	s.barrier.SetShamirConfig(&seal.ShamirConfig{
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
	})
	result, err := s.barrier.InitializeShamir(ctx, seal.Credentials{Secret: req.Secret})
	if err != nil {
		return nil, err
	}
	return &transport.BarrierInitializeShamirResponse{
		Shares:      result.Shares,
		Threshold:   result.Threshold,
		TotalShares: result.TotalShares,
	}, nil
}

// BarrierUnsealWithShare submits a single Shamir share for quorum-based unsealing.
func (s *XKMSService) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	progress, err := s.barrier.UnsealWithShare(ctx, req.Share)
	if err != nil {
		// Return progress alongside the error when available so the
		// caller can see quorum state even on duplicate share, etc.
		if progress != nil {
			return &transport.BarrierUnsealShareResponse{
				Required:  progress.Required,
				Submitted: progress.Submitted,
				Complete:  progress.Complete,
			}, err
		}
		return nil, err
	}
	return &transport.BarrierUnsealShareResponse{
		Required:  progress.Required,
		Submitted: progress.Submitted,
		Complete:  progress.Complete,
	}, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once for batch unsealing.
func (s *XKMSService) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.UnsealWithShares(ctx, req.Shares)
}

// BarrierShamirListShares returns metadata about the current Shamir shares.
func (s *XKMSService) BarrierShamirListShares(ctx context.Context) (*transport.BarrierShamirSharesResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return nil, seal.ErrShamirNotConfigured
	}
	count, err := shamirStrat.ShareCount(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierShamirSharesResponse{
		Count:     count,
		Threshold: shamirStrat.Threshold(),
		Total:     shamirStrat.TotalShares(),
	}, nil
}

// BarrierShamirDeleteShare deletes a specific Shamir share by index.
func (s *XKMSService) BarrierShamirDeleteShare(ctx context.Context, req *transport.BarrierShamirDeleteShareRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return seal.ErrShamirNotConfigured
	}
	return shamirStrat.DeleteShare(ctx, req.Index)
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (s *XKMSService) BarrierShamirDeleteAllShares(ctx context.Context) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return seal.ErrShamirNotConfigured
	}
	return shamirStrat.DeleteAllShares(ctx)
}

// BarrierShamirVerify verifies the integrity of the Shamir share configuration.
func (s *XKMSService) BarrierShamirVerify(ctx context.Context) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		return seal.ErrShamirNotConfigured
	}
	return shamirStrat.VerifyShares(ctx)
}

// BarrierRekey generates new Shamir shares with a new threshold configuration.
func (s *XKMSService) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	result, err := s.barrier.Rekey(ctx, req.Threshold, req.Total)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierRekeyResponse{
		Shares:      result.Shares,
		Threshold:   result.Threshold,
		TotalShares: result.TotalShares,
	}, nil
}

// BarrierGenerateRecoveryKeys generates disaster recovery keys for the barrier.
func (s *XKMSService) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	result, err := s.barrier.GenerateRecoveryKeys(ctx, req.Threshold, req.Total)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierRecoveryKeysResponse{
		Keys:      result.Shares,
		Threshold: result.Threshold,
		Total:     result.TotalShares,
	}, nil
}

// BarrierRecoverWithKeys performs disaster recovery using recovery keys.
func (s *XKMSService) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.RecoverWithKeys(ctx, req.Keys)
}

// BarrierDeleteRecoveryKeys deletes all stored recovery keys.
func (s *XKMSService) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	return s.barrier.DeleteRecoveryKeys(ctx)
}

// BarrierHasRecoveryKeys checks whether recovery keys have been generated.
func (s *XKMSService) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	hasKeys, err := s.barrier.HasRecoveryKeys(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierHasRecoveryKeysResponse{
		HasKeys: hasKeys,
	}, nil
}

// BarrierGenerateRootToken generates a root token using Shamir shares.
func (s *XKMSService) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if s.barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	token, err := s.barrier.GenerateRootToken(ctx, req.Shares)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierRootTokenResponse{
		Token:     token.Token,
		CreatedAt: token.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}
