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
	"log/slog"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// migrationStartGrace is the delay before an asynchronous enable-encryption
// migration begins, giving the transport handler time to flush its
// acknowledgement response before a system-scope migration tears down and
// reopens the barrier the request was served on.
const migrationStartGrace = 750 * time.Millisecond

// EncryptionMigrator enables at-rest encryption on a previously-unencrypted
// barrier by migrating it to a keyed strategy in place. It is the canonical
// go-qrdb SDK interface (satisfied by the embedded *node.Node); aliased here so
// the xkms servicer keeps a local name for its field/setter without redeclaring
// the contract.
type EncryptionMigrator = qrdbsdk.EncryptionMigrator

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
	BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error)
	BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error)
	BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error
	BarrierDeleteRecoveryKeys(ctx context.Context) error
	BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error)
	BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error)
	BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error)
}

// BarrierInitialize initializes the encryption barrier with a secret.
func (s *XKMSService) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.Initialize(ctx, seal.Credentials{Secret: []byte(req.Secret)})
}

// BarrierUnseal unseals the encryption barrier using a secret.
func (s *XKMSService) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if s.barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.barrier.Unseal(ctx, seal.Credentials{Secret: []byte(req.Secret)})
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
//
// Share material is never returned: qrdb's share-free seal contract seals each
// share to an enrolled Security Officer via the CeremonyDistributor, and
// officers claim their shares individually using their mTLS certificate. Only
// the threshold/total metadata is reported.
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
	result, err := s.barrier.InitializeShamir(ctx, seal.Credentials{Secret: []byte(req.Secret)})
	if err != nil {
		return nil, err
	}
	return &transport.BarrierInitializeShamirResponse{
		Threshold:   result.Threshold,
		TotalShares: result.TotalShares,
		ShareCount:  result.ShareCount,
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

// BarrierRekey generates new Shamir shares with a new threshold configuration.
// New shares are sealed to enrolled Security Officers via the
// CeremonyDistributor and are never returned; only the threshold/total
// metadata is reported.
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
		Threshold:   result.Threshold,
		TotalShares: result.TotalShares,
		ShareCount:  result.ShareCount,
	}, nil
}

// BarrierGenerateRecoveryKeys generates disaster recovery keys for the barrier.
// Recovery shares are sealed to enrolled recovery officers via the
// CeremonyDistributor and are never returned; only the threshold/total
// metadata is reported.
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
		Threshold:   result.Threshold,
		TotalShares: result.TotalShares,
		ShareCount:  result.ShareCount,
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

// BarrierEnableEncryption enables at-rest encryption on a previously-unencrypted
// (none-strategy) barrier by migrating its data to a keyed strategy in place. An
// empty TenantID targets the system barrier (admin authority); a non-empty
// TenantID targets that tenant's dedicated barrier.
//
// The migration runs asynchronously: a system-scope migration tears down and
// reopens the barrier this request is served on, so the request is validated
// synchronously (bad input is surfaced to the caller immediately) and the
// migration itself is launched in the background after a short grace period.
// Clients poll BarrierStatus and observe completion when the reported strategy
// changes from "none" to the keyed target.
func (s *XKMSService) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if s.encMigrator == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	scope := qrdbsdk.BarrierScope{Kind: qrdbsdk.ScopeSystem}
	if req.TenantID != "" {
		scope = qrdbsdk.BarrierScope{Kind: qrdbsdk.ScopeTenant, TenantID: req.TenantID}
	}

	opts := qrdbsdk.MigrationOptions{
		TargetStrategy:  seal.StrategyID(req.Strategy),
		Mechanism:       migrationMechanism(req.Mechanism),
		Availability:    migrationAvailability(req.Availability),
		Credentials:     seal.Credentials{Secret: []byte(req.Passphrase)},
		ShamirThreshold: req.ShamirThreshold,
		ShamirTotal:     req.ShamirTotal,
	}
	// Validate synchronously so the caller gets immediate feedback on bad input;
	// the async path can no longer surface a structured error to this client.
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// Single-flight per scope: a second migration on the same barrier while one
	// is already running would race on the swap/in-place rewrite and corrupt it.
	scopeKey := string(scope.Kind) + "\x00" + scope.TenantID
	if _, inFlight := s.migrationsInFlight.LoadOrStore(scopeKey, struct{}{}); inFlight {
		return nil, ErrMigrationInProgress
	}

	migrator := s.encMigrator
	go func() {
		defer s.migrationsInFlight.Delete(scopeKey)
		time.Sleep(migrationStartGrace)
		if err := migrator.EnableEncryption(context.Background(), scope, opts); err != nil {
			slog.Error("enable-encryption migration failed",
				slog.String("scope", string(scope.Kind)),
				slog.String("tenant", scope.TenantID),
				slog.String("strategy", string(opts.TargetStrategy)),
				slog.Any("error", err))
		}
	}()

	return &transport.BarrierEnableEncryptionResponse{
		Status: "migration_started",
		Scope:  string(scope.Kind),
	}, nil
}

// migrationMechanism maps a request mechanism string to the typed mechanism,
// defaulting to swap (the crash-safe copy-and-swap approach) when unset or
// unrecognized.
func migrationMechanism(s string) qrdbsdk.MigrationMechanism {
	if s == string(qrdbsdk.MechanismInPlace) {
		return qrdbsdk.MechanismInPlace
	}
	return qrdbsdk.MechanismSwap
}

// migrationAvailability maps a request availability string to the typed value,
// defaulting to quiesced (block writes during migration) when unset or
// unrecognized.
func migrationAvailability(s string) qrdbsdk.MigrationAvailability {
	if s == string(qrdbsdk.AvailabilityOnline) {
		return qrdbsdk.AvailabilityOnline
	}
	return qrdbsdk.AvailabilityQuiesced
}
