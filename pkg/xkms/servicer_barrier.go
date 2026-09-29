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
//
// Every method but BarrierEnableEncryption operates the system barrier, which
// protects every tenant, so it is platform-scoped (requirePlatformScope,
// go-xkms#1227): a tenant-scoped caller is refused with a *TenantBindingError
// that reads as not-found. BarrierEnableEncryption names its target barrier
// and binds it instead (bindTenantTarget); the per-tenant barrier operations
// live on TenantServicer and keep their own binding.
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
	if req == nil {
		return ErrNilRequest
	}
	// req.Secret is borrowed request material; CredentialsFor copies it into
	// protected memory and leaves the request field intact.
	creds, err := seal.CredentialsFor([]byte(req.Secret))
	if err != nil {
		return err
	}
	defer creds.Secret.Destroy()
	return s.BarrierInitializeWithCredentials(ctx, creds)
}

// BarrierInitializeWithCredentials initializes the system barrier with
// credentials the caller already holds in protected memory. It is the form a
// transport uses when its request decoder places the secret straight into a
// protected buffer (the REST password_b64 field), so the secret never exists
// as a Go string. The caller keeps ownership of creds and destroys it.
//
// The system barrier is platform-global: only a cross-tenant identity may
// operate it (requirePlatformScope).
func (s *XKMSService) BarrierInitializeWithCredentials(ctx context.Context, creds seal.Credentials) error {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier initialize", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	return barrier.Initialize(ctx, creds)
}

// BarrierUnseal unseals the encryption barrier using a secret.
func (s *XKMSService) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	// req.Secret is borrowed request material; CredentialsFor copies it into
	// protected memory and leaves the request field intact.
	creds, err := seal.CredentialsFor([]byte(req.Secret))
	if err != nil {
		return err
	}
	defer creds.Secret.Destroy()
	return s.BarrierUnsealWithCredentials(ctx, creds)
}

// BarrierUnsealWithCredentials unseals the system barrier with credentials
// the caller already holds in protected memory; see
// BarrierInitializeWithCredentials. The caller keeps ownership of creds.
func (s *XKMSService) BarrierUnsealWithCredentials(ctx context.Context, creds seal.Credentials) error {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier unseal", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	return barrier.Unseal(ctx, creds)
}

// BarrierSeal seals the encryption barrier, re-encrypting all data at rest.
func (s *XKMSService) BarrierSeal(ctx context.Context) error {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier seal", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	return barrier.Seal()
}

// BarrierStatus returns the current barrier status including seal state and strategy.
func (s *XKMSService) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier status", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	status := barrier.Status()
	resp := &transport.BarrierStatusResponse{
		Sealed:         status.Sealed,
		Strategy:       string(status.Strategy),
		HardwareBacked: status.HardwareBacked,
	}
	// An uninitialized barrier has no initialization time; the field is
	// omitted rather than rendered as the zero time.
	if !status.InitializedAt.IsZero() {
		resp.InitializedAt = status.InitializedAt.Format(time.RFC3339)
	}
	return resp, nil
}

// BarrierInitializeShamir initializes the barrier with Shamir secret sharing.
// A request that states a shape (a non-zero threshold or total) applies it to
// the barrier's Shamir configuration before initialization; a request that
// states none -- the REST, gRPC and MCP wire forms carry only the secret --
// initializes with the barrier's configured shape, which qrdb validates.
//
// Share material is never returned: qrdb's share-free seal contract seals each
// share to an enrolled Security Officer via the CeremonyDistributor, and
// officers claim their shares individually using their mTLS certificate. Only
// the threshold/total metadata is reported.
func (s *XKMSService) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier initialize shamir", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Threshold != 0 || req.TotalShares != 0 {
		barrier.SetShamirConfig(&seal.ShamirConfig{
			Threshold:   req.Threshold,
			TotalShares: req.TotalShares,
		})
	}
	// req.Secret is borrowed request material; CredentialsFor copies it into
	// protected memory and leaves the request field intact.
	creds, err := seal.CredentialsFor([]byte(req.Secret))
	if err != nil {
		return nil, err
	}
	defer creds.Secret.Destroy()
	result, err := barrier.InitializeShamir(ctx, creds)
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
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier unseal share", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	progress, err := barrier.UnsealWithShare(ctx, req.Share)
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
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier unseal shares", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return barrier.UnsealWithShares(ctx, req.Shares)
}

// BarrierRekey generates new Shamir shares with a new threshold configuration.
// New shares are sealed to enrolled Security Officers via the
// CeremonyDistributor and are never returned; only the threshold/total
// metadata is reported.
func (s *XKMSService) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier rekey", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	result, err := barrier.Rekey(ctx, req.Threshold, req.Total)
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
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier generate recovery keys", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	result, err := barrier.GenerateRecoveryKeys(ctx, req.Threshold, req.Total)
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
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier recover with keys", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return barrier.RecoverWithKeys(ctx, req.Keys)
}

// BarrierDeleteRecoveryKeys deletes all stored recovery keys.
func (s *XKMSService) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier delete recovery keys", ""); err != nil {
		return err
	}
	if barrier == nil {
		return ErrNotConfigured
	}
	return barrier.DeleteRecoveryKeys(ctx)
}

// BarrierHasRecoveryKeys checks whether recovery keys have been generated.
func (s *XKMSService) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier has recovery keys", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	hasKeys, err := barrier.HasRecoveryKeys(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.BarrierHasRecoveryKeysResponse{
		HasKeys: hasKeys,
	}, nil
}

// BarrierGenerateRootToken generates a root token using Shamir shares.
func (s *XKMSService) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	barrier := s.barrier.load()
	if err := requirePlatformScope(ctx, "barrier generate root token", ""); err != nil {
		return nil, err
	}
	if barrier == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	token, err := barrier.GenerateRootToken(ctx, req.Shares)
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
//
// The target is caller-supplied, so it is bound to the caller's tenant
// (bindTenantTarget): a tenant-scoped caller may migrate only its own tenant's
// barrier, and naming another tenant or the system barrier (empty TenantID) is
// refused with a *TenantBindingError that reads as not-found.
func (s *XKMSService) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if s.encMigrator == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := bindTenantTarget(ctx, "barrier enable encryption", req.TenantID); err != nil {
		return nil, err
	}

	scope := qrdbsdk.BarrierScope{Kind: qrdbsdk.ScopeSystem}
	if req.TenantID != "" {
		scope = qrdbsdk.BarrierScope{Kind: qrdbsdk.ScopeTenant, TenantID: req.TenantID}
	}

	// req.Passphrase is borrowed request material; CredentialsFor copies it
	// into protected memory and leaves the request field intact.
	creds, err := seal.CredentialsFor([]byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	opts := qrdbsdk.MigrationOptions{
		TargetStrategy:  seal.StrategyID(req.Strategy),
		Mechanism:       migrationMechanism(req.Mechanism),
		Availability:    migrationAvailability(req.Availability),
		Credentials:     creds,
		ShamirThreshold: req.ShamirThreshold,
		ShamirTotal:     req.ShamirTotal,
	}
	// Validate synchronously so the caller gets immediate feedback on bad input;
	// the async path can no longer surface a structured error to this client.
	if err := opts.Validate(); err != nil {
		creds.Secret.Destroy()
		return nil, err
	}

	// Single-flight per scope: a second migration on the same barrier while one
	// is already running would race on the swap/in-place rewrite and corrupt it.
	scopeKey := string(scope.Kind) + "\x00" + scope.TenantID
	if _, inFlight := s.migrationsInFlight.LoadOrStore(scopeKey, struct{}{}); inFlight {
		creds.Secret.Destroy()
		return nil, ErrMigrationInProgress
	}

	migrator := s.encMigrator
	// #nosec G118 -- the migration deliberately outlives the request: it is a
	// long-running background re-encryption tracked via migrationsInFlight,
	// and cancelling it on request completion would abort the rewrite midway.
	go func() {
		// The migration OWNS the credential from here: it outlives this
		// request, so destroying it earlier would pull the passphrase out
		// from under a running migration. The destroy belongs to the last
		// reader, which is this goroutine.
		defer creds.Secret.Destroy()
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
