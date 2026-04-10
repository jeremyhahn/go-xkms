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

// Package initialize implements the xkmsd initialization ceremony, managing
// barrier initialization, Shamir secret sharing for M-of-N quorum unsealing,
// SO officer certificate enrollment, and credential sealing.
//
// This package is a thin adapter layer over go-qrdb's ceremony package,
// bridging go-xkms's CA interface (ca.XKMSCA) to go-qrdb's CeremonyCA
// interface.
//
// The ceremony progresses through three states:
//   - StateAwaitingInit: barrier has not been initialized
//   - StateEnrolling: M-of-N mode; officers claim certs and shares
//   - StateOperational: system is ready for service
package initialize

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// --- Re-exported types from go-qrdb/sdk/go ceremony ---

// CeremonyState represents the current state of the init ceremony.
type CeremonyState = qrdbsdk.CeremonyState

const (
	// StateAwaitingInit indicates the barrier has not been initialized.
	StateAwaitingInit = qrdbsdk.StateAwaitingInit

	// StateEnrolling indicates M-of-N officer enrollment is in progress.
	StateEnrolling = qrdbsdk.StateEnrolling

	// StateOperational indicates the system is ready for service.
	StateOperational = qrdbsdk.StateOperational
)

// OfficerConfig holds the configuration for an SO officer in M-of-N mode.
type OfficerConfig = qrdbsdk.OfficerConfig

// CeremonyConfig holds the configuration for the init ceremony.
type CeremonyConfig = qrdbsdk.CeremonyConfig

// PendingCert tracks a pending SO certificate claim during the enrollment phase.
type PendingCert = qrdbsdk.PendingCert

// ChallengeResponse holds the challenge-response data for certificate claims.
type ChallengeResponse = qrdbsdk.ChallengeResponse

// InitResult contains the output of a successful initialization ceremony.
type InitResult = qrdbsdk.InitResult

// ClaimCertResult contains the result of a successful certificate claim.
type ClaimCertResult = qrdbsdk.ClaimCertResult

// SignCSRInitResult contains the result of a successful CSR signing
// during the init ceremony.
type SignCSRInitResult = qrdbsdk.SignCSRInitResult

// CredentialServicer is the interface the ceremony needs from the
// credential service to store sensitive credentials.
type CredentialServicer = qrdbsdk.CredentialServicer

// CeremonyService wraps go-qrdb's CeremonyService, providing the same API
// surface with go-xkms CA bridge support. The wrapped service handles all
// ceremony state management, Shamir splitting, and certificate operations.
type CeremonyService struct {
	inner *qrdbsdk.CeremonyService
}

// NewCeremonyService creates a new CeremonyService with the provided dependencies.
// The config, barrier, credService, and logger parameters are required.
// Constructor validation is performed on the config before delegating to the
// upstream ceremony service.
func NewCeremonyService(
	config *CeremonyConfig,
	barrier *seal.Barrier,
	credService CredentialServicer,
	logger *slog.Logger,
) (*CeremonyService, error) {
	// Perform config validation at construction time so callers get
	// immediate feedback on invalid parameters.
	if err := validateCeremonyConfig(config); err != nil {
		return nil, err
	}

	inner, err := qrdbsdk.NewCeremonyService(config, barrier, credService, logger)
	if err != nil {
		return nil, err
	}
	return &CeremonyService{inner: inner}, nil
}

// validateCeremonyConfig validates the ceremony configuration fields that
// the upstream constructor does not check (upstream defers to Initialize).
func validateCeremonyConfig(config *CeremonyConfig) error {
	if config == nil {
		// Let upstream handle nil config (returns ErrNilConfig).
		return nil
	}
	if config.SOPin == "" {
		return ErrInvalidSOPIN
	}
	if config.UserPin == "" {
		return ErrInvalidUserPIN
	}
	if config.Threshold >= 2 {
		if len(config.Officers) == 0 {
			return ErrNoOfficers
		}
		if config.Threshold > len(config.Officers) {
			return ErrInvalidThreshold
		}
		seen := make(map[string]struct{}, len(config.Officers))
		for _, officer := range config.Officers {
			if _, exists := seen[officer.Username]; exists {
				return ErrDuplicateUsername
			}
			seen[officer.Username] = struct{}{}
		}
	}
	return nil
}

// Initialize performs the init ceremony. It initializes the barrier with the
// SO credentials, optionally seals the User PIN via the credential service,
// and in M-of-N mode splits the barrier master key into Shamir shares and
// issues certificates for each officer. In single-admin mode, an SO admin
// certificate is issued and the system transitions directly to operational.
//
// The caInstance parameter is go-xkms's XKMSCA, which is adapted to go-qrdb's
// CeremonyCA interface via CAAdapter.
func (cs *CeremonyService) Initialize(ctx context.Context, caInstance ca.XKMSCA) (*InitResult, error) {
	adapter := NewCAAdapter(caInstance)
	result, err := cs.inner.Initialize(ctx, adapter)
	if err != nil {
		return nil, mapInitError(err)
	}

	// In M-of-N mode, the upstream issues an SO certificate during the
	// common initialization path but M-of-N mode should not expose it.
	// Clear the SO cert/key fields when in enrolling state.
	if result != nil && result.State == StateEnrolling {
		result.SOCertPEM = nil
		result.SOKeyPEM = nil
	}

	// Convert SPKI pin from base64 to hex encoding.
	if result != nil && result.SPKIPin != "" {
		hexPin, convErr := base64ToHexSPKIPin(result.SPKIPin)
		if convErr != nil {
			return nil, ErrInitFailed
		}
		result.SPKIPin = hexPin
	}

	return result, nil
}

// BeginClaimCert initiates the certificate claim process for the named officer.
// It generates a random nonce that the officer must sign with their CSR private
// key to prove possession. The challenge expires after 5 minutes.
func (cs *CeremonyService) BeginClaimCert(ctx context.Context, username string) (*ChallengeResponse, error) {
	return cs.inner.BeginClaimCert(ctx, username)
}

// CompleteClaimCert completes the certificate claim by verifying the officer's
// signature over the challenge nonce. On success, the officer's certificate
// and CA certificate are returned.
func (cs *CeremonyService) CompleteClaimCert(
	ctx context.Context,
	username string,
	nonceHex string,
	signature []byte,
) (*ClaimCertResult, error) {
	result, err := cs.inner.CompleteClaimCert(ctx, username, nonceHex, signature)
	if err != nil {
		return nil, mapClaimCertError(err)
	}
	return result, nil
}

// ClaimShare retrieves the sealed Shamir share for the named officer, deletes
// it from sealed storage, and returns the share as JSON. If all shares and
// certificates have been claimed, the ceremony transitions to operational.
func (cs *CeremonyService) ClaimShare(ctx context.Context, username string) ([]byte, error) {
	result, err := cs.inner.ClaimShare(ctx, username)
	if err != nil {
		return nil, mapClaimShareError(err)
	}
	return result, nil
}

// SignCSRInit signs a Certificate Signing Request during the init ceremony
// with SO PIN authorization. The CSR is validated (PEM decode, DER parse,
// signature verification) before being passed to the CA for signing.
func (cs *CeremonyService) SignCSRInit(ctx context.Context, username, soPin, csrPEM, role string) (*SignCSRInitResult, error) {
	// Validate the CSR before delegating to the upstream service.
	if err := validateCSR(csrPEM); err != nil {
		return nil, err
	}
	return cs.inner.SignCSRInit(ctx, username, soPin, []byte(csrPEM), role)
}

// State returns the current ceremony state. This method is safe for
// concurrent access.
func (cs *CeremonyService) State() CeremonyState {
	return cs.inner.State()
}

// SPKIPin computes and returns the hex-encoded SPKI pin from the CA certificate.
// The CA must have been set via Initialize before calling this method.
func (cs *CeremonyService) SPKIPin() (string, error) {
	pin, err := cs.inner.SPKIPin()
	if err != nil {
		return "", mapSPKIPinError(err)
	}

	// Convert base64 pin from upstream to hex encoding.
	hexPin, convErr := base64ToHexSPKIPin(pin)
	if convErr != nil {
		return "", ErrInitFailed
	}
	return hexPin, nil
}

// ThresholdRegistry returns the threshold registry for registering
// vendor-specific HSM threshold initializers.
func (cs *CeremonyService) ThresholdRegistry() *ThresholdRegistry {
	return cs.inner.ThresholdRegistry()
}

// Cleanup destroys all remaining shares and clears sensitive state.
// This should be called when the ceremony is abandoned or the service
// is shutting down.
func (cs *CeremonyService) Cleanup() {
	cs.inner.Cleanup()
}

// validateCSR validates a PEM-encoded CSR: decodes the PEM block, parses
// the DER content, and verifies the CSR self-signature.
func validateCSR(csrPEM string) error {
	if csrPEM == "" {
		// Let upstream handle the empty case (returns ErrMissingCSRPEM).
		return nil
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return ErrInvalidCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return ErrInvalidCSR
	}
	return nil
}

// base64ToHexSPKIPin converts a base64-encoded SPKI pin (as returned by
// go-qrdb) to a hex-encoded pin (as expected by go-xkms).
func base64ToHexSPKIPin(b64Pin string) (string, error) {
	raw := make([]byte, sha256.Size+4) // extra room for padding
	n, err := base64.StdEncoding.Decode(raw, []byte(b64Pin))
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(raw, []byte(b64Pin))
		if err != nil {
			return "", ErrInitFailed
		}
	}
	if n != sha256.Size {
		return "", ErrInitFailed
	}
	return hex.EncodeToString(raw[:n]), nil
}

// mapInitError maps upstream ceremony errors to xkms-layer errors.
// Errors from the Initialize flow that are typed (CertEncodeError,
// CABundleError, etc.) are wrapped with ErrInitFailed.
func mapInitError(err error) error {
	if err == nil {
		return nil
	}
	// Already an init-failed sentinel.
	if errors.Is(err, ErrInitFailed) {
		return err
	}
	// Already a known sentinel -- pass through.
	if errors.Is(err, ErrAlreadyInitialized) {
		return err
	}
	// Typed errors from M-of-N initialization should be ErrInitFailed.
	var certErr *CertEncodeError
	if errors.As(err, &certErr) {
		return ErrInitFailed
	}
	var csrErr *CSRParseError
	if errors.As(err, &csrErr) {
		// If the inner error is ErrInvalidCSR, return it directly so
		// callers can distinguish CSR validation failures.
		if errors.Is(csrErr.Err, ErrInvalidCSR) {
			return ErrInvalidCSR
		}
		return ErrInitFailed
	}
	var shamirErr *ShamirSplitError
	if errors.As(err, &shamirErr) {
		return ErrInitFailed
	}
	var shareErr *ShareStoreError
	if errors.As(err, &shareErr) {
		return ErrInitFailed
	}
	var bundleErr *CABundleError
	if errors.As(err, &bundleErr) {
		return ErrInitFailed
	}
	return err
}

// mapClaimCertError maps upstream CompleteClaimCert errors to xkms-layer errors.
// ErrChallengeNotFound is mapped to ErrChallengeVerificationFailed since from
// the xkms perspective, a missing challenge means the verification failed.
// CABundleError is mapped to ErrInitFailed.
func mapClaimCertError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrChallengeNotFound) {
		return ErrChallengeVerificationFailed
	}
	var bundleErr *CABundleError
	if errors.As(err, &bundleErr) {
		return ErrInitFailed
	}
	return err
}

// mapClaimShareError maps upstream ClaimShare errors to xkms-layer errors.
// ErrUserNotFound is mapped to ErrShareNotFound since the share lookup
// failed for the given username.
func mapClaimShareError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUserNotFound) {
		return ErrShareNotFound
	}
	return err
}

// mapSPKIPinError maps upstream SPKIPin errors to xkms-layer errors.
// ErrCANotInitialized and CABundleError are mapped to ErrInitFailed.
func mapSPKIPinError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrCANotInitialized) {
		return ErrInitFailed
	}
	var bundleErr *CABundleError
	if errors.As(err, &bundleErr) {
		return ErrInitFailed
	}
	return err
}
