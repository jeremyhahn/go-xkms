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

package admin

import (
	"context"
	"fmt"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// CeremonyNotAvailableError is returned when a ceremony operation is attempted
// but the ceremony client is not configured.
type CeremonyNotAvailableError struct {
	Operation string
}

// Error implements the error interface.
func (e *CeremonyNotAvailableError) Error() string {
	return fmt.Sprintf("admin: ceremony operation %q not available — ceremony client not configured", e.Operation)
}

// CeremonyError wraps an underlying ceremony error with context.
type CeremonyError struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e *CeremonyError) Error() string {
	return fmt.Sprintf("admin: ceremony %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *CeremonyError) Unwrap() error {
	return e.Err
}

// CeremonyInitializeRequest holds the parameters for starting the initialization ceremony.
type CeremonyInitializeRequest struct {
	SOPin                  string                   `json:"so_pin"`
	UserPin                string                   `json:"user_pin"`
	CredentialSealStrategy string                   `json:"credential_seal_strategy,omitempty"`
	Threshold              int                      `json:"threshold"`
	Officers               []CeremonyOfficerRequest `json:"officers,omitempty"`
	Hostname               string                   `json:"hostname,omitempty"`
	SANs                   []string                 `json:"sans,omitempty"`
}

// CeremonyOfficerRequest describes a single security officer for M-of-N initialization.
type CeremonyOfficerRequest struct {
	Username string `json:"username"`
	CSRPEM   string `json:"csr_pem"`
}

// CeremonyInitializeResponse returns the result of a successful ceremony initialization.
type CeremonyInitializeResponse struct {
	SPKIPin    string `json:"spki_pin"`
	CACertPEM  string `json:"ca_cert_pem"`
	TLSCertPEM string `json:"tls_cert_pem"`
	SOCertPEM  string `json:"so_cert_pem,omitempty"`
	SOKeyPEM   string `json:"so_key_pem,omitempty"`
	State      string `json:"state"`
	ShareCount int    `json:"share_count"`
}

// CeremonyStatusResponse describes the current state of the ceremony.
type CeremonyStatusResponse struct {
	State   string `json:"state"`
	SPKIPin string `json:"spki_pin,omitempty"`
}

// ClaimCertBeginRequest initiates a certificate claim challenge for an officer.
type ClaimCertBeginRequest struct {
	Username string `json:"username"`
}

// ClaimCertBeginResponse returns the challenge nonce that the officer must sign.
type ClaimCertBeginResponse struct {
	NonceHex  string `json:"nonce_hex"`
	ExpiresAt string `json:"expires_at"`
}

// ClaimCertCompleteRequest completes a certificate claim by submitting the signed nonce.
type ClaimCertCompleteRequest struct {
	Username  string `json:"username"`
	NonceHex  string `json:"nonce_hex"`
	Signature string `json:"signature"`
}

// ClaimCertCompleteResponse returns the issued certificate after a successful challenge-response.
type ClaimCertCompleteResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// ClaimShareRequest requests the Shamir share for an officer who has claimed their certificate.
type ClaimShareRequest struct {
	Username string `json:"username"`
}

// ClaimShareResponse returns the officer's Shamir share.
type ClaimShareResponse struct {
	ShareJSON string `json:"share_json"`
}

// SignCSRRequest submits a CSR for signing during or after the ceremony.
type SignCSRRequest struct {
	Username string `json:"username"`
	SOPin    string `json:"so_pin"`
	CSRPEM   string `json:"csr_pem"`
	Role     string `json:"role"`
}

// SignCSRResponse returns the signed certificate.
type SignCSRResponse struct {
	CertPEM string `json:"cert_pem"`
}

// CeremonyService defines the interface for M-of-N initialization ceremony operations.
// The ceremony is required when the barrier uses Shamir secret sharing and
// coordinates security officer enrollment, certificate issuance, and share distribution.
type CeremonyService interface {
	// InitializeCeremony starts the initialization ceremony with the provided configuration.
	InitializeCeremony(ctx context.Context, req *CeremonyInitializeRequest) (*CeremonyInitializeResponse, error)
	// CeremonyStatus returns the current ceremony state.
	CeremonyStatus(ctx context.Context) (*CeremonyStatusResponse, error)
	// BeginClaimCert starts a certificate claim challenge for the named officer.
	BeginClaimCert(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error)
	// CompleteClaimCert completes a certificate claim by submitting the signed nonce.
	CompleteClaimCert(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error)
	// ClaimShare retrieves the Shamir share for an officer who has claimed their certificate.
	ClaimShare(ctx context.Context, req *ClaimShareRequest) (*ClaimShareResponse, error)
	// SignCSR submits a CSR for signing during or after the ceremony.
	SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error)
	// CAAdapter returns the CeremonyCA adapter that bridges go-xkms's CA to
	// go-qrdb's CeremonyCA interface. Returns nil when no CA was provided.
	// Use this to configure the embedded QRDB transport via embedded.WithCeremonyCA.
	CAAdapter() qrdbsdk.CeremonyCA
}

// Ensure ceremonyService implements CeremonyService at compile time.
var _ CeremonyService = (*ceremonyService)(nil)

type ceremonyService struct {
	ceremony  db.CeremonyClient
	caAdapter *caAdapter
	logger    *slog.Logger
}

// trustedCAProvider is implemented by *ca.CA and exposes the underlying TrustedCA.
type trustedCAProvider interface {
	TrustedCA() xkmssdk.TrustedCA
}

// NewCeremonyService creates a new ceremony service instance.
//
// The ceremony parameter is the CeremonyClient from the QRDB service (via service.Ceremony()).
// The certificateAuthority parameter provides the CA used during officer enrollment.
// When it implements trustedCAProvider (i.e. is a *ca.CA), the underlying TrustedCA is
// wrapped in a caAdapter so callers can pass it to the embedded QRDB transport via
// embedded.WithCeremonyCA.
//
// When ceremony is nil the service is constructed but all operations return
// CeremonyNotAvailableError, which allows callers to check availability without
// a nil pointer dereference.
func NewCeremonyService(
	ceremony db.CeremonyClient,
	certificateAuthority ca.TCGCA,
	logger *slog.Logger,
) CeremonyService {
	svc := &ceremonyService{
		ceremony: ceremony,
		logger:   logger,
	}
	if p, ok := certificateAuthority.(trustedCAProvider); ok {
		svc.caAdapter = newCAAdapter(p.TrustedCA())
	}
	return svc
}

// CAAdapter returns the CeremonyCA adapter that bridges go-xkms's CA to
// go-qrdb's CeremonyCA interface. Returns nil when no CA was provided or the CA
// does not expose an underlying TrustedCA.
func (s *ceremonyService) CAAdapter() qrdbsdk.CeremonyCA {
	if s.caAdapter == nil {
		return nil
	}
	return s.caAdapter
}

// requireCeremony returns a CeremonyNotAvailableError if the ceremony client is nil.
func (s *ceremonyService) requireCeremony(operation string) error {
	if s.ceremony == nil {
		return &CeremonyNotAvailableError{Operation: operation}
	}
	return nil
}

// InitializeCeremony starts the initialization ceremony with the provided configuration.
func (s *ceremonyService) InitializeCeremony(ctx context.Context, req *CeremonyInitializeRequest) (*CeremonyInitializeResponse, error) {
	if err := s.requireCeremony("initialize"); err != nil {
		return nil, err
	}

	officers := make([]db.CeremonyOfficerRequest, len(req.Officers))
	for i, o := range req.Officers {
		officers[i] = db.CeremonyOfficerRequest{
			Username: o.Username,
			CSRPEM:   o.CSRPEM,
		}
	}

	resp, err := s.ceremony.CeremonyInitialize(ctx, &db.CeremonyInitializeRequest{
		SOPin:                  req.SOPin,
		UserPin:                req.UserPin,
		CredentialSealStrategy: req.CredentialSealStrategy,
		Threshold:              req.Threshold,
		Officers:               officers,
		Hostname:               req.Hostname,
		SANs:                   req.SANs,
	})
	if err != nil {
		return nil, &CeremonyError{Operation: "initialize", Err: err}
	}

	s.logger.Info("ceremony initialized",
		slog.String("state", resp.State),
		slog.Int("share_count", resp.ShareCount))

	return &CeremonyInitializeResponse{
		SPKIPin:    resp.SPKIPin,
		CACertPEM:  resp.CACertPEM,
		TLSCertPEM: resp.TLSCertPEM,
		SOCertPEM:  resp.SOCertPEM,
		SOKeyPEM:   resp.SOKeyPEM,
		State:      resp.State,
		ShareCount: resp.ShareCount,
	}, nil
}

// CeremonyStatus returns the current ceremony state.
func (s *ceremonyService) CeremonyStatus(ctx context.Context) (*CeremonyStatusResponse, error) {
	if err := s.requireCeremony("status"); err != nil {
		return nil, err
	}

	resp, err := s.ceremony.CeremonyStatus(ctx)
	if err != nil {
		return nil, &CeremonyError{Operation: "status", Err: err}
	}

	return &CeremonyStatusResponse{
		State:   resp.State,
		SPKIPin: resp.SPKIPin,
	}, nil
}

// BeginClaimCert starts a certificate claim challenge for the named officer.
func (s *ceremonyService) BeginClaimCert(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error) {
	if err := s.requireCeremony("begin-claim-cert"); err != nil {
		return nil, err
	}

	resp, err := s.ceremony.CeremonyClaimCertBegin(ctx, &db.ClaimCertBeginRequest{
		Username: req.Username,
	})
	if err != nil {
		return nil, &CeremonyError{Operation: "begin-claim-cert", Err: err}
	}

	s.logger.Info("ceremony claim cert begun",
		slog.String("username", req.Username),
		slog.String("expires_at", resp.ExpiresAt))

	return &ClaimCertBeginResponse{
		NonceHex:  resp.NonceHex,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

// CompleteClaimCert completes a certificate claim by submitting the signed nonce.
func (s *ceremonyService) CompleteClaimCert(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error) {
	if err := s.requireCeremony("complete-claim-cert"); err != nil {
		return nil, err
	}

	resp, err := s.ceremony.CeremonyClaimCertComplete(ctx, &db.ClaimCertCompleteRequest{
		Username:  req.Username,
		NonceHex:  req.NonceHex,
		Signature: req.Signature,
	})
	if err != nil {
		return nil, &CeremonyError{Operation: "complete-claim-cert", Err: err}
	}

	s.logger.Info("ceremony claim cert completed",
		slog.String("username", req.Username))

	return &ClaimCertCompleteResponse{
		CertPEM:   resp.CertPEM,
		CACertPEM: resp.CACertPEM,
	}, nil
}

// ClaimShare retrieves the Shamir share for an officer who has claimed their certificate.
func (s *ceremonyService) ClaimShare(ctx context.Context, req *ClaimShareRequest) (*ClaimShareResponse, error) {
	if err := s.requireCeremony("claim-share"); err != nil {
		return nil, err
	}

	resp, err := s.ceremony.CeremonyClaimShare(ctx, &db.ClaimShareRequest{
		Username: req.Username,
	})
	if err != nil {
		return nil, &CeremonyError{Operation: "claim-share", Err: err}
	}

	s.logger.Info("ceremony share claimed",
		slog.String("username", req.Username))

	return &ClaimShareResponse{
		ShareJSON: resp.ShareJSON,
	}, nil
}

// SignCSR submits a CSR for signing during or after the ceremony.
func (s *ceremonyService) SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error) {
	if err := s.requireCeremony("sign-csr"); err != nil {
		return nil, err
	}

	resp, err := s.ceremony.CeremonySignCSR(ctx, &db.SignCSRInitRequest{
		Username: req.Username,
		SOPin:    req.SOPin,
		CSRPEM:   req.CSRPEM,
		Role:     req.Role,
	})
	if err != nil {
		return nil, &CeremonyError{Operation: "sign-csr", Err: err}
	}

	s.logger.Info("ceremony CSR signed",
		slog.String("username", req.Username),
		slog.String("role", req.Role))

	return &SignCSRResponse{
		CertPEM: resp.CertPEM,
	}, nil
}
