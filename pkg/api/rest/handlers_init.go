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

package rest

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// initServicer defines the operations required by the init ceremony handlers.
// This interface decouples the REST layer from the concrete CeremonyService
// implementation. It is satisfied by *initialize.CeremonyService, the service
// layer the other transports reach through the transport.InitCeremonyService
// adapter; the handlers below never touch ceremony internals directly.
type initServicer interface {
	// State returns the current ceremony state.
	State() initialize.CeremonyState

	// BeginClaimCert begins the certificate claim challenge-response flow
	// for the named officer.
	BeginClaimCert(ctx context.Context, username string) (*initialize.ChallengeResponse, error)

	// CompleteClaimCert verifies the officer's signature over the challenge
	// nonce and returns the officer certificate and CA certificate on success.
	CompleteClaimCert(ctx context.Context, username, nonceHex string, signature []byte) (*initialize.ClaimCertResult, error)

	// BeginClaimShare starts the Shamir share claim challenge-response flow
	// for the named officer, binding the challenge to the caller's mTLS
	// certificate thumbprint.
	BeginClaimShare(ctx context.Context, username, callerCertThumbprint string) (*initialize.ChallengeResponse, error)

	// CompleteClaimShare verifies the officer's signature over the challenge
	// nonce and the caller's certificate thumbprint, then releases the sealed
	// Shamir share exactly once.
	CompleteClaimShare(ctx context.Context, username, nonceHex string, signature []byte, callerCertThumbprint string) (*initialize.ShareClaimResult, error)

	// SignCSRInit signs a CSR during the ceremony under SO PIN authorization
	// and returns the issued certificate.
	SignCSRInit(ctx context.Context, username, soPin, csrPEM, role string) (*initialize.SignCSRInitResult, error)

	// RegisterOfficer signs a Security Officer's CSR, binds them to the issued
	// certificate's thumbprint, and assigns a Shamir share index. It returns
	// NO share bytes: splitting happens later, at initialization.
	RegisterOfficer(ctx context.Context, req initialize.RegisterOfficerRequest) (*initialize.RegisterOfficerResult, error)

	// OfficerClaimStatus reports per-officer enrolment and claim state. It
	// never returns share material.
	OfficerClaimStatus(ctx context.Context) ([]*initialize.OfficerStatus, error)

	// EnrollExternalOfficer enrols an officer whose key material was issued by
	// an external CA rather than minted from a CSR by the ceremony CA.
	EnrollExternalOfficer(ctx context.Context, req initialize.EnrollExternalOfficerRequest) (*initialize.EnrollExternalOfficerResponse, error)
}

// InitStatusResponse is the response for the init ceremony status endpoint.
type InitStatusResponse struct {
	State string `json:"state"`
}

// ClaimCertBeginRequest is the request body for beginning a certificate claim.
type ClaimCertBeginRequest struct {
	Username string `json:"username"`
}

// ClaimCertBeginResponse is the response for a successful claim-cert begin.
type ClaimCertBeginResponse struct {
	Nonce     string    `json:"nonce"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClaimCertCompleteRequest is the request body for completing a certificate claim.
type ClaimCertCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // base64-encoded
}

// ClaimCertCompleteResponse is the response for a successful claim-cert complete.
type ClaimCertCompleteResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// ClaimShareBeginRequest is the request body for beginning a Shamir share
// claim. No thumbprint field exists: the handler derives the caller's
// thumbprint from the verified mTLS peer certificate so a client cannot assert
// another officer's identity.
type ClaimShareBeginRequest struct {
	Username string `json:"username"`
}

// ClaimShareBeginResponse is the response for a successful claim-share begin.
type ClaimShareBeginResponse struct {
	Nonce     string    `json:"nonce"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClaimShareCompleteRequest is the request body for completing a Shamir share
// claim.
type ClaimShareCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // base64-encoded
}

// ClaimShareCompleteResponse is the response for a successful share claim.
type ClaimShareCompleteResponse struct {
	ShareIndex int             `json:"share_index"`
	Share      json.RawMessage `json:"share"`
}

// SignCSRInitRequest is the request body for SO-authorized CSR signing during
// the init ceremony. It mirrors transport.SignCSRInitRequest so the REST, QUIC
// and MCP transports accept an identical wire body.
type SignCSRInitRequest struct {
	Username string `json:"username"`
	SOPin    string `json:"so_pin"`
	CSRPEM   string `json:"csr_pem"`
	Role     string `json:"role"`
}

// SignCSRInitResponse is the response for a successful init CSR signing.
type SignCSRInitResponse struct {
	CertPEM string `json:"cert_pem"`
}

// Typed errors for init handlers.
var (
	// ErrClientCertRequired is returned when a share-claim request arrives
	// without a verified mTLS peer certificate. The officer's certificate
	// thumbprint is the authentication for these routes, so a request that
	// cannot present one is refused before the ceremony is consulted.
	ErrClientCertRequired = errors.New("client certificate required")

	ErrMissingUsername  = errors.New("missing username")
	ErrMissingNonce     = errors.New("missing nonce")
	ErrMissingSignature = errors.New("missing signature")
	ErrMissingSOPin     = errors.New("missing so_pin")
	ErrMissingCSRPEM    = errors.New("missing csr_pem")
	ErrMissingRole      = errors.New("missing role")
)

// initErrorStatusMap maps ceremony errors to HTTP status codes for O(1) lookup.
var initErrorStatusMap = map[error]int{
	initialize.ErrNotInEnrollingState:         http.StatusConflict,
	initialize.ErrPendingCertNotFound:         http.StatusNotFound,
	initialize.ErrCertAlreadyClaimed:          http.StatusConflict,
	initialize.ErrShareNotFound:               http.StatusNotFound,
	initialize.ErrShareAlreadyClaimed:         http.StatusConflict,
	initialize.ErrChallengeVerificationFailed: http.StatusUnauthorized,
	initialize.ErrCertThumbprintMismatch:      http.StatusUnauthorized,
	initialize.ErrOfficerNotFound:             http.StatusNotFound,
	initialize.ErrNoPendingShare:              http.StatusNotFound,
	initialize.ErrAlreadyInitialized:          http.StatusConflict,
	initialize.ErrUserNotFound:                http.StatusNotFound,
	initialize.ErrChallengeNotFound:           http.StatusNotFound,
	initialize.ErrChallengeExpired:            http.StatusGone,
	initialize.ErrNotInitializedOrEnrolling:   http.StatusConflict,
	initialize.ErrSOPINMismatch:               http.StatusUnauthorized,
	initialize.ErrInvalidSOPIN:                http.StatusBadRequest,
	initialize.ErrMissingCSRPEM:               http.StatusBadRequest,
	initialize.ErrMissingRole:                 http.StatusBadRequest,
	initialize.ErrInvalidRole:                 http.StatusBadRequest,
	initialize.ErrInvalidCSR:                  http.StatusBadRequest,
	initialize.ErrCANotInitialized:            http.StatusServiceUnavailable,
	initialize.ErrCSRSigningFailed:            http.StatusInternalServerError,
}

// InitHandlers provides HTTP handlers for the init ceremony API.
type InitHandlers struct {
	ceremony initServicer
	logger   *slog.Logger
}

// NewInitHandlers creates a new InitHandlers instance. The ceremony parameter
// accepts any type satisfying the initServicer interface; the production
// wiring passes the *initialize.CeremonyService held by Config.
func NewInitHandlers(ceremony initServicer, logger *slog.Logger) *InitHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &InitHandlers{
		ceremony: ceremony,
		logger:   logger,
	}
}

// HandleGetStatus returns the current init ceremony state.
// GET /api/v1/init/status
func (h *InitHandlers) HandleGetStatus(w http.ResponseWriter, r *http.Request) {
	state := h.ceremony.State()
	resp := InitStatusResponse{
		State: string(state),
	}
	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimCertBegin begins the certificate claim process for an officer.
// POST /api/v1/init/claim-cert/begin
func (h *InitHandlers) HandleClaimCertBegin(w http.ResponseWriter, r *http.Request) {
	var req ClaimCertBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}

	challenge, err := h.ceremony.BeginClaimCert(r.Context(), req.Username)
	if err != nil {
		h.logger.Warn("claim-cert begin failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimCertBeginResponse{
		Nonce:     hex.EncodeToString(challenge.Nonce),
		Username:  challenge.Username,
		ExpiresAt: challenge.ExpiresAt,
	}

	h.logger.Info("claim-cert begin succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimCertComplete completes the certificate claim by verifying the
// officer's signature over the challenge nonce.
// POST /api/v1/init/claim-cert/complete
func (h *InitHandlers) HandleClaimCertComplete(w http.ResponseWriter, r *http.Request) {
	var req ClaimCertCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}
	if req.Nonce == "" {
		writeError(w, ErrMissingNonce, http.StatusBadRequest)
		return
	}
	if req.Signature == "" {
		writeError(w, ErrMissingSignature, http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.CompleteClaimCert(r.Context(), req.Username, req.Nonce, signature)
	if err != nil {
		h.logger.Warn("claim-cert complete failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimCertCompleteResponse{
		CertPEM:   string(result.CertPEM),
		CACertPEM: string(result.CACertPEM),
	}

	h.logger.Info("claim-cert complete succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// callerCertThumbprint derives the caller's certificate thumbprint from the
// verified mTLS peer certificate on the request. It returns
// ErrClientCertRequired when the request carries no peer certificate, so the
// share-claim routes fail closed rather than fall back to username trust.
//
// The value is computed with initialize.CertThumbprint, the single canonical
// binding identifier the ceremony records for each officer at enrollment.
func callerCertThumbprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrClientCertRequired
	}
	return initialize.CertThumbprint(r.TLS.PeerCertificates[0].Raw), nil
}

// HandleClaimShareBegin starts the Shamir share claim handshake for the named
// officer. The officer has no account yet, but they do have the certificate
// claim-cert issued them: its thumbprint is the authentication for this route.
// POST /api/v1/init/claim-share/begin
func (h *InitHandlers) HandleClaimShareBegin(w http.ResponseWriter, r *http.Request) {
	thumbprint, err := callerCertThumbprint(r)
	if err != nil {
		h.logger.Warn("claim-share begin refused: no client certificate",
			slog.String("remote_addr", r.RemoteAddr))
		writeError(w, err, http.StatusUnauthorized)
		return
	}

	var req ClaimShareBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}

	challenge, err := h.ceremony.BeginClaimShare(r.Context(), req.Username, thumbprint)
	if err != nil {
		h.logger.Warn("claim-share begin failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimShareBeginResponse{
		Nonce:     hex.EncodeToString(challenge.Nonce),
		Username:  challenge.Username,
		ExpiresAt: challenge.ExpiresAt,
	}

	h.logger.Info("claim-share begin succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimShareComplete completes the Shamir share claim handshake. Both
// the nonce signature and the caller certificate thumbprint are verified
// before the share is released exactly once.
// POST /api/v1/init/claim-share/complete
func (h *InitHandlers) HandleClaimShareComplete(w http.ResponseWriter, r *http.Request) {
	thumbprint, err := callerCertThumbprint(r)
	if err != nil {
		h.logger.Warn("claim-share complete refused: no client certificate",
			slog.String("remote_addr", r.RemoteAddr))
		writeError(w, err, http.StatusUnauthorized)
		return
	}

	var req ClaimShareCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}
	if req.Nonce == "" {
		writeError(w, ErrMissingNonce, http.StatusBadRequest)
		return
	}
	if req.Signature == "" {
		writeError(w, ErrMissingSignature, http.StatusBadRequest)
		return
	}

	signature, decErr := base64.StdEncoding.DecodeString(req.Signature)
	if decErr != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.CompleteClaimShare(r.Context(), req.Username, req.Nonce, signature, thumbprint)
	if err != nil {
		h.logger.Warn("claim-share complete failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimShareCompleteResponse{
		ShareIndex: result.ShareIndex,
		Share:      json.RawMessage(result.ShareBytes),
	}

	h.logger.Info("claim-share complete succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleSignCSRInit signs a Certificate Signing Request during the init
// ceremony under SO PIN authorization. Unlike the claim endpoints this route
// stays behind the authentication middleware: the caller is an already
// enrolled operator, not an officer bootstrapping their first credential.
// POST /api/v1/init/sign-csr
func (h *InitHandlers) HandleSignCSRInit(w http.ResponseWriter, r *http.Request) {
	var req SignCSRInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}
	if req.SOPin == "" {
		writeError(w, ErrMissingSOPin, http.StatusBadRequest)
		return
	}
	if req.CSRPEM == "" {
		writeError(w, ErrMissingCSRPEM, http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		writeError(w, ErrMissingRole, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.SignCSRInit(r.Context(), req.Username, req.SOPin, req.CSRPEM, req.Role)
	if err != nil {
		// The SO PIN is never echoed back; only the username and the mapped
		// sentinel reach the log.
		h.logger.Warn("init sign-csr failed",
			slog.String("username", req.Username),
			slog.String("role", req.Role),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := SignCSRInitResponse{
		CertPEM: string(result.CertPEM),
	}

	h.logger.Info("init sign-csr succeeded",
		slog.String("username", req.Username),
		slog.String("role", req.Role))

	writeJSON(w, resp, http.StatusOK)
}

// mapInitError maps an init ceremony error to the appropriate HTTP status code.
func mapInitError(err error) int {
	for sentinelErr, status := range initErrorStatusMap {
		if errors.Is(err, sentinelErr) {
			return status
		}
	}
	return http.StatusInternalServerError
}

// ---------------------------------------------------------------------------
// Security Officer enrolment
//
// Step 1 of go-qrdb's Security Officer distribution model. These endpoints
// exist so go-xkms offers the SAME officer flow as every other project in the
// stack rather than requiring callers to reach past this layer for it.
//
// No response below carries share bytes. Registration returns the signed
// certificate and a share INDEX; the shares themselves are sealed into
// memguard enclaves at initialization and released to each officer exactly
// once through the live claim handshake above.
// ---------------------------------------------------------------------------

// OfficerRegisterRequest is the request body for registering a Security
// Officer from their CSR.
type OfficerRegisterRequest struct {
	Username          string `json:"username"`
	CSRPEM            string `json:"csr_pem"`
	AuthenticatorType string `json:"authenticator_type,omitempty"`
	AuthenticatorRef  string `json:"authenticator_ref,omitempty"`
}

// OfficerRegisterResponse returns the issued officer certificate and the
// officer's assigned Shamir share index. It never carries share bytes.
type OfficerRegisterResponse struct {
	CertPEM    string `json:"cert_pem"`
	ShareIndex int    `json:"share_index"`
}

// OfficerStatusEntry is the non-secret public view of one enrolled officer.
type OfficerStatusEntry struct {
	Username       string `json:"username"`
	CertThumbprint string `json:"cert_thumbprint,omitempty"`
	ShareIndex     int    `json:"share_index"`
	AuthFactor     string `json:"auth_factor,omitempty"`
}

// OfficerStatusResponse lists the enrolled officers.
type OfficerStatusResponse struct {
	Officers []OfficerStatusEntry `json:"officers"`
}

// EnrollExternalOfficerRESTRequest is the request body for enrolling an
// officer whose key material was issued elsewhere.
type EnrollExternalOfficerRESTRequest struct {
	Username          string `json:"username"`
	CertPEM           string `json:"cert_pem,omitempty"`
	PubKeyPEM         string `json:"pubkey_pem,omitempty"`
	AuthenticatorType string `json:"authenticator_type,omitempty"`
	AuthenticatorRef  string `json:"authenticator_ref,omitempty"`
}

// HandleOfficerRegister registers a Security Officer.
//
// POST /api/v1/init/officer/register
func (h *InitHandlers) HandleOfficerRegister(w http.ResponseWriter, r *http.Request) {
	var req OfficerRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}
	if req.CSRPEM == "" {
		writeError(w, ErrMissingCSRPEM, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.RegisterOfficer(r.Context(), initialize.RegisterOfficerRequest{
		Username:          req.Username,
		CSRPEM:            []byte(req.CSRPEM),
		AuthenticatorType: initialize.AuthenticatorType(req.AuthenticatorType),
		AuthenticatorRef:  req.AuthenticatorRef,
	})
	if err != nil {
		h.logger.Warn("init officer register failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))
		writeError(w, err, mapInitError(err))
		return
	}

	h.logger.Info("init officer registered",
		slog.String("username", req.Username),
		slog.Int("share_index", result.ShareIndex))

	writeJSON(w, OfficerRegisterResponse{
		CertPEM:    string(result.CertPEM),
		ShareIndex: result.ShareIndex,
	}, http.StatusOK)
}

// HandleOfficerStatus reports per-officer enrolment and claim state.
//
// GET /api/v1/init/officer/status
func (h *InitHandlers) HandleOfficerStatus(w http.ResponseWriter, r *http.Request) {
	officers, err := h.ceremony.OfficerClaimStatus(r.Context())
	if err != nil {
		h.logger.Warn("init officer status failed", slog.String("error", err.Error()))
		writeError(w, err, mapInitError(err))
		return
	}

	entries := make([]OfficerStatusEntry, 0, len(officers))
	for _, o := range officers {
		if o == nil {
			continue
		}
		entries = append(entries, OfficerStatusEntry{
			Username:       o.Username,
			CertThumbprint: o.CertThumbprint,
			ShareIndex:     o.ShareIndex,
			AuthFactor:     string(o.AuthFactor),
		})
	}
	writeJSON(w, OfficerStatusResponse{Officers: entries}, http.StatusOK)
}

// HandleEnrollExternalOfficer enrols an officer holding externally-issued key
// material.
//
// POST /api/v1/init/enroll-external-officer
func (h *InitHandlers) HandleEnrollExternalOfficer(w http.ResponseWriter, r *http.Request) {
	var req EnrollExternalOfficerRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.EnrollExternalOfficer(r.Context(), initialize.EnrollExternalOfficerRequest{
		Username:   req.Username,
		CertPEM:    req.CertPEM,
		PubKeyPEM:  req.PubKeyPEM,
		AuthFactor: req.AuthenticatorType,
	})
	if err != nil {
		h.logger.Warn("init enroll-external-officer failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))
		writeError(w, err, mapInitError(err))
		return
	}

	h.logger.Info("init external officer enrolled", slog.String("username", req.Username))
	writeJSON(w, result, http.StatusOK)
}
