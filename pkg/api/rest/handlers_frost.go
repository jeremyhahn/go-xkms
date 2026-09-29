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

//go:build frost

package rest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// FROST request/response types

// FrostGenerateKeyRequest represents a request to generate FROST keys
type FrostGenerateKeyRequest struct {
	KeyID         string   `json:"key_id,omitempty"`
	Algorithm     string   `json:"algorithm,omitempty"`
	Threshold     int      `json:"threshold"`
	Total         int      `json:"total"`
	Participants  []string `json:"participants,omitempty"`
	ParticipantID uint32   `json:"participant_id,omitempty"`
	DealerMode    bool     `json:"dealer_mode,omitempty"`
}

// FrostGenerateKeyResponse represents the response from key generation
type FrostGenerateKeyResponse struct {
	KeyID          string            `json:"key_id"`
	Algorithm      string            `json:"algorithm"`
	Threshold      int               `json:"threshold"`
	Total          int               `json:"total"`
	GroupPublicKey string            `json:"group_public_key"` // hex-encoded
	ParticipantID  uint32            `json:"participant_id,omitempty"`
	Packages       []FrostKeyPackage `json:"packages,omitempty"` // dealer mode only
	CreatedAt      time.Time         `json:"created_at"`
}

// FrostKeyPackage represents a participant's key package
type FrostKeyPackage struct {
	KeyID              string            `json:"key_id"`
	Algorithm          string            `json:"algorithm"`
	Threshold          int               `json:"threshold"`
	Total              int               `json:"total"`
	ParticipantID      uint32            `json:"participant_id"`
	ParticipantName    string            `json:"participant_name,omitempty"`
	SecretShare        string            `json:"secret_share"`        // hex-encoded
	GroupPublicKey     string            `json:"group_public_key"`    // hex-encoded
	VerificationShares map[uint32]string `json:"verification_shares"` // hex-encoded
}

// FrostKeyInfo represents FROST key information
type FrostKeyInfo struct {
	KeyID          string    `json:"key_id"`
	Algorithm      string    `json:"algorithm"`
	Threshold      int       `json:"threshold"`
	Total          int       `json:"total"`
	ParticipantID  uint32    `json:"participant_id"`
	GroupPublicKey string    `json:"group_public_key"` // hex-encoded
	Participants   []string  `json:"participants,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// FrostImportKeyRequest represents a request to import a FROST key package
type FrostImportKeyRequest struct {
	Package FrostKeyPackage `json:"package"`
}

// FrostImportKeyResponse represents the response from key import
type FrostImportKeyResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	KeyID          string `json:"key_id"`
	ParticipantID  uint32 `json:"participant_id"`
	GroupPublicKey string `json:"group_public_key"` // hex-encoded
}

// FrostListKeysResponse represents the list of FROST keys
type FrostListKeysResponse struct {
	Keys       []FrostKeyInfo         `json:"keys"`
	Total      int                    `json:"total"`
	Pagination transport.PageResponse `json:"pagination"`
}

// FrostDeleteKeyResponse represents the response from key deletion
type FrostDeleteKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// FrostGenerateNoncesRequest represents a request to generate nonces
type FrostGenerateNoncesRequest struct {
	KeyID string `json:"key_id"`
}

// FrostGenerateNoncesResponse represents the response from nonce generation
type FrostGenerateNoncesResponse struct {
	ParticipantID     uint32 `json:"participant_id"`
	SessionID         string `json:"session_id"`
	HidingNonce       string `json:"hiding_nonce"`       // hex-encoded (secret)
	BindingNonce      string `json:"binding_nonce"`      // hex-encoded (secret)
	HidingCommitment  string `json:"hiding_commitment"`  // hex-encoded (public)
	BindingCommitment string `json:"binding_commitment"` // hex-encoded (public)
}

// FrostCommitment represents a participant's nonce commitments
type FrostCommitment struct {
	ParticipantID     uint32 `json:"participant_id"`
	HidingCommitment  string `json:"hiding_commitment"`  // hex-encoded
	BindingCommitment string `json:"binding_commitment"` // hex-encoded
}

// FrostSignRoundRequest represents a request for Round 2 signing
type FrostSignRoundRequest struct {
	KeyID             string            `json:"key_id"`
	Message           string            `json:"message"` // hex-encoded
	SessionID         string            `json:"session_id"`
	HidingNonce       string            `json:"hiding_nonce"`       // hex-encoded
	BindingNonce      string            `json:"binding_nonce"`      // hex-encoded
	HidingCommitment  string            `json:"hiding_commitment"`  // hex-encoded
	BindingCommitment string            `json:"binding_commitment"` // hex-encoded
	Commitments       []FrostCommitment `json:"commitments"`
}

// FrostSignRoundResponse represents the response from Round 2 signing
type FrostSignRoundResponse struct {
	ParticipantID  uint32 `json:"participant_id"`
	SessionID      string `json:"session_id"`
	SignatureShare string `json:"signature_share"` // hex-encoded
}

// FrostSignatureShare represents a participant's signature share
type FrostSignatureShare struct {
	ParticipantID uint32 `json:"participant_id"`
	SessionID     string `json:"session_id"`
	Share         string `json:"share"` // hex-encoded
}

// FrostAggregateRequest represents a request to aggregate signature shares
type FrostAggregateRequest struct {
	KeyID       string                `json:"key_id"`
	Message     string                `json:"message"` // hex-encoded
	Commitments []FrostCommitment     `json:"commitments"`
	Shares      []FrostSignatureShare `json:"shares"`
	Verify      bool                  `json:"verify"`
}

// FrostAggregateResponse represents the aggregated signature response
type FrostAggregateResponse struct {
	Signature string `json:"signature"` // hex-encoded
	Verified  bool   `json:"verified"`
}

// FrostVerifyRequest represents a request to verify a signature
type FrostVerifyRequest struct {
	KeyID     string `json:"key_id"`
	Message   string `json:"message"`   // hex-encoded
	Signature string `json:"signature"` // hex-encoded
}

// FrostVerifyResponse represents the verification result
type FrostVerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// frostService returns the injected xkms service, or writes the
// not-initialized refusal and returns nil.
func (h *HandlerContext) frostService(w http.ResponseWriter) *xkms.XKMSService {
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return nil
	}
	return h.xkmsService
}

// frostKeyInfo renders a service key description for the wire.
func frostKeyInfo(info *xkms.FrostKeyInfo) FrostKeyInfo {
	return FrostKeyInfo{
		KeyID:          info.KeyID,
		Algorithm:      info.Algorithm,
		Threshold:      info.Threshold,
		Total:          info.Total,
		ParticipantID:  info.ParticipantID,
		GroupPublicKey: hexEncode(info.GroupPublicKey),
		Participants:   info.Participants,
		CreatedAt:      info.CreatedAt,
	}
}

// decodeFrostCommitments decodes the hex-encoded commitments of a signing
// request.
func decodeFrostCommitments(in []FrostCommitment) ([]*frost.Commitment, error) {
	commitments := make([]*frost.Commitment, len(in))
	for i, c := range in {
		hc, err := hexDecode(c.HidingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "invalid hiding_commitment hex", Err: err}
		}
		bc, err := hexDecode(c.BindingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "invalid binding_commitment hex", Err: err}
		}
		commitments[i] = &frost.Commitment{
			ParticipantID: c.ParticipantID,
			Commitments: &frost.SigningCommitments{
				ParticipantID:     c.ParticipantID,
				HidingCommitment:  hc,
				BindingCommitment: bc,
			},
		}
	}
	return commitments, nil
}

// FrostGenerateKeyHandler handles POST /api/v1/frost/keys requests.
func (h *HandlerContext) FrostGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostGenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	svc := h.frostService(w)
	if svc == nil {
		return
	}

	gen, err := svc.FrostGenerateKey(r.Context(), &xkms.FrostGenerateKeyRequest{
		KeyID:         req.KeyID,
		Algorithm:     req.Algorithm,
		Threshold:     req.Threshold,
		Total:         req.Total,
		Participants:  req.Participants,
		ParticipantID: req.ParticipantID,
		DealerMode:    req.DealerMode,
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	var packages []FrostKeyPackage
	for _, pkg := range gen.Packages {
		shares := make(map[uint32]string, len(pkg.VerificationShares))
		for id, share := range pkg.VerificationShares {
			shares[id] = hexEncode(share)
		}
		packages = append(packages, FrostKeyPackage{
			KeyID:              gen.KeyID,
			Algorithm:          gen.Algorithm,
			Threshold:          gen.Threshold,
			Total:              gen.Total,
			ParticipantID:      pkg.ParticipantID,
			ParticipantName:    pkg.ParticipantName,
			SecretShare:        hexEncode(pkg.SecretShare),
			GroupPublicKey:     hexEncode(pkg.GroupPublicKey),
			VerificationShares: shares,
		})
	}

	writeJSON(w, FrostGenerateKeyResponse{
		KeyID:          gen.KeyID,
		Algorithm:      gen.Algorithm,
		Threshold:      gen.Threshold,
		Total:          gen.Total,
		GroupPublicKey: hexEncode(gen.GroupPublicKey),
		ParticipantID:  gen.ParticipantID,
		Packages:       packages,
		CreatedAt:      gen.CreatedAt,
	}, http.StatusCreated)
}

// FrostImportKeyHandler handles POST /api/v1/frost/keys/import requests. The
// package is imported into the caller's tenant.
func (h *HandlerContext) FrostImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	pkg := req.Package
	if pkg.KeyID == "" {
		writeError(w, &errs.Message{Msg: "package.key_id is required"}, http.StatusBadRequest)
		return
	}
	secretShare, err := hexDecode(pkg.SecretShare)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid secret_share hex", Err: err}, http.StatusBadRequest)
		return
	}
	groupPubKey, err := hexDecode(pkg.GroupPublicKey)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid group_public_key hex", Err: err}, http.StatusBadRequest)
		return
	}
	shares := make(map[uint32][]byte, len(pkg.VerificationShares))
	for id, shareHex := range pkg.VerificationShares {
		share, err := hexDecode(shareHex)
		if err != nil {
			writeError(w, &errs.Wrapped{Msg: fmt.Sprintf("invalid verification_share hex for participant %d", id), Err: err}, http.StatusBadRequest)
			return
		}
		shares[id] = share
	}

	svc := h.frostService(w)
	if svc == nil {
		return
	}
	if err := svc.FrostImportKey(r.Context(), &xkms.FrostImportKeyRequest{
		KeyID:              pkg.KeyID,
		Algorithm:          pkg.Algorithm,
		Threshold:          pkg.Threshold,
		Total:              pkg.Total,
		ParticipantID:      pkg.ParticipantID,
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: shares,
	}); err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, FrostImportKeyResponse{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantID),
		KeyID:          pkg.KeyID,
		ParticipantID:  pkg.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
	}, http.StatusCreated)
}

// FrostListKeysHandler handles GET /api/v1/frost/keys requests. The listing
// holds only the caller's tenant's keys.
func (h *HandlerContext) FrostListKeysHandler(w http.ResponseWriter, r *http.Request) {
	pageReq, err := transport.PageRequestFromQuery(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	svc := h.frostService(w)
	if svc == nil {
		return
	}

	keys, err := svc.FrostListKeys(r.Context())
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	infos := make([]FrostKeyInfo, 0, len(keys))
	for i := range keys {
		infos = append(infos, frostKeyInfo(&keys[i]))
	}

	paged, pageResp := transport.ApplyPagination(infos, pageReq)
	writeJSON(w, FrostListKeysResponse{
		Keys:       paged,
		Total:      pageResp.Total,
		Pagination: pageResp,
	}, http.StatusOK)
}

// FrostGetKeyHandler handles GET /api/v1/frost/keys/{id} requests.
func (h *HandlerContext) FrostGetKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}
	svc := h.frostService(w)
	if svc == nil {
		return
	}

	info, err := svc.FrostGetKey(r.Context(), keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, frostKeyInfo(info), http.StatusOK)
}

// FrostDeleteKeyHandler handles DELETE /api/v1/frost/keys/{id} requests.
func (h *HandlerContext) FrostDeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}
	svc := h.frostService(w)
	if svc == nil {
		return
	}

	if err := svc.FrostDeleteKey(r.Context(), keyID); err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, FrostDeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", keyID),
	}, http.StatusOK)
}

// FrostGenerateNoncesHandler handles POST /api/v1/frost/keys/{id}/nonces
// requests.
func (h *HandlerContext) FrostGenerateNoncesHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}
	svc := h.frostService(w)
	if svc == nil {
		return
	}

	nonces, err := svc.FrostGenerateNonces(r.Context(), keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, FrostGenerateNoncesResponse{
		ParticipantID:     nonces.ParticipantID,
		SessionID:         nonces.SessionID,
		HidingNonce:       hexEncode(nonces.Nonces.HidingNonce),
		BindingNonce:      hexEncode(nonces.Nonces.BindingNonce),
		HidingCommitment:  hexEncode(nonces.Commitments.HidingCommitment),
		BindingCommitment: hexEncode(nonces.Commitments.BindingCommitment),
	}, http.StatusOK)
}

// FrostSignRoundHandler handles POST /api/v1/frost/keys/{id}/sign requests.
func (h *HandlerContext) FrostSignRoundHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	var req FrostSignRoundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	decoded := make(map[string][]byte, 5)
	for _, field := range []struct {
		name  string
		value string
	}{
		{"message", req.Message},
		{"hiding_nonce", req.HidingNonce},
		{"binding_nonce", req.BindingNonce},
		{"hiding_commitment", req.HidingCommitment},
		{"binding_commitment", req.BindingCommitment},
	} {
		value, err := hexDecode(field.value)
		if err != nil {
			writeError(w, &errs.Wrapped{Msg: "invalid " + field.name + " hex", Err: err}, http.StatusBadRequest)
			return
		}
		decoded[field.name] = value
	}
	commitments, err := decodeFrostCommitments(req.Commitments)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	svc := h.frostService(w)
	if svc == nil {
		return
	}
	share, err := svc.FrostSignRound(r.Context(), &xkms.FrostSignRoundRequest{
		KeyID:             keyID,
		Message:           decoded["message"],
		SessionID:         req.SessionID,
		HidingNonce:       decoded["hiding_nonce"],
		BindingNonce:      decoded["binding_nonce"],
		HidingCommitment:  decoded["hiding_commitment"],
		BindingCommitment: decoded["binding_commitment"],
		Commitments:       commitments,
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, FrostSignRoundResponse{
		ParticipantID:  share.ParticipantID,
		SessionID:      share.SessionID,
		SignatureShare: hexEncode(share.Share),
	}, http.StatusOK)
}

// FrostAggregateHandler handles POST /api/v1/frost/aggregate requests.
func (h *HandlerContext) FrostAggregateHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostAggregateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.KeyID == "" {
		writeError(w, &errs.Message{Msg: "key_id is required"}, http.StatusBadRequest)
		return
	}

	message, err := hexDecode(req.Message)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid message hex", Err: err}, http.StatusBadRequest)
		return
	}
	commitments, err := decodeFrostCommitments(req.Commitments)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	shares := make([]*frost.SignatureShare, len(req.Shares))
	for i, s := range req.Shares {
		share, err := hexDecode(s.Share)
		if err != nil {
			writeError(w, &errs.Wrapped{Msg: "invalid share hex", Err: err}, http.StatusBadRequest)
			return
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: s.ParticipantID,
			SessionID:     s.SessionID,
			Share:         share,
		}
	}

	svc := h.frostService(w)
	if svc == nil {
		return
	}
	agg, err := svc.FrostAggregate(r.Context(), &xkms.FrostAggregateRequest{
		KeyID:       req.KeyID,
		Message:     message,
		Commitments: commitments,
		Shares:      shares,
		Verify:      req.Verify,
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, FrostAggregateResponse{
		Signature: hexEncode(agg.Signature),
		Verified:  agg.Verified,
	}, http.StatusOK)
}

// FrostVerifyHandler handles POST /api/v1/frost/verify requests.
func (h *HandlerContext) FrostVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.KeyID == "" {
		writeError(w, &errs.Message{Msg: "key_id is required"}, http.StatusBadRequest)
		return
	}

	message, err := hexDecode(req.Message)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid message hex", Err: err}, http.StatusBadRequest)
		return
	}
	signature, err := hexDecode(req.Signature)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid signature hex", Err: err}, http.StatusBadRequest)
		return
	}

	svc := h.frostService(w)
	if svc == nil {
		return
	}
	result, err := svc.FrostVerify(r.Context(), req.KeyID, message, signature)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	if !result.Valid {
		writeJSON(w, FrostVerifyResponse{
			Valid:   false,
			Message: "signature verification failed: " + result.Reason,
		}, http.StatusOK)
		return
	}
	writeJSON(w, FrostVerifyResponse{Valid: true, Message: "signature is valid"}, http.StatusOK)
}

// hexEncode encodes bytes to hex string
func hexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// hexDecode decodes hex string to bytes
func hexDecode(s string) ([]byte, error) {
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// frostEnabled reports whether FROST threshold-signature support was
// compiled into this binary (the "frost" build tag).
const frostEnabled = true
