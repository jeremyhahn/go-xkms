// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
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
	KeyID          string             `json:"key_id"`
	Algorithm      string             `json:"algorithm"`
	Threshold      int                `json:"threshold"`
	Total          int                `json:"total"`
	GroupPublicKey string             `json:"group_public_key"` // hex-encoded
	ParticipantID  uint32             `json:"participant_id,omitempty"`
	Packages       []FrostKeyPackage  `json:"packages,omitempty"` // dealer mode only
	CreatedAt      time.Time          `json:"created_at"`
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
	Keys  []FrostKeyInfo `json:"keys"`
	Total int            `json:"total"`
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
	Message           string            `json:"message"`            // hex-encoded
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
	ParticipantID  uint32 `json:"participant_id"`
	SessionID      string `json:"session_id"`
	Share          string `json:"share"` // hex-encoded
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

// FrostGenerateKeyHandler handles POST /api/v1/frost/keys requests
func (h *HandlerContext) FrostGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostGenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Threshold < 2 {
		writeError(w, fmt.Errorf("threshold must be at least 2"), http.StatusBadRequest)
		return
	}
	if req.Total < req.Threshold {
		writeError(w, fmt.Errorf("total must be >= threshold"), http.StatusBadRequest)
		return
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = string(types.FrostAlgorithmEd25519)
	}

	keyID := req.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("frost-key-%d", time.Now().UnixNano())
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	if req.DealerMode {
		// Dealer mode: generate all packages
		td := frost.NewTrustedDealer()
		frostConfig := frost.FrostConfig{
			Threshold:     req.Threshold,
			Total:         req.Total,
			Algorithm:     types.FrostAlgorithm(algorithm),
			ParticipantID: 1,
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			writeError(w, fmt.Errorf("failed to generate FROST packages: %w", err), http.StatusInternalServerError)
			return
		}

		// Convert to response format
		respPackages := make([]FrostKeyPackage, len(packages))
		for i, pkg := range packages {
			vsMap := make(map[uint32]string)
			for id, vs := range pubPkg.VerificationShares {
				vsMap[id] = hexEncode(vs)
			}

			var participantName string
			if i < len(req.Participants) {
				participantName = req.Participants[i]
			}

			respPackages[i] = FrostKeyPackage{
				KeyID:              keyID,
				Algorithm:          algorithm,
				Threshold:          req.Threshold,
				Total:              req.Total,
				ParticipantID:      pkg.ParticipantID,
				ParticipantName:    participantName,
				SecretShare:        hexEncode(pkg.SecretShare.Value),
				GroupPublicKey:     hexEncode(pubPkg.GroupPublicKey),
				VerificationShares: vsMap,
			}
		}

		resp := FrostGenerateKeyResponse{
			KeyID:          keyID,
			Algorithm:      algorithm,
			Threshold:      req.Threshold,
			Total:          req.Total,
			GroupPublicKey: hexEncode(pubPkg.GroupPublicKey),
			Packages:       respPackages,
			CreatedAt:      time.Now(),
		}
		writeJSON(w, resp, http.StatusCreated)
		return
	}

	// Participant mode
	if req.ParticipantID == 0 {
		writeError(w, fmt.Errorf("participant_id is required in participant mode"), http.StatusBadRequest)
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Algorithm:     types.FrostAlgorithm(algorithm),
			Threshold:     req.Threshold,
			Total:         req.Total,
			Participants:  req.Participants,
			ParticipantID: req.ParticipantID,
		},
	}

	key, err := be.GenerateKey(attrs)
	if err != nil {
		writeError(w, fmt.Errorf("failed to generate FROST key: %w", err), http.StatusInternalServerError)
		return
	}

	handle := key.(*frost.FrostKeyHandle)

	resp := FrostGenerateKeyResponse{
		KeyID:          keyID,
		Algorithm:      algorithm,
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: hexEncode(handle.GroupPublicKey),
		ParticipantID:  req.ParticipantID,
		CreatedAt:      time.Now(),
	}
	writeJSON(w, resp, http.StatusCreated)
}

// FrostImportKeyHandler handles POST /api/v1/frost/keys/import requests
func (h *HandlerContext) FrostImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	pkg := req.Package
	if pkg.KeyID == "" {
		writeError(w, fmt.Errorf("package.key_id is required"), http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Decode hex values
	secretShare, err := hexDecode(pkg.SecretShare)
	if err != nil {
		writeError(w, fmt.Errorf("invalid secret_share hex: %w", err), http.StatusBadRequest)
		return
	}

	groupPubKey, err := hexDecode(pkg.GroupPublicKey)
	if err != nil {
		writeError(w, fmt.Errorf("invalid group_public_key hex: %w", err), http.StatusBadRequest)
		return
	}

	vsMap := make(map[uint32][]byte)
	for id, vsHex := range pkg.VerificationShares {
		vs, err := hexDecode(vsHex)
		if err != nil {
			writeError(w, fmt.Errorf("invalid verification_share hex for participant %d: %w", id, err), http.StatusBadRequest)
			return
		}
		vsMap[id] = vs
	}

	keyPackage := &frost.KeyPackage{
		ParticipantID: pkg.ParticipantID,
		SecretShare: &frost.SecretKeyShare{
			Value: secretShare,
		},
		GroupPublicKey:     groupPubKey,
		VerificationShares: vsMap,
		MinSigners:         uint32(pkg.Threshold),
		MaxSigners:         uint32(pkg.Total),
		Algorithm:          types.FrostAlgorithm(pkg.Algorithm),
	}

	metadata := &frost.KeyMetadata{
		KeyID:             pkg.KeyID,
		Algorithm:         types.FrostAlgorithm(pkg.Algorithm),
		Threshold:         pkg.Threshold,
		Total:             pkg.Total,
		ParticipantID:     pkg.ParticipantID,
		CreatedAt:         time.Now().Unix(),
		SecretBackendType: types.BackendTypeSoftware,
	}

	ks := be.KeyStore()
	if err := ks.StoreKeyPackage(pkg.KeyID, keyPackage, metadata); err != nil {
		writeError(w, fmt.Errorf("failed to store key package: %w", err), http.StatusInternalServerError)
		return
	}

	resp := FrostImportKeyResponse{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantID),
		KeyID:          pkg.KeyID,
		ParticipantID:  pkg.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
	}
	writeJSON(w, resp, http.StatusCreated)
}

// FrostListKeysHandler handles GET /api/v1/frost/keys requests
func (h *HandlerContext) FrostListKeysHandler(w http.ResponseWriter, r *http.Request) {
	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	keys, err := be.ListKeys()
	if err != nil {
		writeError(w, fmt.Errorf("failed to list keys: %w", err), http.StatusInternalServerError)
		return
	}

	respKeys := make([]FrostKeyInfo, 0, len(keys))
	for _, k := range keys {
		if k.FrostAttributes != nil {
			var groupPubKey string
			handle, err := be.GetKey(k)
			if err == nil {
				if h, ok := handle.(*frost.FrostKeyHandle); ok {
					groupPubKey = hexEncode(h.GroupPublicKey)
				}
			}

			respKeys = append(respKeys, FrostKeyInfo{
				KeyID:          k.CN,
				Algorithm:      string(k.FrostAttributes.Algorithm),
				Threshold:      k.FrostAttributes.Threshold,
				Total:          k.FrostAttributes.Total,
				ParticipantID:  k.FrostAttributes.ParticipantID,
				GroupPublicKey: groupPubKey,
				Participants:   k.FrostAttributes.Participants,
				CreatedAt:      time.Now(),
			})
		}
	}

	resp := FrostListKeysResponse{
		Keys:  respKeys,
		Total: len(respKeys),
	}
	writeJSON(w, resp, http.StatusOK)
}

// FrostGetKeyHandler handles GET /api/v1/frost/keys/{id} requests
func (h *HandlerContext) FrostGetKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	key, err := be.GetKey(attrs)
	if err != nil {
		writeError(w, fmt.Errorf("key not found: %w", err), http.StatusNotFound)
		return
	}

	handle := key.(*frost.FrostKeyHandle)

	// Get metadata from key list
	keys, _ := be.ListKeys()
	var keyInfo FrostKeyInfo
	for _, k := range keys {
		if k.CN == keyID && k.FrostAttributes != nil {
			keyInfo = FrostKeyInfo{
				KeyID:          k.CN,
				Algorithm:      string(k.FrostAttributes.Algorithm),
				Threshold:      k.FrostAttributes.Threshold,
				Total:          k.FrostAttributes.Total,
				ParticipantID:  handle.ParticipantID,
				GroupPublicKey: hexEncode(handle.GroupPublicKey),
				Participants:   k.FrostAttributes.Participants,
				CreatedAt:      time.Now(),
			}
			break
		}
	}

	if keyInfo.KeyID == "" {
		keyInfo = FrostKeyInfo{
			KeyID:          keyID,
			Algorithm:      string(handle.Algorithm),
			ParticipantID:  handle.ParticipantID,
			GroupPublicKey: hexEncode(handle.GroupPublicKey),
			CreatedAt:      time.Now(),
		}
	}

	writeJSON(w, keyInfo, http.StatusOK)
}

// FrostDeleteKeyHandler handles DELETE /api/v1/frost/keys/{id} requests
func (h *HandlerContext) FrostDeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	if err := be.DeleteKey(attrs); err != nil {
		writeError(w, fmt.Errorf("failed to delete key: %w", err), http.StatusInternalServerError)
		return
	}

	resp := FrostDeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", keyID),
	}
	writeJSON(w, resp, http.StatusOK)
}

// FrostGenerateNoncesHandler handles POST /api/v1/frost/keys/{id}/nonces requests
func (h *HandlerContext) FrostGenerateNoncesHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	noncePackage, err := be.GenerateNonces(keyID)
	if err != nil {
		writeError(w, fmt.Errorf("failed to generate nonces: %w", err), http.StatusInternalServerError)
		return
	}

	resp := FrostGenerateNoncesResponse{
		ParticipantID:     noncePackage.ParticipantID,
		SessionID:         noncePackage.SessionID,
		HidingNonce:       hexEncode(noncePackage.Nonces.HidingNonce),
		BindingNonce:      hexEncode(noncePackage.Nonces.BindingNonce),
		HidingCommitment:  hexEncode(noncePackage.Commitments.HidingCommitment),
		BindingCommitment: hexEncode(noncePackage.Commitments.BindingCommitment),
	}
	writeJSON(w, resp, http.StatusOK)
}

// FrostSignRoundHandler handles POST /api/v1/frost/keys/{id}/sign requests
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

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Decode hex values
	message, err := hexDecode(req.Message)
	if err != nil {
		writeError(w, fmt.Errorf("invalid message hex: %w", err), http.StatusBadRequest)
		return
	}

	hidingNonce, err := hexDecode(req.HidingNonce)
	if err != nil {
		writeError(w, fmt.Errorf("invalid hiding_nonce hex: %w", err), http.StatusBadRequest)
		return
	}

	bindingNonce, err := hexDecode(req.BindingNonce)
	if err != nil {
		writeError(w, fmt.Errorf("invalid binding_nonce hex: %w", err), http.StatusBadRequest)
		return
	}

	hidingCommitment, err := hexDecode(req.HidingCommitment)
	if err != nil {
		writeError(w, fmt.Errorf("invalid hiding_commitment hex: %w", err), http.StatusBadRequest)
		return
	}

	bindingCommitment, err := hexDecode(req.BindingCommitment)
	if err != nil {
		writeError(w, fmt.Errorf("invalid binding_commitment hex: %w", err), http.StatusBadRequest)
		return
	}

	// Get key to find participant ID
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}
	key, err := be.GetKey(attrs)
	if err != nil {
		writeError(w, fmt.Errorf("key not found: %w", err), http.StatusNotFound)
		return
	}
	handle := key.(*frost.FrostKeyHandle)

	// Build nonce package
	noncePackage := &frost.NoncePackage{
		ParticipantID: handle.ParticipantID,
		SessionID:     req.SessionID,
		Nonces: &frost.SigningNonces{
			HidingNonce:  hidingNonce,
			BindingNonce: bindingNonce,
		},
		Commitments: &frost.SigningCommitments{
			ParticipantID:     handle.ParticipantID,
			HidingCommitment:  hidingCommitment,
			BindingCommitment: bindingCommitment,
		},
	}

	// Build commitments list
	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		hc, err := hexDecode(c.HidingCommitment)
		if err != nil {
			writeError(w, fmt.Errorf("invalid hiding_commitment hex: %w", err), http.StatusBadRequest)
			return
		}
		bc, err := hexDecode(c.BindingCommitment)
		if err != nil {
			writeError(w, fmt.Errorf("invalid binding_commitment hex: %w", err), http.StatusBadRequest)
			return
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

	share, err := be.SignRound(keyID, message, noncePackage, commitments)
	if err != nil {
		writeError(w, fmt.Errorf("failed to generate signature share: %w", err), http.StatusInternalServerError)
		return
	}

	resp := FrostSignRoundResponse{
		ParticipantID:  share.ParticipantID,
		SessionID:      share.SessionID,
		SignatureShare: hexEncode(share.Share),
	}
	writeJSON(w, resp, http.StatusOK)
}

// FrostAggregateHandler handles POST /api/v1/frost/aggregate requests
func (h *HandlerContext) FrostAggregateHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostAggregateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, fmt.Errorf("key_id is required"), http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Decode message
	message, err := hexDecode(req.Message)
	if err != nil {
		writeError(w, fmt.Errorf("invalid message hex: %w", err), http.StatusBadRequest)
		return
	}

	// Build commitments list
	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		hc, err := hexDecode(c.HidingCommitment)
		if err != nil {
			writeError(w, fmt.Errorf("invalid hiding_commitment hex: %w", err), http.StatusBadRequest)
			return
		}
		bc, err := hexDecode(c.BindingCommitment)
		if err != nil {
			writeError(w, fmt.Errorf("invalid binding_commitment hex: %w", err), http.StatusBadRequest)
			return
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

	// Build shares list
	shares := make([]*frost.SignatureShare, len(req.Shares))
	for i, s := range req.Shares {
		share, err := hexDecode(s.Share)
		if err != nil {
			writeError(w, fmt.Errorf("invalid share hex: %w", err), http.StatusBadRequest)
			return
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: s.ParticipantID,
			SessionID:     s.SessionID,
			Share:         share,
		}
	}

	signature, err := be.Aggregate(req.KeyID, message, commitments, shares)
	if err != nil {
		writeError(w, fmt.Errorf("failed to aggregate signatures: %w", err), http.StatusInternalServerError)
		return
	}

	// Verify if requested
	verified := false
	if req.Verify {
		if err := be.Verify(req.KeyID, message, signature); err == nil {
			verified = true
		}
	}

	resp := FrostAggregateResponse{
		Signature: hexEncode(signature),
		Verified:  verified,
	}
	writeJSON(w, resp, http.StatusOK)
}

// FrostVerifyHandler handles POST /api/v1/frost/verify requests
func (h *HandlerContext) FrostVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var req FrostVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, fmt.Errorf("key_id is required"), http.StatusBadRequest)
		return
	}

	be, err := getFrostBackend()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	message, err := hexDecode(req.Message)
	if err != nil {
		writeError(w, fmt.Errorf("invalid message hex: %w", err), http.StatusBadRequest)
		return
	}

	signature, err := hexDecode(req.Signature)
	if err != nil {
		writeError(w, fmt.Errorf("invalid signature hex: %w", err), http.StatusBadRequest)
		return
	}

	if err := be.Verify(req.KeyID, message, signature); err != nil {
		resp := FrostVerifyResponse{
			Valid:   false,
			Message: fmt.Sprintf("signature verification failed: %v", err),
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	resp := FrostVerifyResponse{
		Valid:   true,
		Message: "signature is valid",
	}
	writeJSON(w, resp, http.StatusOK)
}

// getFrostBackend retrieves the FROST backend from the keychain service
func getFrostBackend() (*frost.FrostBackend, error) {
	backends := keychain.Backends()
	for _, name := range backends {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue
		}
		backend := ks.Backend()
		if backend.Type() == types.BackendTypeFrost {
			if fb, ok := backend.(*frost.FrostBackend); ok {
				return fb, nil
			}
		}
	}
	return nil, fmt.Errorf("no FROST backend configured")
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
