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

package quic

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	GroupPublicKey string             `json:"group_public_key"`
	ParticipantID  uint32             `json:"participant_id,omitempty"`
	Packages       []FrostKeyPackage  `json:"packages,omitempty"`
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
	SecretShare        string            `json:"secret_share"`
	GroupPublicKey     string            `json:"group_public_key"`
	VerificationShares map[uint32]string `json:"verification_shares"`
}

// FrostKeyInfo represents FROST key information
type FrostKeyInfo struct {
	KeyID          string    `json:"key_id"`
	Algorithm      string    `json:"algorithm"`
	Threshold      int       `json:"threshold"`
	Total          int       `json:"total"`
	ParticipantID  uint32    `json:"participant_id"`
	GroupPublicKey string    `json:"group_public_key"`
	Participants   []string  `json:"participants,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// FrostListKeysResponse represents the list of FROST keys
type FrostListKeysResponse struct {
	Keys  []FrostKeyInfo `json:"keys"`
	Total int            `json:"total"`
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
	GroupPublicKey string `json:"group_public_key"`
}

// FrostDeleteKeyResponse represents the response from key deletion
type FrostDeleteKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// FrostGenerateNoncesResponse represents the response from nonce generation
type FrostGenerateNoncesResponse struct {
	ParticipantID     uint32 `json:"participant_id"`
	SessionID         string `json:"session_id"`
	HidingNonce       string `json:"hiding_nonce"`
	BindingNonce      string `json:"binding_nonce"`
	HidingCommitment  string `json:"hiding_commitment"`
	BindingCommitment string `json:"binding_commitment"`
}

// FrostCommitment represents a participant's nonce commitments
type FrostCommitment struct {
	ParticipantID     uint32 `json:"participant_id"`
	HidingCommitment  string `json:"hiding_commitment"`
	BindingCommitment string `json:"binding_commitment"`
}

// FrostSignRoundRequest represents a request for Round 2 signing
type FrostSignRoundRequest struct {
	Message           string            `json:"message"`
	SessionID         string            `json:"session_id"`
	HidingNonce       string            `json:"hiding_nonce"`
	BindingNonce      string            `json:"binding_nonce"`
	HidingCommitment  string            `json:"hiding_commitment"`
	BindingCommitment string            `json:"binding_commitment"`
	Commitments       []FrostCommitment `json:"commitments"`
}

// FrostSignRoundResponse represents the response from Round 2 signing
type FrostSignRoundResponse struct {
	ParticipantID  uint32 `json:"participant_id"`
	SessionID      string `json:"session_id"`
	SignatureShare string `json:"signature_share"`
}

// FrostSignatureShare represents a participant's signature share
type FrostSignatureShare struct {
	ParticipantID uint32 `json:"participant_id"`
	SessionID     string `json:"session_id"`
	Share         string `json:"share"`
}

// FrostAggregateRequest represents a request to aggregate signature shares
type FrostAggregateRequest struct {
	KeyID       string                `json:"key_id"`
	Message     string                `json:"message"`
	Commitments []FrostCommitment     `json:"commitments"`
	Shares      []FrostSignatureShare `json:"shares"`
	Verify      bool                  `json:"verify"`
}

// FrostAggregateResponse represents the aggregated signature response
type FrostAggregateResponse struct {
	Signature string `json:"signature"`
	Verified  bool   `json:"verified"`
}

// FrostVerifyRequest represents a request to verify a signature
type FrostVerifyRequest struct {
	KeyID     string `json:"key_id"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// FrostVerifyResponse represents the verification result
type FrostVerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// setupFrostRoutes registers FROST endpoints on the HTTP mux
func (s *Server) setupFrostRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/frost/keys", s.handleFrostKeys)
	mux.HandleFunc("/api/v1/frost/keys/", s.handleFrostKeyOperations)
	mux.HandleFunc("/api/v1/frost/keys/import", s.handleFrostImport)
	mux.HandleFunc("/api/v1/frost/aggregate", s.handleFrostAggregate)
	mux.HandleFunc("/api/v1/frost/verify", s.handleFrostVerify)
}

// handleFrostKeys handles FROST key operations
func (s *Server) handleFrostKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleFrostListKeys(w, r)
	case http.MethodPost:
		s.handleFrostGenerateKey(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleFrostListKeys handles listing FROST keys
func (s *Server) handleFrostListKeys(w http.ResponseWriter, r *http.Request) {
	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	keys, err := be.ListKeys()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys: %v", err))
		return
	}

	respKeys := make([]FrostKeyInfo, 0, len(keys))
	for _, k := range keys {
		if k.FrostAttributes != nil {
			var groupPubKey string
			handle, err := be.GetKey(k)
			if err == nil {
				if h, ok := handle.(*frost.FrostKeyHandle); ok {
					groupPubKey = hex.EncodeToString(h.GroupPublicKey)
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

	s.sendJSON(w, http.StatusOK, FrostListKeysResponse{
		Keys:  respKeys,
		Total: len(respKeys),
	})
}

// handleFrostGenerateKey handles FROST key generation
func (s *Server) handleFrostGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req FrostGenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.Threshold < 2 {
		s.sendError(w, http.StatusBadRequest, "threshold must be at least 2")
		return
	}
	if req.Total < req.Threshold {
		s.sendError(w, http.StatusBadRequest, "total must be >= threshold")
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

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.DealerMode {
		td := frost.NewTrustedDealer()
		frostConfig := frost.FrostConfig{
			Threshold:     req.Threshold,
			Total:         req.Total,
			Algorithm:     types.FrostAlgorithm(algorithm),
			ParticipantID: 1,
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate FROST packages: %v", err))
			return
		}

		respPackages := make([]FrostKeyPackage, len(packages))
		for i, pkg := range packages {
			vsMap := make(map[uint32]string)
			for id, vs := range pubPkg.VerificationShares {
				vsMap[id] = hex.EncodeToString(vs)
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
				SecretShare:        hex.EncodeToString(pkg.SecretShare.Value),
				GroupPublicKey:     hex.EncodeToString(pubPkg.GroupPublicKey),
				VerificationShares: vsMap,
			}
		}

		s.sendJSON(w, http.StatusCreated, FrostGenerateKeyResponse{
			KeyID:          keyID,
			Algorithm:      algorithm,
			Threshold:      req.Threshold,
			Total:          req.Total,
			GroupPublicKey: hex.EncodeToString(pubPkg.GroupPublicKey),
			Packages:       respPackages,
			CreatedAt:      time.Now(),
		})
		return
	}

	if req.ParticipantID == 0 {
		s.sendError(w, http.StatusBadRequest, "participant_id is required in participant mode")
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
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate FROST key: %v", err))
		return
	}

	handle := key.(*frost.FrostKeyHandle)

	s.sendJSON(w, http.StatusCreated, FrostGenerateKeyResponse{
		KeyID:          keyID,
		Algorithm:      algorithm,
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: hex.EncodeToString(handle.GroupPublicKey),
		ParticipantID:  req.ParticipantID,
		CreatedAt:      time.Now(),
	})
}

// handleFrostKeyOperations handles operations on specific FROST keys
func (s *Server) handleFrostKeyOperations(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/frost/keys/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	keyID := parts[0]

	var operation string
	if len(parts) > 1 {
		operation = parts[1]
	}

	switch operation {
	case "nonces":
		s.handleFrostGenerateNonces(w, r, keyID)
	case "sign":
		s.handleFrostSignRound(w, r, keyID)
	case "":
		switch r.Method {
		case http.MethodGet:
			s.handleFrostGetKey(w, r, keyID)
		case http.MethodDelete:
			s.handleFrostDeleteKey(w, r, keyID)
		default:
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		s.sendError(w, http.StatusNotFound, "operation not found")
	}
}

// handleFrostGetKey handles retrieving a FROST key
func (s *Server) handleFrostGetKey(w http.ResponseWriter, r *http.Request, keyID string) {
	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	key, err := be.GetKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	handle := key.(*frost.FrostKeyHandle)

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
				GroupPublicKey: hex.EncodeToString(handle.GroupPublicKey),
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
			GroupPublicKey: hex.EncodeToString(handle.GroupPublicKey),
			CreatedAt:      time.Now(),
		}
	}

	s.sendJSON(w, http.StatusOK, keyInfo)
}

// handleFrostDeleteKey handles deleting a FROST key
func (s *Server) handleFrostDeleteKey(w http.ResponseWriter, r *http.Request, keyID string) {
	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	if err := be.DeleteKey(attrs); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, FrostDeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", keyID),
	})
}

// handleFrostGenerateNonces handles generating nonces for Round 1
func (s *Server) handleFrostGenerateNonces(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	noncePackage, err := be.GenerateNonces(keyID)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate nonces: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, FrostGenerateNoncesResponse{
		ParticipantID:     noncePackage.ParticipantID,
		SessionID:         noncePackage.SessionID,
		HidingNonce:       hex.EncodeToString(noncePackage.Nonces.HidingNonce),
		BindingNonce:      hex.EncodeToString(noncePackage.Nonces.BindingNonce),
		HidingCommitment:  hex.EncodeToString(noncePackage.Commitments.HidingCommitment),
		BindingCommitment: hex.EncodeToString(noncePackage.Commitments.BindingCommitment),
	})
}

// handleFrostSignRound handles Round 2 signature share generation
func (s *Server) handleFrostSignRound(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req FrostSignRoundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Decode hex values
	message, err := hex.DecodeString(strings.TrimPrefix(req.Message, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid message hex: %v", err))
		return
	}

	hidingNonce, err := hex.DecodeString(strings.TrimPrefix(req.HidingNonce, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid hiding_nonce hex: %v", err))
		return
	}

	bindingNonce, err := hex.DecodeString(strings.TrimPrefix(req.BindingNonce, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid binding_nonce hex: %v", err))
		return
	}

	hidingCommitment, err := hex.DecodeString(strings.TrimPrefix(req.HidingCommitment, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid hiding_commitment hex: %v", err))
		return
	}

	bindingCommitment, err := hex.DecodeString(strings.TrimPrefix(req.BindingCommitment, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid binding_commitment hex: %v", err))
		return
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}
	key, err := be.GetKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}
	handle := key.(*frost.FrostKeyHandle)

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

	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		hc, err := hex.DecodeString(strings.TrimPrefix(c.HidingCommitment, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid hiding_commitment hex: %v", err))
			return
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid binding_commitment hex: %v", err))
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
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate signature share: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, FrostSignRoundResponse{
		ParticipantID:  share.ParticipantID,
		SessionID:      share.SessionID,
		SignatureShare: hex.EncodeToString(share.Share),
	})
}

// handleFrostImport handles FROST key package import
func (s *Server) handleFrostImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req FrostImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	pkg := req.Package
	if pkg.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "package.key_id is required")
		return
	}

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	secretShare, err := hex.DecodeString(strings.TrimPrefix(pkg.SecretShare, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid secret_share hex: %v", err))
		return
	}

	groupPubKey, err := hex.DecodeString(strings.TrimPrefix(pkg.GroupPublicKey, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid group_public_key hex: %v", err))
		return
	}

	vsMap := make(map[uint32][]byte)
	for id, vsHex := range pkg.VerificationShares {
		vs, err := hex.DecodeString(strings.TrimPrefix(vsHex, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid verification_share hex for participant %d: %v", id, err))
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
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to store key package: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, FrostImportKeyResponse{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantID),
		KeyID:          pkg.KeyID,
		ParticipantID:  pkg.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
	})
}

// handleFrostAggregate handles signature aggregation
func (s *Server) handleFrostAggregate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req FrostAggregateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	message, err := hex.DecodeString(strings.TrimPrefix(req.Message, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid message hex: %v", err))
		return
	}

	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		hc, err := hex.DecodeString(strings.TrimPrefix(c.HidingCommitment, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid hiding_commitment hex: %v", err))
			return
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid binding_commitment hex: %v", err))
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

	shares := make([]*frost.SignatureShare, len(req.Shares))
	for i, sh := range req.Shares {
		share, err := hex.DecodeString(strings.TrimPrefix(sh.Share, "0x"))
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid share hex: %v", err))
			return
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: sh.ParticipantID,
			SessionID:     sh.SessionID,
			Share:         share,
		}
	}

	signature, err := be.Aggregate(req.KeyID, message, commitments, shares)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to aggregate signatures: %v", err))
		return
	}

	verified := false
	if req.Verify {
		if err := be.Verify(req.KeyID, message, signature); err == nil {
			verified = true
		}
	}

	s.sendJSON(w, http.StatusOK, FrostAggregateResponse{
		Signature: hex.EncodeToString(signature),
		Verified:  verified,
	})
}

// handleFrostVerify handles signature verification
func (s *Server) handleFrostVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req FrostVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	be, err := s.getFrostBackend()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	message, err := hex.DecodeString(strings.TrimPrefix(req.Message, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid message hex: %v", err))
		return
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(req.Signature, "0x"))
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid signature hex: %v", err))
		return
	}

	if err := be.Verify(req.KeyID, message, signature); err != nil {
		s.sendJSON(w, http.StatusOK, FrostVerifyResponse{
			Valid:   false,
			Message: fmt.Sprintf("signature verification failed: %v", err),
		})
		return
	}

	s.sendJSON(w, http.StatusOK, FrostVerifyResponse{
		Valid:   true,
		Message: "signature is valid",
	})
}

// getFrostBackend retrieves the FROST backend from the keychain service
func (s *Server) getFrostBackend() (*frost.FrostBackend, error) {
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
