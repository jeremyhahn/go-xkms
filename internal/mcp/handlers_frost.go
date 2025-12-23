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

package mcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// FROST request/response types

// FrostGenerateKeyParams represents parameters for FROST key generation
type FrostGenerateKeyParams struct {
	KeyID         string   `json:"key_id,omitempty"`
	Algorithm     string   `json:"algorithm,omitempty"`
	Threshold     int      `json:"threshold"`
	Total         int      `json:"total"`
	Participants  []string `json:"participants,omitempty"`
	ParticipantID uint32   `json:"participant_id,omitempty"`
	DealerMode    bool     `json:"dealer_mode,omitempty"`
}

// FrostGenerateKeyResult represents the result of FROST key generation
type FrostGenerateKeyResult struct {
	KeyID          string            `json:"key_id"`
	Algorithm      string            `json:"algorithm"`
	Threshold      int               `json:"threshold"`
	Total          int               `json:"total"`
	GroupPublicKey string            `json:"group_public_key"`
	ParticipantID  uint32            `json:"participant_id,omitempty"`
	Packages       []FrostKeyPackage `json:"packages,omitempty"`
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
	SecretShare        string            `json:"secret_share"`
	GroupPublicKey     string            `json:"group_public_key"`
	VerificationShares map[uint32]string `json:"verification_shares"`
}

// FrostImportKeyParams represents parameters for importing a FROST key package
type FrostImportKeyParams struct {
	Package FrostKeyPackage `json:"package"`
}

// FrostImportKeyResult represents the result of FROST key import
type FrostImportKeyResult struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	KeyID          string `json:"key_id"`
	ParticipantID  uint32 `json:"participant_id"`
	GroupPublicKey string `json:"group_public_key"`
}

// FrostGetKeyParams represents parameters for getting a FROST key
type FrostGetKeyParams struct {
	KeyID string `json:"key_id"`
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

// FrostListKeysResult represents the list of FROST keys
type FrostListKeysResult struct {
	Keys  []FrostKeyInfo `json:"keys"`
	Total int            `json:"total"`
}

// FrostDeleteKeyParams represents parameters for deleting a FROST key
type FrostDeleteKeyParams struct {
	KeyID string `json:"key_id"`
}

// FrostDeleteKeyResult represents the result of FROST key deletion
type FrostDeleteKeyResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// FrostGenerateNoncesParams represents parameters for generating nonces
type FrostGenerateNoncesParams struct {
	KeyID string `json:"key_id"`
}

// FrostGenerateNoncesResult represents the result of nonce generation
type FrostGenerateNoncesResult struct {
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

// FrostSignRoundParams represents parameters for Round 2 signing
type FrostSignRoundParams struct {
	KeyID             string            `json:"key_id"`
	Message           string            `json:"message"`
	SessionID         string            `json:"session_id"`
	HidingNonce       string            `json:"hiding_nonce"`
	BindingNonce      string            `json:"binding_nonce"`
	HidingCommitment  string            `json:"hiding_commitment"`
	BindingCommitment string            `json:"binding_commitment"`
	Commitments       []FrostCommitment `json:"commitments"`
}

// FrostSignRoundResult represents the result of Round 2 signing
type FrostSignRoundResult struct {
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

// FrostAggregateParams represents parameters for signature aggregation
type FrostAggregateParams struct {
	KeyID       string                `json:"key_id"`
	Message     string                `json:"message"`
	Commitments []FrostCommitment     `json:"commitments"`
	Shares      []FrostSignatureShare `json:"shares"`
	Verify      bool                  `json:"verify"`
}

// FrostAggregateResult represents the aggregated signature result
type FrostAggregateResult struct {
	Signature string `json:"signature"`
	Verified  bool   `json:"verified"`
}

// FrostVerifyParams represents parameters for signature verification
type FrostVerifyParams struct {
	KeyID     string `json:"key_id"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// FrostVerifyResult represents the verification result
type FrostVerifyResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// handleFrostGenerateKey handles the frost.generateKey method
func (s *Server) handleFrostGenerateKey(req *JSONRPCRequest) (interface{}, error) {
	var params FrostGenerateKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.Threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if params.Total < params.Threshold {
		return nil, fmt.Errorf("total must be >= threshold")
	}

	algorithm := params.Algorithm
	if algorithm == "" {
		algorithm = string(types.FrostAlgorithmEd25519)
	}

	keyID := params.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("frost-key-%d", time.Now().UnixNano())
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	if params.DealerMode {
		td := frost.NewTrustedDealer()
		frostConfig := frost.FrostConfig{
			Threshold:     params.Threshold,
			Total:         params.Total,
			Algorithm:     types.FrostAlgorithm(algorithm),
			ParticipantID: 1,
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate FROST packages: %w", err)
		}

		respPackages := make([]FrostKeyPackage, len(packages))
		for i, pkg := range packages {
			vsMap := make(map[uint32]string)
			for id, vs := range pubPkg.VerificationShares {
				vsMap[id] = hex.EncodeToString(vs)
			}

			var participantName string
			if i < len(params.Participants) {
				participantName = params.Participants[i]
			}

			respPackages[i] = FrostKeyPackage{
				KeyID:              keyID,
				Algorithm:          algorithm,
				Threshold:          params.Threshold,
				Total:              params.Total,
				ParticipantID:      pkg.ParticipantID,
				ParticipantName:    participantName,
				SecretShare:        hex.EncodeToString(pkg.SecretShare.Value),
				GroupPublicKey:     hex.EncodeToString(pubPkg.GroupPublicKey),
				VerificationShares: vsMap,
			}
		}

		return FrostGenerateKeyResult{
			KeyID:          keyID,
			Algorithm:      algorithm,
			Threshold:      params.Threshold,
			Total:          params.Total,
			GroupPublicKey: hex.EncodeToString(pubPkg.GroupPublicKey),
			Packages:       respPackages,
			CreatedAt:      time.Now(),
		}, nil
	}

	if params.ParticipantID == 0 {
		return nil, fmt.Errorf("participant_id is required in participant mode")
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Algorithm:     types.FrostAlgorithm(algorithm),
			Threshold:     params.Threshold,
			Total:         params.Total,
			Participants:  params.Participants,
			ParticipantID: params.ParticipantID,
		},
	}

	key, err := be.GenerateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate FROST key: %w", err)
	}

	handle := key.(*frost.FrostKeyHandle)

	return FrostGenerateKeyResult{
		KeyID:          keyID,
		Algorithm:      algorithm,
		Threshold:      params.Threshold,
		Total:          params.Total,
		GroupPublicKey: hex.EncodeToString(handle.GroupPublicKey),
		ParticipantID:  params.ParticipantID,
		CreatedAt:      time.Now(),
	}, nil
}

// handleFrostImportKey handles the frost.importKey method
func (s *Server) handleFrostImportKey(req *JSONRPCRequest) (interface{}, error) {
	var params FrostImportKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	pkg := params.Package
	if pkg.KeyID == "" {
		return nil, fmt.Errorf("package.key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	secretShare, err := hex.DecodeString(strings.TrimPrefix(pkg.SecretShare, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid secret_share hex: %w", err)
	}

	groupPubKey, err := hex.DecodeString(strings.TrimPrefix(pkg.GroupPublicKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid group_public_key hex: %w", err)
	}

	vsMap := make(map[uint32][]byte)
	for id, vsHex := range pkg.VerificationShares {
		vs, err := hex.DecodeString(strings.TrimPrefix(vsHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid verification_share hex for participant %d: %w", id, err)
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
		return nil, fmt.Errorf("failed to store key package: %w", err)
	}

	return FrostImportKeyResult{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantID),
		KeyID:          pkg.KeyID,
		ParticipantID:  pkg.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
	}, nil
}

// handleFrostListKeys handles the frost.listKeys method
func (s *Server) handleFrostListKeys(req *JSONRPCRequest) (interface{}, error) {
	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	keys, err := be.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
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

	return FrostListKeysResult{
		Keys:  respKeys,
		Total: len(respKeys),
	}, nil
}

// handleFrostGetKey handles the frost.getKey method
func (s *Server) handleFrostGetKey(req *JSONRPCRequest) (interface{}, error) {
	var params FrostGetKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		CN:        params.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	key, err := be.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	handle := key.(*frost.FrostKeyHandle)

	keys, _ := be.ListKeys()
	var keyInfo FrostKeyInfo
	for _, k := range keys {
		if k.CN == params.KeyID && k.FrostAttributes != nil {
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
			KeyID:          params.KeyID,
			Algorithm:      string(handle.Algorithm),
			ParticipantID:  handle.ParticipantID,
			GroupPublicKey: hex.EncodeToString(handle.GroupPublicKey),
			CreatedAt:      time.Now(),
		}
	}

	return keyInfo, nil
}

// handleFrostDeleteKey handles the frost.deleteKey method
func (s *Server) handleFrostDeleteKey(req *JSONRPCRequest) (interface{}, error) {
	var params FrostDeleteKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		CN:        params.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	if err := be.DeleteKey(attrs); err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	return FrostDeleteKeyResult{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", params.KeyID),
	}, nil
}

// handleFrostGenerateNonces handles the frost.generateNonces method
func (s *Server) handleFrostGenerateNonces(req *JSONRPCRequest) (interface{}, error) {
	var params FrostGenerateNoncesParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	noncePackage, err := be.GenerateNonces(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonces: %w", err)
	}

	return FrostGenerateNoncesResult{
		ParticipantID:     noncePackage.ParticipantID,
		SessionID:         noncePackage.SessionID,
		HidingNonce:       hex.EncodeToString(noncePackage.Nonces.HidingNonce),
		BindingNonce:      hex.EncodeToString(noncePackage.Nonces.BindingNonce),
		HidingCommitment:  hex.EncodeToString(noncePackage.Commitments.HidingCommitment),
		BindingCommitment: hex.EncodeToString(noncePackage.Commitments.BindingCommitment),
	}, nil
}

// handleFrostSignRound handles the frost.signRound method
func (s *Server) handleFrostSignRound(req *JSONRPCRequest) (interface{}, error) {
	var params FrostSignRoundParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	// Decode hex values
	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid message hex: %w", err)
	}

	hidingNonce, err := hex.DecodeString(strings.TrimPrefix(params.HidingNonce, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid hiding_nonce hex: %w", err)
	}

	bindingNonce, err := hex.DecodeString(strings.TrimPrefix(params.BindingNonce, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid binding_nonce hex: %w", err)
	}

	hidingCommitment, err := hex.DecodeString(strings.TrimPrefix(params.HidingCommitment, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid hiding_commitment hex: %w", err)
	}

	bindingCommitment, err := hex.DecodeString(strings.TrimPrefix(params.BindingCommitment, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid binding_commitment hex: %w", err)
	}

	attrs := &types.KeyAttributes{
		CN:        params.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}
	key, err := be.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}
	handle := key.(*frost.FrostKeyHandle)

	noncePackage := &frost.NoncePackage{
		ParticipantID: handle.ParticipantID,
		SessionID:     params.SessionID,
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

	commitments := make([]*frost.Commitment, len(params.Commitments))
	for i, c := range params.Commitments {
		hc, err := hex.DecodeString(strings.TrimPrefix(c.HidingCommitment, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid hiding_commitment hex: %w", err)
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid binding_commitment hex: %w", err)
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

	share, err := be.SignRound(params.KeyID, message, noncePackage, commitments)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature share: %w", err)
	}

	return FrostSignRoundResult{
		ParticipantID:  share.ParticipantID,
		SessionID:      share.SessionID,
		SignatureShare: hex.EncodeToString(share.Share),
	}, nil
}

// handleFrostAggregate handles the frost.aggregate method
func (s *Server) handleFrostAggregate(req *JSONRPCRequest) (interface{}, error) {
	var params FrostAggregateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid message hex: %w", err)
	}

	commitments := make([]*frost.Commitment, len(params.Commitments))
	for i, c := range params.Commitments {
		hc, err := hex.DecodeString(strings.TrimPrefix(c.HidingCommitment, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid hiding_commitment hex: %w", err)
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid binding_commitment hex: %w", err)
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

	shares := make([]*frost.SignatureShare, len(params.Shares))
	for i, sh := range params.Shares {
		share, err := hex.DecodeString(strings.TrimPrefix(sh.Share, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid share hex: %w", err)
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: sh.ParticipantID,
			SessionID:     sh.SessionID,
			Share:         share,
		}
	}

	signature, err := be.Aggregate(params.KeyID, message, commitments, shares)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	verified := false
	if params.Verify {
		if err := be.Verify(params.KeyID, message, signature); err == nil {
			verified = true
		}
	}

	return FrostAggregateResult{
		Signature: hex.EncodeToString(signature),
		Verified:  verified,
	}, nil
}

// handleFrostVerify handles the frost.verify method
func (s *Server) handleFrostVerify(req *JSONRPCRequest) (interface{}, error) {
	var params FrostVerifyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid message hex: %w", err)
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(params.Signature, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	if err := be.Verify(params.KeyID, message, signature); err != nil {
		return FrostVerifyResult{
			Valid:   false,
			Message: fmt.Sprintf("signature verification failed: %v", err),
		}, nil
	}

	return FrostVerifyResult{
		Valid:   true,
		Message: "signature is valid",
	}, nil
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

// routeFrostMethods routes FROST-related MCP methods
func (s *Server) routeFrostMethods(req *JSONRPCRequest) (interface{}, error, bool) {
	switch req.Method {
	case "frost.generateKey":
		result, err := s.handleFrostGenerateKey(req)
		return result, err, true
	case "frost.importKey":
		result, err := s.handleFrostImportKey(req)
		return result, err, true
	case "frost.listKeys":
		result, err := s.handleFrostListKeys(req)
		return result, err, true
	case "frost.getKey":
		result, err := s.handleFrostGetKey(req)
		return result, err, true
	case "frost.deleteKey":
		result, err := s.handleFrostDeleteKey(req)
		return result, err, true
	case "frost.generateNonces":
		result, err := s.handleFrostGenerateNonces(req)
		return result, err, true
	case "frost.signRound":
		result, err := s.handleFrostSignRound(req)
		return result, err, true
	case "frost.aggregate":
		result, err := s.handleFrostAggregate(req)
		return result, err, true
	case "frost.verify":
		result, err := s.handleFrostVerify(req)
		return result, err, true
	}
	return nil, nil, false
}
