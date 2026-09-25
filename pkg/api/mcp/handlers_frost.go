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

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// frostInvalidParamsError wraps a malformed FROST request field (a bad hex
// encoding, an out-of-range threshold) as a *KeyOpError carrying
// ErrCodeInvalidParams. err is optional context for a decode failure; it is
// nil for a plain "X is required" refusal. The frost-tagged gRPC transport
// (service_frost.go) carries no counterpart for the hex-decode failures this
// JSON-RPC surface alone can produce -- proto's FROST messages carry raw
// bytes, not hex-encoded strings -- so these are classified the same way
// this package's own "invalid curve"/"invalid wrapping public key PEM"
// checks in handlers.go are: a malformed field is the caller's fault, not
// the server's.
func frostInvalidParamsError(msg string, err error) error {
	if err == nil {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: msg}}
	}
	return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Wrapped{Msg: msg, Err: err}}
}

// frostOperationError wraps an error from a FROST backend operation as a
// *KeyOpError carrying ErrCodeInternalError, mirroring service_frost.go's
// FrostGenerateKey/FrostImportKey/FrostListKeys/FrostDeleteKey/
// FrostGenerateNonces/FrostSignRound/FrostAggregate, which all report
// codes.Internal unconditionally for the same underlying FROST backend
// calls.
func frostOperationError(msg string, err error) error {
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: msg, Err: err}}
}

// frostKeyNotFoundError wraps a FROST key lookup failure as a *KeyOpError
// carrying sdkssh.JSONRPCCodeNotFound, mirroring service_frost.go's
// FrostGetKey and FrostSignRound, which both report codes.NotFound for the
// identical GetKey failure.
func frostKeyNotFoundError(msg string, err error) error {
	return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: &errs.Wrapped{Msg: msg, Err: err}}
}

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
func (s *Server) handleFrostGenerateKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostGenerateKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.Threshold < 2 {
		return nil, frostInvalidParamsError("threshold must be at least 2", nil)
	}
	if params.Total < params.Threshold {
		return nil, frostInvalidParamsError("total must be >= threshold", nil)
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
			return nil, frostOperationError("failed to generate FROST packages", err)
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
		return nil, frostInvalidParamsError("participant_id is required in participant mode", nil)
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

	key, err := be.GenerateKey(ctx, attrs)
	if err != nil {
		return nil, frostOperationError("failed to generate FROST key", err)
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
func (s *Server) handleFrostImportKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostImportKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	pkg := params.Package
	if pkg.KeyID == "" {
		return nil, frostInvalidParamsError("package.key_id is required", nil)
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	secretShare, err := hex.DecodeString(strings.TrimPrefix(pkg.SecretShare, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid secret_share hex", err)
	}

	groupPubKey, err := hex.DecodeString(strings.TrimPrefix(pkg.GroupPublicKey, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid group_public_key hex", err)
	}

	vsMap := make(map[uint32][]byte)
	for id, vsHex := range pkg.VerificationShares {
		vs, err := hex.DecodeString(strings.TrimPrefix(vsHex, "0x"))
		if err != nil {
			return nil, frostInvalidParamsError(fmt.Sprintf("invalid verification_share hex for participant %d", id), err)
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
	if err := ks.StoreKeyPackage(ctx, pkg.KeyID, keyPackage, metadata); err != nil {
		return nil, frostOperationError("failed to store key package", err)
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
func (s *Server) handleFrostListKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	keys, err := be.ListKeys(ctx)
	if err != nil {
		return nil, frostOperationError("failed to list keys", err)
	}

	respKeys := make([]FrostKeyInfo, 0, len(keys))
	for _, k := range keys {
		if k.FrostAttributes != nil {
			var groupPubKey string
			handle, err := be.GetKey(ctx, k)
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
func (s *Server) handleFrostGetKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostGetKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
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

	key, err := be.GetKey(ctx, attrs)
	if err != nil {
		return nil, frostKeyNotFoundError("key not found", err)
	}

	handle := key.(*frost.FrostKeyHandle)

	keys, _ := be.ListKeys(ctx)
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
func (s *Server) handleFrostDeleteKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostDeleteKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
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

	if err := be.DeleteKey(ctx, attrs); err != nil {
		return nil, frostOperationError("failed to delete key", err)
	}

	return FrostDeleteKeyResult{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", params.KeyID),
	}, nil
}

// handleFrostGenerateNonces handles the frost.generateNonces method
func (s *Server) handleFrostGenerateNonces(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostGenerateNoncesParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	noncePackage, err := be.GenerateNonces(params.KeyID)
	if err != nil {
		return nil, frostOperationError("failed to generate nonces", err)
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
func (s *Server) handleFrostSignRound(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostSignRoundParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	// Decode hex values
	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid message hex", err)
	}

	hidingNonce, err := hex.DecodeString(strings.TrimPrefix(params.HidingNonce, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid hiding_nonce hex", err)
	}

	bindingNonce, err := hex.DecodeString(strings.TrimPrefix(params.BindingNonce, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid binding_nonce hex", err)
	}

	hidingCommitment, err := hex.DecodeString(strings.TrimPrefix(params.HidingCommitment, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid hiding_commitment hex", err)
	}

	bindingCommitment, err := hex.DecodeString(strings.TrimPrefix(params.BindingCommitment, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid binding_commitment hex", err)
	}

	attrs := &types.KeyAttributes{
		CN:        params.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}
	key, err := be.GetKey(ctx, attrs)
	if err != nil {
		return nil, frostKeyNotFoundError("key not found", err)
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
			return nil, frostInvalidParamsError("invalid hiding_commitment hex", err)
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			return nil, frostInvalidParamsError("invalid binding_commitment hex", err)
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
		return nil, frostOperationError("failed to generate signature share", err)
	}

	return FrostSignRoundResult{
		ParticipantID:  share.ParticipantID,
		SessionID:      share.SessionID,
		SignatureShare: hex.EncodeToString(share.Share),
	}, nil
}

// handleFrostAggregate handles the frost.aggregate method
func (s *Server) handleFrostAggregate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostAggregateParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid message hex", err)
	}

	commitments := make([]*frost.Commitment, len(params.Commitments))
	for i, c := range params.Commitments {
		hc, err := hex.DecodeString(strings.TrimPrefix(c.HidingCommitment, "0x"))
		if err != nil {
			return nil, frostInvalidParamsError("invalid hiding_commitment hex", err)
		}
		bc, err := hex.DecodeString(strings.TrimPrefix(c.BindingCommitment, "0x"))
		if err != nil {
			return nil, frostInvalidParamsError("invalid binding_commitment hex", err)
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
			return nil, frostInvalidParamsError("invalid share hex", err)
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: sh.ParticipantID,
			SessionID:     sh.SessionID,
			Share:         share,
		}
	}

	signature, err := be.Aggregate(params.KeyID, message, commitments, shares)
	if err != nil {
		return nil, frostOperationError("failed to aggregate signatures", err)
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
func (s *Server) handleFrostVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostVerifyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, frostInvalidParamsError("key_id is required", nil)
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, err
	}

	message, err := hex.DecodeString(strings.TrimPrefix(params.Message, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid message hex", err)
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(params.Signature, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid signature hex", err)
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

// ErrFrostBackendNotConfigured is returned when no registered backend is a
// FROST backend.
var ErrFrostBackendNotConfigured = errors.New("mcp: no FROST backend configured")

// getFrostBackend retrieves the FROST backend from the xkms service. Its
// error is already a *KeyOpError, mirroring service_frost.go's own
// getFrostBackend, whose every caller reports the identical failure as
// codes.Internal ("failed to get FROST backend: %v"): the callers here just
// forward it (return nil, err) rather than re-wrapping it individually.
func (s *Server) getFrostBackend() (*frost.FrostBackend, error) {
	backends := s.xkmsService.BackendNames()
	for _, name := range backends {
		ks, err := s.xkmsService.LookupBackend(name)
		if err != nil {
			continue
		}
		backend := ks.KeyProvider()
		if backend.Type() == types.BackendTypeFrost {
			if fb, ok := backend.(*frost.FrostBackend); ok {
				return fb, nil
			}
		}
	}
	return nil, frostOperationError("failed to get FROST backend", ErrFrostBackendNotConfigured)
}

// routeFrostMethods routes FROST-related MCP methods
func (s *Server) routeFrostMethods(ctx context.Context, req *JSONRPCRequest) (interface{}, error, bool) {
	switch req.Method {
	case "frost.generateKey":
		result, err := s.handleFrostGenerateKey(ctx, req)
		return result, err, true
	case "frost.importKey":
		result, err := s.handleFrostImportKey(ctx, req)
		return result, err, true
	case "frost.listKeys":
		result, err := s.handleFrostListKeys(ctx, req)
		return result, err, true
	case "frost.getKey":
		result, err := s.handleFrostGetKey(ctx, req)
		return result, err, true
	case "frost.deleteKey":
		result, err := s.handleFrostDeleteKey(ctx, req)
		return result, err, true
	case "frost.generateNonces":
		result, err := s.handleFrostGenerateNonces(ctx, req)
		return result, err, true
	case "frost.signRound":
		result, err := s.handleFrostSignRound(ctx, req)
		return result, err, true
	case "frost.aggregate":
		result, err := s.handleFrostAggregate(ctx, req)
		return result, err, true
	case "frost.verify":
		result, err := s.handleFrostVerify(ctx, req)
		return result, err, true
	}
	return nil, nil, false
}
