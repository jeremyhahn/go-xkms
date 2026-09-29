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
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// decodeFrostHex decodes a hex-encoded FROST request field, with or without
// a 0x prefix, refusing a malformed one as invalid params naming field.
func decodeFrostHex(field, value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		return nil, frostInvalidParamsError("invalid "+field+" hex", err)
	}
	return decoded, nil
}

// decodeFrostCommitments decodes the hex-encoded commitments of a signing
// request.
func decodeFrostCommitments(in []FrostCommitment) ([]*frost.Commitment, error) {
	commitments := make([]*frost.Commitment, len(in))
	for i, c := range in {
		hc, err := decodeFrostHex("hiding_commitment", c.HidingCommitment)
		if err != nil {
			return nil, err
		}
		bc, err := decodeFrostHex("binding_commitment", c.BindingCommitment)
		if err != nil {
			return nil, err
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

// frostKeyInfo renders a service key description for the wire.
func frostKeyInfo(info *xkms.FrostKeyInfo) FrostKeyInfo {
	return FrostKeyInfo{
		KeyID:          info.KeyID,
		Algorithm:      info.Algorithm,
		Threshold:      info.Threshold,
		Total:          info.Total,
		ParticipantID:  info.ParticipantID,
		GroupPublicKey: hex.EncodeToString(info.GroupPublicKey),
		Participants:   info.Participants,
		CreatedAt:      info.CreatedAt,
	}
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

// The frost.* handlers are thin adapters over the XKMSService FROST methods,
// which resolve every key inside the caller's tenant (go-xkms#1231); errors
// are classified by mapKeyOpError, so another tenant's key is the same Not
// found a missing key is.

// handleFrostGenerateKey handles the frost.generateKey method
func (s *Server) handleFrostGenerateKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostGenerateKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	gen, err := s.xkmsService.FrostGenerateKey(ctx, &xkms.FrostGenerateKeyRequest{
		KeyID:         params.KeyID,
		Algorithm:     params.Algorithm,
		Threshold:     params.Threshold,
		Total:         params.Total,
		Participants:  params.Participants,
		ParticipantID: params.ParticipantID,
		DealerMode:    params.DealerMode,
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	var packages []FrostKeyPackage
	for _, pkg := range gen.Packages {
		shares := make(map[uint32]string, len(pkg.VerificationShares))
		for id, share := range pkg.VerificationShares {
			shares[id] = hex.EncodeToString(share)
		}
		packages = append(packages, FrostKeyPackage{
			KeyID:              gen.KeyID,
			Algorithm:          gen.Algorithm,
			Threshold:          gen.Threshold,
			Total:              gen.Total,
			ParticipantID:      pkg.ParticipantID,
			ParticipantName:    pkg.ParticipantName,
			SecretShare:        hex.EncodeToString(pkg.SecretShare),
			GroupPublicKey:     hex.EncodeToString(pkg.GroupPublicKey),
			VerificationShares: shares,
		})
	}

	return FrostGenerateKeyResult{
		KeyID:          gen.KeyID,
		Algorithm:      gen.Algorithm,
		Threshold:      gen.Threshold,
		Total:          gen.Total,
		GroupPublicKey: hex.EncodeToString(gen.GroupPublicKey),
		ParticipantID:  gen.ParticipantID,
		Packages:       packages,
		CreatedAt:      gen.CreatedAt,
	}, nil
}

// handleFrostImportKey handles the frost.importKey method. The package is
// imported into the caller's tenant.
func (s *Server) handleFrostImportKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params FrostImportKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	pkg := params.Package
	if pkg.KeyID == "" {
		return nil, frostInvalidParamsError("package.key_id is required", nil)
	}
	secretShare, err := decodeFrostHex("secret_share", pkg.SecretShare)
	if err != nil {
		return nil, err
	}
	groupPubKey, err := decodeFrostHex("group_public_key", pkg.GroupPublicKey)
	if err != nil {
		return nil, err
	}
	shares := make(map[uint32][]byte, len(pkg.VerificationShares))
	for id, shareHex := range pkg.VerificationShares {
		share, err := hex.DecodeString(strings.TrimPrefix(shareHex, "0x"))
		if err != nil {
			return nil, frostInvalidParamsError(fmt.Sprintf("invalid verification_share hex for participant %d", id), err)
		}
		shares[id] = share
	}

	if err := s.xkmsService.FrostImportKey(ctx, &xkms.FrostImportKeyRequest{
		KeyID:              pkg.KeyID,
		Algorithm:          pkg.Algorithm,
		Threshold:          pkg.Threshold,
		Total:              pkg.Total,
		ParticipantID:      pkg.ParticipantID,
		SecretShare:        secretShare,
		GroupPublicKey:     groupPubKey,
		VerificationShares: shares,
	}); err != nil {
		return nil, mapKeyOpError(err)
	}

	return FrostImportKeyResult{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantID),
		KeyID:          pkg.KeyID,
		ParticipantID:  pkg.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
	}, nil
}

// handleFrostListKeys handles the frost.listKeys method. The listing holds
// only the caller's tenant's keys.
func (s *Server) handleFrostListKeys(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	keys, err := s.xkmsService.FrostListKeys(ctx)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	infos := make([]FrostKeyInfo, 0, len(keys))
	for i := range keys {
		infos = append(infos, frostKeyInfo(&keys[i]))
	}
	return FrostListKeysResult{Keys: infos, Total: len(infos)}, nil
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

	info, err := s.xkmsService.FrostGetKey(ctx, params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return frostKeyInfo(info), nil
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

	if err := s.xkmsService.FrostDeleteKey(ctx, params.KeyID); err != nil {
		return nil, mapKeyOpError(err)
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

	nonces, err := s.xkmsService.FrostGenerateNonces(ctx, params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return FrostGenerateNoncesResult{
		ParticipantID:     nonces.ParticipantID,
		SessionID:         nonces.SessionID,
		HidingNonce:       hex.EncodeToString(nonces.Nonces.HidingNonce),
		BindingNonce:      hex.EncodeToString(nonces.Nonces.BindingNonce),
		HidingCommitment:  hex.EncodeToString(nonces.Commitments.HidingCommitment),
		BindingCommitment: hex.EncodeToString(nonces.Commitments.BindingCommitment),
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

	message, err := decodeFrostHex("message", params.Message)
	if err != nil {
		return nil, err
	}
	hidingNonce, err := decodeFrostHex("hiding_nonce", params.HidingNonce)
	if err != nil {
		return nil, err
	}
	bindingNonce, err := decodeFrostHex("binding_nonce", params.BindingNonce)
	if err != nil {
		return nil, err
	}
	hidingCommitment, err := decodeFrostHex("hiding_commitment", params.HidingCommitment)
	if err != nil {
		return nil, err
	}
	bindingCommitment, err := decodeFrostHex("binding_commitment", params.BindingCommitment)
	if err != nil {
		return nil, err
	}
	commitments, err := decodeFrostCommitments(params.Commitments)
	if err != nil {
		return nil, err
	}

	share, err := s.xkmsService.FrostSignRound(ctx, &xkms.FrostSignRoundRequest{
		KeyID:             params.KeyID,
		Message:           message,
		SessionID:         params.SessionID,
		HidingNonce:       hidingNonce,
		BindingNonce:      bindingNonce,
		HidingCommitment:  hidingCommitment,
		BindingCommitment: bindingCommitment,
		Commitments:       commitments,
	})
	if err != nil {
		return nil, mapKeyOpError(err)
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

	message, err := decodeFrostHex("message", params.Message)
	if err != nil {
		return nil, err
	}
	commitments, err := decodeFrostCommitments(params.Commitments)
	if err != nil {
		return nil, err
	}
	shares := make([]*frost.SignatureShare, len(params.Shares))
	for i, sh := range params.Shares {
		share, err := decodeFrostHex("share", sh.Share)
		if err != nil {
			return nil, err
		}
		shares[i] = &frost.SignatureShare{
			ParticipantID: sh.ParticipantID,
			SessionID:     sh.SessionID,
			Share:         share,
		}
	}

	agg, err := s.xkmsService.FrostAggregate(ctx, &xkms.FrostAggregateRequest{
		KeyID:       params.KeyID,
		Message:     message,
		Commitments: commitments,
		Shares:      shares,
		Verify:      params.Verify,
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return FrostAggregateResult{
		Signature: hex.EncodeToString(agg.Signature),
		Verified:  agg.Verified,
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

	message, err := decodeFrostHex("message", params.Message)
	if err != nil {
		return nil, err
	}
	signature, err := decodeFrostHex("signature", params.Signature)
	if err != nil {
		return nil, err
	}

	result, err := s.xkmsService.FrostVerify(ctx, params.KeyID, message, signature)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	if !result.Valid {
		return FrostVerifyResult{
			Valid:   false,
			Message: "signature verification failed: " + result.Reason,
		}, nil
	}
	return FrostVerifyResult{Valid: true, Message: "signature is valid"}, nil
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
