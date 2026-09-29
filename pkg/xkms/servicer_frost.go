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

package xkms

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FROST threshold signatures (RFC 9591) at the service layer.
//
// Every FROST key belongs to the tenant of the identity that created or
// imported it, and every operation that names a key resolves that name inside
// the caller's tenant, taken from the authenticated identity on ctx exactly as
// ListKeys, GetKey and DeleteKey take it (scopedTenantIDFromContext). A key ID
// is unique only within a tenant, so another tenant's key is simply not there:
// the refusal is the same bare ErrKeyNotFound a key no tenant holds produces
// (go-xkms#1231). A platform-scoped caller -- no identity, or the system
// tenant -- lists every tenant's FROST keys, as ListKeys lets it list every
// key, and addresses by ID the platform's own, untenanted keys.
//
// The REST, gRPC and MCP transports are thin adapters over these methods.

var (
	// ErrFrostNotConfigured is returned when no registered backend is a FROST
	// backend.
	ErrFrostNotConfigured = errors.New("keystore: no FROST backend configured")

	// ErrFrostInvalidRequest is the sentinel of every *ErrValidation a FROST
	// request is refused with; the Detail names the offending field.
	ErrFrostInvalidRequest = errors.New("keystore: invalid FROST request")
)

// frostMetricsBackend labels the service-boundary metrics of FROST
// operations.
const frostMetricsBackend = "frost"

// frostKeyIDPrefix prefixes the key ID generated for a request that names
// none.
const frostKeyIDPrefix = "frost-key-"

// FrostGenerateKeyRequest asks for a new FROST key. In participant mode the
// key's own share is generated and stored for the caller's tenant; in dealer
// mode every participant's package is generated and returned, and nothing is
// stored.
type FrostGenerateKeyRequest struct {
	// KeyID names the key; empty generates a name.
	KeyID string
	// Algorithm is the FROST ciphersuite; empty selects FROST-Ed25519-SHA512.
	Algorithm string
	// Threshold is the minimum number of signers (M), at least 2.
	Threshold int
	// Total is the number of participants (N), at least Threshold.
	Total int
	// Participants optionally names each participant.
	Participants []string
	// ParticipantID is this node's participant, required in participant mode.
	ParticipantID uint32
	// DealerMode generates and returns every participant's package.
	DealerMode bool
}

// FrostParticipantPackage is one participant's key package as a trusted
// dealer hands it out.
type FrostParticipantPackage struct {
	ParticipantID      uint32
	ParticipantName    string
	SecretShare        []byte
	GroupPublicKey     []byte
	VerificationShares map[uint32][]byte
}

// FrostGenerateKeyResponse describes a generated FROST key.
type FrostGenerateKeyResponse struct {
	KeyID          string
	Algorithm      string
	Threshold      int
	Total          int
	GroupPublicKey []byte
	// ParticipantID is set in participant mode.
	ParticipantID uint32
	// Packages holds every participant's package in dealer mode.
	Packages  []FrostParticipantPackage
	CreatedAt time.Time
}

// FrostImportKeyRequest imports one participant's key package into the
// caller's tenant.
type FrostImportKeyRequest struct {
	KeyID              string
	Algorithm          string
	Threshold          int
	Total              int
	ParticipantID      uint32
	SecretShare        []byte
	GroupPublicKey     []byte
	VerificationShares map[uint32][]byte
}

// FrostKeyInfo describes a stored FROST key. It carries only public
// material.
type FrostKeyInfo struct {
	KeyID          string
	Algorithm      string
	Threshold      int
	Total          int
	ParticipantID  uint32
	GroupPublicKey []byte
	Participants   []string
	CreatedAt      time.Time
}

// FrostSignRoundRequest asks for this participant's Round 2 signature share.
type FrostSignRoundRequest struct {
	KeyID             string
	Message           []byte
	SessionID         string
	HidingNonce       []byte
	BindingNonce      []byte
	HidingCommitment  []byte
	BindingCommitment []byte
	// Commitments are every signing participant's Round 1 commitments.
	Commitments []*frost.Commitment
}

// FrostAggregateRequest asks for the group signature combining shares.
type FrostAggregateRequest struct {
	KeyID       string
	Message     []byte
	Commitments []*frost.Commitment
	Shares      []*frost.SignatureShare
	// Verify additionally verifies the aggregated signature.
	Verify bool
}

// FrostAggregateResponse carries an aggregated group signature.
type FrostAggregateResponse struct {
	Signature []byte
	// Verified reports whether Verify was requested and succeeded.
	Verified bool
}

// FrostVerifyResponse reports whether a signature verified, and why not when
// it did not.
type FrostVerifyResponse struct {
	Valid  bool
	Reason string
}

// frostBackend returns the registered FROST key provider. Backends are
// visited in name order, so a deployment with more than one resolves the
// same one every time.
func (s *XKMSService) frostBackend() (*frost.FrostBackend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.backends))
	for name := range s.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if fb, ok := s.backends[name].KeyProvider().(*frost.FrostBackend); ok {
			return fb, nil
		}
	}
	return nil, ErrFrostNotConfigured
}

// frostTenant returns the tenant FROST keys are scoped to for the caller on
// ctx: its tenant, or "" -- the platform namespace -- for a platform-scoped
// caller.
func frostTenant(ctx context.Context) (string, error) {
	tenantID := scopedTenantIDFromContext(ctx)
	scoped, err := tenantScopes(tenantID)
	if err != nil {
		return "", err
	}
	if !scoped {
		return "", nil
	}
	return tenantID, nil
}

// frostKeyAttrs names keyID inside the caller's tenant. It returns the key's
// attributes and the storage key ID the round API addresses it by.
func frostKeyAttrs(ctx context.Context, keyID string) (*types.KeyAttributes, string, error) {
	if keyID == "" {
		return nil, "", &ErrValidation{Sentinel: ErrInvalidKeyID, Detail: "key_id is required"}
	}
	tenantID, err := frostTenant(ctx)
	if err != nil {
		return nil, "", err
	}
	storageKeyID, err := frost.StorageKeyID(tenantID, keyID)
	if err != nil {
		return nil, "", &ErrValidation{Sentinel: ErrInvalidKeyID, Detail: err.Error()}
	}
	return &types.KeyAttributes{
		CN:        keyID,
		TenantID:  tenantID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}, storageKeyID, nil
}

// frostKeyError translates a FROST backend error. A key the caller's tenant
// does not hold is the bare ErrKeyNotFound, so the answer is the same whether
// the key is missing everywhere or held by another tenant; anything else is
// an operation failure carrying its cause.
func frostKeyError(err error) error {
	switch {
	case errors.Is(err, frost.ErrKeyNotFound):
		return ErrKeyNotFound
	case errors.Is(err, frost.ErrKeyAlreadyExists):
		return &ErrOperationWrap{Sentinel: ErrKeyAlreadyExists, Err: err}
	case errors.Is(err, frost.ErrInvalidAttributes):
		return &ErrValidation{Sentinel: ErrFrostInvalidRequest, Detail: err.Error()}
	default:
		return &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}
}

// frostInvalid refuses a FROST request with detail as the caller-facing
// message.
func frostInvalid(detail string) error {
	return &ErrValidation{Sentinel: ErrFrostInvalidRequest, Detail: detail}
}

// FrostGenerateKey generates a FROST key. In participant mode the key is
// stored for the caller's tenant; in dealer mode every participant's package
// is returned and nothing is stored.
func (s *XKMSService) FrostGenerateKey(ctx context.Context, req *FrostGenerateKeyRequest) (resp *FrostGenerateKeyResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGenerate, frostMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if req.Threshold < 2 {
		return nil, frostInvalid("threshold must be at least 2")
	}
	if req.Total < req.Threshold {
		return nil, frostInvalid("total must be >= threshold")
	}
	if !req.DealerMode && req.ParticipantID == 0 {
		return nil, frostInvalid("participant_id is required in participant mode")
	}

	algorithm := types.FrostAlgorithm(req.Algorithm)
	if algorithm == "" {
		algorithm = types.FrostAlgorithmEd25519
	}
	keyID := req.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("%s%d", frostKeyIDPrefix, time.Now().UnixNano())
	}
	attrs, _, err := frostKeyAttrs(ctx, keyID)
	if err != nil {
		return nil, err
	}

	be, err := s.frostBackend()
	if err != nil {
		return nil, err
	}
	if req.DealerMode {
		return frostDeal(req, keyID, algorithm)
	}

	attrs.FrostAttributes = &types.FrostAttributes{
		Algorithm:     algorithm,
		Threshold:     req.Threshold,
		Total:         req.Total,
		Participants:  req.Participants,
		ParticipantID: req.ParticipantID,
	}
	key, err := be.GenerateKey(ctx, attrs)
	if err != nil {
		return nil, frostKeyError(err)
	}
	handle, ok := key.(*frost.FrostKeyHandle)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Detail: fmt.Sprintf("unexpected FROST key handle %T", key)}
	}

	return &FrostGenerateKeyResponse{
		KeyID:          keyID,
		Algorithm:      string(algorithm),
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: handle.GroupPublicKey,
		ParticipantID:  handle.ParticipantID,
		CreatedAt:      time.Now(),
	}, nil
}

// frostDeal runs a trusted dealer for req and returns every participant's
// package.
func frostDeal(req *FrostGenerateKeyRequest, keyID string, algorithm types.FrostAlgorithm) (*FrostGenerateKeyResponse, error) {
	packages, pub, err := frost.NewTrustedDealer().Generate(frost.FrostConfig{
		Threshold:     req.Threshold,
		Total:         req.Total,
		Algorithm:     algorithm,
		ParticipantID: 1,
	})
	if err != nil {
		return nil, frostKeyError(err)
	}

	dealt := make([]FrostParticipantPackage, len(packages))
	for i, pkg := range packages {
		shares := make(map[uint32][]byte, len(pub.VerificationShares))
		for id, share := range pub.VerificationShares {
			shares[id] = share
		}
		var name string
		if i < len(req.Participants) {
			name = req.Participants[i]
		}
		dealt[i] = FrostParticipantPackage{
			ParticipantID:      pkg.ParticipantID,
			ParticipantName:    name,
			SecretShare:        pkg.SecretShare.Value,
			GroupPublicKey:     pub.GroupPublicKey,
			VerificationShares: shares,
		}
	}

	return &FrostGenerateKeyResponse{
		KeyID:          keyID,
		Algorithm:      string(algorithm),
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: pub.GroupPublicKey,
		Packages:       dealt,
		CreatedAt:      time.Now(),
	}, nil
}

// FrostImportKey imports one participant's key package into the caller's
// tenant, replacing that tenant's key of the same ID if it has one. An import
// can never reach another tenant's key.
func (s *XKMSService) FrostImportKey(ctx context.Context, req *FrostImportKeyRequest) (err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpImport, frostMetricsBackend, start, err) }()

	if req == nil {
		return ErrNilConfig
	}
	if req.KeyID == "" {
		return frostInvalid("package.key_id is required")
	}
	if len(req.SecretShare) == 0 {
		return frostInvalid("package.secret_share is required")
	}
	if len(req.GroupPublicKey) == 0 {
		return frostInvalid("package.group_public_key is required")
	}
	attrs, _, err := frostKeyAttrs(ctx, req.KeyID)
	if err != nil {
		return err
	}
	be, err := s.frostBackend()
	if err != nil {
		return err
	}

	pkg := &frost.KeyPackage{
		ParticipantID:      req.ParticipantID,
		SecretShare:        &frost.SecretKeyShare{Value: req.SecretShare},
		GroupPublicKey:     req.GroupPublicKey,
		VerificationShares: req.VerificationShares,
		MinSigners:         uint32(req.Threshold),
		MaxSigners:         uint32(req.Total),
		Algorithm:          types.FrostAlgorithm(req.Algorithm),
	}
	if err := be.ImportKeyPackage(ctx, attrs, pkg); err != nil {
		return frostKeyError(err)
	}
	return nil
}

// FrostListKeys lists the FROST keys the caller's tenant holds, ordered by
// key ID. A platform-scoped caller sees every tenant's keys.
func (s *XKMSService) FrostListKeys(ctx context.Context) (keys []FrostKeyInfo, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpList, frostMetricsBackend, start, err) }()

	tenantID := scopedTenantIDFromContext(ctx)
	scoped, err := tenantScopes(tenantID)
	if err != nil {
		return nil, err
	}
	be, err := s.frostBackend()
	if err != nil {
		return nil, err
	}
	listed, err := be.ListKeys(ctx)
	if err != nil {
		return nil, frostKeyError(err)
	}

	visible := make([]*types.KeyAttributes, 0, len(listed))
	for _, attrs := range listed {
		if attrs == nil || (scoped && attrs.TenantID != tenantID) {
			continue
		}
		visible = append(visible, attrs)
	}
	sort.Slice(visible, func(i, j int) bool {
		if visible[i].CN != visible[j].CN {
			return visible[i].CN < visible[j].CN
		}
		return visible[i].TenantID < visible[j].TenantID
	})

	keys = make([]FrostKeyInfo, 0, len(visible))
	for _, attrs := range visible {
		info, err := frostDescribe(ctx, be, attrs)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *info)
	}
	return keys, nil
}

// FrostGetKey describes the caller's tenant's FROST key keyID.
func (s *XKMSService) FrostGetKey(ctx context.Context, keyID string) (info *FrostKeyInfo, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGet, frostMetricsBackend, start, err) }()

	attrs, _, err := frostKeyAttrs(ctx, keyID)
	if err != nil {
		return nil, err
	}
	be, err := s.frostBackend()
	if err != nil {
		return nil, err
	}
	return frostDescribe(ctx, be, attrs)
}

// frostDescribe reads the public description of the key attrs names.
func frostDescribe(ctx context.Context, be *frost.FrostBackend, attrs *types.KeyAttributes) (*FrostKeyInfo, error) {
	pub, meta, err := be.PublicKeyPackage(ctx, attrs)
	if err != nil {
		return nil, frostKeyError(err)
	}
	return &FrostKeyInfo{
		KeyID:          meta.KeyID,
		Algorithm:      string(meta.Algorithm),
		Threshold:      meta.Threshold,
		Total:          meta.Total,
		ParticipantID:  meta.ParticipantID,
		GroupPublicKey: pub.GroupPublicKey,
		Participants:   meta.Participants,
		CreatedAt:      time.Unix(meta.CreatedAt, 0).UTC(),
	}, nil
}

// FrostDeleteKey deletes the caller's tenant's FROST key keyID.
func (s *XKMSService) FrostDeleteKey(ctx context.Context, keyID string) (err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpDelete, frostMetricsBackend, start, err) }()

	attrs, _, err := frostKeyAttrs(ctx, keyID)
	if err != nil {
		return err
	}
	be, err := s.frostBackend()
	if err != nil {
		return err
	}
	if err := be.DeleteKey(ctx, attrs); err != nil {
		return frostKeyError(err)
	}
	return nil
}

// frostStorageKeyID resolves keyID inside the caller's tenant to the storage
// key ID the round API addresses it by.
func (s *XKMSService) frostStorageKeyID(ctx context.Context, keyID string) (*frost.FrostBackend, *types.KeyAttributes, string, error) {
	attrs, storageKeyID, err := frostKeyAttrs(ctx, keyID)
	if err != nil {
		return nil, nil, "", err
	}
	be, err := s.frostBackend()
	if err != nil {
		return nil, nil, "", err
	}
	return be, attrs, storageKeyID, nil
}

// FrostGenerateNonces runs Round 1 for the caller's tenant's key keyID: it
// returns this participant's secret nonces and public commitments.
func (s *XKMSService) FrostGenerateNonces(ctx context.Context, keyID string) (nonces *frost.NoncePackage, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpSign, frostMetricsBackend, start, err) }()

	be, _, storageKeyID, err := s.frostStorageKeyID(ctx, keyID)
	if err != nil {
		return nil, err
	}
	nonces, err = be.GenerateNonces(storageKeyID)
	if err != nil {
		return nil, frostKeyError(err)
	}
	return nonces, nil
}

// FrostSignRound runs Round 2 for the caller's tenant's key: it returns this
// participant's signature share over req.Message.
func (s *XKMSService) FrostSignRound(ctx context.Context, req *FrostSignRoundRequest) (share *frost.SignatureShare, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpSign, frostMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if len(req.Message) == 0 {
		return nil, frostInvalid("message is required")
	}
	if len(req.HidingNonce) == 0 || len(req.BindingNonce) == 0 {
		return nil, frostInvalid("nonces are required")
	}
	if len(req.Commitments) == 0 {
		return nil, frostInvalid("commitments are required")
	}

	be, attrs, storageKeyID, err := s.frostStorageKeyID(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}
	_, meta, err := be.PublicKeyPackage(ctx, attrs)
	if err != nil {
		return nil, frostKeyError(err)
	}

	nonces := &frost.NoncePackage{
		ParticipantID: meta.ParticipantID,
		SessionID:     req.SessionID,
		Nonces: &frost.SigningNonces{
			HidingNonce:  req.HidingNonce,
			BindingNonce: req.BindingNonce,
		},
		Commitments: &frost.SigningCommitments{
			ParticipantID:     meta.ParticipantID,
			HidingCommitment:  req.HidingCommitment,
			BindingCommitment: req.BindingCommitment,
		},
	}
	share, err = be.SignRound(storageKeyID, req.Message, nonces, req.Commitments)
	if err != nil {
		return nil, frostKeyError(err)
	}
	return share, nil
}

// FrostAggregate combines signature shares into the group signature of the
// caller's tenant's key req.KeyID, verifying it when req.Verify is set.
func (s *XKMSService) FrostAggregate(ctx context.Context, req *FrostAggregateRequest) (resp *FrostAggregateResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpSign, frostMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if len(req.Message) == 0 {
		return nil, frostInvalid("message is required")
	}
	if len(req.Commitments) == 0 {
		return nil, frostInvalid("commitments are required")
	}
	if len(req.Shares) == 0 {
		return nil, frostInvalid("shares are required")
	}

	be, _, storageKeyID, err := s.frostStorageKeyID(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := be.Aggregate(storageKeyID, req.Message, req.Commitments, req.Shares)
	if err != nil {
		return nil, frostKeyError(err)
	}

	resp = &FrostAggregateResponse{Signature: signature}
	if req.Verify {
		resp.Verified = be.Verify(storageKeyID, req.Message, signature) == nil
	}
	return resp, nil
}

// FrostVerify verifies signature over message against the group public key
// of the caller's tenant's key keyID. A signature that does not verify is a
// result, not an error; the error is reserved for a key the caller's tenant
// does not hold and a request that cannot be served.
func (s *XKMSService) FrostVerify(ctx context.Context, keyID string, message, signature []byte) (resp *FrostVerifyResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpVerify, frostMetricsBackend, start, err) }()

	if len(message) == 0 {
		return nil, frostInvalid("message is required")
	}
	if len(signature) == 0 {
		return nil, frostInvalid("signature is required")
	}

	be, _, storageKeyID, err := s.frostStorageKeyID(ctx, keyID)
	if err != nil {
		return nil, err
	}
	verifyErr := be.Verify(storageKeyID, message, signature)
	switch {
	case verifyErr == nil:
		return &FrostVerifyResponse{Valid: true}, nil
	case errors.Is(verifyErr, frost.ErrKeyNotFound), errors.Is(verifyErr, frost.ErrBackendClosed):
		return nil, frostKeyError(verifyErr)
	default:
		return &FrostVerifyResponse{Reason: verifyErr.Error()}, nil
	}
}
