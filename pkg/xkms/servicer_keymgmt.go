// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// backendTestSize is the size, in bytes, of the random secret BackendTest
// seals and unseals.
const backendTestSize = 32

// Backend health a BackendStatus response reports.
const (
	backendHealthy     = "healthy"
	backendUnavailable = "unavailable"
)

// Safety report formats SafetyReport accepts. The format names the
// rendering a client asks for; the response carries the same data for each.
var safetyReportFormats = map[string]bool{"": true, "json": true, "table": true, "prometheus": true}

// keyStatusOf maps a record's status to the status a response reports. A
// revoked key is reported compromised: revocation is how a compromised key
// is taken out of service.
var keyStatusOf = map[keypolicy.Status]transport.KeyStatus{
	keypolicy.StatusEnabled:  transport.KeyStatusEnabled,
	keypolicy.StatusDisabled: transport.KeyStatusDisabled,
	keypolicy.StatusRevoked:  transport.KeyStatusCompromised,
}

// settableKeyStatus maps the statuses UpdateKeyStatus sets on a key to the
// record status. An enabled key stores no status, so a record holding only
// that is empty. Revocation is RevokeKey's; the other statuses describe a
// lifecycle the service drives itself.
var settableKeyStatus = map[transport.KeyStatus]keypolicy.Status{
	transport.KeyStatusEnabled:  "",
	transport.KeyStatusDisabled: keypolicy.StatusDisabled,
}

// settableVersionState maps the statuses UpdateKeyStatus sets on one key
// version to its version state.
var settableVersionState = map[transport.KeyStatus]keyversion.State{
	transport.KeyStatusEnabled:  keyversion.StateEnabled,
	transport.KeyStatusDisabled: keyversion.StateDisabled,
}

// symmetricKeyAlgorithms maps a symmetric key's algorithm to the algorithm
// a response reports.
var symmetricKeyAlgorithms = map[types.SymmetricAlgorithm]transport.KeyAlgorithm{
	types.SymmetricAES128GCM:         transport.KeyAlgorithmAES128GCM,
	types.SymmetricAES192GCM:         transport.KeyAlgorithmAES192GCM,
	types.SymmetricAES256GCM:         transport.KeyAlgorithmAES256GCM,
	types.SymmetricChaCha20Poly1305:  transport.KeyAlgorithmChaCha20Poly1305,
	types.SymmetricXChaCha20Poly1305: transport.KeyAlgorithmXChaCha20Poly1305,
}

// hmacKeyAlgorithms maps an HMAC key's hash to the algorithm a response
// reports.
var hmacKeyAlgorithms = map[crypto.Hash]transport.KeyAlgorithm{
	crypto.SHA256: transport.KeyAlgorithmHMACSHA256,
	crypto.SHA384: transport.KeyAlgorithmHMACSHA384,
	crypto.SHA512: transport.KeyAlgorithmHMACSHA512,
}

// rsaKeyAlgorithms maps an RSA key's modulus size to the algorithm a
// response reports.
var rsaKeyAlgorithms = map[int]transport.KeyAlgorithm{
	types.RSAKeySize2048: transport.KeyAlgorithmRSA2048,
	types.RSAKeySize3072: transport.KeyAlgorithmRSA3072,
	types.RSAKeySize4096: transport.KeyAlgorithmRSA4096,
}

// ecdsaKeyAlgorithms maps an ECDSA key's curve name to the algorithm a
// response reports.
var ecdsaKeyAlgorithms = map[string]transport.KeyAlgorithm{
	"P-256": transport.KeyAlgorithmECDSAP256,
	"P-384": transport.KeyAlgorithmECDSAP384,
	"P-521": transport.KeyAlgorithmECDSAP521,
}

// asymmetricUsages maps a public key algorithm to the uses of its keys.
var asymmetricUsages = map[x509.PublicKeyAlgorithm][]transport.KeyUsage{
	x509.RSA: {
		transport.KeyUsageSign, transport.KeyUsageVerify, transport.KeyUsageEncrypt,
		transport.KeyUsageDecrypt, transport.KeyUsageWrapKey,
	},
	x509.ECDSA:   {transport.KeyUsageSign, transport.KeyUsageVerify},
	x509.Ed25519: {transport.KeyUsageSign, transport.KeyUsageVerify},
}

// GetPublicKey returns the DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) of a
// key version: req.Version, or the current version when zero. A symmetric
// key has no public half and is refused.
func (s *XKMSService) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil get public key request"}
	}
	if req.Version > math.MaxUint32 {
		return nil, &InvalidKeyPolicyError{Field: "version", Reason: "over " + strconv.FormatUint(math.MaxUint32, 10)}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	v, err := k.use(uint32(req.Version))
	if err != nil {
		return nil, err
	}
	if v.attrs.IsSymmetric() {
		return nil, &KeyKindError{KeyID: k.keyID, Operation: "get public key", Reason: "a symmetric key has no public key"}
	}

	pub, err := versionPublicKey(ctx, k.backend, v.attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get public key", KeyID: k.keyID, Err: err}
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "marshal public key", KeyID: k.keyID, Err: err}
	}
	return &transport.GetPublicKeyResponse{
		KeyID:     k.keyID,
		PublicKey: der,
		Algorithm: keyAlgorithmOf(v.attrs),
		Version:   uint64(v.number),
		Timestamp: time.Now().Unix(),
	}, nil
}

// versionPublicKey returns the public key of the key version attrs in b:
// from its private key when the backend returns one, which covers the
// software agreement keys that neither sign nor decrypt, else through its
// signer or decrypter. The cloud KMS backends return no private key from
// GetKey for a non-extractable key.
func versionPublicKey(ctx context.Context, b Backend, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	priv, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	if priv == nil {
		return backendPublicKey(ctx, b, attrs)
	}
	return publicKeyOf(priv)
}

// RevokeKey takes a key out of service for good: every later use of it is
// refused. Revocation is terminal; the key stays in its backend so data it
// protected can be recovered by an operator, never by the service.
func (s *XKMSService) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil revoke key request"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if _, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, _ time.Time) error {
		rec.Status = keypolicy.StatusRevoked
		rec.RevokeReason = req.Reason
		return nil
	}); err != nil {
		return nil, err
	}
	return &transport.RevokeKeyResponse{KeyID: k.keyID, Status: transport.KeyStatusCompromised, Timestamp: time.Now().Unix()}, nil
}

// UpdateKeyStatus enables or disables a key: one version when req.Version is
// set, through its version record, else the whole key, through its policy
// record. A revoked key cannot change status.
func (s *XKMSService) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil update key status request"}
	}
	if req.Version > math.MaxUint32 {
		return nil, &InvalidKeyPolicyError{Field: "version", Reason: "over " + strconv.FormatUint(math.MaxUint32, 10)}
	}
	if req.Version > 0 {
		return s.updateVersionStatus(ctx, req)
	}

	status, ok := settableKeyStatus[req.Status]
	if !ok {
		return nil, &InvalidKeyPolicyError{Field: "status", Reason: "want enabled or disabled; revoke a key with RevokeKey"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if _, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, _ time.Time) error {
		if rec.Status == keypolicy.StatusRevoked {
			return &KeyStatusTransitionError{KeyID: k.keyID, From: string(keypolicy.StatusRevoked), To: string(req.Status)}
		}
		rec.Status = status
		return nil
	}); err != nil {
		return nil, err
	}
	return &transport.UpdateKeyStatusResponse{KeyID: k.keyID, Status: req.Status, Timestamp: time.Now().Unix()}, nil
}

// updateVersionStatus enables or disables one version of a key.
func (s *XKMSService) updateVersionStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	state, ok := settableVersionState[req.Status]
	if !ok {
		return nil, &InvalidKeyPolicyError{Field: "status", Reason: "a key version is enabled or disabled"}
	}
	changed, err := s.setKeyVersionState(ctx, &transport.KeyVersionRequest{
		Backend:  req.Backend,
		KeyID:    req.KeyID,
		Version:  uint32(req.Version),
		TenantID: req.TenantID,
	}, state)
	if err != nil {
		return nil, err
	}
	return &transport.UpdateKeyStatusResponse{
		KeyID:     changed.KeyID,
		Version:   req.Version,
		Status:    req.Status,
		Timestamp: time.Now().Unix(),
	}, nil
}

// GetKeyMetadata returns a key's metadata: what its backend holds (algorithm,
// exportability) with what its record holds (status, name, tags, policy).
func (s *XKMSService) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key metadata request"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadPolicyRecord(ctx, k)
	if err != nil {
		return nil, err
	}
	return &transport.KeyMetadataResponse{Metadata: keyMetadataOf(k, rec), Timestamp: time.Now().Unix()}, nil
}

// UpdateKeyMetadata sets a key's display name and description when given,
// merges req.Tags into its tags and removes req.RemoveTags.
func (s *XKMSService) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil update key metadata request"}
	}
	if _, empty := req.Tags[""]; empty {
		return nil, &InvalidKeyPolicyError{Field: "tags", Reason: "a tag name is empty"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, _ time.Time) error {
		if req.Name != "" {
			rec.DisplayName = req.Name
		}
		if req.Description != "" {
			rec.Description = req.Description
		}
		if len(req.Tags) > 0 && rec.Tags == nil {
			rec.Tags = make(map[string]string, len(req.Tags))
		}
		for name, value := range req.Tags {
			rec.Tags[name] = value
		}
		for _, name := range req.RemoveTags {
			delete(rec.Tags, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyMetadataResponse{Metadata: keyMetadataOf(k, rec), Timestamp: time.Now().Unix()}, nil
}

// SetKeyPolicy sets or replaces a key's access policy. Each replacement
// gets the next policy version. A policy narrows what RBAC grants and never
// widens it.
func (s *XKMSService) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	if req == nil || req.Policy == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key policy request"}
	}
	if req.Policy.RequireMFA {
		return nil, &UnenforceablePolicyError{KeyID: req.KeyID, Field: "require_mfa", Reason: "the service has no per-operation MFA challenge"}
	}
	operations, err := policyOperations(req.Policy.AllowedOperations)
	if err != nil {
		return nil, err
	}
	if req.Policy.ExpiresAt < 0 {
		return nil, &InvalidKeyPolicyError{Field: "expires_at", Reason: "negative"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, now time.Time) error {
		var version uint64 = 1
		if rec.Policy != nil {
			version = rec.Policy.Version + 1
		}
		rec.Policy = &keypolicy.Policy{
			Version:           version,
			AllowedOperations: operations,
			AllowedPrincipals: req.Policy.AllowedPrincipals,
			DeniedPrincipals:  req.Policy.DeniedPrincipals,
			ExpiresAt:         req.Policy.ExpiresAt,
			RotationRequired:  req.Policy.RotationRequired,
			MaxUsageCount:     req.Policy.MaxUsageCount,
			UpdatedAt:         now.Unix(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &transport.SetKeyPolicyResponse{KeyID: k.keyID, PolicyVersion: rec.Policy.Version, Timestamp: time.Now().Unix()}, nil
}

// policyOperations converts a policy's allowed operations, refusing one the
// policy cannot name.
func policyOperations(usages []transport.KeyUsage) ([]keypolicy.Operation, error) {
	if len(usages) == 0 {
		return nil, nil
	}
	operations := make([]keypolicy.Operation, len(usages))
	for i, usage := range usages {
		op := keypolicy.Operation(usage)
		if !op.Valid() {
			return nil, &InvalidKeyPolicyError{Field: "allowed_operations", Reason: "unknown operation " + strconv.Quote(string(usage))}
		}
		operations[i] = op
	}
	return operations, nil
}

// GetKeyPolicy returns a key's access policy. A key without one has a nil
// Policy: RBAC alone governs it.
func (s *XKMSService) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key policy request"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadPolicyRecord(ctx, k)
	if err != nil {
		return nil, err
	}
	return &transport.GetKeyPolicyResponse{Policy: keyPolicyOf(k.keyID, rec.Policy), Timestamp: time.Now().Unix()}, nil
}

// DeleteKeyPolicy removes a key's access policy, so RBAC alone governs it
// again.
func (s *XKMSService) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return s.clearPolicyField(ctx, req, func(rec *keypolicy.Record) { rec.Policy = nil })
}

// SetKeyRotationPolicy sets or replaces a key's rotation policy. An enabled
// policy schedules the next rotation one interval from now unless it names
// one; RotateKey moves it on by an interval each time the key rotates. A
// policy with rotation_required set refuses the key once that time passes.
func (s *XKMSService) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil || req.Policy == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key rotation policy request"}
	}
	if err := checkRotationPolicy(req.KeyID, req.Policy); err != nil {
		return nil, err
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, now time.Time) error {
		next := req.Policy.NextRotation
		if req.Policy.Enabled && next == 0 {
			next = now.Unix() + req.Policy.IntervalSeconds
		}
		rec.Rotation = &keypolicy.Rotation{
			Enabled:         req.Policy.Enabled,
			IntervalSeconds: req.Policy.IntervalSeconds,
			NextRotation:    next,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyRotationPolicyResponse{KeyID: k.keyID, Policy: rotationPolicyOf(rec.Rotation), Timestamp: time.Now().Unix()}, nil
}

// checkRotationPolicy refuses a rotation policy the service cannot store or
// enforce. Rotation happens through RotateKey: the service runs no rotation
// scheduler and retires no versions by itself, so a policy asking for
// either is refused rather than stored and ignored.
func checkRotationPolicy(keyID string, p *transport.RotationPolicy) error {
	switch {
	case p.AutoRotate:
		return &UnenforceablePolicyError{KeyID: keyID, Field: "auto_rotate", Reason: "the service runs no rotation scheduler; rotate with RotateKey"}
	case p.RetainVersions != 0:
		return &UnenforceablePolicyError{KeyID: keyID, Field: "retain_versions", Reason: "the service retires no versions by itself; disable them with UpdateKeyStatus"}
	case p.IntervalSeconds < 0:
		return &InvalidKeyPolicyError{Field: "interval_seconds", Reason: "negative"}
	case p.Enabled && p.IntervalSeconds == 0:
		return &InvalidKeyPolicyError{Field: "interval_seconds", Reason: "an enabled policy needs an interval"}
	case p.NextRotation < 0:
		return &InvalidKeyPolicyError{Field: "next_rotation", Reason: "negative"}
	}
	return nil
}

// GetKeyRotationPolicy returns a key's rotation policy, nil when it has
// none.
func (s *XKMSService) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key rotation policy request"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadPolicyRecord(ctx, k)
	if err != nil {
		return nil, err
	}
	return &transport.KeyRotationPolicyResponse{KeyID: k.keyID, Policy: rotationPolicyOf(rec.Rotation), Timestamp: time.Now().Unix()}, nil
}

// DeleteKeyRotationPolicy removes a key's rotation policy.
func (s *XKMSService) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return s.clearPolicyField(ctx, req, func(rec *keypolicy.Record) { rec.Rotation = nil })
}

// SetKeySafety sets a symmetric AEAD key's usage limits: the authenticated
// encryptions it may perform and the plaintext bytes it may encrypt, with
// the usage percentage it is reported at. NIST SP 800-38D §8.3 caps an
// AES-GCM key at 2^32 invocations with random IVs, so a higher operation
// limit is refused; RFC 8439 §4 bounds ChaCha20-Poly1305 far above any
// practical limit. Setting limits starts counting from zero.
func (s *XKMSService) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key safety request"}
	}
	switch {
	case req.MaxOperations == 0 && req.MaxBytes == 0:
		return nil, &InvalidKeyPolicyError{Field: "max_operations", Reason: "set max_operations, max_bytes or both"}
	case req.WarningPercent < 0 || req.WarningPercent > 100:
		return nil, &InvalidKeyPolicyError{Field: "warning_percent", Reason: "want 0 to 100"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	algorithm := k.representative().SymmetricAlgorithm
	if _, aead := symmetricKeyAlgorithms[algorithm]; !aead || k.representative().KeyType == types.KeyTypeHMAC {
		return nil, &KeyKindError{KeyID: k.keyID, Operation: "usage limits", Reason: "usage limits apply to symmetric AEAD keys"}
	}
	if isAESGCM(algorithm) && req.MaxOperations > keypolicy.MaxGCMInvocations {
		return nil, &InvalidKeyPolicyError{Field: "max_operations", Reason: "over the 2^32 AES-GCM invocations NIST SP 800-38D §8.3 allows"}
	}
	if _, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, _ time.Time) error {
		rec.Safety = &keypolicy.Safety{MaxOperations: req.MaxOperations, MaxBytes: req.MaxBytes, WarningPercent: req.WarningPercent}
		rec.Usage.Operations, rec.Usage.Bytes = 0, 0
		return nil
	}); err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: k.keyID, Timestamp: time.Now().Unix()}, nil
}

// isAESGCM reports whether algorithm is an AES-GCM variant.
func isAESGCM(algorithm types.SymmetricAlgorithm) bool {
	return algorithm == types.SymmetricAES128GCM || algorithm == types.SymmetricAES192GCM || algorithm == types.SymmetricAES256GCM
}

// ClearKeySafety removes a key's usage limits.
func (s *XKMSService) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return s.clearPolicyField(ctx, req, func(rec *keypolicy.Record) { rec.Safety = nil })
}

// clearPolicyField removes one part of a key's record.
func (s *XKMSService) clearPolicyField(ctx context.Context, req *transport.KeyManagementRequest, clear func(rec *keypolicy.Record)) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil key management request"}
	}
	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if _, err := s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, _ time.Time) error {
		clear(rec)
		return nil
	}); err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: k.keyID, Timestamp: time.Now().Unix()}, nil
}

// SafetyCheck returns the caller's tenant's keys at or past their warning
// threshold. It only reads.
func (s *XKMSService) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil safety check request"}
	}
	items, err := s.safetyItems(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	warnings := make([]transport.SafetyWarning, 0, len(items))
	for _, item := range items {
		if item.Status != "" {
			warnings = append(warnings, item)
		}
	}
	return &transport.SafetyCheckResponse{Warnings: warnings, Timestamp: time.Now().Unix()}, nil
}

// SafetyReport returns the usage of every key of the caller's tenant with
// usage limits, and how many are at warning and critical. It only reads.
// Data encryption keys belong to go-qrdb's DEKClient, so their counts are
// zero here.
func (s *XKMSService) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil safety report request"}
	}
	if !safetyReportFormats[req.Format] {
		return nil, &InvalidKeyPolicyError{Field: "format", Reason: "want json, table or prometheus"}
	}
	items, err := s.safetyItems(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	resp := &transport.SafetyReportResponse{AllItems: items, TotalKeys: int32(len(items)), Timestamp: time.Now().Unix()}
	for _, item := range items {
		switch item.Status {
		case keypolicy.LevelWarning:
			resp.KeysAtWarning++
		case keypolicy.LevelCritical, keypolicy.LevelExceeded:
			resp.KeysAtCritical++
		}
	}
	return resp, nil
}

// safetyItems returns the usage of every key of tenantID with usage limits.
// Without a key-policy store no key has limits.
func (s *XKMSService) safetyItems(ctx context.Context, tenantID string) ([]transport.SafetyWarning, error) {
	store := s.keyPolicies.load()
	if store == nil {
		return []transport.SafetyWarning{}, nil
	}
	records, err := store.List(ctx, recordTenant(tenantID))
	if err != nil {
		return nil, err
	}
	items := make([]transport.SafetyWarning, 0, len(records))
	for _, rec := range records {
		if rec.Safety == nil {
			continue
		}
		items = append(items, transport.SafetyWarning{
			Type:           "key",
			Path:           rec.Backend + "/" + rec.KeyID,
			UsagePercent:   rec.UsagePercent(),
			Status:         rec.Level(),
			OperationsUsed: rec.Usage.Operations,
			BytesUsed:      rec.Usage.Bytes,
			MaxOperations:  rec.Safety.MaxOperations,
			MaxBytes:       rec.Safety.MaxBytes,
		})
	}
	return items, nil
}

// GetSupportedAlgorithms returns the key algorithms a backend can create
// and use, from its capabilities. Under FIPS 140-3 mode
// (crypto/fips140.Enabled) the algorithms outside the Go Cryptographic
// Module -- ChaCha20-Poly1305, XChaCha20-Poly1305 and X25519 -- are left out.
// HMAC needs the key's raw material in-process, so a hardware-backed backend
// offers none.
func (s *XKMSService) GetSupportedAlgorithms(_ context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil supported algorithms request"}
	}
	b, _, err := s.resolveTenantBackendWithName(req.Backend, req.TenantID)
	if err != nil {
		return nil, err
	}
	return &transport.GetSupportedAlgorithmsResponse{Algorithms: supportedAlgorithms(b.KeyProvider().Capabilities().KeyAlgorithms, fips140.Enabled())}, nil
}

// supportedAlgorithms lists the key algorithms a backend declares it
// generates and operates, without the non-approved ones when fipsMode is
// true. A declared shape the transport vocabulary has no name for is omitted.
func supportedAlgorithms(declared types.KeyAlgorithms, fipsMode bool) []transport.KeyAlgorithm {
	var algorithms []transport.KeyAlgorithm
	add := func(algorithm transport.KeyAlgorithm, ok bool) {
		if ok && (!fipsMode || !fipsUnapprovedKeyAlgorithms[algorithm]) {
			algorithms = append(algorithms, algorithm)
		}
	}
	for _, size := range declared.RSAKeySizes {
		add(lookup(rsaKeyAlgorithms, size))
	}
	for _, curve := range declared.ECDSACurves {
		add(lookup(ecdsaKeyAlgorithms, curve))
	}
	add(transport.KeyAlgorithmEd25519, declared.Ed25519)
	add(transport.KeyAlgorithmX25519, declared.X25519)
	for _, algorithm := range declared.Symmetric {
		add(lookup(symmetricKeyAlgorithms, algorithm))
	}
	for _, hash := range declared.HMAC {
		add(lookup(hmacKeyAlgorithms, hash))
	}
	return algorithms
}

// fipsUnapprovedKeyAlgorithms are the key algorithms FIPS 140-3 does not
// approve; GetSupportedAlgorithms omits them in FIPS mode.
var fipsUnapprovedKeyAlgorithms = map[transport.KeyAlgorithm]bool{
	transport.KeyAlgorithmChaCha20Poly1305:  true,
	transport.KeyAlgorithmXChaCha20Poly1305: true,
	transport.KeyAlgorithmX25519:            true,
}

// lookup returns the value of key in m and whether m has it.
func lookup[K comparable, V any](m map[K]V, key K) (V, bool) {
	value, ok := m[key]
	return value, ok
}

// BackendStatus reports a backend's type, capabilities and health: healthy
// when it lists its keys, unavailable when it cannot. The Backend contract
// carries no device, region or PCR bank, so those fields stay empty.
func (s *XKMSService) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil backend status request"}
	}
	b, _, err := s.resolveTenantBackendWithName(req.Backend, req.TenantID)
	if err != nil {
		return nil, err
	}
	kp := b.KeyProvider()
	status := backendHealthy
	if _, err := b.ListKeys(ctx); err != nil {
		status = backendUnavailable
	}
	return &transport.BackendStatusResponse{
		BackendType:  string(kp.Type()),
		Status:       status,
		Capabilities: capabilitiesMap(kp.Capabilities()),
		Timestamp:    time.Now().Unix(),
	}, nil
}

// capabilitiesMap returns caps as a map from capability name to whether
// the backend has it.
func capabilitiesMap(caps types.Capabilities) map[string]bool {
	return map[string]bool{
		"keys":                 caps.Keys,
		"hardware_backed":      caps.HardwareBacked,
		"signing":              caps.Signing,
		"decryption":           caps.Decryption,
		"key_rotation":         caps.KeyRotation,
		"symmetric_encryption": caps.SymmetricEncryption,
		"sealing":              caps.Sealing,
		"import":               caps.Import,
		"export":               caps.Export,
		"key_agreement":        caps.KeyAgreement,
		"ecies":                caps.ECIES,
		"attestation":          caps.Attestation,
		"quantum_signing":      caps.QuantumSigning,
		"key_encapsulation":    caps.KeyEncapsulation,
	}
}

// BackendTest checks a backend end to end without changing it: it seals a
// random secret under the backend's default sealing key, unseals it and
// compares. The sealing key is the one Seal creates on its first use;
// BackendTest never creates it. A backend that cannot seal, a TPM2 backend,
// whose seal creates a sealed object, and a backend with no default sealing
// key yet are refused (BackendTestUnsupportedError). The seal and the unseal
// are admitted through the key's record like Seal and Unseal. A round trip
// that fails, or that the key's record refuses, is a response with Success
// false, not an error.
func (s *XKMSService) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil backend test request"}
	}
	b, backendName, err := s.resolveTenantBackendWithName(req.Backend, req.TenantID)
	if err != nil {
		return nil, err
	}
	switch {
	case isTPM2Backend(b):
		return nil, &BackendTestUnsupportedError{Backend: backendName, Reason: "a TPM2 seal creates a sealed object"}
	case !b.CanSeal():
		return nil, &BackendTestUnsupportedError{Backend: backendName, Reason: "the backend cannot seal"}
	}

	start := time.Now()
	message, err := backendRoundTrip(ctx, s, b, backendName, req.TenantID)
	if err != nil {
		return nil, err
	}
	return &transport.BackendTestResponse{
		Success:    message == "",
		DurationMS: time.Since(start).Milliseconds(),
		Message:    message,
		Timestamp:  time.Now().Unix(),
	}, nil
}

// backendRoundTrip seals and unseals a random secret in b and returns why
// the round trip failed, or "" when it succeeded. The secret and its
// unsealed copy are wiped.
func backendRoundTrip(ctx context.Context, s *XKMSService, b Backend, backendName, tenantID string) (string, error) {
	// The key is resolved, never created: BackendTest needs only
	// backends:read, and provisioning a sealing key is a keystore write.
	k, _, err := s.sealingKey(ctx, b, backendName, tenantID, "", "", false)
	if errors.Is(err, ErrKeyNotFound) {
		return "", &BackendTestUnsupportedError{Backend: backendName, Reason: "the backend has no default sealing key yet; the first Seal creates it"}
	}
	if err != nil {
		return "sealing key: " + err.Error(), nil
	}
	var attrs *types.KeyAttributes
	if k != nil {
		// The probe is a real seal and unseal under the key, so it is
		// admitted like Seal and Unseal: a disabled, revoked or restricted
		// key fails it, and the seal counts toward the key's usage limits.
		if err := s.admitKey(ctx, k, keypolicy.OpEncrypt, backendTestSize); err != nil {
			return "seal: " + err.Error(), nil
		}
		if err := s.admitKey(ctx, k, keypolicy.OpDecrypt); err != nil {
			return "unseal: " + err.Error(), nil
		}
		cur, err := k.current()
		if err != nil {
			return "sealing key: " + err.Error(), nil
		}
		attrs = cur.attrs
	}

	secret := make([]byte, backendTestSize)
	defer secure.Wipe(secret)
	if _, err := rand.Read(secret); err != nil {
		return "random: " + err.Error(), nil
	}
	sealed, err := b.Seal(ctx, secret, &types.SealOptions{KeyAttributes: attrs})
	if err != nil {
		return "seal: " + err.Error(), nil
	}
	opened, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
	if err != nil {
		return "unseal: " + err.Error(), nil
	}
	defer secure.Wipe(opened)
	if subtle.ConstantTimeCompare(secret, opened) != 1 {
		return "unseal returned different data", nil
	}
	return "", nil
}

// keyRotated restarts a rotated key's usage limits, which bound one key's
// material, and moves its next scheduled rotation on by an interval. A key
// with neither keeps its record as it is.
func (s *XKMSService) keyRotated(ctx context.Context, k *versionedKey) error {
	if s.keyPolicies.load() == nil {
		return nil
	}
	rec, err := s.loadPolicyRecord(ctx, k)
	if err != nil || (rec.Safety == nil && rec.Rotation == nil) {
		return err
	}
	_, err = s.updatePolicyRecord(ctx, k, func(rec *keypolicy.Record, now time.Time) error {
		// The counters move to the new version only if an admission has not
		// already moved them there: Material never zeroes the counters of
		// the version they count (see admitKey).
		rec.Material(k.record.Current)
		if rec.Rotation != nil && rec.Rotation.Enabled {
			rec.Rotation.NextRotation = now.Unix() + rec.Rotation.IntervalSeconds
		}
		return nil
	})
	return err
}

// keyMetadataOf returns the metadata of k with its record rec.
func keyMetadataOf(k *versionedKey, rec *keypolicy.Record) *transport.KeyMetadata {
	attrs := k.representative()
	return &transport.KeyMetadata{
		KeyID:          k.keyID,
		Name:           rec.DisplayName,
		Description:    rec.Description,
		Algorithm:      keyAlgorithmOf(attrs),
		Status:         keyStatusOf[rec.EffectiveStatus()],
		Usage:          keyUsagesOf(attrs),
		Version:        uint64(k.record.Current),
		Exportable:     attrs.Exportable,
		CreatedAt:      rec.CreatedAt,
		UpdatedAt:      rec.UpdatedAt,
		LastUsedAt:     rec.LastUsedAt,
		RotationPolicy: rotationPolicyOf(rec.Rotation),
		Tags:           rec.Tags,
		Owner:          rec.Owner,
	}
}

// keyPolicyOf returns p as the policy of keyID, nil when p is.
func keyPolicyOf(keyID string, p *keypolicy.Policy) *transport.KeyPolicy {
	if p == nil {
		return nil
	}
	operations := make([]transport.KeyUsage, len(p.AllowedOperations))
	for i, op := range p.AllowedOperations {
		operations[i] = transport.KeyUsage(op)
	}
	return &transport.KeyPolicy{
		KeyID:             keyID,
		Version:           p.Version,
		AllowedOperations: operations,
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         p.ExpiresAt,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		UpdatedAt:         p.UpdatedAt,
	}
}

// rotationPolicyOf returns r as a response's rotation policy, nil when r is.
func rotationPolicyOf(r *keypolicy.Rotation) *transport.RotationPolicy {
	if r == nil {
		return nil
	}
	return &transport.RotationPolicy{
		Enabled:         r.Enabled,
		IntervalSeconds: r.IntervalSeconds,
		NextRotation:    r.NextRotation,
	}
}

// keyAlgorithmOf returns the algorithm of a key with attrs, "" for one a
// response has no name for.
func keyAlgorithmOf(attrs *types.KeyAttributes) transport.KeyAlgorithm {
	switch {
	case attrs.KeyType == types.KeyTypeHMAC:
		return hmacKeyAlgorithms[attrs.Hash]
	case attrs.IsSymmetric():
		return symmetricKeyAlgorithms[attrs.SymmetricAlgorithm]
	case attrs.X25519Attributes != nil:
		return transport.KeyAlgorithmX25519
	case attrs.KeyAlgorithm == x509.RSA && attrs.RSAAttributes != nil:
		return rsaKeyAlgorithms[attrs.RSAAttributes.KeySize]
	case attrs.KeyAlgorithm == x509.ECDSA && attrs.ECCAttributes != nil:
		return ecdsaKeyAlgorithms[types.CurveName(attrs.ECCAttributes.Curve)]
	case attrs.KeyAlgorithm == x509.Ed25519:
		return transport.KeyAlgorithmEd25519
	}
	return ""
}

// keyUsagesOf returns the uses of a key with attrs.
func keyUsagesOf(attrs *types.KeyAttributes) []transport.KeyUsage {
	switch {
	case attrs.KeyType == types.KeyTypeHMAC:
		return []transport.KeyUsage{transport.KeyUsageGenerateMAC, transport.KeyUsageVerifyMAC}
	case attrs.IsSymmetric():
		return []transport.KeyUsage{transport.KeyUsageEncrypt, transport.KeyUsageDecrypt, transport.KeyUsageWrapKey}
	case attrs.X25519Attributes != nil:
		return []transport.KeyUsage{transport.KeyUsageDeriveKey}
	}
	return asymmetricUsages[attrs.KeyAlgorithm]
}
