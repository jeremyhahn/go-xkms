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

package pbconv

import (
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The key management converters carry no tenant: the server scopes every
// request to the caller's tenant. A value the other side has no enum for
// converts to the unspecified enum, or to "", which the service refuses.

var keyStatusToProto = map[transport.KeyStatus]pb.KeyStatus{
	transport.KeyStatusEnabled:         pb.KeyStatus_KEY_STATUS_ENABLED,
	transport.KeyStatusDisabled:        pb.KeyStatus_KEY_STATUS_DISABLED,
	transport.KeyStatusPendingDeletion: pb.KeyStatus_KEY_STATUS_PENDING_DELETION,
	transport.KeyStatusDeleted:         pb.KeyStatus_KEY_STATUS_DELETED,
	transport.KeyStatusRotating:        pb.KeyStatus_KEY_STATUS_ROTATING,
	transport.KeyStatusCompromised:     pb.KeyStatus_KEY_STATUS_COMPROMISED,
}

var keyStatusFromProto = invert(keyStatusToProto)

var keyUsageToProto = map[transport.KeyUsage]pb.KeyUsage{
	transport.KeyUsageEncrypt:     pb.KeyUsage_KEY_USAGE_ENCRYPT,
	transport.KeyUsageDecrypt:     pb.KeyUsage_KEY_USAGE_DECRYPT,
	transport.KeyUsageSign:        pb.KeyUsage_KEY_USAGE_SIGN,
	transport.KeyUsageVerify:      pb.KeyUsage_KEY_USAGE_VERIFY,
	transport.KeyUsageWrapKey:     pb.KeyUsage_KEY_USAGE_WRAP_KEY,
	transport.KeyUsageDeriveKey:   pb.KeyUsage_KEY_USAGE_DERIVE_KEY,
	transport.KeyUsageGenerateMAC: pb.KeyUsage_KEY_USAGE_GENERATE_MAC,
	transport.KeyUsageVerifyMAC:   pb.KeyUsage_KEY_USAGE_VERIFY_MAC,
}

var keyUsageFromProto = invert(keyUsageToProto)

var keyAlgorithmToProto = map[transport.KeyAlgorithm]pb.KeyAlgorithm{
	transport.KeyAlgorithmAES128GCM:         pb.KeyAlgorithm_KEY_ALG_AES_128_GCM,
	transport.KeyAlgorithmAES192GCM:         pb.KeyAlgorithm_KEY_ALG_AES_192_GCM,
	transport.KeyAlgorithmAES256GCM:         pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
	transport.KeyAlgorithmChaCha20Poly1305:  pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305,
	transport.KeyAlgorithmXChaCha20Poly1305: pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305,
	transport.KeyAlgorithmRSA2048:           pb.KeyAlgorithm_KEY_ALG_RSA_2048,
	transport.KeyAlgorithmRSA3072:           pb.KeyAlgorithm_KEY_ALG_RSA_3072,
	transport.KeyAlgorithmRSA4096:           pb.KeyAlgorithm_KEY_ALG_RSA_4096,
	transport.KeyAlgorithmECDSAP256:         pb.KeyAlgorithm_KEY_ALG_ECDSA_P256,
	transport.KeyAlgorithmECDSAP384:         pb.KeyAlgorithm_KEY_ALG_ECDSA_P384,
	transport.KeyAlgorithmECDSAP521:         pb.KeyAlgorithm_KEY_ALG_ECDSA_P521,
	transport.KeyAlgorithmEd25519:           pb.KeyAlgorithm_KEY_ALG_ED25519,
	transport.KeyAlgorithmEd448:             pb.KeyAlgorithm_KEY_ALG_ED448,
	transport.KeyAlgorithmX25519:            pb.KeyAlgorithm_KEY_ALG_X25519,
	transport.KeyAlgorithmX448:              pb.KeyAlgorithm_KEY_ALG_X448,
	transport.KeyAlgorithmHMACSHA256:        pb.KeyAlgorithm_KEY_ALG_HMAC_SHA256,
	transport.KeyAlgorithmHMACSHA384:        pb.KeyAlgorithm_KEY_ALG_HMAC_SHA384,
	transport.KeyAlgorithmHMACSHA512:        pb.KeyAlgorithm_KEY_ALG_HMAC_SHA512,
}

var keyAlgorithmFromProto = invert(keyAlgorithmToProto)

// invert returns the map from each value of m to its key.
func invert[K, V comparable](m map[K]V) map[V]K {
	inverse := make(map[V]K, len(m))
	for k, v := range m {
		inverse[v] = k
	}
	return inverse
}

// KeyStatusToProto converts a key status to its wire enum.
func KeyStatusToProto(s transport.KeyStatus) pb.KeyStatus { return keyStatusToProto[s] }

// KeyStatusFromProto converts a wire key status.
func KeyStatusFromProto(s pb.KeyStatus) transport.KeyStatus { return keyStatusFromProto[s] }

// KeyAlgorithmToProto converts a key algorithm to its wire enum.
func KeyAlgorithmToProto(a transport.KeyAlgorithm) pb.KeyAlgorithm { return keyAlgorithmToProto[a] }

// KeyAlgorithmFromProto converts a wire key algorithm.
func KeyAlgorithmFromProto(a pb.KeyAlgorithm) transport.KeyAlgorithm {
	return keyAlgorithmFromProto[a]
}

// KeyUsagesToProto converts key usages to their wire enums.
func KeyUsagesToProto(usages []transport.KeyUsage) []pb.KeyUsage {
	if usages == nil {
		return nil
	}
	out := make([]pb.KeyUsage, len(usages))
	for i, u := range usages {
		out[i] = keyUsageToProto[u]
	}
	return out
}

// KeyUsagesFromProto converts wire key usages.
func KeyUsagesFromProto(usages []pb.KeyUsage) []transport.KeyUsage {
	if usages == nil {
		return nil
	}
	out := make([]transport.KeyUsage, len(usages))
	for i, u := range usages {
		out[i] = keyUsageFromProto[u]
	}
	return out
}

// KeyAlgorithmNamesToProto converts key algorithms to the names the wire
// carries.
func KeyAlgorithmNamesToProto(algorithms []transport.KeyAlgorithm) []string {
	out := make([]string, len(algorithms))
	for i, a := range algorithms {
		out[i] = string(a)
	}
	return out
}

// KeyAlgorithmNamesFromProto converts wire algorithm names.
func KeyAlgorithmNamesFromProto(names []string) []transport.KeyAlgorithm {
	out := make([]transport.KeyAlgorithm, len(names))
	for i, n := range names {
		out[i] = transport.KeyAlgorithm(n)
	}
	return out
}

// RotationPolicyToProto converts a rotation policy to its wire form.
func RotationPolicyToProto(p *transport.RotationPolicy) *pb.RotationPolicy {
	if p == nil {
		return nil
	}
	return &pb.RotationPolicy{
		Enabled:         p.Enabled,
		IntervalSeconds: p.IntervalSeconds,
		NextRotation:    p.NextRotation,
		RetainVersions:  p.RetainVersions,
		AutoRotate:      p.AutoRotate,
	}
}

// RotationPolicyFromProto converts a wire rotation policy.
func RotationPolicyFromProto(p *pb.RotationPolicy) *transport.RotationPolicy {
	if p == nil {
		return nil
	}
	return &transport.RotationPolicy{
		Enabled:         p.Enabled,
		IntervalSeconds: p.IntervalSeconds,
		NextRotation:    p.NextRotation,
		RetainVersions:  p.RetainVersions,
		AutoRotate:      p.AutoRotate,
	}
}

// KeyPolicyToProto converts a key policy to its wire form.
func KeyPolicyToProto(p *transport.KeyPolicy) *pb.KeyPolicy {
	if p == nil {
		return nil
	}
	return &pb.KeyPolicy{
		KeyId:             p.KeyID,
		Version:           p.Version,
		AllowedOperations: KeyUsagesToProto(p.AllowedOperations),
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         p.ExpiresAt,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMfa:        p.RequireMFA,
		UpdatedAt:         p.UpdatedAt,
	}
}

// KeyPolicyFromProto converts a wire key policy.
func KeyPolicyFromProto(p *pb.KeyPolicy) *transport.KeyPolicy {
	if p == nil {
		return nil
	}
	return &transport.KeyPolicy{
		KeyID:             p.KeyId,
		Version:           p.Version,
		AllowedOperations: KeyUsagesFromProto(p.AllowedOperations),
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         p.ExpiresAt,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMFA:        p.RequireMfa,
		UpdatedAt:         p.UpdatedAt,
	}
}

// KeyMetadataToProto converts key metadata to its wire form.
func KeyMetadataToProto(m *transport.KeyMetadata) *pb.KeyMetadata {
	if m == nil {
		return nil
	}
	return &pb.KeyMetadata{
		KeyId:              m.KeyID,
		Name:               m.Name,
		Description:        m.Description,
		Algorithm:          KeyAlgorithmToProto(m.Algorithm),
		Status:             KeyStatusToProto(m.Status),
		Usage:              KeyUsagesToProto(m.Usage),
		Version:            m.Version,
		Exportable:         m.Exportable,
		DeletionProtection: m.DeletionProtection,
		CreatedAt:          m.CreatedAt,
		UpdatedAt:          m.UpdatedAt,
		LastUsedAt:         m.LastUsedAt,
		RotationPolicy:     RotationPolicyToProto(m.RotationPolicy),
		Tags:               m.Tags,
		Owner:              m.Owner,
	}
}

// KeyMetadataFromProto converts wire key metadata.
func KeyMetadataFromProto(m *pb.KeyMetadata) *transport.KeyMetadata {
	if m == nil {
		return nil
	}
	return &transport.KeyMetadata{
		KeyID:              m.KeyId,
		Name:               m.Name,
		Description:        m.Description,
		Algorithm:          KeyAlgorithmFromProto(m.Algorithm),
		Status:             KeyStatusFromProto(m.Status),
		Usage:              KeyUsagesFromProto(m.Usage),
		Version:            m.Version,
		Exportable:         m.Exportable,
		DeletionProtection: m.DeletionProtection,
		CreatedAt:          m.CreatedAt,
		UpdatedAt:          m.UpdatedAt,
		LastUsedAt:         m.LastUsedAt,
		RotationPolicy:     RotationPolicyFromProto(m.RotationPolicy),
		Tags:               m.Tags,
		Owner:              m.Owner,
	}
}

// SafetyWarningsToProto converts key usage items to their wire form.
func SafetyWarningsToProto(items []transport.SafetyWarning) []*pb.SafetyWarning {
	out := make([]*pb.SafetyWarning, len(items))
	for i, w := range items {
		out[i] = &pb.SafetyWarning{
			Type:           w.Type,
			Path:           w.Path,
			UsagePercent:   w.UsagePercent,
			Status:         w.Status,
			OperationsUsed: w.OperationsUsed,
			BytesUsed:      w.BytesUsed,
			MaxOperations:  w.MaxOperations,
			MaxBytes:       w.MaxBytes,
		}
	}
	return out
}

// SafetyWarningsFromProto converts wire key usage items.
func SafetyWarningsFromProto(items []*pb.SafetyWarning) []transport.SafetyWarning {
	out := make([]transport.SafetyWarning, len(items))
	for i, w := range items {
		out[i] = transport.SafetyWarning{
			Type:           w.GetType(),
			Path:           w.GetPath(),
			UsagePercent:   w.GetUsagePercent(),
			Status:         w.GetStatus(),
			OperationsUsed: w.GetOperationsUsed(),
			BytesUsed:      w.GetBytesUsed(),
			MaxOperations:  w.GetMaxOperations(),
			MaxBytes:       w.GetMaxBytes(),
		}
	}
	return out
}

// UpdateKeyMetadataRequestToProto converts a metadata update to its wire
// form.
func UpdateKeyMetadataRequestToProto(r *transport.UpdateKeyMetadataRequest) *pb.UpdateKeyMetadataRequest {
	return &pb.UpdateKeyMetadataRequest{
		KeyId:       r.KeyID,
		Name:        r.Name,
		Description: r.Description,
		Tags:        r.Tags,
		RemoveTags:  r.RemoveTags,
		Backend:     r.Backend,
	}
}

// UpdateKeyMetadataRequestFromProto converts a wire metadata update.
func UpdateKeyMetadataRequestFromProto(r *pb.UpdateKeyMetadataRequest) *transport.UpdateKeyMetadataRequest {
	return &transport.UpdateKeyMetadataRequest{
		KeyID:       r.GetKeyId(),
		Name:        r.GetName(),
		Description: r.GetDescription(),
		Tags:        r.GetTags(),
		RemoveTags:  r.GetRemoveTags(),
		Backend:     r.GetBackend(),
	}
}

// BackendStatusResponseToProto converts a backend status to its wire form.
func BackendStatusResponseToProto(r *transport.BackendStatusResponse) *pb.BackendStatusResponse {
	return &pb.BackendStatusResponse{
		BackendType:  r.BackendType,
		Status:       r.Status,
		Device:       r.Device,
		Region:       r.Region,
		KeyId:        r.KeyID,
		PcrBanks:     r.PCRBanks,
		PcrRegisters: r.PCRRegisters,
		Capabilities: r.Capabilities,
		Timestamp:    r.Timestamp,
	}
}

// BackendStatusResponseFromProto converts a wire backend status.
func BackendStatusResponseFromProto(r *pb.BackendStatusResponse) *transport.BackendStatusResponse {
	return &transport.BackendStatusResponse{
		BackendType:  r.GetBackendType(),
		Status:       r.GetStatus(),
		Device:       r.GetDevice(),
		Region:       r.GetRegion(),
		KeyID:        r.GetKeyId(),
		PCRBanks:     r.GetPcrBanks(),
		PCRRegisters: r.GetPcrRegisters(),
		Capabilities: r.GetCapabilities(),
		Timestamp:    r.GetTimestamp(),
	}
}

// SafetyReportResponseToProto converts a safety report to its wire form.
func SafetyReportResponseToProto(r *transport.SafetyReportResponse) *pb.SafetyReportResponse {
	return &pb.SafetyReportResponse{
		AllItems:       SafetyWarningsToProto(r.AllItems),
		TotalKeys:      r.TotalKeys,
		TotalDeks:      r.TotalDEKs,
		KeysAtWarning:  r.KeysAtWarning,
		KeysAtCritical: r.KeysAtCritical,
		DeksAtWarning:  r.DEKsAtWarning,
		DeksAtCritical: r.DEKsAtCritical,
		Timestamp:      r.Timestamp,
	}
}

// SafetyReportResponseFromProto converts a wire safety report.
func SafetyReportResponseFromProto(r *pb.SafetyReportResponse) *transport.SafetyReportResponse {
	return &transport.SafetyReportResponse{
		AllItems:       SafetyWarningsFromProto(r.GetAllItems()),
		TotalKeys:      r.GetTotalKeys(),
		TotalDEKs:      r.GetTotalDeks(),
		KeysAtWarning:  r.GetKeysAtWarning(),
		KeysAtCritical: r.GetKeysAtCritical(),
		DEKsAtWarning:  r.GetDeksAtWarning(),
		DEKsAtCritical: r.GetDeksAtCritical(),
		Timestamp:      r.GetTimestamp(),
	}
}
