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

package xkms

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// tenantInfoToTransport maps go-qrdb's service-layer TenantInfo (returned by the
// composed TenantService) onto the wire DTO the xkms transports expose. The
// transport DTO is itself an alias of go-qrdb's transport.TenantInfo, so this
// bridges the service-layer quota/entitlement types onto their wire forms while
// surfacing the effective isolation mode (legacy/empty records resolve to
// prefix isolation).
func tenantInfoToTransport(info *qrdbsdk.ServiceTenantInfo) transport.TenantInfo {
	if info == nil {
		return transport.TenantInfo{}
	}
	ti := transport.TenantInfo{
		ID:            info.ID,
		Name:          info.Name,
		IsolationType: transport.TenantIsolationType(info.EffectiveIsolationType()),
		CreatedAt:     info.CreatedAt,
		UpdatedAt:     info.UpdatedAt,
	}
	if info.Quotas != nil {
		ti.Quotas = tenantQuotasToTransport(info.Quotas)
	}
	if info.Entitlements != nil {
		ti.Entitlements = tenantEntitlementsToTransport(info.Entitlements)
	}
	return ti
}

// tenantQuotasToTransport maps the service-layer quota set onto the wire DTO.
func tenantQuotasToTransport(q *qrdbsdk.Quotas) *transport.TenantQuotas {
	return &transport.TenantQuotas{
		MaxDatabases:         q.MaxDatabases,
		MaxRaftGroups:        q.MaxRaftGroups,
		MaxReplicasPerGroup:  q.MaxReplicasPerGroup,
		MaxTotalReplicas:     q.MaxTotalReplicas,
		MaxCollections:       q.MaxCollections,
		MaxKeys:              q.MaxKeys,
		MaxStorageBytes:      q.MaxStorageBytes,
		MaxDatabaseSizeBytes: q.MaxDatabaseSizeBytes,
		MaxUsers:             q.MaxUsers,
		MaxRoles:             q.MaxRoles,
		MaxCertificates:      q.MaxCertificates,
		MaxBackups:           q.MaxBackups,
		MaxVectorDims:        q.MaxVectorDims,
		MaxTSMetrics:         q.MaxTSMetrics,
	}
}

// tenantEntitlementsToTransport maps the service-layer entitlement set onto the
// wire DTO.
func tenantEntitlementsToTransport(e *qrdbsdk.Entitlements) *transport.TenantEntitlements {
	return &transport.TenantEntitlements{
		AllowedIsolationModes:     e.AllowedIsolationModes,
		AllowDedicatedRaft:        e.AllowDedicatedRaft,
		AllowVolumeStorage:        e.AllowVolumeStorage,
		AllowSystemManagedBarrier: e.AllowSystemManagedBarrier,
	}
}

// transportToEntitlements maps the wire entitlement DTO onto the service-layer
// type for an update. AllowDedicatedWAL has no wire field yet and is left at its
// zero value.
func transportToEntitlements(e transport.TenantEntitlements) *qrdbsdk.Entitlements {
	return &qrdbsdk.Entitlements{
		AllowedIsolationModes:     e.AllowedIsolationModes,
		AllowDedicatedRaft:        e.AllowDedicatedRaft,
		AllowVolumeStorage:        e.AllowVolumeStorage,
		AllowSystemManagedBarrier: e.AllowSystemManagedBarrier,
	}
}

// transportToQuotas maps the wire quota DTO onto the service-layer type for an
// update.
func transportToQuotas(q transport.TenantQuotas) *qrdbsdk.Quotas {
	return &qrdbsdk.Quotas{
		MaxDatabases:         q.MaxDatabases,
		MaxRaftGroups:        q.MaxRaftGroups,
		MaxReplicasPerGroup:  q.MaxReplicasPerGroup,
		MaxTotalReplicas:     q.MaxTotalReplicas,
		MaxCollections:       q.MaxCollections,
		MaxKeys:              q.MaxKeys,
		MaxStorageBytes:      q.MaxStorageBytes,
		MaxDatabaseSizeBytes: q.MaxDatabaseSizeBytes,
		MaxUsers:             q.MaxUsers,
		MaxRoles:             q.MaxRoles,
		MaxCertificates:      q.MaxCertificates,
		MaxBackups:           q.MaxBackups,
		MaxVectorDims:        q.MaxVectorDims,
		MaxTSMetrics:         q.MaxTSMetrics,
	}
}
