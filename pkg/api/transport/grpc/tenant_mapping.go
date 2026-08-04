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

package grpc

import (
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// tenantEntitlementsToPB maps the wire entitlement DTO onto its proto form.
func tenantEntitlementsToPB(e transport.TenantEntitlements) *pb.TenantEntitlements {
	return &pb.TenantEntitlements{
		AllowedIsolationModes:     e.AllowedIsolationModes,
		AllowDedicatedRaft:        e.AllowDedicatedRaft,
		AllowVolumeStorage:        e.AllowVolumeStorage,
		AllowSystemManagedBarrier: e.AllowSystemManagedBarrier,
	}
}

// tenantQuotasToPB maps the wire quota DTO onto its proto form.
func tenantQuotasToPB(q transport.TenantQuotas) *pb.TenantQuotas {
	return &pb.TenantQuotas{
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
		MaxTsMetrics:         q.MaxTSMetrics,
	}
}

// pbQuotasToTransport maps a proto quota message onto the wire DTO (nil-safe).
func pbQuotasToTransport(q *pb.TenantQuotas) *transport.TenantQuotas {
	if q == nil {
		return nil
	}
	return &transport.TenantQuotas{
		MaxDatabases:         q.GetMaxDatabases(),
		MaxRaftGroups:        q.GetMaxRaftGroups(),
		MaxReplicasPerGroup:  q.GetMaxReplicasPerGroup(),
		MaxTotalReplicas:     q.GetMaxTotalReplicas(),
		MaxCollections:       q.GetMaxCollections(),
		MaxKeys:              q.GetMaxKeys(),
		MaxStorageBytes:      q.GetMaxStorageBytes(),
		MaxDatabaseSizeBytes: q.GetMaxDatabaseSizeBytes(),
		MaxUsers:             q.GetMaxUsers(),
		MaxRoles:             q.GetMaxRoles(),
		MaxCertificates:      q.GetMaxCertificates(),
		MaxBackups:           q.GetMaxBackups(),
		MaxVectorDims:        q.GetMaxVectorDims(),
		MaxTSMetrics:         q.GetMaxTsMetrics(),
	}
}

// pbEntitlementsToTransport maps a proto entitlement message onto the wire DTO
// (nil-safe).
func pbEntitlementsToTransport(e *pb.TenantEntitlements) *transport.TenantEntitlements {
	if e == nil {
		return nil
	}
	return &transport.TenantEntitlements{
		AllowedIsolationModes:     e.GetAllowedIsolationModes(),
		AllowDedicatedRaft:        e.GetAllowDedicatedRaft(),
		AllowVolumeStorage:        e.GetAllowVolumeStorage(),
		AllowSystemManagedBarrier: e.GetAllowSystemManagedBarrier(),
	}
}
