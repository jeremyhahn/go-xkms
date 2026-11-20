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
	"reflect"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestEntitlementsMappingRoundTripsEveryField proves that a replace through
// the web console keeps the barrier modes, the dedicated WAL grant and the
// volume pool grants (Codex #2200 P1).
func TestEntitlementsMappingRoundTripsEveryField(t *testing.T) {
	in := transport.TenantEntitlements{
		AllowedIsolationModes:     []string{"barrier", "raft"},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: true,
		AllowedBarrierModes:       []string{"tpm2"},
		AllowDedicatedWAL:         true,
		AllowedVolumePools:        []string{"fast", "bulk"},
	}
	sdk := transportToEntitlements(in)
	if !reflect.DeepEqual(sdk.AllowedBarrierModes, []string{"tpm2"}) {
		t.Fatalf("AllowedBarrierModes = %v", sdk.AllowedBarrierModes)
	}
	if !sdk.AllowDedicatedWAL {
		t.Fatal("AllowDedicatedWAL dropped")
	}
	if !reflect.DeepEqual(sdk.AllowedVolumePools, []string{"fast", "bulk"}) {
		t.Fatalf("AllowedVolumePools = %v", sdk.AllowedVolumePools)
	}
	out := tenantEntitlementsToTransport(sdk)
	if !reflect.DeepEqual(*out, in) {
		t.Fatalf("round trip = %+v, want %+v", *out, in)
	}
}

// TestQuotasMappingRoundTripsEveryField proves the system barrier quota, the
// dedicated WAL group cap and the -1 unlimited value survive both directions.
func TestQuotasMappingRoundTripsEveryField(t *testing.T) {
	in := transport.TenantQuotas{
		MaxDatabases:          -1,
		MaxRaftGroups:         2,
		MaxReplicasPerGroup:   3,
		MaxTotalReplicas:      -1,
		MaxCollections:        5,
		MaxKeys:               6,
		MaxStorageBytes:       7,
		MaxDatabaseSizeBytes:  8,
		MaxUsers:              9,
		MaxRoles:              10,
		MaxCertificates:       11,
		MaxBackups:            12,
		MaxVectorDims:         13,
		MaxTSMetrics:          14,
		SystemBarrierQuota:    1 << 30,
		MaxDedicatedWALGroups: 4,
	}
	sdk := transportToQuotas(in)
	if sdk.SystemBarrierQuota != 1<<30 {
		t.Fatalf("SystemBarrierQuota = %d", sdk.SystemBarrierQuota)
	}
	if sdk.MaxDedicatedWALGroups != 4 {
		t.Fatalf("MaxDedicatedWALGroups = %d", sdk.MaxDedicatedWALGroups)
	}
	if sdk.MaxDatabases != -1 {
		t.Fatalf("MaxDatabases = %d, want -1 (unlimited)", sdk.MaxDatabases)
	}
	out := tenantQuotasToTransport(sdk)
	if !reflect.DeepEqual(*out, in) {
		t.Fatalf("round trip = %+v, want %+v", *out, in)
	}

	unlimited := tenantQuotasToTransport(&qrdbsdk.Quotas{SystemBarrierQuota: -1, MaxDedicatedWALGroups: -1})
	if unlimited.SystemBarrierQuota != -1 || unlimited.MaxDedicatedWALGroups != -1 {
		t.Fatalf("unlimited response = %+v", *unlimited)
	}
}
