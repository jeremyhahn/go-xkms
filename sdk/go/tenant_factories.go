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
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// Tenant-scoped PlatformStore types re-exported from pkg/seal.
type (
	// TenantPlatformStoreFactory creates and caches PlatformStore instances
	// scoped to individual tenants via their barrier's namespace isolation.
	TenantPlatformStoreFactory = seal.TenantPlatformStoreFactory

	// SealedPlatformStore implements PlatformStore on top of a storage.Backend.
	SealedPlatformStore = seal.SealedPlatformStore

	// PlatformStore provides a named-secret API for storing and retrieving
	// sealed credentials.
	PlatformStore = seal.PlatformStore
)

// Tenant-scoped PlatformStore constructors re-exported from pkg/seal.
var (
	// NewTenantPlatformStoreFactory creates a new TenantPlatformStoreFactory
	// backed by the given BarrierRegistry.
	NewTenantPlatformStoreFactory = seal.NewTenantPlatformStoreFactory

	// NewTenantPlatformStore creates a PlatformStore scoped to a specific
	// tenant using the tenant's barrier for namespace isolation.
	NewTenantPlatformStore = seal.NewTenantPlatformStore
)

// Tenant-scoped HardwareCertStorage types re-exported from pkg/storage/hardware.
type (
	// TenantCertStorageFactory creates and caches HardwareCertStorage instances
	// scoped to individual tenants via their barrier's namespace isolation.
	TenantCertStorageFactory = hardware.TenantCertStorageFactory

	// HardwareCertStorage is the interface for hardware-backed certificate storage.
	HardwareCertStorage = hardware.HardwareCertStorage
)

// Tenant-scoped HardwareCertStorage constructors re-exported from pkg/storage/hardware.
var (
	// NewTenantCertStorageFactory creates a new TenantCertStorageFactory
	// backed by the given BarrierRegistry.
	NewTenantCertStorageFactory = hardware.NewTenantCertStorageFactory

	// NewTenantCertStorage creates a HardwareCertStorage scoped to a specific
	// tenant using the tenant's barrier for storage isolation.
	NewTenantCertStorage = hardware.NewTenantCertStorage
)
