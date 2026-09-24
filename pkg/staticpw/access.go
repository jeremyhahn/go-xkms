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

package staticpw

// AccessMode identifies the access control strategy the password store
// enforces for a caller.
//
// Only AccessSessionBased is reachable today: TenantPasswordStoreManager
// implements it directly against the qrdb TenantBarrier's own unseal/reseal
// (UnlockTenant/LockTenant in tenant_store_manager.go), with the PIN check
// performed at the servicer layer (XKMSService.verifyPasswordStoreUserPIN in
// pkg/xkms/servicer_password.go) rather than by a wrapper store. There is no
// store implementation of AccessPINPerOperation:
// XKMSService.PasswordStoreSetAccessMode only ever succeeds when the
// requested mode equals the store's already-active mode, and the active mode
// for a tenant store is always AccessSessionBased, so AccessPINPerOperation
// can never become effective through the servicer that owns this vocabulary.
type AccessMode string

const (
	// AccessPINPerOperation requires a PIN for every decryption operation.
	AccessPINPerOperation AccessMode = "pin_per_operation"

	// AccessSessionBased requires a single PIN unlock, then allows free access
	// until the store is locked again.
	AccessSessionBased AccessMode = "session_based"
)
