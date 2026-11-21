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

// Package devicereg is the tenant-scoped registry of paired devices for
// backend mode, where go-xkms is the verifier and the authority for the
// devices a tenant paired (docs/SPEC.md, row device-registry).
//
// A Registry stores one Device record per tenant and ID on the qrdb DAO.
// Pair refuses an ID the tenant already holds; Revoke marks a record
// revoked and keeps it, so a revoked ID is never silently reused. Every
// call is scoped to one tenant: a tenant can neither read nor revoke
// another tenant's device.
//
// The package adds no permission, route or service verb; those belong to
// row device-share-policy. See docs/device-registry/architecture.md.
package devicereg
