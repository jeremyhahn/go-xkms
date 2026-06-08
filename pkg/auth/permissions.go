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

package auth

// Resource and action identifiers for the xkms API authorization surface.
// These mirror the canonical go-qrdb permission vocabulary
// (pkg/permission/constants.go) so a route decorator's resource:action pair
// maps directly onto a qrdb role grant. xkms registers no parallel
// vocabulary; the genuinely xkms-domain permissions (backends:*,
// keys:import/export, certs:read) are part of qrdb's canonical registry.
const (
	// Resources.
	ResourceKeys     = "keys"
	ResourceCerts    = "certs"
	ResourceBackends = "backends"
	ResourceUsers    = "users"

	// Key actions.
	ActionSign    = "sign"
	ActionVerify  = "verify"
	ActionEncrypt = "encrypt"
	ActionDecrypt = "decrypt"
	ActionCreate  = "create"
	ActionRotate  = "rotate"
	ActionDelete  = "delete"
	ActionList    = "list"
	ActionGet     = "get"
	ActionImport  = "import"
	ActionExport  = "export"

	// Certificate actions (qrdb uses generate/revoke/read/list).
	ActionGenerate = "generate"
	ActionRevoke   = "revoke"

	// Shared read/update actions for certs, backends, and users.
	ActionRead   = "read"
	ActionUpdate = "update"
)
