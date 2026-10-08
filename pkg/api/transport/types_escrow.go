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

package transport

import (
	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// Escrow request/response types are aliases of the pkg/escrow domain types,
// which already carry the correct JSON tags and Validate() methods —
// mirroring how types_tenant.go aliases qrdb's own transport types
// instead of re-declaring them.
type (
	EscrowRequest   = escrow.EscrowRequest
	EscrowReceipt   = escrow.EscrowReceipt
	RecoverRequest  = escrow.RecoverRequest
	RecoverResponse = escrow.RecoverResponse
	EscrowRecord    = escrow.EscrowRecord
)
