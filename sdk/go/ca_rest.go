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

import rest "github.com/jeremyhahn/go-xkms/pkg/api/rest"

// CA REST handler re-exports (from pkg/api/rest). Downstream composers
// mount the xkms CA operations API (bundle / certificate / sign-csr /
// issue / revoke / crl / status) on their own routers through these
// aliases instead of importing pkg/api/rest directly.

// CAHandlers provides the HTTP handlers for the CA operations API.
type CAHandlers = rest.CAHandlers

// NewCAHandlers constructs the CA operations HTTP handlers. The ca
// parameter accepts any type satisfying the internal caServicer interface,
// including *XKMSService (xkms.Get()).
var NewCAHandlers = rest.NewCAHandlers
