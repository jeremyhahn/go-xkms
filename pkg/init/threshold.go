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

package initialize

import qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

// ThresholdInitializer provides HSM-layer M-of-N initialization.
// This is OPTIONAL - application-layer Shamir (barrier root key split) works
// with any backend. HSM-layer M-of-N adds defense-in-depth by ALSO splitting
// at the hardware level using the vendor's native protocol.
type ThresholdInitializer = qrdbsdk.ThresholdInitializer

// ThresholdOptions configures the HSM's native threshold scheme.
type ThresholdOptions = qrdbsdk.ThresholdOptions

// ThresholdStatus reports the current state of HSM threshold share import.
type ThresholdStatus = qrdbsdk.ThresholdStatus
