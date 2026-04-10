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

// ThresholdFactory creates a ThresholdInitializer for a specific vendor.
type ThresholdFactory = qrdbsdk.ThresholdFactory

// ThresholdRegistry manages vendor-specific threshold initializer factories.
type ThresholdRegistry = qrdbsdk.ThresholdRegistry

// NewThresholdRegistry creates a new empty threshold registry.
var NewThresholdRegistry = qrdbsdk.NewThresholdRegistry
