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

// NoopThresholdInitializer is a no-op implementation for backends that do not
// support native HSM-layer threshold operations. All mutating operations return
// ErrThresholdNotSupported.
type NoopThresholdInitializer = qrdbsdk.NoopThresholdInitializer

// NewNoopThresholdInitializer creates a new no-op threshold initializer.
func NewNoopThresholdInitializer() *NoopThresholdInitializer {
	return &NoopThresholdInitializer{}
}
