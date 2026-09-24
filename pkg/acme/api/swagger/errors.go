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

package swagger

// ErrAssetLoad indicates that the vendored Swagger UI assets embedded at
// build time could not be loaded. It can only occur if the embedded asset
// tree itself is malformed, which is a packaging defect rather than a
// runtime condition.
type ErrAssetLoad struct {
	Detail string
}

// Error returns the error message.
func (e *ErrAssetLoad) Error() string {
	return "swagger: failed to load vendored UI assets: " + e.Detail
}
