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

package module

import "context"

// CompareAndDelete mirrors mockStorageBackend.Delete (a no-op reporting success).
func (m *mockStorageBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return true, nil
}
