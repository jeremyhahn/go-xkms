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

package symmetric

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// CompareAndDelete mirrors MockFailingStorage.Delete: it fails when
// failOnDelete is set, otherwise reports the key as removed.
func (m *MockFailingStorage) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	if m.failOnDelete {
		return false, &errs.Message{Msg: "storage error: delete failed"}
	}
	return true, nil
}
