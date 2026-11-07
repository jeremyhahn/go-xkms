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

package sealblobstore

import "testing"

func TestEntity_EntityID_RoundTrip(t *testing.T) {
	e := &Entity{
		Label:      "backup-key",
		BackendID:  "tpm2-default",
		PolicyType: "platform_policy",
		SealedData: []byte{0xDE, 0xAD},
	}

	const wantID uint64 = 77
	e.SetEntityID(wantID)

	if got := e.EntityID(); got != wantID {
		t.Errorf("EntityID() = %d, want %d", got, wantID)
	}
}
