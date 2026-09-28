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

package api

import "testing"

// TestAllProtocols verifies the canonical protocol set: every protocol the
// package heading promises ("All services MUST be exposed via ALL
// protocols") is present, in the documented order, with no duplicates.
func TestAllProtocols(t *testing.T) {
	want := []Protocol{ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP, ProtocolUnix}

	got := AllProtocols()

	if len(got) != len(want) {
		t.Fatalf("AllProtocols() returned %d protocols, want %d: %v", len(got), len(want), got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("AllProtocols()[%d] = %q, want %q", i, got[i], p)
		}
	}

	seen := make(map[Protocol]bool, len(got))
	for _, p := range got {
		if seen[p] {
			t.Errorf("AllProtocols() contains duplicate protocol %q", p)
		}
		seen[p] = true
	}
}

// TestAllProtocols_ReturnsFreshSlice guards against a shared backing array:
// a caller mutating the returned slice must never corrupt a later caller's
// view of the canonical protocol set.
func TestAllProtocols_ReturnsFreshSlice(t *testing.T) {
	first := AllProtocols()
	first[0] = "mutated"

	second := AllProtocols()
	if second[0] != ProtocolREST {
		t.Fatalf("AllProtocols() shares backing storage across calls; second call got %q after "+
			"the first caller mutated its slice", second[0])
	}
}
