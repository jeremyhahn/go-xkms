// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package hardware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestChainMemberIndex pins the exact shape of a chain member's CKA_ID: a
// prefix match would take a certificate named id-chain and the members of
// id-chain2's chain along with id's own chain.
func TestChainMemberIndex(t *testing.T) {
	for name, tc := range map[string]struct {
		id, candidate string
		wantIdx       int
		wantOK        bool
	}{
		"first member":                  {id: "foo", candidate: "foo-chain-0", wantIdx: 0, wantOK: true},
		"later member":                  {id: "foo", candidate: "foo-chain-12", wantIdx: 12, wantOK: true},
		"the certificate itself":        {id: "foo", candidate: "foo", wantOK: false},
		"a certificate named foo-chain": {id: "foo", candidate: "foo-chain", wantOK: false},
		"another record's chain":        {id: "foo", candidate: "foo-chain2-chain-0", wantOK: false},
		"missing index":                 {id: "foo", candidate: "foo-chain-", wantOK: false},
		"non-numeric index":             {id: "foo", candidate: "foo-chain-a", wantOK: false},
		"negative index":                {id: "foo", candidate: "foo-chain--1", wantOK: false},
		"member of a longer id":         {id: "foo-chain", candidate: "foo-chain-chain-0", wantIdx: 0, wantOK: true},
	} {
		t.Run(name, func(t *testing.T) {
			idx, ok := chainMemberIndex(tc.id, tc.candidate)
			if ok != tc.wantOK || idx != tc.wantIdx {
				t.Fatalf("chainMemberIndex(%q, %q) = (%d, %v), want (%d, %v)", tc.id, tc.candidate, idx, ok, tc.wantIdx, tc.wantOK)
			}
		})
	}
}

func TestIsChainMemberID(t *testing.T) {
	for candidate, want := range map[string]bool{
		"foo-chain-0":       true,
		"foo-chain-12":      true,
		"foo-chain-a":       false,
		"myapp-chain-id-0":  false,
		"foo-chain-":        false,
		"-chain-0":          false,
		"foo":               false,
		"foo-chain":         false,
		"a-chain-b-chain-3": true,
		"a-chain-3-chain-x": false,
		"chain-0":           false,
		"x-chain--1":        false,
	} {
		assert.Equal(t, want, isChainMemberID(candidate), candidate)
	}
}

// TestIsReservedChainID pins the ids a caller must never be able to name a
// certificate with. "test-chain" is issue #615: a fixture that names its
// certificate id-chain looks exactly like the chain record of "id", so every
// chain operation on it collides with the reservation deterministically.
func TestIsReservedChainID(t *testing.T) {
	for candidate, want := range map[string]bool{
		"foo-chain":     true,
		"foo-chain-0":   true,
		"foo-chain-a":   false,
		"foo-chained":   false,
		"foo":           false,
		"-chain":        true,
		"a-chain-chain": true,
		"test-chain":    true,
		"test-cert":     false,
	} {
		assert.Equal(t, want, isReservedChainID(candidate), candidate)
	}
}
