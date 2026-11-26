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

package kvadapter

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestEveryIndexMethodRefusesWithTheCapabilitySentinel pins the contract that
// lets a go-qrdb DAO be built over this adapter at all.
//
// Since go-qrdb v0.8.0-alpha, pkg/dao calls RegisterEntityIndexes at
// construction and branches on the reply: an error matching
// ErrKVIndexUnsupported means "no index subsystem, plan full scans", and any
// other error aborts construction. This adapter cannot index -- it bridges an
// opaque byte-oriented storage.Backend -- so its refusal MUST match that
// sentinel or every DAO over it fails to construct.
//
// That is not hypothetical. On the v0.6.0 -> v0.9.0 bump this adapter reported
// only its local sentinel, and 28 tests across pkg/api/rest failed with
// "failed to create DAO: kvadapter: RegisterEntityIndexes teams: secondary
// indexing is not supported" -- a capability signal being read as a failure.
//
// Both sentinels are asserted deliberately: dropping the local one breaks
// in-repo callers that test for it, and dropping the go-qrdb one breaks DAO
// construction. Neither may be removed without replacing this test.
//
// The whole index surface is checked, not just registration. pkg/dao consults the sentinel on query paths
// as well (it decides there whether to fall back to a full scan), so a method
// that refused with an unmatched error would turn a planned scan into a hard
// query failure.
func TestEveryIndexMethodRefusesWithTheCapabilitySentinel(t *testing.T) {
	a := &KVStoreAdapter{}
	ctx := context.Background()

	queryResults, queryErr := a.QueryIndex(ctx, "by_name", []byte("x"))
	scanResults, scanErr := a.ScanIndex(ctx, "by_name", []byte("a"), []byte("z"))
	compoundResults, compoundErr := a.QueryCompoundIndex(ctx, "by_tenant_name", [][]byte{[]byte("t")})
	scanCompoundResults, scanCompoundErr := a.ScanCompoundIndex(ctx, "by_tenant_name", [][]byte{[]byte("t")}, []byte("a"), []byte("z"))

	if queryResults != nil || scanResults != nil || compoundResults != nil || scanCompoundResults != nil {
		t.Errorf("an index refusal returned results; want nil alongside the error")
	}

	for _, tc := range []struct {
		method string
		name   string
		err    error
	}{
		{"RegisterEntityIndexes", "teams", a.RegisterEntityIndexes("teams", nil)},
		{"QueryIndex", "by_name", queryErr},
		{"ScanIndex", "by_name", scanErr},
		{"QueryCompoundIndex", "by_tenant_name", compoundErr},
		{"ScanCompoundIndex", "by_tenant_name", scanCompoundErr},
	} {
		if tc.err == nil {
			t.Errorf("%s returned nil; want a refusal — silently succeeding would let a "+
				"caller believe this store maintains indexes", tc.method)
			continue
		}
		if !errors.Is(tc.err, ErrIndexingNotSupported) {
			t.Errorf("%s error does not match ErrIndexingNotSupported; in-repo callers "+
				"detect the local sentinel to fall back to Scan/List. err=%v", tc.method, tc.err)
		}
		if !errors.Is(tc.err, qrdbsdk.ErrKVIndexUnsupported) {
			t.Errorf("%s error does not match qrdbsdk.ErrKVIndexUnsupported; "+
				"go-qrdb would treat this capability gap as a hard failure. err=%v", tc.method, tc.err)
		}
		var typed *IndexingNotSupportedError
		if !errors.As(tc.err, &typed) {
			t.Errorf("%s error is not an *IndexingNotSupportedError. err=%v", tc.method, tc.err)
			continue
		}
		if typed.Op != tc.method || typed.Name != tc.name {
			t.Errorf("%s refusal names Op=%q Name=%q; want Op=%q Name=%q",
				tc.method, typed.Op, typed.Name, tc.method, tc.name)
		}
	}
}
