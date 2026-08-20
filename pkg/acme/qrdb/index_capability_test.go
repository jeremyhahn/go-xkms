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

package qrdb

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestRemoteAdapterRefusalMatchesQRDBCapabilitySentinel pins the contract that
// lets a go-qrdb DAO be constructed over the remote-transport adapter.
//
// Since go-qrdb v0.8.0-alpha, pkg/dao negotiates index capability at DAO
// construction: an error matching ErrKVIndexUnsupported means "no index
// subsystem, plan full scans", and any other error aborts construction. This
// adapter fronts a bare KVServicer with no index subsystem, so its refusal
// MUST match the sentinel.
//
// Every index method is asserted, not just registration. pkg/dao consults the
// sentinel on query paths too, so a method refusing with an unmatched error
// would turn a planned full scan into a hard query failure.
//
// This adapter previously returned a bare errs.Message here, which go-qrdb
// does not recognise. It was mis-triaged as latent because no test exercised
// it -- but nothing testing a path is not the same as nothing reaching it, and
// NewProvider(svc, nil) installs exactly this adapter (see the provider test
// below).
func TestRemoteAdapterRefusalMatchesQRDBCapabilitySentinel(t *testing.T) {
	a := NewKVStoreAdapter(NewMemoryKVClient())
	ctx := context.Background()

	queryErr := func() error { _, err := a.QueryIndex(ctx, "by_name", []byte("x")); return err }()
	scanErr := func() error { _, err := a.ScanIndex(ctx, "by_name", []byte("a"), []byte("z")); return err }()
	compoundErr := func() error {
		_, err := a.QueryCompoundIndex(ctx, "by_tenant_name", [][]byte{[]byte("t")})
		return err
	}()
	scanCompoundErr := func() error {
		_, err := a.ScanCompoundIndex(ctx, "by_tenant_name", [][]byte{[]byte("t")}, []byte("a"), []byte("z"))
		return err
	}()

	for _, tc := range []struct {
		method string
		err    error
	}{
		{"RegisterEntityIndexes", a.RegisterEntityIndexes("orders", nil)},
		{"QueryIndex", queryErr},
		{"ScanIndex", scanErr},
		{"QueryCompoundIndex", compoundErr},
		{"ScanCompoundIndex", scanCompoundErr},
	} {
		if tc.err == nil {
			t.Errorf("%s returned nil; want a refusal — silently succeeding would let a caller "+
				"believe this remote adapter maintains indexes", tc.method)
			continue
		}
		if !errors.Is(tc.err, qrdbsdk.ErrKVIndexUnsupported) {
			t.Errorf("%s error does not match qrdbsdk.ErrKVIndexUnsupported; go-qrdb would read this "+
				"capability gap as a hard failure and refuse to construct the DAO. err=%v", tc.method, tc.err)
		}
	}
}

// TestDefaultProviderInstallsAnAdapterQRDBCanNegotiateWith is the test whose
// absence let the defect above be called latent.
//
// NewProvider(svc, nil) is the documented default: it builds a KVStoreAdapter
// from the service's KVClient. That store is handed to DAO construction, so if
// its index refusal is not recognisable to go-qrdb, the default remote ACME
// path cannot build a DAO at all. Asserting the refusal through the PROVIDER
// (rather than only through a hand-built adapter) is what makes the reachable
// path, not just the type, covered.
func TestDefaultProviderInstallsAnAdapterQRDBCanNegotiateWith(t *testing.T) {
	p := NewProvider(&mockProviderService{kvClient: NewMemoryKVClient()}, nil)

	store := p.KVStore()
	if store == nil {
		t.Fatal("NewProvider(svc, nil) returned a provider with a nil KVStore; the default path is " +
			"supposed to install a KVStoreAdapter built from svc.KV()")
	}

	err := store.RegisterEntityIndexes("orders", nil)
	if err == nil {
		t.Fatal("default provider's KVStore accepted index registration; this adapter has no index " +
			"subsystem and must refuse, or callers are handed a store they wrongly believe indexes")
	}
	if !errors.Is(err, qrdbsdk.ErrKVIndexUnsupported) {
		t.Errorf("default provider's KVStore refuses index registration with an error go-qrdb cannot "+
			"recognise, so every DAO on this path fails to construct. err=%v", err)
	}
}
