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

package rest

import (
	"context"
	"errors"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

var errPutRecorded = errors.New("put recorded")

// putRecordingKV records the context of each Put and refuses it.
type putRecordingKV struct {
	qrdbtransport.GuardedKVClient
	tenants []string
	bound   []bool
}

func (k *putRecordingKV) Put(ctx context.Context, _ string, _ []byte) error {
	k.tenants = append(k.tenants, qrdbtenant.FromContext(ctx))
	v, _ := ctx.Value(tokenCallCtxKey{}).(string)
	k.bound = append(k.bound, v == "service")
	return errPutRecorded
}

func TestNewRefreshStore_RunsOnSystemTenantAsService(t *testing.T) {
	kv := &putRecordingKV{}
	store, err := newRefreshStore(kv, serviceBind)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	ctx := qrdbtenant.WithTenantID(context.Background(), "acme")
	if err := store.Save(ctx, &token.Record{Family: "f", JTI: "j", TenantID: "acme", Subject: "s"}); !errors.Is(err, errPutRecorded) {
		t.Fatalf("Save err = %v, want the recorded Put", err)
	}
	if len(kv.tenants) != 1 {
		t.Fatalf("Put calls = %d, want 1", len(kv.tenants))
	}
	if kv.tenants[0] != qrdbsdk.SystemTenantID {
		t.Errorf("Put tenant = %q, want the system tenant", kv.tenants[0])
	}
	if !kv.bound[0] {
		t.Error("Put did not run on the service context")
	}
}

func TestNewRefreshStore_NilBindKeepsTheCallerContext(t *testing.T) {
	kv := &putRecordingKV{}
	store, err := newRefreshStore(kv, nil)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	ctx := qrdbtenant.WithTenantID(context.Background(), "acme")
	if err := store.Save(ctx, &token.Record{Family: "f", JTI: "j", TenantID: "acme", Subject: "s"}); !errors.Is(err, errPutRecorded) {
		t.Fatalf("Save err = %v, want the recorded Put", err)
	}
	if kv.tenants[0] != "acme" || kv.bound[0] {
		t.Errorf("Put ran on tenant %q bound=%v, want the caller's context", kv.tenants[0], kv.bound[0])
	}
}
