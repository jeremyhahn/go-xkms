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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

type tokenCallCtxKey struct{}

type recordingUserResolver struct{ bound bool }

func (r *recordingUserResolver) ResolveUser(ctx context.Context, id *auth.Identity) (*auth.Identity, error) {
	r.bound = ctx.Value(tokenCallCtxKey{}) == "service"
	return id, nil
}

func serviceBind(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, tokenCallCtxKey{}, "service"), nil
}

func TestTokenStores_RunOnServiceCallContext(t *testing.T) {
	ctx := context.Background()
	res := &recordingUserResolver{}
	if _, err := bindUserResolver(res, serviceBind).ResolveUser(ctx, &auth.Identity{}); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !res.bound {
		t.Error("user resolver did not run on the service context")
	}
}

func TestTokenStores_BindErrorFailsTheCall(t *testing.T) {
	bindErr := errors.New("no service principal")
	fail := func(context.Context) (context.Context, error) { return nil, bindErr }
	kv := &putRecordingKV{}
	store, err := newRefreshStore(kv, fail)
	if err != nil {
		t.Fatalf("newRefreshStore: %v", err)
	}
	if err := store.Save(context.Background(), &token.Record{}); !errors.Is(err, bindErr) {
		t.Fatalf("Save err = %v, want the bind error", err)
	}
	if len(kv.tenants) != 0 {
		t.Fatal("refresh store reached despite the bind error")
	}
	res := &recordingUserResolver{}
	if _, err := bindUserResolver(res, fail).ResolveUser(context.Background(), &auth.Identity{}); !errors.Is(err, bindErr) {
		t.Fatalf("ResolveUser err = %v, want the bind error", err)
	}
}

func TestTokenStores_NilBindKeepsTheStore(t *testing.T) {
	res := &recordingUserResolver{}
	if got := bindUserResolver(res, nil); got != token.UserResolver(res) {
		t.Fatal("nil bind must return the resolver unchanged")
	}
}
