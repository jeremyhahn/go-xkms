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

// recordingRefreshStore records whether each call ran on the bound context.
type recordingRefreshStore struct{ bound []bool }

func (r *recordingRefreshStore) mark(ctx context.Context) {
	r.bound = append(r.bound, ctx.Value(tokenCallCtxKey{}) == "service")
}

func (r *recordingRefreshStore) Save(ctx context.Context, _ *token.Record) error {
	r.mark(ctx)
	return nil
}

func (r *recordingRefreshStore) Get(ctx context.Context, _, _ string) (*token.Record, error) {
	r.mark(ctx)
	return nil, nil
}

func (r *recordingRefreshStore) MarkRotated(ctx context.Context, _, _ string) error {
	r.mark(ctx)
	return nil
}

func (r *recordingRefreshStore) RevokeFamily(ctx context.Context, _ string) error {
	r.mark(ctx)
	return nil
}

func (r *recordingRefreshStore) RevokeBySubject(ctx context.Context, _ string) error {
	r.mark(ctx)
	return nil
}

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
	inner := &recordingRefreshStore{}
	store := bindRefreshStore(inner, serviceBind)
	if err := store.Save(ctx, &token.Record{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.Get(ctx, "f", "j"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := store.MarkRotated(ctx, "f", "j"); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if err := store.RevokeFamily(ctx, "f"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if err := store.RevokeBySubject(ctx, "s"); err != nil {
		t.Fatalf("RevokeBySubject: %v", err)
	}
	if len(inner.bound) != 5 {
		t.Fatalf("refresh store calls = %d, want 5", len(inner.bound))
	}
	for i, b := range inner.bound {
		if !b {
			t.Errorf("refresh store call %d did not run on the service context", i)
		}
	}

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
	inner := &recordingRefreshStore{}
	if err := bindRefreshStore(inner, fail).Save(context.Background(), &token.Record{}); !errors.Is(err, bindErr) {
		t.Fatalf("Save err = %v, want the bind error", err)
	}
	if len(inner.bound) != 0 {
		t.Fatal("refresh store reached despite the bind error")
	}
	res := &recordingUserResolver{}
	if _, err := bindUserResolver(res, fail).ResolveUser(context.Background(), &auth.Identity{}); !errors.Is(err, bindErr) {
		t.Fatalf("ResolveUser err = %v, want the bind error", err)
	}
}

func TestTokenStores_NilBindKeepsTheStore(t *testing.T) {
	inner := &recordingRefreshStore{}
	if got := bindRefreshStore(inner, nil); got != token.RefreshStore(inner) {
		t.Fatal("nil bind must return the store unchanged")
	}
	res := &recordingUserResolver{}
	if got := bindUserResolver(res, nil); got != token.UserResolver(res) {
		t.Fatal("nil bind must return the resolver unchanged")
	}
}
