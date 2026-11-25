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

package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type boundKey struct{}

// boundKV refuses a write or read whose context was not bound.
type boundKV struct {
	*guardedMemoryKV
}

var errUnbound = errors.New("unbound call")

func (k *boundKV) Put(ctx context.Context, key string, value []byte) error {
	if ctx.Value(boundKey{}) == nil {
		return errUnbound
	}
	return k.guardedMemoryKV.Put(ctx, key, value)
}

func (k *boundKV) Get(ctx context.Context, key string) ([]byte, error) {
	if ctx.Value(boundKey{}) == nil {
		return nil, errUnbound
	}
	return k.guardedMemoryKV.Get(ctx, key)
}

func bindCall(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, boundKey{}, true), nil
}

func TestQRDBRefreshStore_CallContextBindsEveryCall(t *testing.T) {
	store, err := NewQRDBRefreshStore(&boundKV{newGuardedMemoryKV()}, WithCallContext(bindCall))
	require.NoError(t, err)
	ctx := context.Background()

	rec := &Record{JTI: "j1", Family: "f1", Subject: "bea", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, store.Save(ctx, rec))
	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NoError(t, store.MarkRotated(ctx, "f1", "j1"))
	require.NoError(t, store.RevokeFamily(ctx, "f1"))
}

func TestQRDBRefreshStore_CallContextFailureSurfaces(t *testing.T) {
	refused := errors.New("no service context")
	store, err := NewQRDBRefreshStore(newGuardedMemoryKV(), WithCallContext(func(context.Context) (context.Context, error) {
		return nil, refused
	}))
	require.NoError(t, err)

	err = store.Save(context.Background(), &Record{JTI: "j1", Family: "f1", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	require.ErrorIs(t, err, refused)
	_, err = store.Get(context.Background(), "f1", "j1")
	require.ErrorIs(t, err, refused)
}
