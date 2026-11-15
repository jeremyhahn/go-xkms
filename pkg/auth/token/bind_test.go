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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type boundKey struct{}

// ctxRecordingStore records whether each call arrived on the bound context.
type ctxRecordingStore struct {
	RefreshStore
	unbound []string
}

func (s *ctxRecordingStore) check(ctx context.Context, op string) {
	if ctx.Value(boundKey{}) == nil {
		s.unbound = append(s.unbound, op)
	}
}

func (s *ctxRecordingStore) Save(ctx context.Context, rec *Record) error {
	s.check(ctx, "Save")
	return s.RefreshStore.Save(ctx, rec)
}

func (s *ctxRecordingStore) Get(ctx context.Context, family, jti string) (*Record, error) {
	s.check(ctx, "Get")
	return s.RefreshStore.Get(ctx, family, jti)
}

func (s *ctxRecordingStore) MarkRotated(ctx context.Context, family, jti string) error {
	s.check(ctx, "MarkRotated")
	return s.RefreshStore.MarkRotated(ctx, family, jti)
}

func (s *ctxRecordingStore) RevokeFamily(ctx context.Context, family string) error {
	s.check(ctx, "RevokeFamily")
	return s.RefreshStore.RevokeFamily(ctx, family)
}

func (s *ctxRecordingStore) RevokeBySubject(ctx context.Context, subject string) error {
	s.check(ctx, "RevokeBySubject")
	return s.RefreshStore.RevokeBySubject(ctx, subject)
}

func bindForTest(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, boundKey{}, true), nil
}

// TestBindRefreshStore_RunsEveryCallOnTheBoundContext is #2541's third
// layer: an anonymous WebAuthn login mints a token pair, and the qrdb refresh
// store must persist it as the node's service principal, not on the
// request's context.
func TestBindRefreshStore_RunsEveryCallOnTheBoundContext(t *testing.T) {
	inner := &ctxRecordingStore{RefreshStore: NewMemoryRefreshStore()}
	store := BindRefreshStore(inner, bindForTest)
	ctx := context.Background()

	rec := &Record{Family: "f1", JTI: "j1", Subject: "u1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, store.Save(ctx, rec))
	_, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NoError(t, store.MarkRotated(ctx, "f1", "j1"))
	require.NoError(t, store.RevokeFamily(ctx, "f1"))
	require.NoError(t, store.RevokeBySubject(ctx, "u1"))

	assert.Empty(t, inner.unbound, "every refresh store call runs on the bound context")
}

func TestBindRefreshStore_BindErrorFailsTheCall(t *testing.T) {
	inner := &ctxRecordingStore{RefreshStore: NewMemoryRefreshStore()}
	bindErr := errors.New("no service context")
	store := BindRefreshStore(inner, func(context.Context) (context.Context, error) { return nil, bindErr })

	err := store.Save(context.Background(), &Record{Family: "f1", JTI: "j1", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	require.ErrorIs(t, err, bindErr)
	_, err = store.Get(context.Background(), "f1", "j1")
	require.ErrorIs(t, err, bindErr)
}

func TestBindRefreshStore_NilBindReturnsTheStore(t *testing.T) {
	inner := NewMemoryRefreshStore()
	assert.Same(t, inner, BindRefreshStore(inner, nil))
}
