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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

// CallContextFunc derives the context a go-qrdb call runs on from the caller's.
type CallContextFunc func(context.Context) (context.Context, error)

// boundRefreshStore runs every call of the wrapped store on the bound context.
type boundRefreshStore struct {
	inner token.RefreshStore
	bind  CallContextFunc
}

// bindRefreshStore wraps store so its calls run on bind's context; nil bind returns store.
func bindRefreshStore(store token.RefreshStore, bind CallContextFunc) token.RefreshStore {
	if bind == nil {
		return store
	}
	return &boundRefreshStore{inner: store, bind: bind}
}

func (b *boundRefreshStore) Save(ctx context.Context, rec *token.Record) error {
	c, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.inner.Save(c, rec)
}

func (b *boundRefreshStore) Get(ctx context.Context, family, jti string) (*token.Record, error) {
	c, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.inner.Get(c, family, jti)
}

func (b *boundRefreshStore) MarkRotated(ctx context.Context, family, jti string) error {
	c, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.inner.MarkRotated(c, family, jti)
}

func (b *boundRefreshStore) RevokeFamily(ctx context.Context, family string) error {
	c, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.inner.RevokeFamily(c, family)
}

func (b *boundRefreshStore) RevokeBySubject(ctx context.Context, tenant, subject string) error {
	c, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.inner.RevokeBySubject(c, tenant, subject)
}

// boundUserResolver runs every lookup of the wrapped resolver on the bound context.
type boundUserResolver struct {
	inner token.UserResolver
	bind  CallContextFunc
}

// bindUserResolver wraps resolver so its lookups run on bind's context; nil bind returns resolver.
func bindUserResolver(resolver token.UserResolver, bind CallContextFunc) token.UserResolver {
	if bind == nil {
		return resolver
	}
	return &boundUserResolver{inner: resolver, bind: bind}
}

func (b *boundUserResolver) ResolveUser(ctx context.Context, id *auth.Identity) (*auth.Identity, error) {
	c, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.inner.ResolveUser(c, id)
}
