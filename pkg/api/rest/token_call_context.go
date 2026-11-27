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

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

// CallContextFunc derives the context a go-qrdb call runs on from the caller's.
type CallContextFunc func(context.Context) (context.Context, error)

// newRefreshStore builds the qrdb refresh store, its KV calls bound by bind on the system tenant; nil bind keeps the caller's context.
func newRefreshStore(kv qrdbtransport.KVClient, bind CallContextFunc) (*token.QRDBRefreshStore, error) {
	if bind == nil {
		return token.NewQRDBRefreshStore(kv)
	}
	return token.NewQRDBRefreshStore(kv, token.WithCallContext(token.CallContext(bind)))
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
