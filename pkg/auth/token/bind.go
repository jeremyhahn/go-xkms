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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// CallContext derives the context a refresh store call runs on from the
// caller's. Over an embedded qrdb node the server passes Node.ServiceContext.
type CallContext func(ctx context.Context) (context.Context, error)

// BindRefreshStore returns a RefreshStore that runs every call of store on
// the context bind derives from the caller's. Refresh-token records are
// xkms's own persistence, as its storage is: a login that mints them is
// often anonymous (a WebAuthn sign-up, #2541), so over an embedded node they
// are written as the node's service principal. A nil bind returns store.
func BindRefreshStore(store RefreshStore, bind CallContext) RefreshStore {
	if bind == nil {
		return store
	}
	return &boundRefreshStore{store: store, bind: bind}
}

// BindUserResolver returns resolver with every lookup run on the context
// bind derives from the caller's. A refresh is a public call (#2541): its
// current-account lookup is xkms's own read of the identity plane, so it
// runs as the bound principal; the account checks themselves stay the
// resolver's. A nil bind returns resolver unchanged.
func BindUserResolver(resolver UserResolver, bind CallContext) UserResolver {
	if bind == nil || resolver == nil {
		return resolver
	}
	return &boundUserResolver{resolver: resolver, bind: bind}
}

// boundUserResolver runs a UserResolver's lookup on a bound context.
type boundUserResolver struct {
	resolver UserResolver
	bind     CallContext
}

// ResolveUser resolves id on the bound context.
func (b *boundUserResolver) ResolveUser(ctx context.Context, id *auth.Identity) (*auth.Identity, error) {
	bound, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.resolver.ResolveUser(bound, id)
}

type boundRefreshStore struct {
	store RefreshStore
	bind  CallContext
}

func (b *boundRefreshStore) Save(ctx context.Context, rec *Record) error {
	bound, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.store.Save(bound, rec)
}

func (b *boundRefreshStore) Get(ctx context.Context, family, jti string) (*Record, error) {
	bound, err := b.bind(ctx)
	if err != nil {
		return nil, err
	}
	return b.store.Get(bound, family, jti)
}

func (b *boundRefreshStore) MarkRotated(ctx context.Context, family, jti string) error {
	bound, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.store.MarkRotated(bound, family, jti)
}

func (b *boundRefreshStore) RevokeFamily(ctx context.Context, family string) error {
	bound, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.store.RevokeFamily(bound, family)
}

func (b *boundRefreshStore) RevokeBySubject(ctx context.Context, subject string) error {
	bound, err := b.bind(ctx)
	if err != nil {
		return err
	}
	return b.store.RevokeBySubject(bound, subject)
}
