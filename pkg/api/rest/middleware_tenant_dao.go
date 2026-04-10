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

package rest

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// tenantDAOFactoryKey is the context key for the TenantDAOFactory.
type tenantDAOFactoryKey struct{}

// WithTenantDAOFactory injects a TenantDAOFactory into the context.
func WithTenantDAOFactory(ctx context.Context, factory *staticpw.TenantDAOFactory) context.Context {
	return context.WithValue(ctx, tenantDAOFactoryKey{}, factory)
}

// GetTenantDAOFactory retrieves the TenantDAOFactory from the context.
// Returns nil if no factory is present.
func GetTenantDAOFactory(ctx context.Context) *staticpw.TenantDAOFactory {
	val := ctx.Value(tenantDAOFactoryKey{})
	if val == nil {
		return nil
	}
	factory, ok := val.(*staticpw.TenantDAOFactory)
	if !ok {
		return nil
	}
	return factory
}

// TenantDAOMiddleware injects the TenantDAOFactory into the request context
// for downstream handlers. This allows handlers to resolve tenant-scoped
// DAO stores using the authenticated identity's TenantID.
//
// The middleware is lightweight: it injects the factory reference, not
// actual DAO stores. Handlers call PasswordStoreForTenant or
// TeamStoreForTenant on demand, avoiding unnecessary store creation.
func TenantDAOMiddleware(factory *staticpw.TenantDAOFactory) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if factory != nil {
				ctx := WithTenantDAOFactory(r.Context(), factory)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ResolvePasswordDAOStore resolves the appropriate password DAOStore from
// the request context. If a TenantDAOFactory is present and the identity
// has a TenantID, a tenant-scoped store is returned. Otherwise, the system
// store is returned. Returns an error if the store cannot be resolved.
func ResolvePasswordDAOStore(r *http.Request) (*staticpw.DAOStore, error) {
	factory := GetTenantDAOFactory(r.Context())
	if factory == nil {
		return nil, ErrServiceUnavailable
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && identity.TenantID != "" {
		return factory.PasswordStoreForTenant(identity.TenantID)
	}
	return factory.SystemPasswordStore()
}

// ResolveTeamDAOStore resolves the appropriate team DAOTeamStore from
// the request context. If a TenantDAOFactory is present and the identity
// has a TenantID, a tenant-scoped store is returned. Otherwise, the system
// store is returned. Returns an error if the store cannot be resolved.
func ResolveTeamDAOStore(r *http.Request) (*staticpw.DAOTeamStore, error) {
	factory := GetTenantDAOFactory(r.Context())
	if factory == nil {
		return nil, ErrServiceUnavailable
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && identity.TenantID != "" {
		return factory.TeamStoreForTenant(identity.TenantID)
	}
	return factory.SystemTeamStore()
}
