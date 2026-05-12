// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
)

// Tenant context key type for type-safe context values
type tenantContextKey struct{}

var (
	// tenantIDKey is the context key for storing tenant ID
	tenantIDKey = tenantContextKey{}

	// ErrTenantNotFound is returned when a tenant cannot be found
	ErrTenantNotFound = errors.New("middleware: tenant not found")

	// ErrTenantInactive is returned when a tenant is not active
	ErrTenantInactive = errors.New("middleware: tenant is not active")

	// ErrTenantRequired is returned when a tenant ID is required but not provided
	ErrTenantRequired = errors.New("middleware: tenant ID is required")
)

// TenantHeader is the HTTP header for specifying tenant ID
const TenantHeader = "X-Tenant-ID"

// TenantExtractor defines how tenant ID is extracted from requests
type TenantExtractor func(r *http.Request) string

// DefaultTenantExtractor extracts tenant ID from X-Tenant-ID header
func DefaultTenantExtractor(r *http.Request) string {
	return r.Header.Get(TenantHeader)
}

// SubdomainTenantExtractor extracts tenant ID from the first subdomain
// e.g., "tenant1.acme.example.com" -> "tenant1"
func SubdomainTenantExtractor(r *http.Request) string {
	host := r.Host
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return parts[0]
	}
	return ""
}

// PathTenantExtractor extracts tenant ID from the URL path
// e.g., "/tenant1/acme/directory" -> "tenant1"
func PathTenantExtractor(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 && parts[0] != "" && parts[0] != "acme" {
		return parts[0]
	}
	return ""
}

// TenantMiddlewareConfig configures the tenant middleware
type TenantMiddlewareConfig struct {
	// StorageFactory is the tenant-aware storage factory
	StorageFactory storage.TenantAwareFactory

	// Logger is the structured logger
	Logger *slog.Logger

	// TenantExtractor is the function to extract tenant ID from requests
	// If nil, uses DefaultTenantExtractor (X-Tenant-ID header)
	TenantExtractor TenantExtractor

	// DefaultTenant is used when no tenant is specified in the request
	// If empty and RequireTenant is true, requests without tenant will be rejected
	DefaultTenant string

	// RequireTenant indicates whether a tenant ID is required for all requests
	// When true, requests without a valid tenant ID will receive a 400 error
	RequireTenant bool

	// ValidateTenant indicates whether to verify the tenant exists and is active
	// When true, unknown or inactive tenants will receive appropriate errors
	ValidateTenant bool
}

// TenantMiddleware adds tenant context to requests.
// It extracts the tenant ID from the request, optionally validates it,
// and adds the tenant-scoped storage factory to the request context.
type TenantMiddleware struct {
	config *TenantMiddlewareConfig
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(config *TenantMiddlewareConfig) *TenantMiddleware {
	if config.TenantExtractor == nil {
		config.TenantExtractor = DefaultTenantExtractor
	}
	return &TenantMiddleware{config: config}
}

// Middleware returns an HTTP middleware handler that adds tenant context
func (m *TenantMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract tenant ID from request
		tenantID := m.config.TenantExtractor(r)

		// Use default tenant if not specified
		if tenantID == "" {
			tenantID = m.config.DefaultTenant
		}

		// Check if tenant is required
		if tenantID == "" && m.config.RequireTenant {
			m.config.Logger.Warn("tenant ID required but not provided",
				slog.String("path", r.URL.Path),
				slog.String("method", r.Method))
			writeError(w, common.Unauthorized("Tenant ID is required"))
			return
		}

		// If no tenant ID and not required, proceed without tenant context
		if tenantID == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validate tenant if configured
		if m.config.ValidateTenant {
			tenantDAO, err := m.config.StorageFactory.TenantDAO()
			if err != nil {
				m.config.Logger.Error("failed to create tenant DAO",
					slog.String("error", err.Error()))
				writeError(w, common.ServerInternal("Failed to validate tenant"))
				return
			}

			tenant, err := tenantDAO.Get(ctx, entities.StringToEntityID(tenantID))
			if err != nil {
				m.config.Logger.Warn("tenant not found",
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()))
				writeError(w, common.Unauthorized("Unknown tenant"))
				return
			}

			if tenant.Status != "active" {
				m.config.Logger.Warn("tenant is not active",
					slog.String("tenant_id", tenantID),
					slog.String("status", tenant.Status))
				writeError(w, common.Unauthorized("Tenant is not active"))
				return
			}
		}

		// Add tenant ID to context
		ctx = context.WithValue(ctx, tenantIDKey, tenantID)

		// Log tenant context
		m.config.Logger.Debug("tenant context set",
			slog.String("tenant_id", tenantID),
			slog.String("path", r.URL.Path))

		// Continue with tenant context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TenantFromContext extracts the tenant ID from the request context
func TenantFromContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(tenantIDKey).(string); ok {
		return tenantID
	}
	return ""
}

// WithTenant adds a tenant ID to the context
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenantScopedFactory returns a tenant-scoped storage factory from the context.
// If the storage factory supports tenant awareness and a tenant ID is in context,
// returns a factory scoped to that tenant. Otherwise returns the original factory.
func GetTenantScopedFactory(ctx context.Context, factory storage.Factory) (storage.Factory, error) {
	tenantID := TenantFromContext(ctx)
	if tenantID == "" {
		return factory, nil
	}

	// Check if factory supports tenant awareness
	tenantAware, ok := factory.(storage.TenantAwareFactory)
	if !ok {
		return factory, nil
	}

	// Return tenant-scoped factory
	return tenantAware.ForTenant(tenantID)
}
