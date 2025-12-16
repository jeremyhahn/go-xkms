// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
)

// UserChecker checks whether users exist in the system.
type UserChecker interface {
	HasAnyUsers(ctx context.Context) (bool, error)
}

// AdaptiveAuthenticator automatically switches between NoOp and required
// authentication based on whether users exist in the system.
//
// When no users exist (bootstrap mode), all requests are allowed.
// When users exist, authentication is required via the configured authenticator.
type AdaptiveAuthenticator struct {
	// userChecker checks for existing users
	userChecker UserChecker
	// requiredAuth is the authenticator to use when users exist
	requiredAuth Authenticator
	// noopAuth is the authenticator to use when no users exist
	noopAuth Authenticator
	// logger for logging auth mode changes
	logger *slog.Logger

	// cacheExpiry controls how often to refresh the user check
	cacheExpiry time.Duration
	// lastCheck is the time of the last user check
	lastCheck time.Time
	// hasUsers is the cached result of the user check
	hasUsers bool
	// cacheMu protects the cache
	cacheMu sync.RWMutex
}

// AdaptiveConfig configures the adaptive authenticator.
type AdaptiveConfig struct {
	// UserChecker checks for existing users (required)
	UserChecker UserChecker
	// RequiredAuthenticator is used when users exist (required)
	RequiredAuthenticator Authenticator
	// CacheExpiry controls how often to refresh the user check (default: 30s)
	CacheExpiry time.Duration
	// Logger for logging (optional)
	Logger *slog.Logger
}

// NewAdaptiveAuthenticator creates a new adaptive authenticator.
func NewAdaptiveAuthenticator(config *AdaptiveConfig) (*AdaptiveAuthenticator, error) {
	if config == nil {
		return nil, errConfigRequired
	}
	if config.UserChecker == nil {
		return nil, errUserCheckerRequired
	}
	if config.RequiredAuthenticator == nil {
		return nil, errAuthenticatorRequired
	}

	cacheExpiry := config.CacheExpiry
	if cacheExpiry == 0 {
		cacheExpiry = 30 * time.Second
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &AdaptiveAuthenticator{
		userChecker:  config.UserChecker,
		requiredAuth: config.RequiredAuthenticator,
		noopAuth:     NewNoOpAuthenticator(),
		logger:       logger,
		cacheExpiry:  cacheExpiry,
	}, nil
}

// AuthenticateHTTP authenticates an HTTP request.
// When no users exist, returns an anonymous identity.
// When users exist, delegates to the required authenticator.
func (a *AdaptiveAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	if a.shouldRequireAuth(r.Context()) {
		return a.requiredAuth.AuthenticateHTTP(r)
	}
	return a.noopAuth.AuthenticateHTTP(r)
}

// AuthenticateGRPC authenticates a gRPC request.
// When no users exist, returns an anonymous identity.
// When users exist, delegates to the required authenticator.
func (a *AdaptiveAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	if a.shouldRequireAuth(ctx) {
		return a.requiredAuth.AuthenticateGRPC(ctx, md)
	}
	return a.noopAuth.AuthenticateGRPC(ctx, md)
}

// Name returns the authenticator name.
func (a *AdaptiveAuthenticator) Name() string {
	if a.shouldRequireAuth(context.Background()) {
		return "adaptive:" + a.requiredAuth.Name()
	}
	return "adaptive:noop"
}

// shouldRequireAuth checks if authentication should be required.
func (a *AdaptiveAuthenticator) shouldRequireAuth(ctx context.Context) bool {
	// Check cache
	a.cacheMu.RLock()
	if time.Since(a.lastCheck) < a.cacheExpiry {
		hasUsers := a.hasUsers
		a.cacheMu.RUnlock()
		return hasUsers
	}
	a.cacheMu.RUnlock()

	// Cache expired, refresh
	return a.refreshUserCheck(ctx)
}

// refreshUserCheck refreshes the cached user check.
func (a *AdaptiveAuthenticator) refreshUserCheck(ctx context.Context) bool {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	// Double-check in case another goroutine refreshed
	if time.Since(a.lastCheck) < a.cacheExpiry {
		return a.hasUsers
	}

	hasUsers, err := a.userChecker.HasAnyUsers(ctx)
	if err != nil {
		// On error, keep using cached value or default to requiring auth
		a.logger.Warn("failed to check user status, using cached value",
			"error", err,
			"cached_has_users", a.hasUsers)
		return a.hasUsers
	}

	// Log mode change
	if hasUsers != a.hasUsers {
		if hasUsers {
			a.logger.Info("users detected, switching to required authentication",
				"authenticator", a.requiredAuth.Name())
		} else {
			a.logger.Info("no users detected, switching to bootstrap mode (no auth required)")
		}
	}

	a.hasUsers = hasUsers
	a.lastCheck = time.Now()
	return hasUsers
}

// RequiresAuth returns whether authentication is currently required.
func (a *AdaptiveAuthenticator) RequiresAuth() bool {
	return a.shouldRequireAuth(context.Background())
}

// CurrentAuthenticator returns the currently active authenticator.
func (a *AdaptiveAuthenticator) CurrentAuthenticator() Authenticator {
	if a.shouldRequireAuth(context.Background()) {
		return a.requiredAuth
	}
	return a.noopAuth
}

// ForceRefresh forces a refresh of the user check cache.
func (a *AdaptiveAuthenticator) ForceRefresh(ctx context.Context) {
	a.cacheMu.Lock()
	a.lastCheck = time.Time{} // Reset last check time
	a.cacheMu.Unlock()
	a.refreshUserCheck(ctx)
}

// Error variables
var (
	errConfigRequired        = newAuthError("config is required")
	errUserCheckerRequired   = newAuthError("user checker is required")
	errAuthenticatorRequired = newAuthError("required authenticator is required")
)

func newAuthError(msg string) error {
	return &authError{msg: msg}
}

type authError struct {
	msg string
}

func (e *authError) Error() string {
	return e.msg
}
