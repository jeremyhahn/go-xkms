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

package client

import (
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmsauth "github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Option configures a TrustedCA instance.
type Option func(*TrustedCA) error

// WithQRDB sets the QRDB service for storage operations.
// This is required for multi-tenant mode.
func WithQRDB(svc qrdb.Service) Option {
	return func(tca *TrustedCA) error {
		tca.qrdbService = svc
		return nil
	}
}

// WithAuthClient sets the authentication client for token validation.
// Required for multi-tenant mode with JWT authentication.
func WithAuthClient(client auth.Client) Option {
	return func(tca *TrustedCA) error {
		tca.authClient = client
		return nil
	}
}

// WithAuthorizer sets the qrdb-backed authorizer the admin API authorizes
// through. It is the same *auth.Authorizer the xkms REST/gRPC/QUIC/MCP
// transports use, so a role grant means the same thing on every surface.
// Leaving it unset disables authorization (RBAC-disabled deployments) but never
// disables authentication.
func WithAuthorizer(authorizer *xkmsauth.Authorizer) Option {
	return func(tca *TrustedCA) error {
		tca.authorizer = authorizer
		return nil
	}
}

// WithCA sets the Certificate Authority.
func WithCA(ca ca.TCGCA) Option {
	return func(tca *TrustedCA) error {
		tca.ca = ca
		return nil
	}
}

// WithStorageFactory sets the ACME storage factory.
func WithStorageFactory(factory storage.Factory) Option {
	return func(tca *TrustedCA) error {
		tca.storageFactory = factory
		return nil
	}
}

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(tca *TrustedCA) error {
		tca.logger = logger
		return nil
	}
}

// WithVersion sets the version string.
func WithVersion(version string) Option {
	return func(tca *TrustedCA) error {
		tca.version = version
		return nil
	}
}

// WithMultiTenant enables multi-tenant mode.
// This requires a QRDB instance to be configured.
func WithMultiTenant() Option {
	return func(tca *TrustedCA) error {
		tca.multiTenant = true
		return nil
	}
}

// WithListenAddr sets the HTTP server listen address.
func WithListenAddr(addr string) Option {
	return func(tca *TrustedCA) error {
		tca.listenAddr = addr
		return nil
	}
}

// WithAdminListenAddr sets the admin HTTP server listen address.
func WithAdminListenAddr(addr string) Option {
	return func(tca *TrustedCA) error {
		tca.adminListenAddr = addr
		return nil
	}
}

// WithConfig sets the configuration.
func WithConfig(cfg *TrustedCAConfig) Option {
	return func(tca *TrustedCA) error {
		tca.config = cfg
		return nil
	}
}

// WithKMSService sets an explicit KMS service for tenant-scoped key management.
func WithKMSService(kms kms.KMSService) Option {
	return func(tca *TrustedCA) error {
		tca.kmsService = kms
		return nil
	}
}

// WithChallengeMap sets the ACME challenge validators.
// Each entry maps a challenge type (e.g., "http-01", "dns-01") to its verifier function.
func WithChallengeMap(challengeMap map[string]acmecommon.ChallengeVerifierFunc) Option {
	return func(tca *TrustedCA) error {
		tca.challengeMap = challengeMap
		return nil
	}
}

// WithExternalURL sets the external URL for the ACME server.
// This is the URL that clients will use to access the ACME server.
func WithExternalURL(url string) Option {
	return func(tca *TrustedCA) error {
		tca.externalURL = url
		return nil
	}
}

// WithRateLimit sets the rate limiting configuration.
// maxRequests is the maximum number of requests per interval per client.
// interval is the time window for rate limiting.
func WithRateLimit(maxRequests int, interval time.Duration) Option {
	return func(tca *TrustedCA) error {
		tca.rateLimitRequests = maxRequests
		tca.rateLimitInterval = interval
		return nil
	}
}
