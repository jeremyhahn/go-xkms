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

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	xkmsauth "github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Option configures a TrustedCA instance.
type Option func(*TrustedCA) error

// WithQRDB sets the go-qrdb client -- typically a datastore's Client() --
// the tenant-aware admin service delegates tenant roles, users, and CA
// records to. This is required for multi-tenant mode.
func WithQRDB(client admin.QRDBClient) Option {
	return func(tca *TrustedCA) error {
		tca.qrdbClient = client
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

// WithMultiTenant enables multi-tenant mode. This requires a go-qrdb client
// to be configured with WithQRDB; New returns ErrMissingQRDB otherwise. It
// is the only switch for multi-tenancy on a standalone TrustedCA -- there is
// no config-file equivalent, matching xkmsd's embedded ACME server, which
// always constructs its admin service tenant-aware and has no
// pkg/config.ACMEConfig multi-tenant key (go-xkms#946).
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

// WithAttestingVerifiers sets the verifiers for the attestation challenges
// (enroll-01, endorse-01, device-attest-01). Each reports the identity the
// device attested, which the server requires to match the order's identifier
// (go-xkms#828); an attestation challenge with no entry is refused, so a
// verifier registered only through WithChallengeMap never authorizes one.
func WithAttestingVerifiers(verifiers map[string]acmecommon.AttestingVerifier) Option {
	return func(tca *TrustedCA) error {
		tca.attesting = verifiers
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

// WithTenantRateLimit sets the per-tenant overall admission-control quota
// (#886), shared across every account belonging to the same tenant, applied
// on top of (never instead of) WithRateLimit's per-client limiter. It is
// only meaningful in multi-tenant mode (WithMultiTenant); Serve mounts it
// only when maxRequests > 0, so leaving it unset keeps today's behavior (no
// per-tenant quota) instead of silently picking a default.
func WithTenantRateLimit(maxRequests int, interval time.Duration) Option {
	return func(tca *TrustedCA) error {
		tca.tenantRateLimitRequests = maxRequests
		tca.tenantRateLimitInterval = interval
		return nil
	}
}
