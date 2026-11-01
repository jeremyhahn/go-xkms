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

package server

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleServerConfigs lists every shipped daemon configuration example,
// relative to the repository root. Client configuration (configs/xkms-client.yaml)
// is a different schema and is deliberately absent.
var exampleServerConfigs = []string{
	"examples/config.example.yaml",
	"examples/config/config-default.yaml",
	"examples/config/config-grpc.yaml",
	"examples/config/config-mcp.yaml",
	"examples/config/config-quic.yaml",
	"examples/config/config-rest.yaml",
	"examples/config/config-server.yaml",
	"configs/xkmsd.yaml",
	"configs/xkmsd.yaml.example",
	"configs/xkmsd-dev.yaml",
	"configs/xkmsd-local.yaml",
	"configs/xkmsd-integration.yaml",
}

// repoPath resolves a repository-root-relative path for tests running in
// pkg/server.
func repoPath(rel string) string {
	return filepath.Join("..", "..", rel)
}

// TestExampleConfigs_ProduceValidAuthenticator loads every shipped daemon
// configuration example and runs the same fail-closed authentication setup the
// daemon runs at startup. An example that names an auth type without the
// configuration that type requires (mtls without TLS, composite without
// methods, a declared-but-empty auth.jwt) aborts startup, so shipping one is a
// broken example rather than a documentation detail.
//
// Placeholder key paths in the examples are replaced with a real generated key
// so the test checks the wiring, not the operator's filesystem.
func TestExampleConfigs_ProduceValidAuthenticator(t *testing.T) {
	for _, rel := range exampleServerConfigs {
		t.Run(rel, func(t *testing.T) {
			cfg, err := config.Load(repoPath(rel))
			require.NoError(t, err, "example configuration must load and validate")

			// Examples reference placeholder key material that does not exist
			// on disk. Substitute a real key so authenticator construction
			// exercises the configured wiring.
			if cfg.Auth.JWT != nil && cfg.Auth.JWT.PublicKeyFile != "" {
				cfg.Auth.JWT.PublicKeyFile = writeTestJWTPublicKey(t)
			}

			s := &Server{
				config: cfg,
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			// A jwt/composite example is not required to carry a JWT key file:
			// server.New provisions a signing key in the default backend and
			// createJWTAuthenticator verifies against that issuer's public key.
			// This test builds the Server directly, so stand the issuer in
			// explicitly — otherwise it would assert a requirement production
			// does not have.
			authTypeForIssuer := strings.ToLower(strings.TrimSpace(cfg.Auth.Type))
			needsIssuer := cfg.Auth.Enabled &&
				(authTypeForIssuer == "jwt" || authTypeForIssuer == "composite") &&
				(cfg.Auth.JWT == nil || cfg.Auth.JWT.PublicKeyFile == "")
			if needsIssuer {
				s.tokenIssuer = newTestTokenIssuer(t)
			}

			require.NoError(t, s.initializeAuthentication(),
				"example configuration must produce an authenticator")
			require.NotNil(t, s.authenticator)
			assert.NotEqual(t, "noop", s.authenticator.Name(),
				"an example must never resolve to the no-op authenticator")
		})
	}
}

// TestExampleConfigs_SecretsResolve runs every shipped config through the
// server's own config secret resolution (resolveConfigSecrets, the step
// server.New takes before it starts the backends). A literal in a protected
// target such as backends.pkcs11.pin is refused there by design (go-xkms#654),
// so a shipped config carrying one can load and validate and still never
// start a daemon: that is how the compose xkms-server the PKCS#11 module suites
// dial stopped coming up (DS-3769).
func TestExampleConfigs_SecretsResolve(t *testing.T) {
	for _, rel := range exampleServerConfigs {
		t.Run(rel, func(t *testing.T) {
			cfg, err := config.Load(repoPath(rel))
			require.NoError(t, err, "example configuration must load and validate")

			s := &Server{ctx: t.Context(), config: cfg}
			require.NoError(t, s.resolveConfigSecrets(),
				"every secret-bearing field must be unset or a resolvable reference")
		})
	}
}

// TestExampleConfigs_AuthCompanionConfigPresent asserts the companion
// configuration each auth type requires is actually present in the example
// files, independent of the substitution the test above performs. This is what
// catches an example that would fail at startup with a missing JWT key.
func TestExampleConfigs_AuthCompanionConfigPresent(t *testing.T) {
	for _, rel := range exampleServerConfigs {
		t.Run(rel, func(t *testing.T) {
			cfg, err := config.Load(repoPath(rel))
			require.NoError(t, err)

			if !cfg.Auth.Enabled {
				return
			}

			switch strings.ToLower(strings.TrimSpace(cfg.Auth.Type)) {
			case "jwt", "adaptive":
				// An auth.jwt section is optional: the daemon provisions its
				// own session-signing key and verifies bearer tokens against
				// it, so an example that omits the section still starts. What
				// must not happen is a *declared but empty* key file, which
				// reads as "verify against this operator-supplied key" while
				// naming no key.
				if cfg.Auth.JWT != nil {
					assert.NotEmpty(t, cfg.Auth.JWT.PublicKeyFile,
						"auth.jwt is declared for auth.type %q, so it must name a public_key_file "+
							"(omit the section entirely to use the daemon's own signing key)", cfg.Auth.Type)
				}
			case "mtls":
				assert.True(t, cfg.TLS.Enabled,
					"auth.type mtls requires tls.enabled: true")
			case "composite":
				// composite derives the jwt+mtls session-vehicle chain when
				// no explicit methods are configured, so an absent or empty
				// auth.composite section is valid.
				_ = cfg.Auth.Composite
			}
		})
	}
}

// newTestTokenIssuer builds a token issuer over a throwaway software key, so a
// test that constructs a Server directly can stand in for what server.New
// provisions from the default backend.
func newTestTokenIssuer(t *testing.T) *token.Issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, err := token.NewIssuer(&token.Config{
		Signer: key,
		KeyAttributes: &types.KeyAttributes{
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               stdcrypto.SHA256,
		},
		RefreshStore: token.NewMemoryRefreshStore(),
	})
	require.NoError(t, err)
	return issuer
}
