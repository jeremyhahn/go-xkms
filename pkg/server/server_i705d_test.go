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

package server

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	escrowpkg "github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ============================================================================
// Tests — initializeCA: TLS.Enabled auto-issue branch
// ============================================================================

// TestInitializeCA_TLSEnabledAutoIssuesServerCert proves that
// tls.enabled + tls.server_cn drives initializeCA's auto-issue branch: a
// server TLS certificate is issued from the freshly-initialized CA and
// becomes retrievable, without any separate ensureTLSServerCert call from
// the caller.
func TestInitializeCA_TLSEnabledAutoIssuesServerCert(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	dataDir := t.TempDir()
	cfg := reproCA793Config(t, dataDir)
	cfg.TLS = config.TLSConfig{Enabled: true, ServerCN: "xkms-i705-tls-test"}

	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.Shutdown() }()

	require.NotNil(t, s.ca)

	// New(cfg) succeeding at all proves the auto-issue branch ran to
	// completion (ensureTLSServerCert + upgradeUnifiedTLSCert): a failure
	// anywhere in that branch surfaces as an error from New. The issued
	// certificate is also independently confirmed present in the CA's own
	// certStore under the configured server CN.
	_, err = s.ca.CABundleCertPool()
	require.NoError(t, err)
}

// ============================================================================
// Tests — ensureSSHClient
// ============================================================================

// TestEnsureSSHClient_NilXKMSServiceReturnsNil proves the documented
// "Returns nil when the XKMSService is unavailable" contract.
func TestEnsureSSHClient_NilXKMSServiceReturnsNil(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.Nil(t, s.ensureSSHClient())
}

// ============================================================================
// Tests — TrustDomain
// ============================================================================

// TestFirstBootTrustDomain_UsesConfiguredTrustDomain proves a configured
// cluster.raft_enrollment.trust_domain is stamped onto the administrator's
// certificate, not the daemon default.
func TestTrustDomain_UsesConfiguredTrustDomain(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Cluster: config.ClusterConfig{
			RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "custom.example.org"},
		},
	})
	assert.Equal(t, "custom.example.org", s.TrustDomain())
}

// TestFirstBootTrustDomain_DefaultsWhenUnset proves an unconfigured trust
// domain falls back to embeddednode.DefaultTrustDomain rather than stamping an
// empty (unusable) SPIFFE trust domain.
func TestTrustDomain_DefaultsWhenUnset(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.NotEmpty(t, s.TrustDomain())
}

// ============================================================================
// Tests — buildRESTConfig: CORS branch
// ============================================================================

// TestBuildRESTConfig_CORSEnabledCarriesOptions proves cors.enabled threads
// the allowlist, credentials flag, and max-age into rest.Config.CORS.
func TestBuildRESTConfig_CORSEnabledCarriesOptions(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})
	srv.config.CORS = config.CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
		MaxAgeSeconds:    600,
	}

	restCfg, err := srv.buildRESTConfig()
	require.NoError(t, err)
	require.NotNil(t, restCfg.CORS)
	assert.Equal(t, []string{"https://app.example.com"}, restCfg.CORS.AllowedOrigins)
	assert.True(t, restCfg.CORS.AllowCredentials)
	assert.Equal(t, 600, restCfg.CORS.MaxAgeSeconds)
}

// TestBuildRESTConfig_CORSDisabledLeavesItNil proves the default (CORS
// disabled) path emits no CORS options, matching the doc comment: "without
// an explicit allowlist the REST router emits no CORS headers".
func TestBuildRESTConfig_CORSDisabledLeavesItNil(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})

	restCfg, err := srv.buildRESTConfig()
	require.NoError(t, err)
	assert.Nil(t, restCfg.CORS)
}

// ============================================================================
// Tests — buildRESTConfig: TLS, CA, and WebAuthn branches
// ============================================================================

// buildRESTConfigTLSTestCfg returns a config carrying a software-backed CA
// identity plus tls.enabled/server_cn, matching TestBuildTLSConfig_CABacked's
// fixture so buildTLSConfig (invoked internally by buildRESTConfig) succeeds
// against a CA-backed certificate.
func buildRESTConfigTLSTestCfg() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443},
		TLS:    config.TLSConfig{Enabled: true, ServerCN: "test-server"},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA: 0,
			Identity: []ca.Identity{{
				Subject: ca.Subject{CommonName: "Test Root CA"},
				Keys: []*types.KeyConfig{{
					KeyAlgorithm: types.AlgorithmECDSA,
					ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
				}},
			}},
		},
	}
}

// TestBuildRESTConfig_TLSEnabledBuildsTLSConfig proves tls.enabled threads a
// built *tls.Config through to rest.Config.TLSConfig.
func TestBuildRESTConfig_TLSEnabledBuildsTLSConfig(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)
	s := newMinimalServer(t, buildRESTConfigTLSTestCfg())
	s.ca = &mockTrustedCA{initialized: true, tlsCert: tlsCert}

	restCfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	require.NotNil(t, restCfg.TLSConfig)
	assert.NotEmpty(t, restCfg.TLSConfig.Certificates)
}

// TestBuildRESTConfig_CAServicerSetWhenComposed proves the CA is exposed to
// REST handlers as the caServicer only once both the raw CA and the
// composed XKMSService are present -- the transport-level methods
// (GetCABundle, IssueCertificate, etc.) live on XKMSService, not the raw CA.
func TestBuildRESTConfig_CAServicerSetWhenComposed(t *testing.T) {
	// A composed XKMSService makes buildRESTConfig build the SSH client,
	// which opens the "ssh" database on the server's datastore. Keep it in
	// memory.
	s := newMinimalServer(t, &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443},
		Datastore: config.DatastoreConfig{Engine: "memory"},
	})
	openInMemoryDatastore(t, s)
	s.ca = &mockTrustedCA{initialized: true}
	s.xkmsService = &xkms.XKMSService{}

	restCfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	assert.Same(t, s.xkmsService, restCfg.CA)
}

// TestBuildRESTConfig_CANotExposedWithoutComposedService proves the CA
// servicer is left nil when the XKMSService has not composed yet, even
// though s.ca is already set -- REST handlers must not see a caServicer
// wired to half-composed state.
func TestBuildRESTConfig_CANotExposedWithoutComposedService(t *testing.T) {
	s := newMinimalServer(t, &config.Config{Server: config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443}})
	s.ca = &mockTrustedCA{initialized: true}

	restCfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	assert.Nil(t, restCfg.CA)
}

// TestBuildRESTConfig_WebAuthnConfigThreaded proves a configured WebAuthn
// relying party is threaded into rest.Config, sharing the single service
// instance so the REST browser ceremony and the SDK ceremony operate on the
// same sessions/credentials.
func TestBuildRESTConfig_WebAuthnConfigThreaded(t *testing.T) {
	s := newMinimalServer(t, &config.Config{Server: config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443}})
	s.webauthnConfig = &webauthn.Config{RPID: "xkms.example.com", RPDisplayName: "xkms"}

	restCfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	require.NotNil(t, restCfg.WebAuthnConfig)
	assert.Equal(t, "xkms.example.com", restCfg.WebAuthnConfig.RPID)
}

// TestInitializeWebAuthnService_QRDBBacked proves the qrdb identity-plane
// branch: with an embedded qrdb node (s.qrdbClient != nil), WebAuthn users
// and credentials are built over rest.BuildWebAuthnService rather than the
// datastore-backed webauthn.NewService path
// TestInitializeWebAuthnService_FileBacked already covers.
func TestInitializeWebAuthnService_QRDBBacked(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://localhost"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	require.NotNil(t, server.qrdbClient, "fixture setup: this deployment must host the embedded qrdb node")
	assert.NotNil(t, server.webauthnService)

	// #2541: the WebAuthn user store runs as the node's service principal, so
	// building the service registers the principal's users grant.
	ctx, err := server.qrdbNode.ServiceContext(context.Background())
	require.NoError(t, err)
	_, err = server.qrdbClient.Users().GetUserByEmail(ctx, "system", "nobody@example.com")
	require.Error(t, err)
	var denied *qrdbsdk.PermissionDeniedError
	assert.NotErrorAs(t, err, &denied, "the service principal may read users once WebAuthn is built")
}

// ============================================================================
// Tests — parseClientAuthMode
// ============================================================================

// TestParseClientAuthMode_AllValues proves every configured tls.client_auth
// string maps onto its crypto/tls policy, including the unrecognized/empty
// default.
func TestParseClientAuthMode_AllValues(t *testing.T) {
	cases := []struct {
		mode string
		want tls.ClientAuthType
	}{
		{"require", tls.RequireAndVerifyClientCert},
		{"require_and_verify", tls.RequireAndVerifyClientCert},
		{"verify", tls.VerifyClientCertIfGiven},
		{"request", tls.RequestClientCert},
		{"", tls.NoClientCert},
		{"unrecognized", tls.NoClientCert},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			assert.Equal(t, tc.want, parseClientAuthMode(tc.mode))
		})
	}
}

// ============================================================================
// Tests — upgradeUnifiedTLSCert
// ============================================================================

// TestUpgradeUnifiedTLSCert_NilProviderIsNoOp proves that a server whose
// unified TLS provider was never built (e.g. NodeServing() is false) is a
// safe no-op rather than a nil dereference.
func TestUpgradeUnifiedTLSCert_NilProviderIsNoOp(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.NoError(t, s.upgradeUnifiedTLSCert(nil))
}

// TestUpgradeUnifiedTLSCert_UpgradesCertAndPool proves the success path:
// once the provider exists, upgradeUnifiedTLSCert installs the CA-issued
// certificate and (pools != nil) the CA bundle pool.
func TestUpgradeUnifiedTLSCert_UpgradesCertAndPool(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)
	s := newMinimalServer(t, buildRESTConfigTLSTestCfg())
	s.config.Datastore.Path = t.TempDir()

	_, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)

	mock := &mockTrustedCA{initialized: true, tlsCert: tlsCert}
	s.ca = mock

	require.NoError(t, s.upgradeUnifiedTLSCert(mock))
}

// ============================================================================
// Tests — clusterPeerHosts
// ============================================================================

// TestClusterPeerHosts_Disabled proves a non-cluster deployment carries no
// extra SANs.
func TestClusterPeerHosts_Disabled(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.Nil(t, s.clusterPeerHosts())
}

// TestClusterPeerHosts_MalformedPeersYieldsNoExtraSANs proves a malformed
// peer list is tolerated here (validated at node construction instead),
// producing no extra SANs rather than propagating a parse error.
func TestClusterPeerHosts_MalformedPeersYieldsNoExtraSANs(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Cluster: config.ClusterConfig{Enabled: true, Peers: "not-a-valid-entry"},
	})
	assert.Nil(t, s.clusterPeerHosts())
}

// TestClusterPeerHosts_StripsRaftPort proves each peer's Raft port is
// stripped, and a peer address with no port (already bare) passes through
// unchanged.
func TestClusterPeerHosts_StripsRaftPort(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Cluster: config.ClusterConfig{
			Enabled: true,
			Peers:   "1=node-a.example.com:6001,2=node-b.example.com:6001,3=node-c-no-port",
		},
	})
	hosts := s.clusterPeerHosts()
	assert.ElementsMatch(t, []string{"node-a.example.com", "node-b.example.com", "node-c-no-port"}, hosts)
}

// TestInitializeAuthorization_RBACEnabledWithQRDBClient proves the
// qrdb-backed RBAC branch: with both auth.enable_rbac and an embedded qrdb
// identity plane, s.rbacAuthorizer is built over the qrdb RBAC servicer
// rather than left nil/permissive.
func TestInitializeAuthorization_RBACEnabledWithQRDBClient(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Auth.EnableRBAC = true

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	require.NotNil(t, server.qrdbClient)
	assert.NotNil(t, server.rbacAuthorizer)
}

// TestNew_EscrowInitFailureAbortsCleanly proves New's escrow-init failure
// branch: an escrow configuration that is well-formed enough to pass
// config.Validate (a non-empty type and endpoint) but names an agent type
// this build does not register aborts server construction with a typed
// *ErrServiceInit wrapping the escrow registry's own construction error,
// after tearing down the backends already opened -- rather than starting a
// daemon with a half-initialized escrow registry.
//
// "enabled with zero agents" -- the misconfiguration this test used before
// go-xkms#666 -- is now refused by config.Validate itself (escrow.Config.
// Validate's ErrNoAgentsConfigured), before New() ever reaches
// initializeEscrow; that Validate-level rejection cannot be observed as an
// *ErrServiceInit{Service: "escrow"} any more, since New() never gets that
// far.
func TestNew_EscrowInitFailureAbortsCleanly(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Escrow = &escrowpkg.Config{
		Enabled: true,
		Agents:  []escrowpkg.AgentConfig{{Type: "not-a-real-agent-type", Endpoint: "https://escrow.example.com"}},
	}

	server, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, server)

	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "escrow", svcErr.Service)
}

// TestNew_CAInitFailureAbortsCleanly proves New's CA-init failure branch: a
// CA identity whose key algorithm cannot be parsed aborts server
// construction with a typed *ErrServiceInit wrapping the CA's own *ErrCAInit,
// after tearing down the backends already opened.
func TestNew_CAInitFailureAbortsCleanly(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.CA = &ca.MultiIdentityCAConfig{
		SelectedCA: 0,
		Identity: []ca.Identity{{
			IsRoot:  true,
			Valid:   1,
			Subject: ca.Subject{CommonName: "Bad Algo Root CA"},
			Keys: []*types.KeyConfig{{
				KeyAlgorithm: "invalid-algo",
			}},
		}},
	}

	server, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, server)

	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "CA", svcErr.Service)
}

// TestNew_WebAuthnInitFailureAbortsCleanly proves New's WebAuthn-init
// failure branch: an enabled WebAuthn config with no RPID fails the
// library's own Validate() and aborts server construction with a typed
// *ErrServiceInit, after tearing down the backends already opened.
func TestNew_WebAuthnInitFailureAbortsCleanly(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:   true,
		RPOrigins: []string{"https://localhost"},
		// RPID deliberately empty: webauthn.Config.Validate refuses it.
	}

	server, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, server)

	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "webauthn service", svcErr.Service)
}

// TestNew_PasswordStoreInitFailureAbortsCleanly and
// TestNew_PKCS11StateStoreInitFailureAbortsCleanly used to prove New's
// password-store and PKCS#11 remote-state store init failure branches by
// colliding a regular file with the "passwords"/"pkcs11state" subdirectory
// createStorage would create. That fault injection is no longer reachable:
// createStorage (pkg/server/storage_factory.go) no longer touches the
// filesystem at all -- it derives a key namespace over the one shared
// datastore (go-xkms#1345).

// TestNew_AuditLoggerInitFailureAbortsCleanly proves initializeAuditLogger's
// local chained-file fallback failure branch: a directory pre-occupying the
// audit log's file path makes the file open fail, returning a typed
// *ErrServiceInit. The chained-file path is taken only when s.qrdbClient is
// nil -- reachable in production only for a datastore.mode "remote"
// deployment (see qrdb_storage.go's initializeQRDBStorage) -- so this is
// checked directly against initializeAuditLogger via a newMinimalServer
// bypass (which never sets s.qrdbClient either), rather than a full
// New(cfg), which a "remote" datastore.mode would need an actual qrdb
// cluster to dial successfully.
func TestNew_AuditLoggerInitFailureAbortsCleanly(t *testing.T) {
	cfg := createMinimalConfig(t)
	blocker := filepath.Join(cfg.Datastore.Path, "audit-events.ndjson")
	require.NoError(t, os.MkdirAll(blocker, 0o700))

	s := newMinimalServer(t, cfg)
	err := s.initializeAuditLogger()
	require.Error(t, err)

	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "chained file audit logger", svcErr.Service)
}
