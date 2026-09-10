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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	"github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/unix"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/factor"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	pinadapter "github.com/jeremyhahn/go-xkms/pkg/storage/pinadapter"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// webAuthnSystemTenant is the qrdb tenant scope used to persist WebAuthn users
// and credentials when xkms hosts or dials the qrdb engine. WebAuthn identities
// are system-scoped; per-tenant WebAuthn enrollment is handled through the
// tenant barrier subsystem, not through a separate relying party.
const webAuthnSystemTenant = "system"

// noiseBootstrapStopTimeout bounds how long Shutdown waits for the Noise
// bootstrap server to drain. It also decides the fate of the server's
// protected static key: draining inside this window is the only proof its
// handshake workers have exited, and without that proof the key is retained
// rather than freed.
const noiseBootstrapStopTimeout = 10 * time.Second

// noiseStopDrained reports whether stopping the Noise bootstrap server can be
// read as a completed drain — the only state in which the protected pages
// behind its static key are provably unreferenced.
//
// Since go-truststrap v0.3.0-alpha (go-truststrap#13, pinned here at
// v0.4.0-alpha) noiseboot.Server.Stop's nil is authoritative: it is returned
// only after the run's WaitGroup has genuinely emptied, and every other
// outcome is a non-nil sentinel — ErrShutdownIncomplete when the CALLER's
// deadline expires first, ErrServerNotStarted before Start. Concurrent callers
// each wait under their own context and may see different outcomes, but no
// caller ever receives a nil that is not backed by a real drain, and once
// drained every later Stop returns nil stably.
//
// The error is therefore the whole decision. This function used to also
// require the caller's context to be unexpired, because the previous pin
// returned nil on its own timeout path too and the context was the only
// signal that told the two apart. Against the current contract that conjunct
// is not merely redundant, it is wrong in one case: a server that finished
// draining as the deadline expired reports nil — upstream re-checks its
// drained channel before ever saying ErrShutdownIncomplete, precisely so that
// a finished server is not reported as incomplete — and reading the expired
// context over that nil retained a key that was safe to wipe and reported a
// shutdown incomplete that was not (go-xkms#83).
//
// One function rather than the condition written out at each site: the two
// sites that stop this server once reached different answers, which is
// exactly the failure a shared decision prevents.
func noiseStopDrained(stopErr error) bool {
	return stopErr == nil
}

// Server represents the unified xkms server that runs all protocols
type Server struct {
	config       *config.Config
	mu           sync.RWMutex
	backends     map[string]xkms.Backend
	keyProviders map[string]types.KeyProvider
	logger       *slog.Logger

	// sshClient is the shared SSH SDK client wired into every transport. It
	// is built once, lazily, via ensureSSHClient.
	sshClient sdkssh.Client
	sshOnce   sync.Once

	// xkmsService is the composed XKMS service injected into every transport
	// constructor. It is resolved once from the package singleton at the
	// composition root (New) and threaded through dependency injection from
	// there; transports never call xkms.Get() themselves. It is nil when the
	// service has not been initialized, and transports preserve the
	// ErrNotInitialized contract in that case.
	xkmsService *xkms.XKMSService

	// Protocol servers
	unixGRPCServer       *unix.GRPCServer
	restServer           *rest.Server
	moduleREST           *rest.Server
	moduleRESTOnce       sync.Once
	moduleMCP            *mcp.Server
	moduleMCPOnce        sync.Once
	unifiedTLS           *unifiedTLSProvider
	noiseBootstrapServer *noiseboot.Server

	// noiseBootstrapKey is the protected static key the bootstrap server's
	// handshakes read in place. It lives here, alongside the server it
	// belongs to, because noiseboot.Server.Start does NOT block — it launches
	// an accept loop and returns — so the goroutine that called Start cannot
	// know when the last handshake has finished. Only Shutdown can, and only
	// when Stop drains within its deadline.
	noiseBootstrapKey *noiseproto.StaticKey

	// p256BootstrapKey is the same thing for the FIPS-approved suite,
	// TSBOOT1_P256_AESGCM_SHA256, which the same listener serves on the same
	// port -- the suite is chosen per connection from the client's first
	// frame, not per listener. It has the identical lifetime rule as
	// noiseBootstrapKey and is claimed, destroyed and retained beside it.
	//
	// Either key may be nil: a suite whose key is absent is not offered, and
	// a FIPS build has no Noise key at all.
	p256BootstrapKey *bootstrap.P256StaticKey

	// retainedNoiseKeys holds static keys a shutdown could not prove
	// unreferenced. They are never destroyed: the pages stay locked for the
	// life of the process, which is the deliberate trade against freeing
	// memory a live handshake is reading.
	//
	// They are kept REACHABLE rather than simply dropped. memguard already
	// pins every live buffer in a package-level list, so an unreferenced
	// StaticKey is not collectable and its pages cannot be reclaimed — but
	// "we are retaining this" and "we dropped the only pointer to it" should
	// not look identical in the source, and holding the owner is what would
	// let a future reclamation path exist at all.
	retainedNoiseKeys []*noiseproto.StaticKey

	// retainedP256Keys is the same retention set for the approved suite's
	// keys, kept separate only because the two are different types.
	retainedP256Keys []*bootstrap.P256StaticKey

	// shutdownOnce/shutdownErr latch the shutdown outcome: concurrent callers
	// must not both close shutdownCh, and must not reach different
	// conclusions about whether components drained.
	shutdownOnce sync.Once
	shutdownErr  error

	// metricsServer is the Prometheus metrics HTTP server. It is stored here so
	// Shutdown can stop it; otherwise its ListenAndServe blocks forever and the
	// startMetrics goroutine never releases its wg slot.
	metricsServer *http.Server

	// Authentication
	authenticator auth.Authenticator

	// liveAuthenticator is what every transport actually receives. It is an
	// auth.Authenticator that forwards to whichever authenticator is current,
	// so a listener constructed at startup uses the authenticator installed by
	// a later Reload instead of the one it captured. s.authenticator remains
	// the concrete authenticator in force, which is what reload rollback,
	// logging and the nil check read.
	liveAuthenticator *auth.LiveAuthenticator
	webauthnConfig    *webauthn.Config

	// tokenIssuer mints the access/refresh pairs behind the login flows
	// (WebAuthn passkey login, PIV/mTLS cert login) and the /api/v1/auth
	// session endpoints. Nil when no backends are available.
	tokenIssuer *token.Issuer

	// defaultBackendName is the resolved default backend, recorded by
	// initializeKeyStore so later initialization stages use the same
	// resolution instead of re-deriving (or consulting the singleton).
	defaultBackendName string

	// webauthnService is the single WebAuthn relying-party service shared
	// between the REST browser ceremony and the SDK ceremony (via
	// XKMSService.SetWebAuthn). It is non-nil only when WebAuthn is enabled.
	webauthnService *webauthn.Service

	// Authorization. rbacAuthorizer is the single qrdb-backed authorizer that
	// gates every transport (REST, gRPC, QUIC).
	rbacAuthorizer *auth.Authorizer

	// Audit logging
	auditLogger audit.Logger

	// Barrier (seal/unseal)
	barrier *seal.Barrier

	// sealStrategies holds the sealing strategies composed for the system
	// barrier (hardware/cloud strategies from the preference order plus the
	// software baseline). They are captured at barrier init so the barrier
	// registry can build a hardware-backed StrategyRegistry from the same
	// instances for per-tenant barrier sealing.
	sealStrategies []seal.SealingStrategy

	// Barrier registry (multi-tenant)
	barrierRegistry *seal.BarrierRegistry

	// nodeSealEnabled indicates the qrdb node's OWN barrier is used (the flip):
	// Storage.Backend=="qrdb" && Barrier.Enabled && auto-unseal creds present.
	// When true, the node encrypts its data-plane KV (encfs), auto-unseals at
	// construction, and s.barrier/s.barrierRegistry/s.tenantService come from
	// the node — xkms's own barrier/registry construction is skipped. When
	// false, everything behaves exactly as before (xkms's own barrier).
	nodeSealEnabled bool

	// nodeSealStrategy is the resolved hardware SealingStrategy fed to the node
	// barrier (nil for passphrase mode).
	nodeSealStrategy seal.SealingStrategy

	// nodeSealTPM is the single open TPM backend produced by the seal autodetect;
	// it is reused by the general tpm2 backend to avoid a second TPM open (a
	// swtpm emulator hangs on reopen). nil when no TPM strategy is resolved.
	nodeSealTPM types.Sealer

	// nodeSealClose releases the autodetect TPM open; deferred to node shutdown
	// since the same open backs both the seal strategy and the tpm2 backend.
	nodeSealClose func() error

	// nodeSealPassphrase is the resolved boot-time unseal passphrase (empty for
	// hardware/TPM mode).
	nodeSealPassphrase []byte

	// clusterCAKeyStrategy is the cluster CA key custody strategy (barrier / hsm
	// / tpm-kek) built during cluster ACME provisioning. It is stateful (the
	// barrier strategy retains its bootstrap key-storage handle for promotion),
	// so the SAME instance is used for the pre-node BootstrapBackends and the
	// post-node RuntimeBackend that initializeCA signs from. nil except when
	// cluster ACME enrollment provisioned the cluster mTLS.
	clusterCAKeyStrategy clustercapkg.ClusterCAKeyStrategy

	// volumePool backs dedicated-isolation (barrier/volume/raft) tenants with
	// per-tenant Pebble storage drawn from the configured pool. It is nil when
	// no volume pools are declared, in which case dedicated-isolation tenant
	// registration falls back to the system store. The server owns its
	// lifecycle and closes it during Shutdown.
	volumePool *seal.VolumePoolSubsystem

	// tenantService is go-qrdb's canonical TenantService composed on top of the
	// barrier registry with xkms hardware seal strategies injected. It owns the
	// entitlement-gated isolation modes, system-managed auto-unseal, quotas, and
	// volume/raft tenant lifecycle; the xkms tenant servicer delegates to it.
	tenantService qrdbsdk.ServiceTenantServicer

	// PIN backend
	pinManager qrdbsdk.PINBackend

	// Password store
	passwordStore *staticpw.BackendStore

	// PKCS#11 remote-state store — persists a remote-mode PKCS#11 module's token
	// and object state in the embedded qrdb node. Nil unless enabled.
	pkcs11StateStore *pkcs11state.Store

	// Platform store
	platformStore seal.PlatformStore

	// Policy manager
	policyManager *policy.Manager

	// Health checker
	healthChecker *qrdbsdk.HealthChecker

	// Metrics
	metricsCollector *metrics.ResourceCollector

	// CA for certificate authority operations
	ca ca.TrustedCA

	// Credential service for managing backend credentials
	credentialService *credentialspkg.Service

	// Ceremony service for init ceremony
	ceremonyService *initialize.CeremonyService

	// Factor registry for hardware auth factors (PIV, PKCS#11, FIDO2, mTLS)
	factorRegistry *qrdbsdk.AuthFactorRegistry

	// qrdbStorage is the single shared qrdb-backed storage backend used when
	// the configured storage backend is "qrdb". All per-subdir storage views
	// are key-prefixed views over this one backend (see createStorage). It is
	// nil for non-qrdb backends and is the sole owner of the qrdb lifecycle:
	// only the server closes it, during Shutdown.
	qrdbStorage storage.Backend

	// qrdbNode is the in-process qrdb engine that xkms hosts as its single
	// core: storage, barrier, bootstrap, and clustering all come from this
	// node. xkms contributes hardware seal strategies and auth factors on
	// top via the node builder. It is non-nil only for the embedded qrdb
	// transport (standalone/clustered hosting); remote deployments dial an
	// external cluster instead. The server owns its lifecycle and closes it
	// during Shutdown.
	qrdbNode *qrdbnode.Node

	// raftClusterAdvertiser holds the running Noise NK bootstrap advertiser
	// started by the first node of a clustered deployment when Raft mTLS is
	// auto-provisioned (raft builds only), so Shutdown can stop it. It is nil
	// when this node is not the cluster bootstrapper or when clustering/raft is
	// off. The minimal interface avoids importing the qrdb clusterenroll package
	// into non-raft builds.
	raftClusterAdvertiser interface{ Stop() }

	// qrdbClient is the SDK client exposing the node's services (KV, Users,
	// Roles, factors, barrier). For embedded hosting it is node.Client(); for
	// remote deployments it is the dialed cluster client.
	qrdbClient *qrdbsdk.Client

	// qrdbAuditSink is the compliance-grade audit sink supplied to the
	// embedded qrdb node at construction (sdk.WithAuditLogger). It is the
	// HMAC-chained file logger when file audit is configured, otherwise an
	// in-memory ring buffer so audit emission and querying always function.
	// It backs Client().Audit(); the server owns its lifecycle and closes it
	// during Shutdown. It is nil for non-embedded (remote) qrdb deployments.
	qrdbAuditSink qrdbsdk.NodeAuditLogger

	// clusterAdvertiser publishes this node's Raft address and client-facing
	// API endpoints into the cluster registry and keeps the lease alive, so a
	// peer can turn a leader replica ID into a dialable API address. It is nil
	// on a standalone node and on a node with no advertisable host.
	clusterAdvertiser *qrdbsdk.NodeAdvertiser

	// uiAssets is the compiled web UI filesystem (rooted at the vite dist
	// output) served by the REST transport. It is installed by the
	// composition root via SetUIAssets before Start; nil (or a config-level
	// disable) leaves the UI unmounted.
	uiAssets fs.FS

	// authDecorator optionally wraps the built authenticator before it is
	// published (desktop loopback-token composite). Set via
	// WithAuthenticatorDecorator.
	authDecorator func(auth.Authenticator) auth.Authenticator

	// restListener, when non-nil, is handed to the REST transport so it
	// serves a pre-bound listener (loopback launcher: 127.0.0.1:0) instead of
	// binding the configured port. Set via SetRESTListener.
	restListener net.Listener

	// Lifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shutdownCh chan struct{}
}

// SetUIAssets installs the compiled web UI filesystem (rooted at the vite
// dist output) served by the REST transport. Call before Start; a nil
// assets value leaves the UI unmounted.
func (s *Server) SetUIAssets(assets fs.FS) {
	s.uiAssets = assets
}

// SetRESTListener hands the REST transport a pre-bound listener to serve
// instead of binding the configured port. The loopback launcher uses this
// with a 127.0.0.1:0 listener so the embedded desktop engine is off-box
// unreachable. Call before Start.
func (s *Server) SetRESTListener(l net.Listener) {
	s.restListener = l
}

// ensureSSHClient lazily builds the shared SSH SDK client used by every
// transport (REST/gRPC/QUIC/MCP/unix). The client is embedded: SSH metadata
// (public keys + backend references) lives in the "ssh" storage view, and key
// generation/signing is delegated to the server's configured crypto backends
// via a backend provider, so a remote "Backend: tpm2" request mints the key in
// the TPM and the private key never leaves the device. Returns nil when the
// XKMSService is unavailable (SSH routes are then not mounted).
func (s *Server) ensureSSHClient() sdkssh.Client {
	s.sshOnce.Do(func() {
		if s.xkmsService == nil {
			return
		}
		sshStorage, err := s.createStorage("ssh")
		if err != nil {
			s.logger.Error("Failed to create SSH storage", slog.Any("error", err))
			return
		}
		resolver := sshbackend.ResolverFunc(func(_ context.Context, backendID string) (types.KeyProvider, error) {
			b, lerr := s.xkmsService.LookupBackend(backendID)
			if lerr != nil {
				return nil, lerr
			}
			return b.KeyProvider(), nil
		})
		provider, err := sshbackend.New(resolver)
		if err != nil {
			s.logger.Error("Failed to build SSH backend provider", slog.Any("error", err))
			return
		}
		client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: sshStorage, BackendProvider: provider})
		if err != nil {
			s.logger.Error("Failed to build SSH client", slog.Any("error", err))
			return
		}
		s.sshClient = client
		s.logger.Info("SSH subsystem initialized")
	})
	return s.sshClient
}

// New creates a new unified server instance
// Option customizes server construction. Options are additive and applied
// before subsystem initialization; they can only add capabilities (e.g.
// compose an extra authenticator), never bypass the fail-closed defaults.
type Option func(*Server)

// WithAuthenticatorDecorator wraps the configured authenticator once it has
// been built, before it is published to the transports. The decorator
// receives the resolved authenticator and returns the one to use — typically
// a composite that also accepts a loopback per-launch token (desktop
// standalone). It can only add acceptance paths on top of the configured
// chain; it cannot disable the underlying authenticator.
func WithAuthenticatorDecorator(fn func(auth.Authenticator) auth.Authenticator) Option {
	return func(s *Server) { s.authDecorator = fn }
}

func New(cfg *config.Config, opts ...Option) (*Server, error) {
	// Setup logging
	logger := setupLogger(cfg.Logging)

	// Apply the configured weak-hash policy to pkg/types. This is the
	// composition root: pkg/types refuses the collision-broken digests until
	// something applies a configuration, so a deployment that needs SHA-1/MD5
	// for legacy interop or PKCS#11 conformance gets them only by setting
	// crypto.allow_weak_hashes, and a deployment that says nothing keeps the
	// secure default. In FIPS mode SetAllowWeakHashes ignores the request: the
	// approved-algorithm boundary belongs to the validated module, which the Go
	// toolchain selects (GOFIPS140 at build time, GODEBUG=fips140 at run time),
	// and no configuration file can widen it.
	types.SetAllowWeakHashes(cfg.Crypto.AllowWeakHashes)

	// Same shape for the key-wrap constructions that authenticate nothing.
	// pkg/types refuses RSA_PKCS1_V1_5, AES_CBC_PAD and AES_CBC until this
	// applies a configuration, because C_UnwrapKey takes a caller-supplied
	// blob over every transport and each of them turns it into a decryption
	// oracle. FIPS mode ignores the request on the same terms.
	types.SetAllowLegacyKeyWrap(cfg.Crypto.AllowLegacyKeyWrap)

	// Log the resulting posture so which algorithms this process will perform is
	// unambiguous in the operator's logs, and name the digests when the operator
	// has opted into the forgeable ones.
	switch {
	case types.FIPSMode():
		logger.Info("FIPS 140-3 mode active; non-approved algorithms are refused",
			slog.Any("refused_hashes", types.WeakHashNames()),
			slog.Any("refused_key_wrap", types.LegacyKeyWrapNames()))
	case types.AllowWeakHashes():
		logger.Warn("crypto.allow_weak_hashes is enabled; collision-broken digests will be used "+
			"for signing, certificates and attestation. Signatures produced over them are forgeable; "+
			"enable this only for legacy interop or PKCS#11 conformance",
			slog.Any("admitted_hashes", types.WeakHashNames()))
	default:
		logger.Info("collision-broken digests are refused (crypto.allow_weak_hashes=false)",
			slog.Any("refused_hashes", types.WeakHashNames()),
			slog.Bool("legacy_key_wrap_available", types.AllowLegacyKeyWrap()))
	}

	// The unauthenticated key-wrap constructions get their own warning: an
	// operator who enabled them has opened a decryption oracle on C_UnwrapKey,
	// which is a different exposure from a forgeable signature.
	if !types.FIPSMode() && types.AllowLegacyKeyWrap() {
		logger.Warn("crypto.allow_legacy_key_wrap is enabled; C_UnwrapKey accepts a caller-supplied "+
			"blob under these mechanisms, so an unwrap success is not evidence the blob came from "+
			"this service",
			slog.Any("admitted_key_wrap", types.LegacyKeyWrapNames()))
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:       cfg,
		keyProviders: make(map[string]types.KeyProvider),
		backends:     make(map[string]xkms.Backend),
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		shutdownCh:   make(chan struct{}),
	}

	// Apply construction options before any subsystem initializes.
	for _, opt := range opts {
		opt(s)
	}

	// Decide whether the qrdb node's own barrier encrypts the data plane (the
	// flip), and resolve the auto-unseal material — BEFORE the node is built so
	// the seal strategy can be injected as a node option and a single TPM open
	// is shared with the tpm2 backend. A no-op unless Storage.Backend=="qrdb",
	// the barrier is enabled, and auto-unseal credentials are available.
	if err := s.resolveNodeSeal(); err != nil {
		cancel()
		return nil, &ErrServiceInit{Service: "node seal", Err: err}
	}

	// Initialize the shared qrdb storage backend (when configured). This must
	// happen before initializeBackends, because per-subdir storage views are
	// key-prefixed views over this single shared backend.
	if err := s.initializeQRDBStorage(); err != nil {
		cancel()
		return nil, &ErrServiceInit{Service: "qrdb storage", Err: err}
	}

	// Initialize backends
	if err := s.initializeBackends(); err != nil {
		cancel()
		if closeErr := s.closeQRDBStorage(); closeErr != nil {
			s.logger.Error("failed to close qrdb storage during backend init failure", "error", closeErr)
		}
		return nil, &ErrServiceInit{Service: "backends", Err: err}
	}

	// Initialize keystore with default backend
	if err := s.initializeKeyStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "keystore", Err: err}
	}

	// Initialize the session-token issuer (JWT signing key in the default
	// backend + refresh-token store). Must precede authentication so the JWT
	// authenticator can fall back to the issuer's public key, and precede the
	// WebAuthn service so ceremony completion mints real tokens.
	if err := s.initializeTokenIssuer(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "token issuer", Err: err}
	}

	// Initialize authentication
	if err := s.initializeAuthentication(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "authentication", Err: err}
	}

	// Initialize the shared WebAuthn relying-party service (when enabled). This
	// single instance is wired into both the XKMSService (SDK ceremony) and the
	// REST server (browser ceremony) so sessions and credentials live in one
	// place.
	if err := s.initializeWebAuthnService(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "webauthn service", Err: err}
	}

	// Initialize authorization
	if err := s.initializeAuthorization(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "authorization", Err: err}
	}

	// Initialize audit logger
	if err := s.initializeAuditLogger(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "audit logger", Err: err}
	}

	// Initialize barrier (seal/unseal)
	if err := s.initializeBarrier(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "barrier", Err: err}
	}

	// Initialize barrier registry
	if err := s.initializeBarrierRegistry(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "barrier registry", Err: err}
	}

	// Initialize PIN manager
	if err := s.initializePINManager(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "PIN manager", Err: err}
	}

	// Initialize password store
	if err := s.initializePasswordStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "password store", Err: err}
	}

	// Initialize the PKCS#11 remote-state store
	if err := s.initializePKCS11StateStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "pkcs11 state store", Err: err}
	}

	// Initialize platform store
	if err := s.initializePlatformStore(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "platform store", Err: err}
	}

	// Initialize credential service
	if err := s.initializeCredentialService(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "credential service", Err: err}
	}

	// Initialize policy manager
	if err := s.initializePolicyManager(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "policy manager", Err: err}
	}

	// Initialize health checker
	if err := s.initializeHealth(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "health checker", Err: err}
	}

	// Initialize CA from config (optional)
	if err := s.initializeCA(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "CA", Err: err}
	}

	// Initialize hardware auth-factor registry (PIV, PKCS#11, FIDO2, mTLS)
	if err := s.initializeFactorRegistry(); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "factor registry", Err: err}
	}

	// Run qrdb's canonical first-boot: the system tenant, the built-in roles,
	// the administrator and the administrator's certificate, exactly as qrdbd
	// and quicbaasd create them.
	//
	// It runs HERE, after initializeCA, because the administrator's certificate
	// is issued by the CA. Bootstrapping earlier — while the embedded node was
	// being built — created the administrator before any CA existed, leaving an
	// identity with no bound certificate that nobody could authenticate as.
	//
	// It is idempotent, so every start and every node of a cluster runs it, and
	// it is fatal: a daemon whose bootstrap did not happen surfaces later as an
	// unexplained authentication failure rather than as the missing bootstrap.
	if err := s.runFirstBoot(ctx); err != nil {
		cancel()
		s.closeBackends()
		return nil, &ErrServiceInit{Service: "first-boot", Err: err}
	}

	// Wire all subsystems into the XKMSService singleton so it implements
	// the full embedded.XKMSServicer interface for in-process SDK access.
	// The resolved service is also captured on the server so the transport
	// constructors receive it via dependency injection.
	if svc, err := xkms.Get(); err == nil {
		// Published under the lock: with the unified API server enabled the
		// embedded node serves module RPCs concurrently with this
		// composition, and the module resolver reads the reference through
		// xkmsServiceRef.
		s.mu.Lock()
		s.xkmsService = svc
		s.mu.Unlock()
		if s.barrier != nil {
			svc.SetBarrier(s.barrier)
		}
		if s.webauthnService != nil {
			svc.SetWebAuthn(s.webauthnService)
		}
		if s.pinManager != nil {
			svc.SetPINManager(s.pinManager)
		}
		if s.passwordStore != nil {
			if s.qrdbClient != nil {
				svc.SetUserClients(s.qrdbClient.Users(), s.qrdbClient.Roles())
			}
			svc.SetPasswordStore(s.passwordStore)
			// Wire tenant password store manager if barrier registry is available
			if s.barrierRegistry != nil {
				pwManager, pwErr := staticpw.NewTenantPasswordStoreManager(s.barrierRegistry, s.passwordStore)
				if pwErr != nil {
					s.logger.Warn("Failed to create tenant password store manager", "error", pwErr)
				} else {
					svc.SetPasswordStoreManager(pwManager)
					s.logger.Info("Tenant password store manager wired into service")
				}
			}
		}
		if s.pkcs11StateStore != nil {
			svc.SetPKCS11StateStore(s.pkcs11StateStore)
		}
		if s.platformStore != nil {
			svc.SetPlatformStore(s.platformStore)
		}
		if s.policyManager != nil {
			svc.SetPolicyManager(s.policyManager)
		}
		if s.qrdbClient != nil {
			svc.SetCustodianClient(s.qrdbClient.CustodianGroups())
		}
		if s.qrdbClient != nil {
			svc.SetShareClient(s.qrdbClient.Shares())
		}
		// UserAuthFactors returns nil when the transport predates the
		// user-side surface, so the servicer stays unconfigured rather than
		// holding a typed-nil client that would panic on first call.
		if s.qrdbClient != nil {
			if factors := s.qrdbClient.UserAuthFactors(); factors != nil {
				svc.SetUserAuthFactorClient(factors)
			}
		}
		// The audit client is wired read-only: the servicer exposes QueryAudit
		// and nothing else, so the viewer can read the chain while emission
		// stays with pkg/audit's Logger.
		if s.qrdbClient != nil {
			if auditClient := s.qrdbClient.Audit(); auditClient != nil {
				svc.SetAuditClient(auditClient)
			}
		}
		// Wire the read-only cluster surface. Only attach the live qrdb
		// cluster client when clustering is enabled; a standalone node leaves
		// the reader nil and the servicer reports single-node status. The
		// shard and this node's replica id come from operator cluster config.
		if s.qrdbClient != nil && s.config.Cluster.Enabled {
			svc.SetClusterClient(
				&clusterClientAdapter{cluster: s.qrdbClient.Cluster()},
				s.config.Cluster.ShardID,
				s.config.Cluster.NodeID,
			)
		} else {
			svc.SetClusterClient(nil, s.config.Cluster.ShardID, s.config.Cluster.NodeID)
		}
		if s.barrierRegistry != nil {
			svc.SetBarrierRegistry(s.barrierRegistry)
		}
		// Wire the embedded qrdb node as the encryption-migration provider so
		// BarrierEnableEncryption can migrate an unencrypted barrier to a keyed
		// strategy in place. The node satisfies xkms.EncryptionMigrator (its
		// EnableEncryption parameter types are the qrdb SDK aliases).
		if s.qrdbNode != nil {
			svc.SetEncryptionMigrator(s.qrdbNode)
		}
		if s.tenantService != nil {
			svc.SetTenantService(s.tenantService)
		}
		if s.credentialService != nil {
			svc.SetCredentialService(s.credentialService)
		}
		if s.ceremonyService != nil {
			svc.SetCeremonyService(initialize.NewCeremonyAdapter(s.ceremonyService))
		}
		if s.ca != nil {
			// s.ca is ca.TrustedCA which doesn't include the *Raw adapter methods.
			// The concrete *ca.CA struct satisfies provider.CA via its Raw methods
			// in service_adapter.go. Type-assert to wire the typed interface.
			if caProvider, ok := s.ca.(provider.CA); ok {
				svc.SetCA(caProvider)
			}
		}
		// Wire the hardware-attestation trust anchors. Without them,
		// attestation-gated CSR signing fails closed, so a broken anchor
		// configuration is fatal at startup rather than silently permissive.
		if s.config.Attestation != nil {
			verifiers, attErr := s.config.Attestation.Verifiers()
			if attErr != nil {
				return nil, attErr
			}
			if attErr := svc.SetAttestationVerifiers(verifiers); attErr != nil {
				return nil, attErr
			}
			s.logger.Info("Hardware attestation trust anchors wired",
				"formats", svc.AttestationFormats())
		}
	}

	return s, nil
}

// setupLogger configures the logger based on config
func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	// Parse log level
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level: level,
	}

	// Create handler based on format
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text", "console":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// getBuildVersion retrieves the version from build information
func getBuildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	// Try to get version from VCS (git tag)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.version" {
			if setting.Value != "" && setting.Value != "devel" {
				return setting.Value
			}
		}
		if setting.Key == "vcs.revision" {
			// Get short commit hash (first 7 chars)
			if len(setting.Value) >= 7 {
				return setting.Value[:7]
			}
			return setting.Value
		}
	}

	// Try module version
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return "dev"
}

// initializeBackends creates and initializes all enabled backends
func (s *Server) initializeBackends() error {
	s.logger.Info("Initializing backends...")

	// Initialize Software backend (unified asymmetric + symmetric with import/export support)
	if s.config.Backends.Software != nil && s.config.Backends.Software.Enabled {
		keyStorage, err := s.createStorageAt(s.config.Backends.Software.Path)
		if err != nil {
			return &ErrStorageCreate{Resource: "software key storage", Err: err}
		}

		softwareBackend, err := software.NewBackend(&software.Config{
			KeyStorage: keyStorage,
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "software", Err: err}
		}

		s.keyProviders["software"] = softwareBackend
		s.logger.Info("Software backend initialized", "backend", "software", "path", s.config.Backends.Software.Path)
	}

	// Initialize PKCS8 backend (software keys)
	if s.config.Backends.PKCS8 != nil && s.config.Backends.PKCS8.Enabled {
		keyStorage, err := s.createStorageAt(s.config.Backends.PKCS8.Path)
		if err != nil {
			return &ErrStorageCreate{Resource: "PKCS8 key storage", Err: err}
		}

		pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
			KeyStorage: keyStorage,
			// Encryption-at-rest is provided by the storage layer (the node
			// barrier's sealed KV), not a per-key password; permit plaintext DER
			// exactly when the node seal is engaged or the operator runs
			// insecure. See allowNodeLocalPlaintextKeys.
			AllowPlaintextKeys: s.allowNodeLocalPlaintextKeys(),
		})
		if err != nil {
			return &ErrBackendCreate{Backend: "PKCS8", Err: err}
		}

		s.keyProviders["pkcs8"] = pkcs8Backend
		s.logger.Info("PKCS8 backend initialized",
			"backend", "pkcs8",
			"path", s.config.Backends.PKCS8.Path,
			"allow_plaintext_keys", s.allowNodeLocalPlaintextKeys(),
			"node_seal", s.nodeSealEnabled)
	}

	// Initialize other backends based on build tags
	// Each backend has separate files with build tags that automatically
	// compile the real implementation or a stub based on build flags

	if err := s.initTPM2Backend(); err != nil {
		return &ErrBackendInit{Backend: "TPM2", Err: err}
	}

	if err := s.initPKCS11Backend(); err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}

	if err := s.initAWSKMSBackend(); err != nil {
		return &ErrBackendInit{Backend: "AWS KMS", Err: err}
	}

	if err := s.initGCPKMSBackend(); err != nil {
		return &ErrBackendInit{Backend: "GCP KMS", Err: err}
	}

	if err := s.initAzureKVBackend(); err != nil {
		return &ErrBackendInit{Backend: "Azure Key Vault", Err: err}
	}

	if err := s.initVaultBackend(); err != nil {
		return &ErrBackendInit{Backend: "Vault", Err: err}
	}

	if err := s.initPhoneBackend(); err != nil {
		return &ErrBackendInit{Backend: "phone", Err: err}
	}

	if len(s.keyProviders) == 0 {
		return ErrNoBackendsInitialized
	}

	return nil
}

// initializeKeyStore creates keystores for all backends
func (s *Server) initializeKeyStore() error {
	// Create certificate storage (shared across all keystores)
	certStorage, err := s.createStorage("certs")
	if err != nil {
		return &ErrStorageCreate{Resource: "certificate storage", Err: err}
	}

	// Create a keystore for each backend
	for name, backend := range s.keyProviders {
		keystore, err := xkms.New(&xkms.BackendConfig{
			Backend:     backend,
			CertStorage: certStorage,
		})
		if err != nil {
			return &ErrKeystoreCreate{Backend: name, Err: err}
		}

		s.backends[name] = keystore
		s.logger.Info("KeyStore initialized", "backend", name)
	}

	if len(s.backends) == 0 {
		return ErrNoKeystoresInitialized
	}

	// Determine the default backend by the one shared rule, so the same
	// configuration resolves to the same store on every start. Ranging
	// s.backends to take "the first" entry read Go's randomized map iteration
	// order, so a config with no default_backend — or one naming a backend
	// that is not compiled into this build — selected a different store on
	// each start, and nothing said so (#171).
	configuredDefault := string(s.config.Default)
	defaultBackend := xkms.ResolveDefaultBackend(configuredDefault, s.backends)
	if configuredDefault != "" && defaultBackend != configuredDefault {
		s.logger.Warn("configured default backend is not loaded, using resolved default",
			"configured", configuredDefault,
			"resolved", defaultBackend)
	}
	s.defaultBackendName = defaultBackend

	// Initialize the global xkms service with the keystores. The resolved
	// service is captured on the server in New() and injected into every
	// transport constructor; the singleton exists for embedded SDK access.
	serviceConfig := &xkms.ServiceConfig{
		Backends:       s.backends,
		DefaultBackend: defaultBackend,
	}
	if err := xkms.Initialize(serviceConfig); err != nil {
		return &ErrServiceInit{Service: "xkms service", Err: err}
	}

	s.logger.Info("xKMS service initialized",
		"default_backend", defaultBackend,
		"backends", len(s.backends))

	return nil
}

// initializeAuthentication sets up the authentication subsystem.
//
// Authenticator selection is fail-closed. The no-op authenticator is reachable
// only through an explicit, unambiguous opt-in — auth.enabled=false or
// auth.type "none"/"noop"/"" — which config.ComplianceGaps() reports, so the
// daemon refuses to start on it at all and offers no override. Every
// other outcome that cannot produce a real authenticator (an unrecognized
// auth.type, a broken JWT key, a composite chain with nothing to derive) is a
// fatal startup error rather than a silently unauthenticated server.
func (s *Server) initializeAuthentication() error {
	if err := s.buildAuthenticator(); err != nil {
		return err
	}
	// Apply an authenticator decorator (e.g. desktop loopback-token composite)
	// before publishing. Decorators add acceptance paths on top of the
	// configured authenticator; they never replace it with a weaker one.
	if s.authDecorator != nil {
		s.authenticator = s.authDecorator(s.authenticator)
		s.logger.Info("Authenticator decorated", slog.String("name", s.authenticator.Name()))
	}
	// Publish on every success path. buildAuthenticator assigns s.authenticator
	// from several branches, so publishing here rather than at each assignment
	// keeps the holder and the concrete authenticator from drifting apart.
	s.publishAuthenticator()
	return nil
}

// publishAuthenticator makes the authenticator now in force the one every
// transport uses, including listeners that were constructed earlier. The
// holder is created on first use so it exists before any transport is built,
// whatever order a caller initializes the server in.
func (s *Server) publishAuthenticator() {
	if s.liveAuthenticator == nil {
		s.liveAuthenticator = auth.NewLiveAuthenticator(s.authenticator)
		return
	}
	s.liveAuthenticator.Store(s.authenticator)
}

// buildAuthenticator resolves the configured authenticator into
// s.authenticator. Callers go through initializeAuthentication, which also
// publishes the result to the running transports.
func (s *Server) buildAuthenticator() error {
	s.logger.Info("Initializing authentication...")

	// Build WebAuthn config if enabled (do this first as WebAuthn can work
	// independently of the general auth system - it IS a form of
	// authentication). rest.WebAuthnConfigFromXKMS is the conversion path
	// shared with a host's self-built WebAuthn surface (pkg/apimodule
	// WithWebAuthnConfig), so xkmsd and a host apply the identical defaults
	// (display name falls back to the RP identifier; a single HTTPS origin
	// is derived from the RP identifier when neither is configured).
	if s.config.WebAuthn != nil && s.config.WebAuthn.Enabled {
		s.webauthnConfig = rest.WebAuthnConfigFromXKMS(s.config.WebAuthn)
		s.logger.Info("WebAuthn configured",
			"rp_id", s.config.WebAuthn.RPID,
			"rp_display_name", s.webauthnConfig.RPDisplayName)
	}

	// If auth is disabled, use NoOp authenticator. This is an explicit opt-in
	// that config.ComplianceGaps() flags, so cmd/xkmsd refuses to start on it
	// outright; only embedded and test callers of this package reach here.
	if !s.config.Auth.Enabled {
		s.authenticator = auth.NewNoOpAuthenticator()
		s.logger.Warn("Authentication disabled (auth.enabled=false), using NoOp authenticator: all requests are anonymous")
		return nil
	}

	// Determine the required authenticator based on config type
	var requiredAuth auth.Authenticator
	switch strings.ToLower(strings.TrimSpace(s.config.Auth.Type)) {
	case "none", "noop", "":
		// Explicit, unambiguous opt-in to unauthenticated access. This mirrors
		// config.AuthConfig.CreateAuthenticator and is reported by
		// config.ComplianceGaps(), so the daemon refuses to start on it
		// outright; only embedded and test callers of this package reach here.
		s.authenticator = auth.NewNoOpAuthenticator()
		s.logger.Warn("Authentication explicitly set to no-op, all requests are anonymous",
			"type", s.config.Auth.Type)
		return nil

	case "jwt":
		// JWT authenticator requires a public key
		if s.config.Auth.JWT == nil || s.config.Auth.JWT.PublicKeyFile == "" {
			return ErrJWTPublicKeyRequired
		}
		jwtAuth, err := s.createJWTAuthenticator()
		if err != nil {
			return &ErrServiceInit{Service: "JWT authenticator", Err: err}
		}
		requiredAuth = jwtAuth
		s.logger.Info("JWT authentication configured",
			"issuer", s.config.Auth.JWT.Issuer)

	case "mtls":
		// mTLS authentication uses client certificates
		if !s.config.TLS.Enabled {
			return ErrMTLSRequiresTLS
		}
		mtlsConfig := &auth.MTLSConfig{}
		if us := s.mtlsUserStore(); us != nil {
			mtlsConfig.UserStore = us
		}
		mtlsAuth := auth.NewMTLSAuthenticator(mtlsConfig)
		requiredAuth = mtlsAuth
		s.logger.Info("mTLS authentication configured")

	case "composite":
		compositeAuth, err := s.createCompositeAuthenticator()
		if err != nil {
			return err
		}
		requiredAuth = compositeAuth

	case "adaptive":
		// Adaptive mode (anonymous until the first user exists) was removed:
		// first boot provisions the administrator and their mTLS credential
		// at startup, so there is no pre-credential window for it to bridge
		// and no reason to ever serve anonymously. Fail with the replacement
		// spelled out rather than silently mapping to a different behavior.
		return &ErrAdaptiveRemoved{}

	default:
		// Fail closed: an unrecognized auth.type is almost always a typo, and
		// admitting every request because of one would be the worst possible
		// outcome. Unauthenticated access must be requested explicitly.
		return &ErrUnknownAuthType{Type: s.config.Auth.Type}
	}

	// Every branch above either assigns requiredAuth or returns an
	// error, so a nil authenticator here would be a programming error rather
	// than a configuration one. Fail closed instead of admitting all requests.
	if requiredAuth == nil {
		return &ErrUnknownAuthType{Type: s.config.Auth.Type}
	}
	s.authenticator = requiredAuth

	return nil
}

// createCompositeAuthenticator builds a CompositeAuthenticator from the
// configured composite authentication methods.
//
// When no methods are configured, the chain is DERIVED from the deployment's
// session vehicles — the exact set every login ceremony resolves to:
//
//   - jwt: the JWT pairs the WebAuthn (FIDO2) and PIV login ceremonies mint;
//     included when a verification key exists (operator public-key file or
//     the built-in token issuer's signing key).
//   - mtls: cert-based enrollment is the stack's bootstrap plane — the
//     first-boot administrator's ONLY credential is the SPKI-bound
//     certificate; included whenever TLS is enabled.
//
// An empty derivation (no TLS, no JWT key) fails closed: there is nothing a
// caller could authenticate with, and unauthenticated access must be an
// explicit opt-in, never a fallback.
func (s *Server) createCompositeAuthenticator() (auth.Authenticator, error) {
	if s.config.Auth.Composite == nil || len(s.config.Auth.Composite.Methods) == 0 {
		return s.deriveCompositeAuthenticator()
	}

	authenticators := make([]auth.Authenticator, 0, len(s.config.Auth.Composite.Methods))

	// compositeMethodFactory maps method names to factory functions for O(1) dispatch.
	type methodFactory func() (auth.Authenticator, error)
	compositeMethodFactory := map[string]methodFactory{
		"jwt": func() (auth.Authenticator, error) {
			if s.config.Auth.JWT == nil || s.config.Auth.JWT.PublicKeyFile == "" {
				return nil, ErrCompositeJWTRequired
			}
			return s.createJWTAuthenticator()
		},
		"mtls": func() (auth.Authenticator, error) {
			if !s.config.TLS.Enabled {
				return nil, ErrCompositeMTLSRequiresTLS
			}
			mtlsConfig := &auth.MTLSConfig{}
			if us := s.mtlsUserStore(); us != nil {
				mtlsConfig.UserStore = us
			}
			return auth.NewMTLSAuthenticator(mtlsConfig), nil
		},
	}

	for _, method := range s.config.Auth.Composite.Methods {
		factory, ok := compositeMethodFactory[method]
		if !ok {
			return nil, &ErrCompositeMethodCreate{Method: method, Err: ErrUnknownCompositeMethod}
		}
		authenticator, err := factory()
		if err != nil {
			return nil, &ErrCompositeMethodCreate{Method: method, Err: err}
		}
		authenticators = append(authenticators, authenticator)
	}

	compositeAuth, err := auth.NewCompositeAuthenticator(authenticators...)
	if err != nil {
		return nil, &ErrServiceInit{Service: "composite authenticator", Err: err}
	}

	s.logger.Info("Composite authentication configured", "methods", s.config.Auth.Composite.Methods)
	return compositeAuth, nil
}

// deriveCompositeAuthenticator builds the session-vehicle chain (jwt + mtls)
// from what the deployment actually provides. See
// createCompositeAuthenticator for the derivation contract.
func (s *Server) deriveCompositeAuthenticator() (auth.Authenticator, error) {
	var chain []auth.Authenticator
	derived := make([]string, 0, 2)

	hasKeyFile := s.config.Auth.JWT != nil && s.config.Auth.JWT.PublicKeyFile != ""
	if hasKeyFile || s.tokenIssuer != nil {
		jwtAuth, err := s.createJWTAuthenticator()
		if err != nil {
			return nil, &ErrServiceInit{Service: "JWT authenticator for composite chain", Err: err}
		}
		chain = append(chain, jwtAuth)
		derived = append(derived, "jwt")
	}
	if s.config.TLS.Enabled {
		mtlsConfig := &auth.MTLSConfig{}
		if us := s.mtlsUserStore(); us != nil {
			mtlsConfig.UserStore = us
		}
		chain = append(chain, auth.NewMTLSAuthenticator(mtlsConfig))
		derived = append(derived, "mtls")
	}
	if len(chain) == 0 {
		return nil, ErrCompositeMethodsRequired
	}
	if len(chain) == 1 {
		// A single-vehicle deployment keeps the concrete authenticator (and
		// its informative Name) rather than a one-element composite wrapper.
		s.logger.Info("Composite authentication configured", "methods", derived, "derived", true)
		return chain[0], nil
	}

	compositeAuth, err := auth.NewCompositeAuthenticator(chain...)
	if err != nil {
		return nil, &ErrServiceInit{Service: "composite authenticator", Err: err}
	}
	s.logger.Info("Composite authentication configured", "methods", derived, "derived", true)
	return compositeAuth, nil
}

// initializeWebAuthnService builds the single WebAuthn relying-party service
// shared between the REST browser ceremony and the SDK ceremony. It is a no-op
// when WebAuthn is not enabled (webauthnConfig is nil).
//
// When xkms hosts or dials the qrdb engine, users and credentials are
// persisted on the qrdb node — the single source of identity — via
// rest.BuildWebAuthnService, the construction path shared with a host's
// self-built WebAuthn surface (pkg/api/rest NewHostServer / pkg/apimodule),
// so xkmsd and a host configure WebAuthn identically. Otherwise (no qrdb
// identity plane) they are persisted in the configured datastore
// (BackendUserStore / BackendCredentialStore) so registrations survive
// restarts in every storage mode — a construction path a host has no
// equivalent for, since composing the module implies embedding qrdb.
// Sessions are always ephemeral and live in memory.
func (s *Server) initializeWebAuthnService() error {
	if s.webauthnConfig == nil {
		return nil
	}

	s.logger.Info("Initializing WebAuthn service...")

	if s.qrdbClient != nil {
		svc, err := rest.BuildWebAuthnService(rest.WebAuthnServiceParams{
			Config:      s.webauthnConfig,
			QRDBClient:  s.qrdbClient,
			TenantID:    webAuthnSystemTenant,
			TokenIssuer: s.tokenIssuer,
			Logger:      s.logger,
		})
		if err != nil {
			return &ErrServiceInit{Service: "webauthn service", Err: err}
		}
		s.webauthnService = svc
		s.logger.Info("WebAuthn service initialized", "rp_id", s.webauthnConfig.RPID, "store", "qrdb")
		return nil
	}

	// No qrdb identity plane (non-qrdb storage mode): persist WebAuthn
	// users and credentials in the configured datastore so registrations
	// survive restarts. Sessions remain in-memory (short-lived challenge
	// state); a cluster-safe session store is a clustering concern.
	waStore, err := s.createStorage("webauthn")
	if err != nil {
		return &ErrServiceInit{Service: "webauthn store", Err: err}
	}

	params := webauthn.ServiceParams{
		Config:          s.webauthnConfig,
		UserStore:       webauthn.NewBackendUserStore(waStore),
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: webauthn.NewBackendCredentialStore(waStore),
		Logger:          s.logger,
	}

	// Wire the session-token issuer so ceremony completion mints verifiable
	// access/refresh JWTs. Without it the library falls back to an unsigned
	// base64 user ID, which no authenticator accepts — a login flow that
	// cannot actually log anyone in.
	if s.tokenIssuer != nil {
		params.JWTGenerator = rest.NewWebAuthnTokenAdapter(s.tokenIssuer, webAuthnSystemTenant)
	} else {
		s.logger.Warn("WebAuthn service has no token issuer: ceremony tokens will not authenticate API requests")
	}

	svc, err := webauthn.NewService(params)
	if err != nil {
		return &ErrServiceInit{Service: "webauthn service", Err: err}
	}

	s.webauthnService = svc
	s.logger.Info("WebAuthn service initialized", "rp_id", s.webauthnConfig.RPID, "store", "datastore")
	return nil
}

// initializeAuthorization sets up the authorization subsystem. All transports
// (REST, gRPC, QUIC, MCP) authorize through the single qrdb-backed Authorizer —
// the canonical role/permission engine. When RBAC is disabled the Authorizer is
// left nil and the gate stays open, which is the configured intent.
//
// RBAC enabled without a hosted qrdb identity plane (a non-qrdb storage backend)
// also leaves the Authorizer nil, which would silently degrade every transport
// to allow-all. That combination is refused before startup reaches here:
// Config.ComplianceGaps reports it and cmd/xkmsd aborts, with no override. The
// warning below therefore only fires for an embedded or test caller that
// constructs this package directly.
func (s *Server) initializeAuthorization() error {
	s.logger.Info("Initializing authorization...")

	if s.config.Auth.EnableRBAC && s.qrdbClient != nil {
		s.rbacAuthorizer = auth.NewAuthorizer(s.qrdbClient.RBAC())
		s.logger.Info("RBAC authorization enabled (qrdb-backed)")
	} else {
		s.rbacAuthorizer = nil
		if s.config.Auth.EnableRBAC {
			s.logger.Warn("RBAC enabled but no qrdb identity plane; authorization is permissive")
		} else {
			s.logger.Info("Authorization disabled (allow all)")
		}
	}

	return nil
}

// initializeAuditLogger selects the audit emission Logger. xkms owns no audit
// storage: emits are routed to the hosted qrdb node's HMAC-chained audit
// subsystem through Client().Audit() (QRDBLogger). The node's audit sink — the
// HMAC-chained file logger or in-memory ring buffer — was wired in at node
// construction by initEmbeddedQRDBNode (see newQRDBAuditSink), so this runs
// after the node is up and a live client exists.
//
// When no qrdb client is present (non-qrdb storage backends with no identity
// plane), a NoOpLogger discards events.
func (s *Server) initializeAuditLogger() error {
	s.logger.Info("Initializing audit logger...")

	if s.qrdbClient != nil {
		s.auditLogger = audit.NewQRDBLogger(s.qrdbClient.Audit())
		s.logger.Info("Audit logging routed to qrdb chained subsystem")
		return nil
	}

	// No qrdb client (non-qrdb storage backend): audit still lands on a
	// tamper-evident chain — a local chained file with the identical record
	// shape — never a silent no-op. A deployment with no storage path at
	// all has nowhere durable to write; that is a configuration with no
	// audit story and the file sink is rooted in the CWD as a last resort.
	auditPath := "audit-events.ndjson"
	if s.config.Storage.Path != "" {
		auditPath = filepath.Join(s.config.Storage.Path, "audit-events.ndjson")
	}
	chained, err := audit.NewChainedFileLogger(auditPath)
	if err != nil {
		return &ErrServiceInit{Service: "chained file audit logger", Err: err}
	}
	s.auditLogger = chained
	s.logger.Info("Audit logging routed to local chained file", "path", auditPath)

	return nil
}

// mtlsUserStore returns the UserStore the mTLS authenticator uses to resolve a
// client certificate's SPKI thumbprint to a user. When xkms hosts (or dials)
// the qrdb engine, identity is resolved against qrdb's user store — the single
// source of identity for the stack — via the GetUserByCertThumbprint index,
// with role ids resolved to names through the role client. Absent a qrdb
// client (non-qrdb storage backends), the mTLS authenticator falls back to
// certificate-field extraction (handled in buildIdentity when the store is
// nil).
func (s *Server) mtlsUserStore() auth.UserStore {
	if qs := s.qrdbUserStore(); qs != nil {
		return qs
	}
	return nil
}

// qrdbUserStore builds the qrdb-backed identity store (cert-thumbprint
// resolution + user existence checks) when xkms hosts or dials the qrdb
// engine. It returns nil when no qrdb client is configured, so callers can
// distinguish "no identity plane" from a usable store.
func (s *Server) qrdbUserStore() *auth.QRDBUserStore {
	if s.qrdbClient == nil {
		return nil
	}
	return auth.NewQRDBUserStore(s.qrdbClient.Users(), s.qrdbClient.Roles())
}

// initializeBarrier creates and configures the barrier (seal/unseal) subsystem.
// The barrier wraps storage with transparent AES-256-GCM encryption.
func (s *Server) initializeBarrier() error {
	if s.nodeSealEnabled {
		// The node's own barrier was adopted at node construction
		// (initEmbeddedQRDBNode) — s.barrier already points at it. Skip the
		// hand-rolled construction so there is a single barrier.
		s.logger.Info("Barrier: using the adopted qrdb node barrier")
		return nil
	}
	if !s.config.Barrier.Enabled {
		s.logger.Info("Barrier disabled")
		return nil
	}

	s.logger.Info("Initializing barrier...")

	// Create barrier storage backend
	barrierStorage, err := s.createStorage("barrier")
	if err != nil {
		return &ErrStorageCreate{Resource: "barrier storage", Err: err}
	}

	// Build sealing strategies. Hardware/cloud strategies whose backend was
	// configured in the preference order are composed from the already-
	// initialized backends; software is always appended as the baseline.
	strategies, err := s.buildHardwareSealStrategies()
	if err != nil {
		return &ErrServiceInit{Service: "barrier", Err: err}
	}
	// Retain the composed strategies so the barrier registry can build a
	// hardware-backed StrategyRegistry from the same instances for per-tenant
	// barrier sealing (see initializeBarrierRegistry).
	s.sealStrategies = strategies

	// Determine root key path
	rootKeyPath := s.config.Barrier.RootKeyPath
	if rootKeyPath == "" {
		rootKeyPath = "barrier/root-key"
	}

	// Build preference order
	var prefOrder []seal.StrategyID
	for _, id := range s.config.Barrier.PreferenceOrder {
		prefOrder = append(prefOrder, seal.StrategyID(id))
	}

	barrierConfig := seal.BarrierConfig{
		RootKeyPath:     rootKeyPath,
		PreferenceOrder: prefOrder,
		AuditLogger:     s.auditLogger,
	}

	barrier, err := seal.NewBarrier(s.logger, barrierStorage, barrierConfig, strategies...)
	if err != nil {
		return &ErrServiceInit{Service: "barrier", Err: err}
	}

	s.barrier = barrier
	s.logger.Info("Barrier initialized", "root_key_path", rootKeyPath)

	return nil
}

// initializeBarrierRegistry creates the barrier registry for multi-tenant
// isolation and composes go-qrdb's TenantService on top of it with xkms
// hardware seal strategies injected. The registry owns the per-tenant barrier
// lifecycle; the TenantService adds entitlement-gated isolation modes
// (prefix/barrier/volume/raft), system-managed auto-unseal, quotas, and the
// strategy-by-name resolution that lets a tenant barrier be sealed by a TPM,
// PKCS#11 token, or cloud KMS.
func (s *Server) initializeBarrierRegistry() error {
	if s.nodeSealEnabled {
		// The node's own barrier registry + tenant service were adopted at node
		// construction. Nothing to build here.
		s.logger.Info("Barrier registry: using the adopted qrdb node registry + tenant service")
		return nil
	}
	if s.barrier == nil {
		s.logger.Info("Barrier registry skipped (no barrier)")
		return nil
	}

	// Build the volume-pool subsystem so dedicated-isolation tenants
	// (barrier/volume/raft) can draw a durable per-tenant Pebble path. When no
	// data directory is configured (in-memory deployments) the pool is nil and
	// only prefix-isolated tenants are available.
	pool, err := s.buildVolumePool()
	if err != nil {
		return &ErrServiceInit{Service: "barrier registry", Err: err}
	}

	var regOpts []seal.BarrierRegistryOption
	if pool != nil {
		s.volumePool = pool
		regOpts = append(regOpts,
			seal.WithVolumePool(pool.Manager, pool.StateStore, pool.DefaultPoolName),
			seal.WithPerTenantRegistry(pool.PerTenantRegistry),
		)
	}

	registry, err := seal.NewBarrierRegistry(s.barrier, regOpts...)
	if err != nil {
		return &ErrServiceInit{Service: "barrier registry", Err: err}
	}
	s.barrierRegistry = registry

	// Compose go-qrdb's TenantService on top of the registry. The hardware
	// StrategyRegistry built from the system barrier's strategies lets a
	// per-tenant barrier be initialized with an explicit hardware/cloud strategy
	// (TenantBarrierInitWithStrategy). xkms operates its own tenants as the
	// trust anchor, so the operator default entitlements permit every isolation
	// mode; downstream multi-tenant billing planes (quicbaas) tighten these per
	// plan via UpdateEntitlements.
	tenantSvc, err := seal.NewHardwareTenantService(
		s.barrier, registry, s.logger, s.sealStrategies,
		qrdbsdk.WithTenantDefaultEntitlements(xkmsDefaultEntitlements()),
	)
	if err != nil {
		return &ErrServiceInit{Service: "tenant service", Err: err}
	}
	s.tenantService = tenantSvc

	// Re-register dedicated-isolation tenants from their persisted pool
	// assignments and unseal system-managed (auto-unseal) barriers credential-
	// free. A nil pool short-circuits inside RestoreVolumeTenants.
	if err := registry.RestoreVolumeTenants(context.Background()); err != nil {
		s.logger.Warn("RestoreVolumeTenants failed; some tenant barriers may be deferred",
			"error", err.Error())
	}

	s.logger.Info("Barrier registry initialized", "volume_pool", pool != nil)

	return nil
}

// buildVolumePool provisions a single default volume pool rooted under the
// configured storage path so dedicated-isolation tenants get durable per-tenant
// Pebble storage. It returns (nil, nil) when no storage path is configured
// (in-memory deployments), in which case only prefix-isolated tenants are
// available. The pool name "default" matches the name RegisterTenantPooled
// draws from.
func (s *Server) buildVolumePool() (*seal.VolumePoolSubsystem, error) {
	if s.config.Storage.Path == "" {
		return nil, nil
	}
	dataDir := s.config.Storage.Path
	poolRoot := filepath.Join(dataDir, "tenant-volumes")
	pools := []qrdbsdk.DaemonVolumePoolConfig{{
		Name:  "default",
		Paths: []string{poolRoot},
	}}
	return seal.BuildVolumePoolSubsystem(dataDir, pools, s.logger, s.config.Cluster.Enabled)
}

// xkmsDefaultEntitlements returns the operator default entitlements for xkms's
// own tenants. xkms is the trust anchor that operates its tenants directly
// (there is no untrusted billing plane inside xkms itself), so every isolation
// mode and the system-managed auto-unseal key-management mode are permitted by
// default. Consumers that expose tenants to untrusted callers tighten these per
// plan via UpdateEntitlements.
func xkmsDefaultEntitlements() *qrdbsdk.Entitlements {
	return &qrdbsdk.Entitlements{
		AllowedIsolationModes: []string{
			string(qrdbsdk.TenantIsolationPrefix),
			string(qrdbsdk.TenantIsolationBarrier),
			string(qrdbsdk.TenantIsolationVolume),
			string(qrdbsdk.TenantIsolationRaft),
		},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: true,
		AllowDedicatedWAL:         true,
	}
}

// initializePINManager creates and configures the PIN management subsystem.
func (s *Server) initializePINManager() error {
	if !s.config.PIN.Enabled {
		s.logger.Info("PIN management disabled")
		return nil
	}

	s.logger.Info("Initializing PIN manager...")

	// Create the PIN manager based on strategy
	strategy := s.config.PIN.Strategy
	if strategy == "" {
		strategy = "software"
	}

	pinDir := s.config.Storage.Path + "/pin"

	switch strategy {
	case "software":
		fileStore, err := filestorage.New(pinDir)
		if err != nil {
			return &ErrStorageCreate{Resource: "PIN state directory", Err: err}
		}
		pinStore, err := pinadapter.New(fileStore)
		if err != nil {
			return &ErrServiceInit{Service: "software PIN manager", Err: err}
		}
		hashConfig := qrdbsdk.AutoDetectHashConfig()
		backend, err := qrdbsdk.NewSoftwareBackend(pinStore, hashConfig)
		if err != nil {
			return &ErrServiceInit{Service: "software PIN manager", Err: err}
		}
		s.pinManager = backend
	default:
		return &ErrUnknownPINStrategy{Strategy: strategy}
	}

	s.logger.Info("PIN manager initialized",
		slog.String("strategy", strategy))

	return nil
}

// initializePasswordStore initializes the static password store.
func (s *Server) initializePasswordStore() error {
	passwordStoragePath := s.config.Storage.Path + "/passwords"

	backend, err := s.createStorage("passwords")
	if err != nil {
		return &ErrStorageCreate{Resource: "password storage", Err: err}
	}

	s.passwordStore = staticpw.NewStore(backend)
	s.logger.Info("Password store initialized", "path", passwordStoragePath)
	return nil
}

// initializePKCS11StateStore builds the store that persists a remote-mode
// PKCS#11 module's token and object state in the embedded qrdb node. It uses the
// same createStorage seam every other server subsystem does, so the records
// inherit the node's durability and, per tenant, its barrier encryption.
func (s *Server) initializePKCS11StateStore() error {
	backend, err := s.createStorage("pkcs11state")
	if err != nil {
		return &ErrStorageCreate{Resource: "pkcs11 state storage", Err: err}
	}
	store, err := pkcs11state.NewStore(backend)
	if err != nil {
		return &ErrStorageCreate{Resource: "pkcs11 state storage", Err: err}
	}
	s.pkcs11StateStore = store
	s.logger.Info("PKCS#11 remote-state store initialized")
	return nil
}

// initializePlatformStore initializes the platform sealed credential store.
func (s *Server) initializePlatformStore() error {
	// Platform store requires barrier to be initialized for sealing
	if s.barrier == nil {
		s.logger.Info("Platform store skipped: barrier not configured")
		return nil
	}

	s.logger.Info("Platform store initialized")
	return nil
}

// initializeCredentialService initializes the credential management service
// for sealing/unsealing backend credentials (PKCS#11 User PIN, TPM2 auth, etc.)
func (s *Server) initializeCredentialService() error {
	strategy := s.config.Credentials.SealStrategy
	if strategy == "" {
		strategy = "manual"
	}

	cfg := &credentialspkg.Config{
		Strategy: strategy,
	}

	svc, err := credentialspkg.New(cfg, s.platformStore, s.barrier, s.logger)
	if err != nil {
		return &ErrServiceInit{Service: "credential service", Err: err, Sentinel: ErrCredentialServiceFailed}
	}

	s.credentialService = svc
	s.logger.Info("Credential service initialized", "strategy", strategy)
	return nil
}

// initializePolicyManager initializes the PCR policy manager.
func (s *Server) initializePolicyManager() error {
	// Policy manager is optional, only for TPM-equipped servers
	s.logger.Info("Policy manager initialization deferred (requires TPM PCR reader)")
	return nil
}

// initializeFactorRegistry composes the canonical go-xkms hardware auth
// factors (PIV, PKCS#11, FIDO2, mTLS) into a qrdb AuthFactorRegistry. The registry is
// injected into the embedded qrdb node via WithFactorRegistry (in
// initEmbeddedQRDBNode) so the node's unified AuthFactorService can verify
// hardware factor challenges during custodian enrollment and Shamir unseal
// ceremonies. It is also exposed via FactorRegistry() for downstream embedders.
// The function is idempotent: a second call returns nil immediately, preserving
// the registry instance already injected into the qrdb node.
func (s *Server) initializeFactorRegistry() error {
	if s.factorRegistry != nil {
		return nil
	}
	registry, err := factor.NewDefaultRegistry(factor.Config{})
	if err != nil {
		return &ErrServiceInit{Service: "factor registry", Err: err}
	}
	s.factorRegistry = registry
	s.logger.Info("Auth-factor registry initialized", "factors", registry.List())
	return nil
}

// FactorRegistry returns the hardware auth-factor registry.
func (s *Server) FactorRegistry() *qrdbsdk.AuthFactorRegistry {
	return s.factorRegistry
}

// Barrier returns the barrier instance.
func (s *Server) Barrier() *seal.Barrier {
	return s.barrier
}

// BarrierRegistry returns the barrier registry instance.
func (s *Server) BarrierRegistry() *seal.BarrierRegistry {
	return s.barrierRegistry
}

// PINBackend returns the PIN backend instance.
func (s *Server) PINBackend() qrdbsdk.PINBackend {
	return s.pinManager
}

// PasswordStore returns the password store instance.
func (s *Server) PasswordStore() *staticpw.BackendStore {
	return s.passwordStore
}

// PlatformStore returns the platform store instance.
func (s *Server) PlatformStore() seal.PlatformStore {
	return s.platformStore
}

// PolicyManager returns the policy manager instance.
func (s *Server) PolicyManager() *policy.Manager {
	return s.policyManager
}

// SetCA sets the Certificate Authority for CA-backed TLS and certificate operations.
func (s *Server) SetCA(trustedCA ca.TrustedCA) {
	s.ca = trustedCA
}

// SetCeremonyService sets the init ceremony service.
func (s *Server) SetCeremonyService(svc *initialize.CeremonyService) {
	s.ceremonyService = svc
}

// SetCredentialService sets the credential management service.
func (s *Server) SetCredentialService(svc *credentialspkg.Service) {
	s.credentialService = svc
}

// CredentialService returns the credential management service.
func (s *Server) CredentialService() *credentialspkg.Service {
	return s.credentialService
}

// createJWTAuthenticator creates a JWT authenticator from configuration.
func (s *Server) createJWTAuthenticator() (*auth.JWTAuthenticator, error) {
	// An operator-supplied public key file always wins (external IdP tokens).
	// Without one, fall back to the built-in token issuer's public key so the
	// login flows (WebAuthn passkey, PIV/mTLS cert login) verify without any
	// extra key management.
	var (
		pubKey   interface{}
		issuer   string
		audience []string
	)

	switch {
	case s.config.Auth.JWT != nil && s.config.Auth.JWT.PublicKeyFile != "":
		pubKeyData, err := os.ReadFile(s.config.Auth.JWT.PublicKeyFile)
		if err != nil {
			return nil, &ErrFileRead{Path: "public key file", Err: err}
		}
		parsed, err := parsePublicKey(pubKeyData)
		if err != nil {
			return nil, &ErrTLSCertOp{Operation: "parse public key", Err: err}
		}
		pubKey = parsed
		issuer = s.config.Auth.JWT.Issuer
		audience = s.config.Auth.JWT.Audience

	case s.tokenIssuer != nil:
		pubKey = s.tokenIssuer.PublicKey()
		issuer = s.tokenIssuer.IssuerName()
		audience = s.tokenIssuer.Audience()

	default:
		return nil, ErrJWTConfigRequired
	}

	return auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  pubKey,
		Issuer:     issuer,
		Audience:   audience,
		HeaderName: "Authorization",
	})
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(data []byte) (interface{}, error) {
	// Try parsing as PEM first
	block, _ := pemDecode(data)
	if block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		// Try parsing as certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert.PublicKey, nil
		}
	}

	// Try parsing as raw DER
	key, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}

	return nil, ErrParsePublicKey
}

// pemDecode decodes a PEM block.
func pemDecode(data []byte) (*pemBlock, []byte) {
	// Simple PEM decoder
	const pemHeader = "-----BEGIN "
	const pemFooter = "-----END "

	start := bytes.Index(data, []byte(pemHeader))
	if start < 0 {
		return nil, data
	}

	rest := data[start+len(pemHeader):]
	endOfType := bytes.IndexByte(rest, '-')
	if endOfType < 0 {
		return nil, data
	}

	blockType := string(rest[:endOfType])
	rest = rest[endOfType:]

	// Find end of header line
	headerEnd := bytes.IndexByte(rest, '\n')
	if headerEnd < 0 {
		return nil, data
	}
	rest = rest[headerEnd+1:]

	// Find footer
	footer := []byte(pemFooter + blockType)
	footerStart := bytes.Index(rest, footer)
	if footerStart < 0 {
		return nil, data
	}

	base64Data := rest[:footerStart]
	// Remove newlines and decode base64
	base64Data = bytes.ReplaceAll(base64Data, []byte("\n"), nil)
	base64Data = bytes.ReplaceAll(base64Data, []byte("\r"), nil)

	decoded := make([]byte, base64Encoding.DecodedLen(len(base64Data)))
	n, err := base64Encoding.Decode(decoded, base64Data)
	if err != nil {
		return nil, data
	}

	// Find end of footer line
	rest = rest[footerStart+len(footer):]
	if len(rest) > 0 && rest[0] == '\n' {
		rest = rest[1:]
	}

	return &pemBlock{
		Type:  blockType,
		Bytes: decoded[:n],
	}, rest
}

type pemBlock struct {
	Type  string
	Bytes []byte
}

// base64Encoding is the standard base64 encoding for PEM data
var base64Encoding = base64.StdEncoding

// initializeHealth creates and configures the health checker.
func (s *Server) initializeHealth() error {
	s.logger.Info("Initializing health checker...")

	s.healthChecker = qrdbsdk.NewHealthChecker()

	// Register backend health checks
	for name, keystore := range s.backends {
		backendName := name // Capture for closure
		ks := keystore      // Capture for closure

		s.healthChecker.RegisterCheck(fmt.Sprintf("backend-%s", backendName), func(ctx context.Context) qrdbsdk.HealthCheckResult {
			start := time.Now()

			// Check if backend is responsive by listing keys with a timeout
			checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			// Run the check in a goroutine to respect the timeout
			done := make(chan error, 1)
			go func() {
				_, err := ks.ListKeys(checkCtx)
				done <- err
			}()

			select {
			case err := <-done:
				latency := time.Since(start)
				if err != nil {
					return qrdbsdk.HealthCheckResult{
						Name:    fmt.Sprintf("backend-%s", backendName),
						Status:  qrdbsdk.HealthCheckStatusUnhealthy,
						Message: fmt.Sprintf("Backend %s is not responding", backendName),
						Error:   err.Error(),
						Latency: latency,
					}
				}
				return qrdbsdk.HealthCheckResult{
					Name:    fmt.Sprintf("backend-%s", backendName),
					Status:  qrdbsdk.HealthCheckStatusHealthy,
					Message: fmt.Sprintf("Backend %s is responding", backendName),
					Latency: latency,
				}
			case <-checkCtx.Done():
				return qrdbsdk.HealthCheckResult{
					Name:    fmt.Sprintf("backend-%s", backendName),
					Status:  qrdbsdk.HealthCheckStatusUnhealthy,
					Message: fmt.Sprintf("Backend %s check timed out", backendName),
					Error:   "timeout",
					Latency: time.Since(start),
				}
			}
		})
	}

	s.logger.Info("Health checker initialized", "checks", len(s.healthChecker.GetAllChecks()))
	return nil
}

// initializeCA creates and initializes a Certificate Authority from config.
// If config.CA is nil, the CA is not configured and initialization is skipped.
// On first startup (no existing CA data), Init() creates new root/intermediate certificates.
// On subsequent startups, Load() restores the CA from stored certificates and keys.
func (s *Server) initializeCA() error {
	if s.config.CA == nil {
		return nil
	}

	s.logger.Info("Initializing CA...")

	// Validate the CA configuration
	if err := s.config.CA.Validate(); err != nil {
		return &ErrCAInit{Operation: "validate CA configuration", Err: err}
	}

	// Resolve the keystore backend for the CA's root identity
	if len(s.config.CA.Identity) == 0 {
		return ErrCANoIdentities
	}
	keystoreType := s.config.CA.Identity[0].GetStoreType()
	var backend xkms.Backend
	if s.clusterCAKeyStrategy != nil {
		// Cluster-ACME mode: the cluster CA key custody strategy resolves this
		// node's runtime keystore. For the barrier strategy the first node's
		// bootstrap key is promoted into the replicated barrier-encrypted store
		// and every node loads it, so any node can issue (IssuerForIdentity
		// resolves the cluster intermediate signing key). hsm/tpm-kek resolve
		// their respective durable stores.
		clusterBackend, err := s.resolveClusterCARuntimeBackend()
		if err != nil {
			return &ErrCAInit{Operation: "resolve cluster CA keystore", Err: err}
		}
		backend = clusterBackend
	} else {
		b, ok := s.backends[string(keystoreType)]
		if !ok {
			return &ErrBackendNotAvailable{Backend: string(keystoreType), Purpose: "CA keystore"}
		}
		backend = b
	}

	// Create certificate storage for the CA
	caStorage, err := s.createStorage("ca")
	if err != nil {
		return &ErrStorageCreate{Resource: "CA storage directory", Err: err}
	}
	certAdapter := storage.NewCertAdapter(caStorage)
	caCertStore, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
	})
	if err != nil {
		return &ErrServiceInit{Service: "CA certificate store", Err: err}
	}

	// Persist certificate serial numbers in the datastore so uniqueness
	// survives restarts (and replicates under Raft). Without this the CA falls
	// back to in-memory serial tracking, which risks issuing duplicate serials
	// after a restart — a violation of X.509 serial uniqueness.
	serialStore, err := s.createStorage("ca-serials")
	if err != nil {
		return &ErrServiceInit{Service: "CA serial store", Err: err}
	}

	// Persist certificate revocations in the datastore so the revocation set
	// survives restarts (and replicates under Raft). Without this, revoked
	// certificates silently become un-revoked after a restart.
	revocationStore, err := s.createStorage("ca-revocations")
	if err != nil {
		return &ErrServiceInit{Service: "CA revocation store", Err: err}
	}

	// Resolve credential:// password references in the CA config before the CA's
	// internal ToKeyAttributes path reads them. The registry falls back to literal
	// pass-through for non-URI values, so existing plaintext passwords are unchanged.
	// Modifications are made directly on the in-memory config; the loaded YAML is
	// never re-serialised, so resolved plaintext does not persist to disk.
	reg := s.buildSecretRegistry()
	for i := range s.config.CA.Identity {
		id := &s.config.CA.Identity[i]
		for j := range id.Keys {
			if id.Keys[j].Password == "" {
				continue
			}
			sv, resolveErr := reg.Resolve(s.ctx, id.Keys[j].Password)
			if resolveErr != nil {
				return &ErrCAInit{Operation: "resolve key password credential", Err: resolveErr}
			}
			// nolint:staticcheck // go-xkms#41: SecretValue.String copies the
			// plaintext into an unwipeable heap string. The replacement
			// (WithBytes, or a SecretValue-typed config field) is borrow-scoped
			// and changes who owns this password for the life of the config, so
			// it is a custody change rather than a call-site swap. Delete this
			// directive when #41 lands.
			id.Keys[j].Password = sv.String()
			sv.Clear()
		}
		if id.Keystores != nil && id.Keystores.Software != nil && id.Keystores.Software.Password != "" {
			sv, resolveErr := reg.Resolve(s.ctx, id.Keystores.Software.Password)
			if resolveErr != nil {
				return &ErrCAInit{Operation: "resolve software keystore password credential", Err: resolveErr}
			}
			// nolint:staticcheck // go-xkms#41: same custody change as above —
			// String hands back an unwipeable heap copy, and the borrow-scoped
			// replacement cannot outlive its callback the way this field does.
			// Delete this directive when #41 lands.
			id.Keystores.Software.Password = sv.String()
			sv.Clear()
		}
	}

	// Create the CA instance
	trustedCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:          s.config.CA,
		KeyStore:        backend,
		CertStore:       caCertStore,
		SerialGen:       ca.NewSerialGenerator(ca.NewBackendStorage(serialStore)),
		RevocationStore: revocationStore,
	})
	if err != nil {
		return &ErrCAInit{Operation: "create CA", Err: err}
	}

	// Adopt any CA certificates pre-staged by the cluster ACME first-node
	// provisioner (pkg/trust/clusterca) so Load finds the full hierarchy and
	// does not re-Init (which would fork a second root). No-op when no staged
	// material exists.
	if err := s.adoptStagedClusterCACerts(caCertStore); err != nil {
		return &ErrCAInit{Operation: "adopt staged cluster CA certificates", Err: err}
	}

	// Try to load existing CA state (certificates and keys from a previous run).
	// If loading fails, the CA has not been initialized yet, so create it.
	if err := trustedCA.Load(s.ctx); err != nil {
		s.logger.Info("No existing CA found, initializing new CA", "reason", err.Error())
		if initErr := trustedCA.Init(s.ctx); initErr != nil {
			return &ErrCAInit{Operation: "initialize new CA", Err: initErr}
		}
	}

	s.ca = trustedCA

	cn := s.config.CA.Identity[0].Subject.CommonName
	s.logger.Info("CA initialized", "identity", cn)

	// If TLS is enabled with a server_cn, auto-issue a TLS server certificate
	// so that buildTLSConfig() can retrieve it for HTTPS/gRPC/QUIC.
	if s.config.TLS.Enabled && s.config.TLS.ServerCN != "" {
		// Boot-time issuance writes the key + certificate into the
		// replicated store; on a cluster this races the initial leader
		// election, so not-leader failures are retried (leader_retry.go).
		if err := retryNotLeader(s.ctx, s.logger, "tls server certificate", func() error {
			return s.ensureTLSServerCert(trustedCA, keystoreType)
		}); err != nil {
			return &ErrTLSCertOp{Operation: "ensure TLS server certificate", Err: err}
		}
		// Swap the CA-issued certificate into the unified API server's
		// rotating provider; until now it served the bootstrap material.
		if err := s.upgradeUnifiedTLSCert(trustedCA); err != nil {
			s.logger.Warn("unified API server keeps serving the bootstrap TLS certificate",
				slog.Any("error", err))
		}
	}

	return nil
}

// tlsBootstrapCA is the subset of ca.TrustedCA the TLS-server-certificate
// bootstrap path (ensureTLSServerCert / syncExistingTLSCert /
// storeTLSCertInBackend) depends on: reading/issuing TLS material
// (ca.CATLSConfig, ca.CAIssuer), the CA's own certificate (ca.CATrustChain),
// and its certificate store (ca.CAStores). Declaring this instead of the
// full ca.TrustedCA keeps the bootstrap path's dependency honest — it never
// touches attestation, cross-signing, revocation, or TCG enrollment.
type tlsBootstrapCA interface {
	ca.CATLSConfig
	ca.CAIssuer
	ca.CATrustChain
	ca.CAStores
}

// ensureTLSServerCert checks if a TLS server certificate exists for the configured
// server CN and issues one from the CA if it doesn't. This enables CA-backed TLS
// without requiring pre-generated cert/key files.
func (s *Server) ensureTLSServerCert(xkmsCA tlsBootstrapCA, keystoreType types.StoreType) error {
	serverCN := s.config.TLS.ServerCN

	// Build key attributes for the TLS server cert using the CA identity's store type
	identity := s.config.CA.Identity[s.config.CA.SelectedCA]
	attrs := &types.KeyAttributes{
		CN:        serverCN,
		StoreType: keystoreType,
		KeyType:   types.KeyTypeTLS,
	}

	// Build SANs from configuration alone (serverCertSANs): the server CN,
	// the loopback names when tls.include_localhost_sans says so, the machine
	// hostname, server.host and tls.extra_sans, so remote clients that dial
	// the node by name pass hostname verification. The certificate used to
	// carry an unconditional 0.0.0.0 IP SAN as well; no client ever dials
	// that address, and a wildcard is not a name a certificate should
	// present (#140).
	dnsNames, ipAddrs := s.serverCertSANs(serverCN, false)

	// An existing certificate is reused only while it presents exactly the
	// configured SANs. One issued before a configuration change -- or before
	// the SANs became configuration at all -- is retired and reissued, or the
	// new setting would never reach an upgraded node.
	retired := false
	if existing, err := xkmsCA.TLSCertificate(s.ctx, attrs); err == nil {
		leaf := tlsLeaf(existing)
		if leaf != nil && certSANsMatch(leaf, dnsNames, ipAddrs) {
			s.logger.Info("TLS server certificate already exists", "cn", serverCN)
			return nil
		}
		if leaf == nil {
			s.logger.Warn("TLS server certificate exists but carries no leaf to inspect; reissuing", "cn", serverCN)
		} else {
			s.logger.Info("TLS server certificate no longer presents the configured SANs; reissuing",
				"cn", serverCN, "have_dns", leaf.DNSNames, "want_dns", dnsNames)
		}
		if err := s.retireTLSServerCert(xkmsCA, serverCN, keystoreType); err != nil {
			return err
		}
		retired = true
	}

	s.logger.Info("Issuing TLS server certificate from CA", "cn", serverCN)

	sanIPs := make([]string, 0, len(ipAddrs))
	for _, ip := range ipAddrs {
		sanIPs = append(sanIPs, ip.String())
	}
	request := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   serverCN,
			Organization: identity.Subject.Organization,
			Country:      identity.Subject.Country,
		},
		SANS:     &ca.SubjectAlternativeNames{DNS: dnsNames, IPs: sanIPs},
		Valid:    s.config.CA.DefaultValidityDays,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	issued, err := xkmsCA.IssueCertificateWithProfile(s.ctx, request, "server")
	if errors.Is(err, ca.ErrCertificateAlreadyExists) {
		// Stale state: the CA's certStore has a certificate the backend lacks
		// (volumes partially cleaned between runs). It is synced to the
		// backend only while it presents the configured SANs; otherwise it
		// is as stale as any other and is retired and reissued, or an
		// upgraded node would keep the old names through this path too.
		existing, gerr := xkmsCA.CertStore().GetCertificate(serverCN)
		if gerr != nil {
			return &ErrTLSCertOp{Operation: "retrieve existing TLS cert from CA certStore", Err: gerr}
		}
		if certSANsMatch(existing, dnsNames, ipAddrs) {
			return s.syncExistingTLSCert(xkmsCA, serverCN, keystoreType)
		}
		s.logger.Info("TLS server certificate in the CA certStore no longer presents the configured SANs; reissuing",
			"cn", serverCN, "have_dns", existing.DNSNames, "want_dns", dnsNames)
		if err := s.retireTLSServerCert(xkmsCA, serverCN, keystoreType); err != nil {
			return err
		}
		retired = true
		issued, err = xkmsCA.IssueCertificateWithProfile(s.ctx, request, "server")
	}
	if err != nil {
		return &ErrTLSCertOp{Operation: "issue TLS server certificate", Err: err}
	}

	// Store the issued cert in the backend's cert storage so that
	// ca.TLSCertificate() → keyStore.GetTLSCertificate() can find it.
	// The CA stores certs in its own certStore, but GetTLSCertificate
	// looks in the compositeBackend's certStorage (separate storage).
	// After a reissue the chain must land too: GetTLSCertificate prefers
	// the stored chain, and a stale chain would pair the old leaf with the
	// new key.
	if err := s.storeTLSCertInBackend(s.ctx, xkmsCA, serverCN, keystoreType, issued.Certificate, retired); err != nil {
		return err
	}

	s.logger.Info("TLS server certificate issued", "cn", serverCN)
	return nil
}

// tlsLeaf returns the certificate a TLS server would actually present: the
// first entry of the Certificate slice, which the backend assembles from a
// stored chain when it has one. The pre-parsed Leaf is only a fallback,
// because the backend sets it from the standalone certificate, and judging
// health by it would let a stale chain pass unnoticed.
func tlsLeaf(cert tls.Certificate) *x509.Certificate {
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			return leaf
		}
	}
	return cert.Leaf
}

// retireTLSServerCert removes a server certificate whose SANs no longer match
// configuration from both places it lives -- the CA's certStore, which is
// what makes IssueCertificateWithProfile refuse a second certificate for the
// CN, and the backend's cert storage, which is what TLSCertificate serves --
// so the reissue that follows starts clean.
func (s *Server) retireTLSServerCert(xkmsCA tlsBootstrapCA, serverCN string, keystoreType types.StoreType) error {
	// Either store may already lack the certificate -- the split-store
	// states this path recovers from -- and absence is exactly what
	// retirement wants.
	if store := xkmsCA.CertStore(); store != nil {
		if err := store.DeleteCertificate(serverCN); err != nil && !errors.Is(err, certstore.ErrCertNotFound) {
			return &ErrTLSCertOp{Operation: "retire stale TLS cert from CA certStore", Err: err}
		}
	}
	backend, ok := s.backends[string(keystoreType)]
	if !ok {
		return &ErrBackendNotAvailable{Backend: string(keystoreType), Purpose: "TLS cert storage"}
	}
	if err := backend.DeleteCert(s.ctx, serverCN); err != nil &&
		!errors.Is(err, xkms.ErrCertNotFound) && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, os.ErrNotExist) {
		return &ErrTLSCertOp{Operation: "retire stale TLS cert from backend", Err: err}
	}
	return nil
}

// syncExistingTLSCert handles the case where the CA's certStore already has a TLS
// certificate (from a previous run) but the backend's certStorage doesn't. This
// happens when Docker volumes are partially cleaned between runs. The function
// retrieves the existing cert from the CA's certStore and stores it in the backend.
func (s *Server) syncExistingTLSCert(xkmsCA tlsBootstrapCA, serverCN string, keystoreType types.StoreType) error {
	s.logger.Info("TLS cert exists in CA but not in backend, syncing", "cn", serverCN)

	cert, err := xkmsCA.CertStore().GetCertificate(serverCN)
	if err != nil {
		return &ErrTLSCertOp{Operation: "retrieve existing TLS cert from CA certStore", Err: err}
	}

	// A sync repairs a split state; the chain the backend will prefer has to
	// land with the leaf, or a stale chain could outlive this repair.
	if err := s.storeTLSCertInBackend(s.ctx, xkmsCA, serverCN, keystoreType, cert, true); err != nil {
		return err
	}

	s.logger.Info("TLS server certificate synced from CA to backend", "cn", serverCN)
	return nil
}

// storeTLSCertInBackend stores a TLS certificate and its chain in the backend's
// cert storage so that ca.TLSCertificate() → keyStore.GetTLSCertificate() can
// find it. The CA stores certs in its own certStore, but GetTLSCertificate looks
// in the compositeBackend's certStorage (separate storage).
//
// chainRequired makes a chain persistence failure fatal. It is set after a
// stale certificate was retired: GetTLSCertificate prefers the stored chain,
// so a chain that failed to update would pair the old leaf with the new key
// and break every handshake. On a first issuance a missing chain only
// degrades to serving the leaf alone.
func (s *Server) storeTLSCertInBackend(ctx context.Context, xkmsCA tlsBootstrapCA, serverCN string, keystoreType types.StoreType, cert *x509.Certificate, chainRequired bool) error {
	backend, ok := s.backends[string(keystoreType)]
	if !ok {
		return &ErrBackendNotAvailable{Backend: string(keystoreType), Purpose: "TLS cert storage"}
	}

	// Everything the chain needs is loaded before the backend is touched, so
	// a required chain that cannot be built leaves the backend exactly as it
	// was: no half-replaced state for the next start to read as healthy.
	caCert, caErr := xkmsCA.CACertificate()
	if caErr != nil || caCert == nil {
		if chainRequired {
			cause := caErr
			if cause == nil {
				cause = ErrTLSCertChainCAUnavailable
			}
			return &ErrTLSCertOp{Operation: "load CA certificate for the reissued TLS cert chain", Err: cause}
		}
		// First issuance without a CA certificate: the leaf alone is served.
		if err := backend.SaveCert(ctx, serverCN, cert); err != nil {
			return &ErrTLSCertOp{Operation: "store TLS cert in backend", Err: err}
		}
		s.logger.Warn("TLS cert chain not stored: CA certificate unavailable", "error", caErr)
		return nil
	}
	chain := []*x509.Certificate{cert, caCert}

	if chainRequired {
		// The backend prefers a stored chain over the standalone leaf when
		// it assembles the served certificate, so after a retirement the
		// chain is replaced FIRST: if that fails nothing has changed, and
		// the stale chain can never be paired with a new leaf.
		if err := backend.SaveCertChain(ctx, serverCN, chain); err != nil {
			return &ErrTLSCertOp{Operation: "store reissued TLS cert chain in backend", Err: err}
		}
		if err := backend.SaveCert(ctx, serverCN, cert); err != nil {
			return &ErrTLSCertOp{Operation: "store reissued TLS cert in backend", Err: err}
		}
		return nil
	}

	if err := backend.SaveCert(ctx, serverCN, cert); err != nil {
		return &ErrTLSCertOp{Operation: "store TLS cert in backend", Err: err}
	}
	if chainErr := backend.SaveCertChain(ctx, serverCN, chain); chainErr != nil {
		s.logger.Warn("Failed to store TLS cert chain in backend", "error", chainErr)
	}
	return nil
}

// Start starts all enabled protocol servers
func (s *Server) Start() error {
	s.logger.Info("Starting xkms server...")

	// Initialize CA bundler from TLS configuration so REST, gRPC, and Noise
	// subsystems can serve the CA certificate bundle for trust bootstrap.
	if s.config.TLS.Enabled && s.config.TLS.CAFile != "" {
		bundler, err := newTLSCABundler(s.config.TLS.CAFile)
		if err != nil {
			s.logger.Warn("Failed to initialize CA bundler", slog.Any("error", err))
		} else {
			rest.SetCABundler(bundler)
			grpcinternal.SetCABundler(bundler)
			s.logger.Info("CA bundler initialized from TLS CA file", "ca_file", s.config.TLS.CAFile)
		}
	} else if s.config.TLS.Enabled && s.ca != nil && s.ca.IsInitialized() {
		// When using CA-backed TLS (no CAFile), create bundler from the CA instance
		bundler, err := newCAInstanceBundler(s.ca)
		if err != nil {
			s.logger.Warn("Failed to initialize CA bundler from CA instance", slog.Any("error", err))
		} else {
			rest.SetCABundler(bundler)
			grpcinternal.SetCABundler(bundler)
			s.logger.Info("CA bundler initialized from CA instance")
		}
	}

	// Initialize metrics if enabled
	if s.config.Metrics.Enabled {
		if err := s.initializeMetrics(); err != nil {
			s.logger.Error("Failed to initialize metrics", slog.Any("error", err))
			return &ErrServiceInit{Service: "metrics", Err: err}
		}
	}

	// Network serving runs exclusively on the unified API server: the
	// embedded qrdb node's multi-protocol server took xkmsd's
	// REST/gRPC/MCP ports during node construction (buildXKMSQRDBConfig;
	// config.Validate guarantees qrdb storage + TLS material) and serves
	// the xkms capability plane through the registered ServiceModule.
	// QUIC is HTTP/3 on the REST port, advertised via Alt-Svc. Local IPC
	// stays in-process: xkmsd's own plaintext Unix socket serves local
	// clients in every storage mode, and the loopback desktop engine
	// serves an injected listener.
	if s.config.NetworkServing() {
		s.logger.Info("unified API server: embedded qrdb node serves the network protocols via the xkms ServiceModule",
			"rest_port", s.config.Server.RESTPort,
			"grpc_port", s.config.Server.GRPCPort,
			"mcp_port", s.config.Server.MCPPort,
			"quic", "http3 on rest_port")
	}

	// Unix socket for local IPC. xkmsd always serves its own socket: the
	// local IPC contract is plaintext gRPC guarded by filesystem
	// permissions, and the plaintext clients (pkcs11 module, CLI, SDK unix
	// transport) depend on it in every storage mode. The embedded node's
	// TLS-only UDS is deliberately not used for this plane
	// (buildXKMSQRDBConfig leaves the node's Unix protocol off).
	if s.config.Protocols.Unix {
		s.wg.Add(1)
		go s.startUnix()
	}

	// Loopback desktop engine: serve REST on the injected pre-bound
	// listener (127.0.0.1:0) only. Network REST is the unified server's.
	if s.restListener != nil {
		s.wg.Add(1)
		go s.startREST()
	}

	// Start Noise bootstrap server if enabled
	if s.config.Protocols.Noise {
		s.wg.Add(1)
		go s.startNoiseBootstrap()
	}

	// Start metrics server if enabled
	if s.config.Metrics.Enabled {
		s.wg.Add(1)
		go s.startMetrics()
	}

	// Mark service as fully started for startup probes
	if s.healthChecker != nil {
		s.healthChecker.MarkStarted()
		s.logger.Info("Health checker marked as started")
	}

	s.logger.Info("All servers started successfully")

	return nil
}

// startUnix starts the Unix domain socket server (IPC, HTTP or gRPC based on configuration)
func (s *Server) startUnix() {
	defer s.wg.Done()

	// Determine socket path
	socketPath := s.config.Unix.SocketPath
	if socketPath == "" {
		socketPath = unix.DefaultSocketPath
	}

	// Determine protocol (default to gRPC)
	protocol := s.config.Unix.Protocol
	if protocol == "" {
		protocol = "grpc"
	}

	// Start server based on protocol configuration
	switch protocol {
	case "grpc":
		s.logger.Info("Starting Unix socket with gRPC protocol", "socket", socketPath)

		// Create Unix gRPC server configuration
		// Note: Logger is nil - the unix package will use its internal noOpLogger
		grpcConfig := &unix.GRPCConfig{
			SocketPath:      socketPath,
			Logger:          nil,
			XKMSService:     s.xkmsService,
			SSHClient:       s.ensureSSHClient(),
			BarrierRegistry: s.barrierRegistry,
			// Host the embedded qrdb node's control plane (cluster admin,
			// rebalance, user auth factors) on the unix socket — xkmsctl's
			// default transport. Same socket-file-mode trust boundary as the
			// keystore service above.
			ExtraServices: []func(*grpc.Server){s.registerQRDBControlPlane},
		}

		grpcServer, err := unix.NewGRPCServer(grpcConfig)
		if err != nil {
			s.logger.Error("Failed to create Unix gRPC server", slog.Any("error", err))
			return
		}

		// Store the server so Shutdown can stop it. If Shutdown already began
		// (ctx cancelled) before we got here, do not start — return so this
		// goroutine releases its wg slot instead of blocking in Start (which
		// Shutdown could not stop, since it copied a nil reference).
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		s.unixGRPCServer = grpcServer
		s.mu.Unlock()

		if err := grpcServer.Start(); err != nil {
			s.logger.Error("Unix gRPC server error", slog.Any("error", err))
		}

	default:
		s.logger.Error("Unknown Unix socket protocol", "protocol", protocol)
	}
}

// xkmsServiceRef returns the composed XKMSService reference under the
// server lock, or nil while composition is still running. The module's
// lazy resolvers read through this so the unified server's concurrent RPCs
// never race the composition-time assignment.
func (s *Server) xkmsServiceRef() *xkms.XKMSService {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.xkmsService
}

// ModuleRESTServer resolves the *rest.Server backing the unified-API-server
// module's HTTP surface (pkg/apimodule RegisterHTTP). It prefers the running
// legacy REST server so both surfaces share one handler state; when the
// legacy REST transport is disabled it lazily constructs a non-listening
// rest.Server from the identical configuration. Returns nil while the
// XKMSService is still composing — module routes answer 503 until then.
func (s *Server) ModuleRESTServer() *rest.Server {
	s.mu.Lock()
	if s.restServer != nil {
		srv := s.restServer
		s.mu.Unlock()
		return srv
	}
	composing := s.xkmsService == nil
	s.mu.Unlock()
	if composing {
		return nil
	}

	s.moduleRESTOnce.Do(func() {
		cfg, err := s.buildRESTConfig()
		if err != nil {
			s.logger.Error("module REST binding: config build failed", slog.Any("error", err))
			return
		}
		srv, err := rest.NewServer(cfg)
		if err != nil {
			s.logger.Error("module REST binding: server construction failed", slog.Any("error", err))
			return
		}
		s.mu.Lock()
		s.moduleREST = srv
		s.mu.Unlock()
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.moduleREST != nil {
		return s.moduleREST
	}
	return s.restServer
}

// buildRESTConfig assembles the full REST server configuration from the
// composed server state. It is shared by the legacy in-process REST listener
// (startREST) and the unified-API-server ServiceModule's lazy REST binding
// (pkg/apimodule), so both surfaces are built from identical wiring.
func (s *Server) buildRESTConfig() (*rest.Config, error) {
	restConfig := &rest.Config{
		Host:              s.config.Server.Host,
		Port:              s.config.Server.RESTPort,
		Backends:          s.backends,
		Version:           getBuildVersion(),
		Authenticator:     s.liveAuthenticator,
		EnableRBAC:        s.config.Auth.EnableRBAC,
		RBACAuthorizer:    s.rbacAuthorizer,
		AuditLogger:       s.auditLogger,
		Barrier:           s.barrier,
		PINManager:        s.pinManager,
		PasswordStore:     s.passwordStore,
		PlatformStore:     s.platformStore,
		PolicyManager:     s.policyManager,
		BarrierRegistry:   s.barrierRegistry,
		CustodianEnabled:  s.qrdbClient != nil,
		ShareEnabled:      s.qrdbClient != nil,
		CeremonyService:   s.ceremonyService,
		CredentialService: s.credentialService,
		XKMSService:       s.xkmsService,
		SSHClient:         s.ensureSSHClient(),
	}

	// Embedded web UI: serve the compiled SPA (installed via SetUIAssets)
	// unless the configuration explicitly disables it. The prefix and root
	// redirect come from the ui config section; empty prefix selects the
	// REST transport's default.
	if s.uiAssets != nil && s.config.UIEnabled() {
		restConfig.UI = &rest.UIOptions{
			Enabled:      true,
			PathPrefix:   s.config.UI.PathPrefix,
			Assets:       s.uiAssets,
			RedirectRoot: s.config.UI.RedirectRoot,
		}
	}

	// Cross-origin access is opt-in: without an explicit allowlist the REST
	// router emits no CORS headers and browsers enforce same-origin (the
	// embedded web UI is served same-origin and needs none).
	if s.config.CORS.Enabled {
		restConfig.CORS = &rest.CORSOptions{
			AllowedOrigins:   s.config.CORS.AllowedOrigins,
			AllowCredentials: s.config.CORS.AllowCredentials,
			MaxAgeSeconds:    s.config.CORS.MaxAgeSeconds,
		}
	}

	// Session-token plane: the issuer behind the login flows plus a
	// dedicated, stricter per-client limiter on the login/refresh/ceremony
	// endpoints (hardware-ceremony endpoints are expensive and the exchange
	// endpoints are unauthenticated by design).
	if s.tokenIssuer != nil {
		restConfig.TokenIssuer = s.tokenIssuer
		restConfig.AuthUserStore = s.mtlsUserStore()

		loginRate := 10
		if s.config.Auth.Session != nil && s.config.Auth.Session.LoginRatePerMin > 0 {
			loginRate = s.config.Auth.Session.LoginRatePerMin
		}
		restConfig.AuthRateLimiter = ratelimit.New(&ratelimit.Config{
			Enabled:           true,
			RequestsPerMinute: loginRate,
		})

		if s.config.Auth.PIVLogin != nil {
			restConfig.PIVLogin = &rest.PIVLoginOptions{
				Enabled:        s.config.Auth.PIVLogin.Enabled,
				TrustedIssuers: s.config.Auth.PIVLogin.TrustedIssuers,
			}
		}
	}

	// When xkms hosts/dials the qrdb engine, persist WebAuthn users and
	// credentials on qrdb — the single source of identity.
	if s.qrdbClient != nil {
		restConfig.WebAuthnUsers = s.qrdbClient.Users()
		restConfig.WebAuthnKV = s.qrdbClient.KV()
	}

	// Pass the XKMSService as CA servicer. The XKMSService wraps the raw CA
	// with transport-level methods (GetCABundle, IssueCertificate, etc.) that
	// match the caServicer interface expected by the REST handlers.
	if s.ca != nil && s.xkmsService != nil {
		restConfig.CA = s.xkmsService
	}

	// Add WebAuthn config if enabled, sharing the single service instance so the
	// REST browser ceremony and the SDK ceremony operate on the same sessions
	// and credentials.
	if s.webauthnConfig != nil {
		restConfig.WebAuthnConfig = s.webauthnConfig
		restConfig.WebAuthnService = s.webauthnService
		s.logger.Info("WebAuthn enabled for REST server",
			"rp_id", s.webauthnConfig.RPID)
	}

	// Add TLS config if enabled
	if s.config.TLS.Enabled {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		restConfig.TLSConfig = tlsConfig
	}

	return restConfig, nil
}

// startREST starts the REST API server
func (s *Server) startREST() {
	defer s.wg.Done()

	restConfig, err := s.buildRESTConfig()
	if err != nil {
		s.logger.Error("Failed to build REST server config", slog.Any("error", err))
		return
	}

	// Loopback launcher: serve a pre-bound listener (127.0.0.1:0) instead of
	// binding the configured port, so the desktop standalone engine is
	// off-box unreachable and its ephemeral port is known to the shell.
	if s.restListener != nil {
		restConfig.Listener = s.restListener
	}

	// Create REST server
	restSrv, err := rest.NewServer(restConfig)
	if err != nil {
		s.logger.Error("Failed to create REST server", slog.Any("error", err))
		return
	}

	// Store the server so Shutdown can stop it. If Shutdown already began (ctx
	// cancelled) before we got here, do not start — return so this goroutine
	// releases its wg slot instead of blocking in Start.
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.restServer = restSrv
	s.mu.Unlock()

	// Configure health checker for REST API
	if s.healthChecker != nil {
		restSrv.SetHealthChecker(s.healthChecker)
		s.logger.Info("Health checker configured for REST server")
	}

	s.logger.Info("Starting REST server",
		"port", s.config.Server.RESTPort,
		"auth", s.authenticator.Name(),
		"rbac", s.config.Auth.EnableRBAC)

	if err := restSrv.Start(); err != nil {
		s.logger.Error("REST server error", slog.Any("error", err))
	}
}

// initializeMetrics initializes the metrics subsystem
func (s *Server) initializeMetrics() error {
	s.logger.Info("Initializing metrics...")

	// Enable metrics collection
	metrics.Enable()

	// Start resource collector with 30-second interval
	s.metricsCollector = metrics.StartResourceCollector(s.ctx, 30*time.Second)

	// Initialize backend health metrics
	for name := range s.keyProviders {
		metrics.SetBackendHealth(name, true)
	}

	s.logger.Info("Metrics initialized successfully")
	return nil
}

// listenAddr joins the configured bind host with a listener's port the way
// net.Listen expects it: an IPv6 host is bracketed ("[::1]:9090"), the empty
// default host binds every interface (":9090"). Every daemon listener that
// takes an address string builds it here, so server.host is consumed the same
// way by all of them; building it with "%s:%d" produced "::1:9090" for an
// IPv6 host, which net.Listen rejects (#140, review on #492).
func (s *Server) listenAddr(port int) string {
	return net.JoinHostPort(s.config.Server.Host, strconv.Itoa(port))
}

// startMetrics starts the Prometheus metrics server
func (s *Server) startMetrics() {
	defer s.wg.Done()

	addr := s.listenAddr(s.config.Metrics.Port)

	mux := http.NewServeMux()
	mux.Handle(s.config.Metrics.Path, promhttp.Handler())

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
	}

	// Publish the server so Shutdown can stop it. Guard against a Shutdown that
	// already began (ctx cancelled): in that case do not start serving, so this
	// goroutine returns promptly and releases its wg slot.
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.metricsServer = server
	s.mu.Unlock()

	s.logger.Info("Starting metrics server", "address", addr, "path", s.config.Metrics.Path)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error("Metrics server error", slog.Any("error", err))
	}
}

// startMCP starts the MCP JSON-RPC server
// buildMCPConfig assembles the MCP server configuration from the composed
// server state. It is shared by the legacy JSON-RPC listener (startMCP) and
// the unified-API-server ServiceModule's lazy MCP binding (pkg/apimodule),
// so both surfaces run the identical wiring and gates.
func (s *Server) buildMCPConfig() (*mcp.Config, error) {
	// Get default keystore for MCP (use first available if no default specified)
	var defaultKS xkms.Backend
	if s.config.Default != "" {
		defaultKS = s.backends[string(s.config.Default)]
	}
	if defaultKS == nil {
		for _, ks := range s.backends {
			defaultKS = ks
			break
		}
	}
	if defaultKS == nil {
		return nil, &MCPConfigError{Reason: "no keystore available"}
	}

	addr := s.listenAddr(s.config.Server.MCPPort)

	return &mcp.Config{
		Addr:        addr,
		Logger:      s.logger.With("component", "mcp"),
		XKMSService: s.xkmsService,
		SSHClient:   s.ensureSSHClient(),
		// Thread the resolved authenticator through: mcp.NewServer now
		// rejects a nil authenticator rather than silently substituting a
		// no-op one, so omitting it would leave MCP unable to start.
		Authenticator: s.liveAuthenticator,
		// Authorization uses the same qrdb-backed authorizer as REST, gRPC,
		// and QUIC. mcp.NewServer fails closed when RBAC is enabled without a
		// usable authorizer (RBAC on, no qrdb identity plane), so MCP never
		// runs believing it enforces RBAC while allowing every method.
		EnableRBAC: s.config.Auth.EnableRBAC,
		Authorizer: s.rbacAuthorizer,
		// BarrierRegistry gates per-request tenant access the same way REST,
		// gRPC, and QUIC do (see pkg/api/tenantgate).
		BarrierRegistry: s.barrierRegistry,
	}, nil
}

// MCPConfigError reports why the MCP configuration could not be assembled.
type MCPConfigError struct{ Reason string }

// Error implements the error interface.
func (e *MCPConfigError) Error() string { return "server: mcp config: " + e.Reason }

// ModuleMCPServer resolves the *mcp.Server backing the unified-API-server
// module's real MCP tools (pkg/apimodule RegisterMCP). It prefers the
// running legacy MCP server; when the legacy MCP transport is disabled it
// lazily constructs a non-listening mcp.Server from the identical
// configuration. Returns nil while the XKMSService is still composing.
func (s *Server) ModuleMCPServer() *mcp.Server {
	s.mu.Lock()
	composing := s.xkmsService == nil
	s.mu.Unlock()
	if composing {
		return nil
	}

	s.moduleMCPOnce.Do(func() {
		cfg, err := s.buildMCPConfig()
		if err != nil {
			s.logger.Error("module MCP binding: config build failed", slog.Any("error", err))
			return
		}
		srv, err := mcp.NewServer(cfg)
		if err != nil {
			s.logger.Error("module MCP binding: server construction failed", slog.Any("error", err))
			return
		}
		s.mu.Lock()
		s.moduleMCP = srv
		s.mu.Unlock()
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.moduleMCP
}

// startNoiseBootstrap starts the Noise_NK bootstrap server for secure CA bundle distribution.
func (s *Server) startNoiseBootstrap() {
	defer s.wg.Done()

	addr := s.listenAddr(s.config.Server.NoisePort)

	// Get CA bundler
	bundler := grpcinternal.GetCABundler()
	if bundler == nil {
		s.logger.Error("Noise bootstrap requires a CA bundler to be configured")
		return
	}

	noiseCfg := s.config.Bootstrap.Noise

	// Parse timeouts
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	if noiseCfg.ReadTimeout != "" {
		if d, err := time.ParseDuration(noiseCfg.ReadTimeout); err == nil {
			readTimeout = d
		}
	}
	if noiseCfg.WriteTimeout != "" {
		if d, err := time.ParseDuration(noiseCfg.WriteTimeout); err == nil {
			writeTimeout = d
		}
	}

	maxConns := noiseCfg.MaxConnections
	if maxConns <= 0 {
		maxConns = 100
	}

	// Resolve which handshake suites this build can offer and load a static
	// key for each, BEFORE the listener is constructed. A build that can serve
	// no suite says so once, here, instead of binding a port and then refusing
	// every handshake (go-xkms#269, go-trusted-platform#209).
	//
	// Ownership stays here until the keys are published to the Server below:
	// every early return between the two points has to release the protected
	// pages, and the pre-publication cancellation path is a normal shutdown
	// race, not an exceptional one.
	keys, err := s.loadBootstrapKeys()
	if err != nil {
		s.logger.Error("Failed to load bootstrap static keys", slog.Any("error", err))
		return
	}
	// This goroutine owns the keys ONLY until it publishes them below.
	//
	// It used to own them outright, on the stated premise that "Start blocks
	// until the server has stopped". That premise is false:
	// noiseboot.Server.Start binds the listener, launches its accept loop in
	// a goroutine, and returns nil. Destroying on the way out of this
	// function therefore freed the protected pages while the published server
	// and every future handshake still aliased the key — a use-after-free
	// reachable by any client that connected afterwards.
	//
	// So ownership moves to the Server at publication, and Shutdown destroys
	// the keys once Stop has confirmed the workers exited. Every exit path
	// BEFORE publication still has to release them, which is what published
	// tracks.
	published := false
	defer func() {
		if !published {
			keys.destroy()
		}
	}()

	serverCfg := &noiseboot.ServerConfig{
		ListenAddr: addr,
		// Both keys alias protected private scalars, so the bootstrap server
		// reads them in place. They stay valid until Shutdown stops the server
		// and destroys them. A nil key means that suite is not offered, and
		// the listener refuses its suite byte per connection; loadBootstrapKeys
		// has already guaranteed at least one is set.
		StaticKey:      bootstrap.NoiseServerStaticKey(keys.noise),
		P256StaticKey:  keys.p256,
		CABundler:      bundler,
		MaxConnections: maxConns,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		Logger:         s.logger.With("component", "noise_bootstrap"),
	}

	server, err := noiseboot.NewServer(serverCfg)
	if err != nil {
		s.logger.Error("Failed to create Noise bootstrap server", slog.Any("error", err))
		return
	}

	// Do not start at all if Shutdown has already begun.
	s.mu.Lock()
	cancelled := s.ctx.Err() != nil
	s.mu.Unlock()
	if cancelled {
		return
	}

	s.logger.Info("Starting Noise bootstrap server", "address", addr)

	if err := server.Start(); err != nil {
		// No accept loop exists, so nothing can be reading the key. The defer
		// releases it.
		s.logger.Error("Noise bootstrap server error", slog.Any("error", err))
		return
	}

	// Publish only AFTER Start succeeds, and re-check the shutdown context
	// under the same lock.
	//
	// Publishing before Start left a window that made the key destruction
	// unsafe again: Shutdown could snapshot a server that had not started,
	// call Stop on it (which returns ErrServerNotStarted without waiting for
	// anything), read that as a clean drain, and destroy the key — and only
	// then would this goroutine reach Start and hand the accept loop a DHKey
	// aliasing freed pages.
	//
	// Ordering it this way closes the window from both sides, because both
	// sides move under s.mu. Either Shutdown observes a published, started
	// server and stops it, or it does not observe one at all and this
	// goroutine sees the cancelled context and stops the server itself.
	s.mu.Lock()
	cancelled = s.ctx.Err() != nil
	if !cancelled {
		s.noiseBootstrapServer = server
		s.noiseBootstrapKey = keys.noise
		s.p256BootstrapKey = keys.p256
		published = true
	}
	s.mu.Unlock()

	if !cancelled {
		return
	}

	// Shutdown began while we were starting, so it never saw this server and
	// stopping it is ours to do — with the same rule about the key: destroy
	// only on a confirmed drain.
	s.logger.Info("Shutdown began during Noise bootstrap startup; stopping the server it did not see")

	stopCtx, cancelStop := context.WithTimeout(context.Background(), noiseBootstrapStopTimeout)
	stopErr := server.Stop(stopCtx)
	if stopErr != nil {
		s.logger.Error("Error stopping the Noise bootstrap server", slog.Any("error", stopErr))
	}

	// The same decision Shutdown makes, through the same function. This path
	// once read the context alone, which treats a Stop that never waited for
	// anything as a completed drain and destroys a key whose handshake workers
	// may still be running.
	joined := noiseStopDrained(stopErr)
	cancelStop()

	if !joined {
		// Retained rather than freed, and deliberately kept reachable: see
		// the note on retention in Shutdown.
		published = true
		s.retainBootstrapKeys(keys)
		s.logger.Warn("retaining the bootstrap static keys: Stop did not " +
			"confirm a drain during startup teardown")
	}
}

// retainNoiseKey parks a static key that a shutdown could not prove
// unreferenced, keeping its owner reachable for the life of the Server.
func (s *Server) retainNoiseKey(key *noiseproto.StaticKey) {
	if key == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.retainedNoiseKeys = append(s.retainedNoiseKeys, key)
}

// retainBootstrapKeys parks both of a listener's static keys under the same
// rule retainNoiseKey applies to one: a key a shutdown could not prove
// unreferenced is kept, not freed. Nil fields are skipped, so a build that
// offered only one suite retains only that suite's key.
func (s *Server) retainBootstrapKeys(keys *bootstrapKeys) {
	if keys == nil {
		return
	}

	s.retainNoiseKey(keys.noise)

	if keys.p256 == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.retainedP256Keys = append(s.retainedP256Keys, keys.p256)
}

// loadNoiseStaticKey loads the Noise static key from config. The returned key
// holds its private scalar in protected memory; the caller owns it and must
// Destroy it once the bootstrap server that uses it has stopped.
func (s *Server) loadNoiseStaticKey() (*noiseproto.StaticKey, error) {
	noiseCfg := s.config.Bootstrap.Noise

	// Try hex key first (inline config)
	if noiseCfg.StaticKeyHex != "" {
		// The configured string is immutable and cannot be wiped; the copy we
		// make for decoding can be, so it does not outlive this call.
		hexKey := []byte(noiseCfg.StaticKeyHex)
		defer noiseproto.WipeBytes(hexKey)
		return noiseproto.DecodeStaticKey(hexKey)
	}

	// Try key file
	if noiseCfg.StaticKeyFile != "" {
		// #nosec G304 - Key file path from trusted config
		data, err := os.ReadFile(noiseCfg.StaticKeyFile)
		if err != nil {
			return nil, &ErrFileRead{Path: "noise key file", Err: err}
		}
		// TrimSpace returns a subslice of data, so wiping data covers both.
		defer noiseproto.WipeBytes(data)
		return noiseproto.DecodeStaticKey(bytes.TrimSpace(data))
	}

	// Generate a new key (first-time setup)
	s.logger.Warn("No Noise static key configured, generating ephemeral key. This is NOT recommended for production.")
	return noiseproto.GenerateStaticKey()
}

// buildTLSConfig builds a crypto/tls.Config from the server configuration
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLS.Enabled {
		return nil, ErrTLSNotEnabled
	}

	// Load server certificate -- prefer CA-backed (hardware crypto.Signer) over file-based
	var cert tls.Certificate
	var certLoaded bool
	if s.ca != nil && s.ca.IsInitialized() {
		// CA-backed TLS: the CA provides a tls.Certificate with crypto.Signer
		// from the configured backend. Private key management is handled by the CA.
		identity := s.config.CA.Identity[s.config.CA.SelectedCA]
		keystoreType := identity.GetStoreType()
		attrs, tlsErr := types.KeyAttributesFromConfig(identity.Keys[0])
		if tlsErr == nil {
			attrs.CN = s.config.TLS.ServerCN
			attrs.StoreType = keystoreType
			attrs.KeyType = types.KeyTypeTLS
			var err error
			cert, err = s.ca.TLSCertificate(s.ctx, attrs)
			if err != nil {
				if s.config.TLS.CertFile == "" && s.config.TLS.KeyFile == "" {
					return nil, &ErrTLSCertOp{Operation: "load CA-backed TLS certificate", Err: err, Sentinel: ErrCATLSCertFailed}
				}
				s.logger.Warn("CA-backed TLS unavailable, falling back to file-based TLS",
					"error", err)
			} else {
				s.logger.Info("Using CA-backed TLS certificate", "cn", s.config.TLS.ServerCN)
				certLoaded = true
			}
		} else {
			if s.config.TLS.CertFile == "" && s.config.TLS.KeyFile == "" {
				return nil, &ErrTLSCertOp{Operation: "build TLS key attributes from CA config", Err: tlsErr, Sentinel: ErrCATLSCertFailed}
			}
			s.logger.Warn("Failed to build TLS key attributes from CA config, falling back to file-based TLS",
				"error", tlsErr)
		}
	}
	if !certLoaded && s.config.TLS.CertFile != "" && s.config.TLS.KeyFile != "" {
		// File-based TLS: backward compatible with existing deployments
		var err error
		cert, err = tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
		if err != nil {
			return nil, &ErrTLSCertOp{Operation: "load server certificate", Err: err}
		}
		certLoaded = true
		s.logger.Info("Using file-based TLS certificate")
	}
	if !certLoaded {
		return nil, ErrNoTLSCertAvailable
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Default to TLS 1.3; operators may opt down via config
	}

	// Set TLS version based on configuration
	if s.config.TLS.MinVersion != "" {
		minVersion := parseTLSVersion(s.config.TLS.MinVersion)
		if minVersion > 0 {
			tlsConfig.MinVersion = minVersion
		}
	}

	if s.config.TLS.MaxVersion != "" {
		maxVersion := parseTLSVersion(s.config.TLS.MaxVersion)
		if maxVersion > 0 {
			tlsConfig.MaxVersion = maxVersion
		}
	}

	// Build the unified ClientCAs pool from the primary CA file plus
	// any additional client CAs configured via TLS.ClientCAs. The helper
	// canonicalizes each path and deduplicates by filename so the same
	// CA referenced from multiple sources is loaded only once.
	primary := []string{}
	if s.config.TLS.CAFile != "" {
		primary = append(primary, s.config.TLS.CAFile)
	}
	clientPool, err := loadClientCAsUnion(primary, s.config.TLS.ClientCAs)
	if err != nil {
		// Map the helper's typed error into the legacy CA parse sentinel
		// when the failure is the primary CAFile entry to keep callers
		// that match on ErrCAParseCert stable.
		var certParseErr *ErrCertParse
		if errors.As(err, &certParseErr) && s.config.TLS.CAFile != "" && certParseErr.Path != "" {
			if abs, absErr := filepath.Abs(s.config.TLS.CAFile); absErr == nil && abs == certParseErr.Path {
				return nil, ErrCAParseCert
			}
		}
		return nil, err
	}
	if clientPool != nil {
		tlsConfig.ClientCAs = clientPool
	}

	// Configure client authentication (mTLS) if specified
	switch s.config.TLS.ClientAuth {
	case "require", "require_and_verify":
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "verify":
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case "request":
		tlsConfig.ClientAuth = tls.RequestClientCert
	default:
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	// Set cipher suites if specified
	if len(s.config.TLS.CipherSuites) > 0 {
		tlsConfig.CipherSuites = parseCipherSuites(s.config.TLS.CipherSuites)
	}

	// Configure server cipher preference

	return tlsConfig, nil
}

// parseTLSVersion converts a version string to a tls.uint16 version constant
func parseTLSVersion(version string) uint16 {
	switch version {
	case "TLS1.2", "tls1.2", "1.2":
		return tls.VersionTLS12
	case "TLS1.3", "tls1.3", "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// parseCipherSuites converts cipher suite names to their corresponding constants
func parseCipherSuites(names []string) []uint16 {
	cipherMap := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	var result []uint16
	for _, name := range names {
		if cipher, ok := cipherMap[name]; ok {
			result = append(result, cipher)
		}
	}
	return result
}

// handleHealth handles health check requests

// Shutdown gracefully shuts down all servers
func (s *Server) Shutdown() error {
	// Latched. Concurrent callers used to race into close(s.shutdownCh) and
	// panic on close-of-closed; they also each independently stopped the
	// bootstrap server and could destroy the same protected key twice. Now
	// the first caller performs the shutdown and everyone receives its
	// result.
	s.shutdownOnce.Do(func() { s.shutdownErr = s.shutdown() })
	return s.shutdownErr
}

func (s *Server) shutdown() error {
	s.logger.Info("Shutting down server...")

	// Components that could not be proven drained. Collected rather than
	// logged-and-forgotten: a shutdown that returns nil over a timed-out
	// drain tells a caller holding a borrowed key that freeing it is safe.
	var incomplete []string

	// Stop metrics collector if running
	if s.metricsCollector != nil {
		s.logger.Info("Stopping metrics collector...")
		s.metricsCollector.Stop()
	}

	// Cancel context to signal all goroutines
	s.cancel()

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Copy server references under lock to avoid races with startup goroutines
	// We copy first, then release the lock before calling shutdown operations
	// which could take a long time
	// The Noise bootstrap server and its key are CLAIMED here, not merely
	// read: taken and cleared in one critical section so a concurrent
	// Shutdown cannot snapshot the same key, stop the same server
	// independently, and destroy pages the other caller is still draining.
	// A write lock rather than a read lock, for the same reason.
	s.mu.Lock()
	unixGRPC := s.unixGRPCServer
	restSrv := s.restServer
	noiseSrv := s.noiseBootstrapServer
	noiseKeys := &bootstrapKeys{noise: s.noiseBootstrapKey, p256: s.p256BootstrapKey}
	s.noiseBootstrapServer = nil
	s.noiseBootstrapKey = nil
	s.p256BootstrapKey = nil
	raftAdv := s.raftClusterAdvertiser
	metricsSrv := s.metricsServer
	s.mu.Unlock()

	// Shutdown metrics server. Without this its ListenAndServe blocks forever,
	// so the startMetrics goroutine never calls wg.Done and the wait below can
	// only end via the timeout branch.
	if metricsSrv != nil {
		s.logger.Info("Shutting down metrics server...")
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down metrics server", slog.Any("error", err))
		}
	}

	// Shutdown Unix gRPC socket server
	if unixGRPC != nil {
		s.logger.Info("Shutting down Unix gRPC socket server...")
		if err := unixGRPC.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down Unix gRPC socket server", slog.Any("error", err))
		}
	}

	// Shutdown REST server
	if restSrv != nil {
		s.logger.Info("Shutting down REST server...")
		if err := restSrv.Stop(shutdownCtx); err != nil {
			s.logger.Error("Error shutting down REST server", slog.Any("error", err))
		}
	}

	// Shutdown Noise bootstrap server
	if noiseSrv != nil {
		s.logger.Info("Shutting down Noise bootstrap server...")

		// Its own deadline, derived from the shutdown budget. Stop's outcome
		// has to be attributable to THIS server: sharing shutdownCtx would
		// let a slow earlier step exhaust the budget and make a bootstrap
		// server that drained instantly look like one that hung.
		noiseCtx, cancelNoise := context.WithTimeout(shutdownCtx, noiseBootstrapStopTimeout)
		stopErr := noiseSrv.Stop(noiseCtx)
		if stopErr != nil {
			s.logger.Error("Error shutting down Noise bootstrap server", slog.Any("error", stopErr))
		}

		joined := noiseStopDrained(stopErr)
		cancelNoise()

		if joined {
			noiseKeys.destroy()
		} else {
			incomplete = append(incomplete, "noise bootstrap handshake workers")
			s.retainBootstrapKeys(noiseKeys)
			s.logger.Warn("retaining the bootstrap static keys: Stop did not " +
				"confirm a drain, so a handshake may still be reading them")
		}
	}

	// Shutdown the Raft cluster-TLS Noise advertiser (first node only)
	if raftAdv != nil {
		s.logger.Info("Stopping Raft cluster-TLS advertiser...")
		raftAdv.Stop()
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All servers stopped")
	case <-shutdownCtx.Done():
		s.logger.Warn("Shutdown timeout exceeded, forcing stop")
		incomplete = append(incomplete, "server goroutines")
	}

	// Close audit logger
	if s.auditLogger != nil {
		if err := s.auditLogger.Close(); err != nil {
			s.logger.Error("Failed to close audit logger", slog.Any("error", err))
		}
	}

	// Close all backends
	for name, ks := range s.backends {
		s.logger.Info("Closing backend...", "backend", name)
		if err := ks.Close(); err != nil {
			s.logger.Error("Error closing backend", slog.Any("error", err), "backend", name)
		}
	}

	// Close all key providers
	s.closeBackends()

	// A key retained by startNoiseBootstrap's own teardown happens in a
	// goroutine that cannot reach this function's incomplete list, so read
	// the retention set instead. The retained key IS the observable record
	// that some worker could not be confirmed finished; leaving that visible
	// only in a log line was the last place an incomplete shutdown could
	// still report success.
	s.mu.RLock()
	retained := len(s.retainedNoiseKeys) + len(s.retainedP256Keys)
	s.mu.RUnlock()
	if retained > 0 {
		incomplete = append(incomplete,
			fmt.Sprintf("%d retained bootstrap static key(s)", retained))
	}

	close(s.shutdownCh)

	if len(incomplete) > 0 {
		s.logger.Warn("server shutdown complete, but some components could not "+
			"be confirmed drained", "components", strings.Join(incomplete, ", "))
		return fmt.Errorf("%w: %s", ErrShutdownIncomplete, strings.Join(incomplete, ", "))
	}

	s.logger.Info("Server shutdown complete")
	return nil
}

// closeBackends closes all key provider connections and, when in use, the
// shared qrdb storage backend. closeQRDBStorage is idempotent, so callers may
// invoke closeBackends on any error path without double-close concerns.
func (s *Server) closeBackends() {
	for name, backend := range s.keyProviders {
		s.logger.Info("Closing key provider...", "key_provider", name)
		if err := backend.Close(); err != nil {
			s.logger.Error("Error closing backend", slog.Any("error", err), "backend", name)
		}
	}
	if err := s.closeQRDBStorage(); err != nil {
		s.logger.Error("Error closing qrdb storage", slog.Any("error", err))
	}
}

// WaitForShutdown blocks until the server is shut down
func (s *Server) WaitForShutdown() {
	<-s.shutdownCh
}

// SetupSignalHandler sets up signal handling for graceful shutdown
func SetupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is called in the goroutine below

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		slog.Info("Received shutdown signal")
		cancel()
	}()

	return ctx
}

// RESTServer returns the REST server instance
func (s *Server) RESTServer() *rest.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.restServer
}

// MCPServer returns the MCP dispatch backend the unified server's module
// tools drive (nil until first resolved via ModuleMCPServer).
func (s *Server) MCPServer() *mcp.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.moduleMCP
}

// NoiseBootstrapServer returns the Noise bootstrap server instance
func (s *Server) NoiseBootstrapServer() *noiseboot.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.noiseBootstrapServer
}

// UnixGRPCServer returns the Unix gRPC socket server instance
func (s *Server) UnixGRPCServer() *unix.GRPCServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unixGRPCServer
}
