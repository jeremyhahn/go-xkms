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
	"errors"
	"fmt"
)

// Sentinel errors for static conditions.
var (
	// ErrPhoneConfigNil indicates the phone backend configuration is nil.
	// ErrShutdownIncomplete reports that Shutdown finished without being able
	// to confirm every component had drained. The server IS shut down and
	// needs no second call; what the error says is that some worker could not
	// be proven finished, so anything it may still be reading — protected key
	// pages above all — was retained rather than freed.
	//
	// It exists because the alternative was returning nil over a timed-out
	// drain, which tells a caller holding a borrowed key that destroying it
	// is safe. Every component in this shutdown path now reports incomplete
	// the same way; this is the layer that had to start listening.
	ErrShutdownIncomplete = errors.New("server: shutdown could not confirm every component drained")

	ErrPhoneConfigNil = errors.New("server: phone backend configuration is not set")

	// ErrPhoneBackendCreate indicates the phone backend could not be created.
	ErrPhoneBackendCreate = errors.New("server: failed to create phone backend")

	// ErrNilSender indicates a nil Sender was passed to RegisterPhoneBackend.
	ErrNilSender = errors.New("server: sender must not be nil")

	// ErrJWTPublicKeyRequired indicates JWT authentication requires a public key file.
	ErrJWTPublicKeyRequired = errors.New("server: JWT authentication requires public_key_file configuration")

	// ErrJWTConfigRequired indicates JWT configuration is required but missing.
	ErrJWTConfigRequired = errors.New("server: JWT configuration is required")

	// ErrMTLSRequiresTLS indicates mTLS authentication requires TLS to be enabled.
	ErrMTLSRequiresTLS = errors.New("server: mTLS authentication requires TLS to be enabled")

	// ErrCompositeMethodsRequired indicates composite authentication requires at least one method.
	ErrCompositeMethodsRequired = errors.New("server: composite authentication requires at least one method in composite.methods")

	// ErrCompositeJWTRequired indicates composite authentication method 'jwt' requires JWT configuration.
	ErrCompositeJWTRequired = errors.New("server: composite authentication method 'jwt' requires JWT configuration")

	// ErrCompositeMTLSRequiresTLS indicates composite authentication method 'mtls' requires TLS.
	ErrCompositeMTLSRequiresTLS = errors.New("server: composite authentication method 'mtls' requires TLS to be enabled")

	// ErrUnknownCompositeMethod indicates an unknown composite authentication method was specified.
	ErrUnknownCompositeMethod = errors.New("server: unknown composite authentication method")

	// ErrTLSNotEnabled indicates TLS is not enabled in configuration.
	ErrTLSNotEnabled = errors.New("server: TLS is not enabled in configuration")

	// ErrParsePublicKey indicates a public key could not be parsed.
	ErrParsePublicKey = errors.New("server: unable to parse public key")

	// ErrCANotInitialized indicates the CA has not been initialized yet.
	ErrCANotInitialized = errors.New("server: CA not initialized")

	// ErrCALoadFailed indicates the CA failed to load from storage.
	ErrCALoadFailed = errors.New("server: failed to load CA")

	// ErrCATLSCertFailed indicates the CA failed to provide a TLS certificate.
	ErrCATLSCertFailed = errors.New("server: CA failed to provide TLS certificate")

	// ErrCredentialServiceFailed indicates the credential service failed to initialize.
	ErrCredentialServiceFailed = errors.New("server: failed to initialize credential service")

	// ErrEscrowRegistryFailed indicates the external key-escrow agent
	// registry failed to initialize from config.Escrow.
	ErrEscrowRegistryFailed = errors.New("server: failed to initialize escrow registry")

	// ErrBackendNotCompiled indicates a backend was requested but not compiled in.
	ErrBackendNotCompiled = errors.New("server: backend not compiled in")

	// ErrNoBackendsInitialized indicates no backends were initialized.
	ErrNoBackendsInitialized = errors.New("server: no backends initialized")

	// ErrNoKeystoresInitialized indicates no keystores were initialized.
	ErrNoKeystoresInitialized = errors.New("server: no keystores initialized")

	// ErrNoBackendsAvailable indicates no full-service backends are available.
	ErrNoBackendsAvailable = errors.New("server: no backends available - at least one full-service backend must be initialized")

	// ErrNoTLSCertAvailable indicates no TLS certificate is available.
	ErrNoTLSCertAvailable = errors.New("server: no TLS certificate available: configure CA or TLS cert/key files")

	// ErrCANoIdentities indicates the CA configuration has no identities.
	ErrCANoIdentities = errors.New("server: CA configuration has no identities")

	// ErrCAParseCert indicates a CA certificate could not be parsed.
	ErrCAParseCert = errors.New("server: failed to parse CA certificate")

	// ErrCAFileNotConfigured indicates no CA file is configured.
	ErrCAFileNotConfigured = errors.New("server: no CA file configured")

	// ErrCAFileReadFailed indicates the CA file could not be read.
	ErrCAFileReadFailed = errors.New("server: failed to read CA file")

	// ErrCAParseFailed indicates the CA certificate could not be parsed.
	ErrCAParseFailed = errors.New("server: failed to parse CA certificate PEM")
)

// ErrAdaptiveRemoved reports the removed "adaptive" auth mode with its
// replacement spelled out. Adaptive existed to bridge the window before any
// credential existed; first boot now provisions the administrator and their
// mTLS credential at startup, so the window is gone and the mode with it.
type ErrAdaptiveRemoved struct{}

// Error names the removed mode and the replacement configuration.
func (e *ErrAdaptiveRemoved) Error() string {
	return "server: auth.type \"adaptive\" was removed: use auth.type \"composite\" " +
		"(derives the jwt+mtls session-vehicle chain automatically; the first-boot " +
		"administrator authenticates with the generated mTLS credential from the first request)"
}

// ErrBackendInit represents a failure to initialize a specific backend.
type ErrBackendInit struct {
	Backend string
	Err     error
}

// Error returns the error message.
func (e *ErrBackendInit) Error() string {
	return fmt.Sprintf("failed to initialize %s backend: %s", e.Backend, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBackendInit) Unwrap() error {
	return e.Err
}

// ErrStorageCreate represents a failure to create a storage resource.
type ErrStorageCreate struct {
	Resource string
	Err      error
}

// Error returns the error message.
func (e *ErrStorageCreate) Error() string {
	return fmt.Sprintf("failed to create %s: %s", e.Resource, e.Err)
}

// QRDBNodeError reports a failure constructing or closing the in-process qrdb
// node that xkms hosts as its core engine.
type QRDBNodeError struct {
	Stage string
	Err   error
}

// Error returns the error message.
func (e *QRDBNodeError) Error() string {
	return fmt.Sprintf("qrdb node: %s: %s", e.Stage, e.Err)
}

// Unwrap returns the wrapped cause.
func (e *QRDBNodeError) Unwrap() error { return e.Err }

// Unwrap returns the underlying error.
func (e *ErrStorageCreate) Unwrap() error {
	return e.Err
}

// ErrBackendCreate represents a failure to create a specific backend.
type ErrBackendCreate struct {
	Backend string
	Err     error
}

// Error returns the error message.
func (e *ErrBackendCreate) Error() string {
	return fmt.Sprintf("failed to create %s backend: %s", e.Backend, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBackendCreate) Unwrap() error {
	return e.Err
}

// ErrConfigRequired represents a missing required configuration field.
type ErrConfigRequired struct {
	Field   string
	Backend string
	Hint    string
}

// Error returns the error message.
func (e *ErrConfigRequired) Error() string {
	msg := fmt.Sprintf("%s is required for %s backend", e.Field, e.Backend)
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// ErrKeystoreCreate represents a failure to create a keystore for a backend.
type ErrKeystoreCreate struct {
	Backend string
	Err     error
}

// Error returns the error message.
func (e *ErrKeystoreCreate) Error() string {
	return fmt.Sprintf("failed to create keystore for backend '%s': %s", e.Backend, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrKeystoreCreate) Unwrap() error {
	return e.Err
}

// ErrServiceInit represents a failure to initialize a server subsystem.
// When Sentinel is set, errors.Is will match both the Sentinel and the wrapped Err.
type ErrServiceInit struct {
	Service  string
	Err      error
	Sentinel error
}

// Error returns the error message.
func (e *ErrServiceInit) Error() string {
	return fmt.Sprintf("failed to initialize %s: %s", e.Service, e.Err)
}

// Unwrap returns the error chain. When Sentinel is set, both Sentinel and Err
// are part of the chain so errors.Is matches either.
func (e *ErrServiceInit) Unwrap() []error {
	if e.Sentinel != nil {
		return []error{e.Sentinel, e.Err}
	}
	return []error{e.Err}
}

// ErrConfigReload represents a failure to reload server configuration.
type ErrConfigReload struct {
	Component string
	Err       error
}

// Error returns the error message.
func (e *ErrConfigReload) Error() string {
	return fmt.Sprintf("failed to reload %s configuration: %s", e.Component, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrConfigReload) Unwrap() error {
	return e.Err
}

// ErrUnknownBackendType indicates an unknown backend type was specified.
type ErrUnknownBackendType struct {
	Type string
}

// Error returns the error message.
func (e *ErrUnknownBackendType) Error() string {
	return fmt.Sprintf("unknown backend type: %s", e.Type)
}

// ErrUnknownPINStrategy indicates an unknown PIN strategy was specified.
type ErrUnknownPINStrategy struct {
	Strategy string
}

// Error returns the error message.
func (e *ErrUnknownPINStrategy) Error() string {
	return fmt.Sprintf("unknown PIN strategy: %s", e.Strategy)
}

// ErrBackendNotAvailable indicates a requested backend is not available.
type ErrBackendNotAvailable struct {
	Backend string
	Purpose string
}

// Error returns the error message.
func (e *ErrBackendNotAvailable) Error() string {
	if e.Purpose != "" {
		return fmt.Sprintf("backend %q not available for %s", e.Backend, e.Purpose)
	}
	return fmt.Sprintf("backend %q not available", e.Backend)
}

// ErrCAInit represents a failure during CA initialization.
type ErrCAInit struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrCAInit) Error() string {
	return fmt.Sprintf("failed to %s: %s", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCAInit) Unwrap() error {
	return e.Err
}

// ErrTLSCertOp represents a failure during a TLS certificate operation.
// When Sentinel is set, errors.Is will match both the Sentinel and the wrapped Err.
// ErrTLSCertChainCAUnavailable is the cause of an ErrTLSCertOp when a
// reissued TLS server certificate needs its chain stored but the CA
// certificate that completes the chain cannot be loaded or is absent.
var ErrTLSCertChainCAUnavailable = errors.New("server: CA certificate unavailable for the TLS certificate chain")

type ErrTLSCertOp struct {
	Operation string
	Err       error
	Sentinel  error
}

// Error returns the error message.
func (e *ErrTLSCertOp) Error() string {
	return fmt.Sprintf("failed to %s: %s", e.Operation, e.Err)
}

// Unwrap returns the error chain. When Sentinel is set, both Sentinel and Err
// are part of the chain so errors.Is matches either.
func (e *ErrTLSCertOp) Unwrap() []error {
	if e.Sentinel != nil {
		return []error{e.Sentinel, e.Err}
	}
	return []error{e.Err}
}

// ErrCompositeMethodCreate represents a failure to create an authenticator for a composite method.
type ErrCompositeMethodCreate struct {
	Method string
	Err    error
}

// Error returns the error message.
func (e *ErrCompositeMethodCreate) Error() string {
	return fmt.Sprintf("failed to create %s authenticator for composite: %s", e.Method, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCompositeMethodCreate) Unwrap() error {
	return e.Err
}

// ErrFileRead represents a failure to read a file.
type ErrFileRead struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e *ErrFileRead) Error() string {
	return fmt.Sprintf("failed to read %s: %s", e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrFileRead) Unwrap() error {
	return e.Err
}

// ErrCertParse represents a failure to parse a certificate at a specific path.
type ErrCertParse struct {
	Path string
}

// Error returns the error message.
func (e *ErrCertParse) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to parse additional client CA certificate at %s", e.Path)
	}
	return "failed to parse CA certificate"
}

// ErrNotCompiledIn represents a backend that was not compiled into the binary.
type ErrNotCompiledIn struct {
	Backend string
	Tag     string
}

// Error returns the error message.
func (e *ErrNotCompiledIn) Error() string {
	return fmt.Sprintf("%s: %s (use -tags %s)", ErrBackendNotCompiled, e.Backend, e.Tag)
}

// Unwrap returns the sentinel ErrBackendNotCompiled so errors.Is works.
func (e *ErrNotCompiledIn) Unwrap() error {
	return ErrBackendNotCompiled
}

// ErrCABundleGet represents a failure to get the CA bundle.
type ErrCABundleGet struct {
	Operation string
	Err       error
}

// Error returns the error message.
func (e *ErrCABundleGet) Error() string {
	return fmt.Sprintf("failed to get %s: %s", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrCABundleGet) Unwrap() error {
	return e.Err
}

// ErrSealStrategyBuild represents a failure constructing a hardware or cloud
// sealing strategy from an already-initialized backend. Strategy names the
// barrier strategy ID that failed; Err carries the underlying cause.
type ErrSealStrategyBuild struct {
	Strategy string
	Err      error
}

// Error returns the error message.
func (e *ErrSealStrategyBuild) Error() string {
	return fmt.Sprintf("failed to build %s seal strategy: %s", e.Strategy, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrSealStrategyBuild) Unwrap() error {
	return e.Err
}

// ErrPlatformStoreBuild represents a failure constructing the platform
// store's sealer or its sealed storage backend for the configured
// credentials.seal_strategy. Strategy names the strategy that failed; Err
// carries the underlying cause.
type ErrPlatformStoreBuild struct {
	Strategy string
	Err      error
}

// Error returns the error message.
func (e *ErrPlatformStoreBuild) Error() string {
	return fmt.Sprintf("failed to build platform store for strategy %q: %s", e.Strategy, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrPlatformStoreBuild) Unwrap() error {
	return e.Err
}

// ErrPlatformStoreStrategyUnavailable represents a credentials.seal_strategy
// that initializePlatformStore cannot build a sealer for. Reason explains
// why: a real structural dependency (e.g. a secret only resolvable once the
// credential service the platform store itself gates exists), not a stub —
// startup fails closed rather than silently skipping the store.
type ErrPlatformStoreStrategyUnavailable struct {
	Strategy string
	Reason   string
}

// Error returns the error message.
func (e *ErrPlatformStoreStrategyUnavailable) Error() string {
	return fmt.Sprintf("platform store: strategy %q is not available: %s", e.Strategy, e.Reason)
}

// ErrSealBackendNotConfigured indicates a hardware/cloud seal strategy was
// listed in the barrier preference order but its backend is not configured or
// not compiled into the binary, so no sealer is available to back it.
type ErrSealBackendNotConfigured struct {
	Strategy string
}

// Error returns the error message.
func (e *ErrSealBackendNotConfigured) Error() string {
	return fmt.Sprintf("seal strategy %q selected in barrier preference order but its backend is not configured", e.Strategy)
}

// ErrUnsupportedStorageBackend indicates an unsupported storage backend was specified.
type ErrUnsupportedStorageBackend struct {
	Backend string
}

// Error returns the error message.
func (e *ErrUnsupportedStorageBackend) Error() string {
	return fmt.Sprintf("unsupported storage backend: %s", e.Backend)
}

// ErrUnknownAuthType indicates the configured auth.type is not a recognized
// authentication method. It is fatal: falling back to an unauthenticated server
// would turn a configuration typo into a silently wide-open API. The only ways
// to run without authentication are the explicit opt-ins auth.enabled=false or
// auth.type="none"/"noop", both of which are reported by
// config.ComplianceGaps() and therefore cannot start cmd/xkmsd at all: the
// daemon refuses a configuration with any gap and offers no override. This
// package stays permissive so embedded and test callers can still construct an
// unauthenticated server deliberately.
type ErrUnknownAuthType struct {
	Type string
}

// Error returns the error message.
func (e *ErrUnknownAuthType) Error() string {
	return fmt.Sprintf(
		"server: unknown auth.type %q: valid types are \"jwt\", \"mtls\", \"composite\", "+
			"or \"none\"/\"noop\" to disable authentication explicitly", e.Type)
}

// ErrNoBootstrapSuite reports that the bootstrap listener was enabled but this
// binary can run neither handshake suite, so there is nothing to serve.
//
// It is raised while the listener is being CONFIGURED rather than at key
// generation inside the accept loop. A FIPS build cannot run Noise_NK -- it
// mandates X25519, which SP 800-56A Rev. 3 does not approve -- and before this
// existed such a build bound no bootstrap listener at all while logging only
// the key-generation failure, so the missing service looked like a connectivity
// problem to every client and like nothing at all to the operator.
//
// Both fields carry the reason the corresponding suite was rejected, each
// wrapping bootstrap.ErrSuiteUnavailable, and both are exposed through Unwrap
// so errors.Is reaches them.
type ErrNoBootstrapSuite struct {
	// Noise is why Noise_NK_25519_ChaChaPoly_SHA256 is unavailable.
	Noise error

	// P256 is why TSBOOT1_P256_AESGCM_SHA256 is unavailable. The approved
	// suite is available in every build, so a non-nil value here means
	// go-truststrap itself could not generate a key.
	P256 error
}

// Error returns the error message.
func (e *ErrNoBootstrapSuite) Error() string {
	return fmt.Sprintf(
		"server: bootstrap is enabled but this build can run no handshake suite: "+
			"Noise_NK: %v; TSBOOT1_P256_AESGCM_SHA256: %v", e.Noise, e.P256)
}

// Unwrap exposes both rejection reasons so errors.Is and errors.As reach the
// suite-level sentinels behind them.
func (e *ErrNoBootstrapSuite) Unwrap() []error {
	return []error{e.Noise, e.P256}
}

// ErrP256KeyLength reports a configured P-256 bootstrap static key whose
// hex-encoded form is the wrong length -- a truncated file, a stray character,
// or a value that is not a scalar at all.
//
// It does NOT catch a Curve25519 key pasted into the P-256 field: both curves
// use a 32-byte scalar, so both encode to 64 hex characters. That mistake
// produces a valid key that simply is not the one clients pinned, and it is
// caught by comparing the served public key against the distributed one, not
// by any length check.
type ErrP256KeyLength struct {
	Got  int
	Want int
}

// Error returns the error message.
func (e *ErrP256KeyLength) Error() string {
	return fmt.Sprintf(
		"server: P-256 bootstrap static key is %d hex characters, want %d",
		e.Got, e.Want)
}

// ErrFileWrite represents a failure to write a file.
type ErrFileWrite struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e *ErrFileWrite) Error() string {
	return fmt.Sprintf("failed to write %s: %s", e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrFileWrite) Unwrap() error {
	return e.Err
}

// ErrBarrierKeyLoad represents a failure to read a bootstrap static key from
// the barrier's sealed storage that is NOT "no key stored yet" (see
// isBarrierKeyNotFound in bootstrap_key_custody.go, which callers treat as
// "fall back to legacy config or generate", not as a failure). A sealed
// barrier, a corrupt ciphertext, or an underlying storage error all surface
// here.
type ErrBarrierKeyLoad struct {
	Key string
	Err error
}

// Error returns the error message.
func (e *ErrBarrierKeyLoad) Error() string {
	return fmt.Sprintf("failed to load barrier-sealed key %q: %s", e.Key, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBarrierKeyLoad) Unwrap() error {
	return e.Err
}

// ErrBarrierKeySeal represents a failure to seal a bootstrap static key into
// the barrier's storage, whether the failure is in hex-encoding the key or in
// the barrier's own Put.
type ErrBarrierKeySeal struct {
	Key string
	Err error
}

// Error returns the error message.
func (e *ErrBarrierKeySeal) Error() string {
	return fmt.Sprintf("failed to seal key %q into the barrier: %s", e.Key, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrBarrierKeySeal) Unwrap() error {
	return e.Err
}

// ErrConfigSecretResolution reports that resolveConfigSecrets found at least
// one secret-bearing config field whose reference this server's secret
// registry claimed but could not resolve -- a genuine credential-store
// failure. It does NOT cover an unconfigured or literal field: the walker
// reports those too, as qrdbsecret.UnresolvableTargetError, but
// resolveConfigSecrets treats them as expected and excludes them here. Err is
// the joined set of underlying go-qrdb secret errors (typically one or more
// *qrdbsecret.ResolutionFailedError).
type ErrConfigSecretResolution struct {
	Err error
}

// Error returns the error message.
func (e *ErrConfigSecretResolution) Error() string {
	return fmt.Sprintf("failed to resolve config secret reference(s): %s", e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrConfigSecretResolution) Unwrap() error {
	return e.Err
}

// ErrFrostSecretBackendUnavailable indicates backends.frost.secret_backend
// names a backend that is not present in s.keyProviders at the point FROST
// initializes. config.Config.Validate already refuses a secret_backend
// naming a section that is absent or disabled, so reaching this at runtime
// means the named backend's own initialization failed earlier in
// initializeBackends, or it requires a build tag this binary was not built
// with (e.g. pkcs11 without -tags pkcs11) — not a plain config mistake.
type ErrFrostSecretBackendUnavailable struct {
	Backend string
}

// Error returns the error message.
func (e *ErrFrostSecretBackendUnavailable) Error() string {
	return fmt.Sprintf("FROST backends.frost.secret_backend %q is not an initialized backend", e.Backend)
}
