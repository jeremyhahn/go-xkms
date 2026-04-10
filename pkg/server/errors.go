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

	// ErrAuditPathRequired indicates audit logging requires a path to be configured.
	ErrAuditPathRequired = errors.New("server: audit logging requires a path to be configured")

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

	// ErrBackendNotCompiled indicates a backend was requested but not compiled in.
	ErrBackendNotCompiled = errors.New("server: backend not compiled in")

	// ErrNoBackendsInitialized indicates no backends were initialized.
	ErrNoBackendsInitialized = errors.New("server: no backends initialized")

	// ErrNoKeystoresInitialized indicates no keystores were initialized.
	ErrNoKeystoresInitialized = errors.New("server: no keystores initialized")

	// ErrNoBackendsAvailable indicates no full-service backends are available.
	ErrNoBackendsAvailable = errors.New("server: no backends available - at least one full-service backend must be initialized")

	// ErrBootstrapRequiresUserStore indicates the bootstrap service requires a user store.
	ErrBootstrapRequiresUserStore = errors.New("server: bootstrap service requires user store")

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

// ErrUnsupportedStorageBackend indicates an unsupported storage backend was specified.
type ErrUnsupportedStorageBackend struct {
	Backend string
}

// Error returns the error message.
func (e *ErrUnsupportedStorageBackend) Error() string {
	return fmt.Sprintf("unsupported storage backend: %s", e.Backend)
}
