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

package xkms

import (
	webauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// WebAuthn relying-party re-exports (from pkg/webauthn and
// pkg/webauthn/http). pkg/webauthn is the single canonical WebAuthn RP
// implementation in the stack; downstream composers wire it through these
// SDK aliases only.

// WebAuthnConfig configures the WebAuthn relying party (RP ID, origins,
// attestation preferences).
type WebAuthnConfig = webauthn.Config

// WebAuthnService is the canonical WebAuthn relying-party service
// (registration + assertion ceremonies, challenge/session state).
type WebAuthnService = webauthn.Service

// WebAuthnServiceParams carries the dependencies for NewWebAuthnService.
type WebAuthnServiceParams = webauthn.ServiceParams

// NewWebAuthnService constructs the WebAuthn relying-party service.
var NewWebAuthnService = webauthn.NewService

// NewWebAuthnMemorySessionStore constructs the in-memory ceremony session
// store with the default TTL.
var NewWebAuthnMemorySessionStore = webauthn.NewMemorySessionStore

// WebAuthnCredentialStore is the persistence contract the relying party
// saves and reads passkey credentials through. A composer implements or
// wraps it to attach its own persistence side effects — see
// WithServiceModuleWebAuthnCredentialStoreDecorator.
type WebAuthnCredentialStore = webauthn.CredentialStore

// WebAuthnCredential is the stored passkey record: credential id, user
// handle, public key, sign counter, and transports.
type WebAuthnCredential = webauthn.Credential

// WebAuthnQRDBUserStoreOptions configures the qrdb-backed WebAuthn user and
// credential store adapter.
type WebAuthnQRDBUserStoreOptions = webauthn.QRDBUserStoreOptions

// NewWebAuthnQRDBUserStoreAdapter constructs qrdb-backed WebAuthn user and
// credential stores from the given options.
var NewWebAuthnQRDBUserStoreAdapter = webauthn.NewQRDBUserStoreAdapter

// ErrWebAuthnNoCredentials is returned when a WebAuthn login ceremony is
// requested for a user that has no registered credentials. Downstream
// composers compare against this sentinel (errors.Is) to surface the
// "no passkey enrolled" case distinctly from other login failures.
var ErrWebAuthnNoCredentials = webauthn.ErrNoCredentials

// WebAuthnLegacyCredentialMigration names the shared legacy keyspace, the
// qrdb user client that resolves each credential's tenant, and the tenant
// credential store MigrateWebAuthnLegacyCredentials moves credentials into.
type WebAuthnLegacyCredentialMigration = webauthn.LegacyCredentialMigration

// WebAuthnCredentialMigrationReport counts the credentials one run
// migrated, skipped (another tenant's) and failed to move.
type WebAuthnCredentialMigrationReport = webauthn.CredentialMigrationReport

// MigrateWebAuthnLegacyCredentials moves the tenant's enrolled WebAuthn
// credentials out of the shared "__xkms:webauthn/credentials/" keyspace into
// the tenant's credential store, deleting each legacy key only after the
// new record is saved. Call it each time a tenant's credential store is
// opened (the store returned by NewWebAuthnQRDBUserStoreAdapter), before
// serving a ceremony from it. It is idempotent: a second run migrates
// nothing. A credential that cannot be moved is reported, never dropped:
// the run returns a *WebAuthnCredentialMigrationIncompleteError with the
// report.
var MigrateWebAuthnLegacyCredentials = webauthn.MigrateLegacyCredentials

// WebAuthnCredentialMigrationIncompleteError is returned when any legacy
// record was left in place; its Failures carry the per-record errors below.
type WebAuthnCredentialMigrationIncompleteError = webauthn.CredentialMigrationIncompleteError

// WebAuthnCredentialMigrationConfigError reports a missing migration field.
type WebAuthnCredentialMigrationConfigError = webauthn.CredentialMigrationConfigError

// WebAuthnLegacyCredentialScanError reports a legacy keyspace that cannot be
// read, such as one behind a sealed barrier.
type WebAuthnLegacyCredentialScanError = webauthn.LegacyCredentialScanError

// WebAuthnLegacyCredentialCorruptError reports a legacy record that does not
// decode to the credential its key names.
type WebAuthnLegacyCredentialCorruptError = webauthn.LegacyCredentialCorruptError

// WebAuthnCredentialOwnerUnresolvedError reports a legacy credential whose
// user or tenant cannot be resolved.
type WebAuthnCredentialOwnerUnresolvedError = webauthn.CredentialOwnerUnresolvedError

// WebAuthnCredentialMoveError reports a failed save or legacy delete.
type WebAuthnCredentialMoveError = webauthn.CredentialMoveError

// WebAuthnUser is the interface a WebAuthn account entity satisfies.
type WebAuthnUser = webauthn.User

// WebAuthnDefaultUser is the default WebAuthnUser implementation.
type WebAuthnDefaultUser = webauthn.DefaultUser

// WebAuthnHTTPHandler serves the WebAuthn registration and assertion
// ceremony HTTP endpoints for a WebAuthnService.
type WebAuthnHTTPHandler = webauthnhttp.Handler

// NewWebAuthnHTTPHandler constructs the WebAuthn ceremony HTTP handler.
var NewWebAuthnHTTPHandler = webauthnhttp.NewHandler

// WebAuthnUserStore is the user persistence contract a WebAuthnService
// resolves users and credentials through.
type WebAuthnUserStore = webauthn.UserStore

// ErrWebAuthnCredentialNotFound reports a credential ID the user store
// does not hold.
var ErrWebAuthnCredentialNotFound = webauthn.ErrCredentialNotFound

// IsWebAuthnUserNotFound reports whether err means the user does not exist.
var IsWebAuthnUserNotFound = webauthn.IsUserNotFound

// IsWebAuthnCredentialNotFound reports whether err means the credential
// does not exist.
var IsWebAuthnCredentialNotFound = webauthn.IsCredentialNotFound

// WebAuthnUserIDFromHandle decodes a WebAuthn user handle into the numeric
// user ID the QRDB user store assigns.
var WebAuthnUserIDFromHandle = webauthn.UserIDFromHandle

// WebAuthnAuthResponse is the ceremony HTTP response that carries the
// session after a finished login or registration.
type WebAuthnAuthResponse = webauthnhttp.AuthResponse

// WebAuthnBeginLoginRequest is the ceremony HTTP body that starts a login.
type WebAuthnBeginLoginRequest = webauthnhttp.BeginLoginRequest

// WebAuthnErrorResponse is the ceremony HTTP error body.
type WebAuthnErrorResponse = webauthnhttp.ErrorResponse

// WebAuthnHeaderSessionID is the header that carries the ceremony session ID.
const WebAuthnHeaderSessionID = webauthnhttp.HeaderSessionID

// WebAuthn ceremony HTTP error codes (WebAuthnErrorResponse.Code).
const (
	WebAuthnErrorCodeInvalidRequest         = webauthnhttp.ErrorCodeInvalidRequest
	WebAuthnErrorCodeInvalidSession         = webauthnhttp.ErrorCodeInvalidSession
	WebAuthnErrorCodeSessionExpired         = webauthnhttp.ErrorCodeSessionExpired
	WebAuthnErrorCodeUserNotFound           = webauthnhttp.ErrorCodeUserNotFound
	WebAuthnErrorCodeNoCredentials          = webauthnhttp.ErrorCodeNoCredentials
	WebAuthnErrorCodeVerificationFailed     = webauthnhttp.ErrorCodeVerificationFailed
	WebAuthnErrorCodeRegistrationRefused    = webauthnhttp.ErrorCodeRegistrationRefused
	WebAuthnErrorCodeSessionLimit           = webauthnhttp.ErrorCodeSessionLimit
	WebAuthnErrorCodeInternalError          = webauthnhttp.ErrorCodeInternalError
	WebAuthnErrorCodeUnauthenticated        = webauthnhttp.ErrorCodeUnauthenticated
	WebAuthnErrorCodeSessionAccountMismatch = webauthnhttp.ErrorCodeSessionAccountMismatch
	WebAuthnErrorCodeCredentialExists       = webauthnhttp.ErrorCodeCredentialExists
)

// WebAuthnMountChi mounts the ceremony routes on a chi router.
var WebAuthnMountChi = webauthnhttp.MountChi

// WebAuthnMountMux mounts the ceremony routes on a gorilla/mux *mux.Router.
var WebAuthnMountMux = webauthnhttp.MountMux

// WebAuthnMountStdlib mounts the ceremony routes on a net/http ServeMux
// under a prefix.
var WebAuthnMountStdlib = webauthnhttp.MountStdlib

// WebAuthnRouteEntry describes one ceremony route (method, path, handler).
type WebAuthnRouteEntry = webauthnhttp.RouteEntry

// NewWebAuthnFIDO2Servicer wraps a WebAuthnService in the canonical FIDO2
// transport-servicer adapter — the same ceremony adaptation (options
// marshaling, attestation/assertion parsing, user resolution) the
// XKMSService singleton performs. Composers that manage per-tenant
// relying-party services use it to expose the transport FIDO2 wire shape
// (BeginRegistration / FinishRegistration / BeginAuthentication /
// FinishAuthentication) without initializing the singleton.
var NewWebAuthnFIDO2Servicer = pkgxkms.NewFIDO2Servicer
