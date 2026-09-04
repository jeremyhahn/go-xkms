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

// WebAuthnUser is the interface a WebAuthn account entity satisfies.
type WebAuthnUser = webauthn.User

// WebAuthnDefaultUser is the default WebAuthnUser implementation.
type WebAuthnDefaultUser = webauthn.DefaultUser

// WebAuthnHTTPHandler serves the WebAuthn registration and assertion
// ceremony HTTP endpoints for a WebAuthnService.
type WebAuthnHTTPHandler = webauthnhttp.Handler

// NewWebAuthnHTTPHandler constructs the WebAuthn ceremony HTTP handler.
var NewWebAuthnHTTPHandler = webauthnhttp.NewHandler

// NewWebAuthnFIDO2Servicer wraps a WebAuthnService in the canonical FIDO2
// transport-servicer adapter — the same ceremony adaptation (options
// marshaling, attestation/assertion parsing, user resolution) the
// XKMSService singleton performs. Composers that manage per-tenant
// relying-party services use it to expose the transport FIDO2 wire shape
// (BeginRegistration / FinishRegistration / BeginAuthentication /
// FinishAuthentication) without initializing the singleton.
var NewWebAuthnFIDO2Servicer = pkgxkms.NewFIDO2Servicer
